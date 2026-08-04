"""نقطة تشغيل Mini SIEM Dashboard."""
import secrets
import csv
import time
import platform
import os
from collections import defaultdict, deque
from io import BytesIO, StringIO
from flask import Flask, abort, flash, redirect, render_template, request, send_file, session, url_for
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename
from config import (ADMIN_PASSWORD_HASH, ADMIN_USERNAME, ALLOWED_EXTENSIONS, DEV_TOOLS, LOCAL_SOURCES_ENABLED, MAX_CONTENT_LENGTH,
                    SECRET_KEY, UPLOAD_DIR, UPLOAD_RATE_LIMIT)
from database import (cleanup_data, clear_all_data, create_upload, dashboard_data, enrich_iocs, finish_upload, get_alert, init_db, list_alerts,
                      get_event, list_events, list_iocs, save_alerts, save_events, save_iocs, update_alert_state)
from detector import run_detection
from ioc import extract_iocs
from sanitizer import sanitize
from local_sources import read_source, source_status, sources
from parser import parse_file_text, parse_evtx_bytes

app = Flask(__name__)
app.config.update(SECRET_KEY=SECRET_KEY, MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH, MAX_FORM_MEMORY_SIZE=MAX_CONTENT_LENGTH, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=os.environ.get("MINI_SIEM_COOKIE_SECURE","0")=="1")
init_db()
UPLOAD_DIR.mkdir(exist_ok=True)
_upload_attempts = defaultdict(deque)


def allowed_file(name):
    return "." in name and name.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def valid_mime(file):
    """Browser MIME is only a hint; reject clearly executable/archive payloads."""
    mime = (file.mimetype or "").lower()
    return mime.startswith("text/") or mime in {
        "application/octet-stream", "application/json", "application/xml",
        "text/xml", "text/csv", "application/vnd.ms-evtx"
    }

@app.context_processor
def add_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return {"csrf_token": session["csrf_token"], "auth_configured": bool(ADMIN_PASSWORD_HASH), "local_sources_enabled": LOCAL_SOURCES_ENABLED}

@app.before_request
def verify_csrf_token():
    if request.method == "POST":
        supplied = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not secrets.compare_digest(supplied, expected):
            abort(400)

@app.before_request
def require_login_and_rate_limit():
    if ADMIN_PASSWORD_HASH and request.endpoint not in {"login", "static"} and not session.get("authenticated"):
        return redirect(url_for("login", next=request.path))
    if request.endpoint in {"upload", "sanitizer_page"} and request.method == "POST":
        key = request.remote_addr or "unknown"
        now = time.monotonic(); attempts = _upload_attempts[key]
        while attempts and now - attempts[0] > 600: attempts.popleft()
        if len(attempts) >= UPLOAD_RATE_LIMIT:
            flash("تم تجاوز عدد محاولات الرفع المسموح. حاولي بعد عشر دقائق.", "error")
            return redirect(request.path)
        attempts.append(now)

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"
    response.headers["Cache-Control"] = "no-store"
    return response

@app.route("/login", methods=["GET", "POST"])
def login():
    if not ADMIN_PASSWORD_HASH:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if secrets.compare_digest(username, ADMIN_USERNAME) and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session.clear(); session["authenticated"] = True; session["csrf_token"] = secrets.token_urlsafe(32)
            return redirect(url_for("dashboard"))
        flash("اسم المستخدم أو كلمة المرور غير صحيحة.", "error")
    return render_template("login.html")

@app.post("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))

def _decode_text(content):
    if content.startswith((b'\xff\xfe', b'\xfe\xff')):
        return content.decode("utf-16")
    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("ترميز الملف غير مدعوم. احفظيه بصيغة UTF-8 أو UTF-16.") from exc

def _analyze(filename, log_type, content):
    if filename.lower().endswith('.evtx'):
        events = parse_evtx_bytes(content)
        summary = {'total_lines': len(events), 'parsed_lines': len(events), 'rejected_lines': 0, 'rejections': []}
    else:
        text = _decode_text(content)
        if "\x00" in text: raise ValueError("الملف ثنائي وليس سجلًا نصيًا مدعومًا.")
        events, summary = parse_file_text(text, filename)
    if not events: raise ValueError("لم نجد أحداثًا مدعومة. راجعي صيغة الملف ونوع السجل.")
    file_id = create_upload(filename, log_type)
    saved = save_events(file_id, events); normalized = [dict(row) for row in saved]
    save_iocs(file_id, normalized, extract_iocs)
    alerts = run_detection(normalized); save_alerts(file_id, alerts)
    finish_upload(file_id, summary['total_lines'], len(saved), len(alerts), summary['rejected_lines'], summary['rejections'])
    return summary, len(saved), len(alerts)

@app.route("/")
def dashboard():
    days=request.args.get('range',0,type=int)
    if days not in {0,1,7,30}: days=0
    summary, charts, recent = dashboard_data(days)
    return render_template("dashboard.html", summary=summary, charts=charts, recent=recent, days=days)

@app.route("/health")
def health():
    return {"status": "ok"}

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        file = request.files.get("log_file")
        log_type = request.form.get("log_type", "Auto")
        if not file or not file.filename:
            flash("اختاري ملف سجل أولًا.", "error"); return redirect(url_for("upload"))
        if not allowed_file(file.filename) or not valid_mime(file):
            flash("نوع الملف غير مسموح. استخدمي LOG أو TXT أو CSV أو JSON أو XML أو EVTX.", "error"); return redirect(url_for("upload"))
        filename = secure_filename(file.filename)
        if not filename:
            flash("اسم الملف غير صالح.", "error"); return redirect(url_for("upload"))
        try:
            content = file.stream.read(MAX_CONTENT_LENGTH + 1)
            if len(content) > MAX_CONTENT_LENGTH:
                flash(f"حجم الملف أكبر من الحد المسموح ({MAX_CONTENT_LENGTH // 1024 // 1024}MB).", "error"); return redirect(url_for("upload"))
            parse_summary, event_count, alert_count = _analyze(filename, log_type, content)
            flash(f"تم التحليل: {parse_summary['total_lines']} سطرًا، {parse_summary['parsed_lines']} محللًا، {parse_summary['rejected_lines']} مرفوضًا، {alert_count} تنبيهًا.", "success")
            return redirect(url_for("dashboard"))
        except ValueError as exc:
            flash(str(exc), "error")
        except Exception:
            app.logger.exception("Upload analysis failed")
            flash("تعذر تحليل الملف بأمان. تأكدي من أن تنسيقه صحيح.", "error")
        return redirect(url_for("upload"))
    return render_template("upload.html")

@app.route("/events")
def events():
    page = max(request.args.get("page", 1, type=int), 1)
    filters = {key: request.args.get(key, "").strip() for key in ("search", "ip", "type", "severity")}
    sort = request.args.get("sort", "time_desc")
    rows, total, types = list_events(filters, page, sort=sort)
    return render_template("events.html", events=rows, total=total, types=types, filters=filters, sort=sort, page=page, pages=max(1, (total+19)//20))

@app.route("/events/<int:event_id>")
def event_details(event_id):
    event = get_event(event_id)
    if not event: abort(404)
    return render_template("event_details.html", event=event)

@app.route("/events.csv")
def events_csv():
    filters = {key: request.args.get(key, "").strip() for key in ("search", "ip", "type", "severity")}
    rows, _, _ = list_events(filters, 1, per_page=5000, sort=request.args.get("sort", "time_desc"))
    output = BytesIO(); text = StringIO(); writer = csv.writer(text)
    writer.writerow(["timestamp","source","source_ip","username","event_type","status","severity","provider","event_id","computer","raw_line"])
    for row in rows: writer.writerow([row[x] for x in ("event_time","source","source_ip","username","event_type","status","severity","provider","event_id","computer","raw_line")])
    output.write(('\ufeff'+text.getvalue()).encode('utf-8')); output.seek(0)
    return send_file(output, as_attachment=True, download_name="events.csv", mimetype="text/csv; charset=utf-8")

@app.route("/alerts")
def alerts(): return render_template("alerts.html", alerts=list_alerts())

@app.route("/iocs")
def iocs():
    from threat_intelligence import env
    configured=bool(env('ABUSEIPDB_API_KEY') or env('VIRUSTOTAL_API_KEY'))
    return render_template("iocs.html", iocs=list_iocs(), configured=configured)

@app.post("/iocs/enrich")
def enrich_iocs_page():
    from threat_intelligence import env
    if not (env('ABUSEIPDB_API_KEY') or env('VIRUSTOTAL_API_KEY')):
        abort(404)
    else:
        enrich_iocs(); flash("اكتمل تحديث مؤشرات الاختراق المتاحة.","success")
    return redirect(url_for('iocs'))

@app.post('/retention')
def retention():
    days=request.form.get('days',90,type=int); removed=cleanup_data(days)
    flash(f'تم حذف {removed} ملف تحليل أقدم من {days} يومًا. الملفات الأصلية لم تكن مخزنة.', 'success')
    return redirect(url_for('dashboard'))

@app.post('/clear-test-data')
def clear_test_data():
    if not DEV_TOOLS: abort(404)
    clear_all_data(); flash('تم مسح بيانات الاختبار المخزنة فقط.','success')
    return redirect(url_for('dashboard'))

@app.route("/sanitizer", methods=["GET", "POST"])
def sanitizer_page():
    if request.method=="POST":
        file=request.files.get("log_file"); mode=request.form.get("mode","redaction")
        if not file or not allowed_file(file.filename) or not valid_mime(file): flash("اختر ملف سجل نصي مسموحًا.","error"); return redirect(url_for("sanitizer_page"))
        content=file.stream.read(MAX_CONTENT_LENGTH+1)
        if len(content)>MAX_CONTENT_LENGTH or b"\x00" in content: flash("الملف غير صالح أو كبير جدًا.","error"); return redirect(url_for("sanitizer_page"))
        try: original=_decode_text(content)
        except ValueError as exc: flash(str(exc),"error"); return redirect(url_for("sanitizer_page"))
        try: cleaned,counts=sanitize(original,mode)
        except ValueError as exc: flash(str(exc),"error"); return redirect(url_for("sanitizer_page"))
        if request.form.get("download"):
            return send_file(BytesIO(cleaned.encode()),as_attachment=True,download_name="sanitized_"+secure_filename(file.filename),mimetype="text/plain")
        return render_template("sanitizer.html",before=original[:12000],preview=cleaned[:12000],counts=counts,mode=mode)
    return render_template("sanitizer.html",preview=None,counts=None,mode="redaction")

@app.route('/local-sources',methods=['GET','POST'])
def local_sources_page():
    if not LOCAL_SOURCES_ENABLED:
        abort(404)
    if request.method=='POST':
        key=request.form.get('source',''); limit=request.form.get('limit',100)
        try:
            text=read_source(key,limit); suffix='.json' if platform.system()=='Windows' else '.log'; events,parse_summary=parse_file_text(text,key+suffix)
            file_id=create_upload('Local source: '+key,'Local Device')
            saved=save_events(file_id,events); save_iocs(file_id,[dict(x) for x in saved],extract_iocs)
            alerts=run_detection([dict(x) for x in saved]); save_alerts(file_id,alerts); finish_upload(file_id,parse_summary['total_lines'],len(saved),len(alerts),parse_summary['rejected_lines'],parse_summary['rejections'])
            flash(f'تم استيراد {len(saved)} حدث من المصدر المحلي.','success')
        except PermissionError: flash('لا توجد صلاحية لقراءة هذا السجل. امنح صلاحية قراءة السجل فقط، ولا تشغل التطبيق كمسؤول.','error')
        except Exception as exc: flash(f'تعذر قراءة المصدر: {str(exc)}','error')
        return redirect(url_for('local_sources_page'))
    rows=[{'key':k,'location':v[0],'type':v[1],'status':source_status(k)} for k,v in sources().items()]
    return render_template('local_sources.html',sources=rows)

@app.route("/alerts/<int:alert_id>", methods=["GET", "POST"])
def alert_details(alert_id):
    if request.method == "POST":
        state = request.form.get("state")
        if state in {"New", "Investigating", "Closed"}:
            update_alert_state(alert_id, state); flash("تم تحديث حالة التنبيه.", "success")
        return redirect(url_for("alert_details", alert_id=alert_id))
    alert, linked = get_alert(alert_id)
    if not alert: flash("التنبيه غير موجود.", "error"); return redirect(url_for("alerts"))
    return render_template("alert_details.html", alert=alert, linked=linked)

@app.errorhandler(RequestEntityTooLarge)
def file_too_large(error):
    flash("حجم الملف أكبر من الحد المسموح (5MB).", "error")
    return redirect(url_for("upload"))

@app.errorhandler(400)
def bad_request(error):
    flash("تم حظر الطلب للحماية. حدّثي الصفحة ثم حاولي مرة أخرى.", "error")
    return redirect(request.referrer or url_for("dashboard"))

if __name__ == "__main__":
    init_db(); UPLOAD_DIR.mkdir(exist_ok=True)
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
