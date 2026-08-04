"""قواعد كشف تعليمية: لا تنفذ أو تفسر أي نص قادم من ملف السجل."""
from collections import defaultdict
from datetime import datetime, timedelta
import os

ERROR_CODES = {401, 403, 404}
SUSPICIOUS_PATHS = ("/admin", "/phpmyadmin", "/.env", "/wp-login.php", "/etc/passwd")
FAILED_LOGIN_THRESHOLD = max(2, int(os.getenv("FAILED_LOGIN_THRESHOLD", "5")))


def _windows(events, predicate, minimum, minutes=1):
    """يرجع مجموعات IP التي تحقق العدد المطلوب ضمن نافذة زمنية."""
    grouped = defaultdict(list)
    for event in events:
        value=event.get("event_time")
        if isinstance(value,str):
            try: event["event_time"]=datetime.fromisoformat(value)
            except ValueError: event["event_time"]=None
        if event["source_ip"] and event["event_time"] and predicate(event): grouped[event["source_ip"]].append(event)
    results = []
    for ip, group in grouped.items():
        group.sort(key=lambda x: x["event_time"])
        left = 0
        for right, current in enumerate(group):
            while current["event_time"] - group[left]["event_time"] > timedelta(minutes=minutes):
                left += 1
            window = group[left:right + 1]
            if len(window) >= minimum:
                results.append((ip, window))
                break
    return results


def run_detection(events):
    """يعيد تنبيهات متوافقة مع جدول alerts دون حفظها في قاعدة البيانات."""
    alerts = []

    def add(rule, title, severity, ip, selected, description):
        selected = sorted(selected, key=lambda x: x.get("event_time") or datetime.min)
        stamp = lambda value: value.isoformat(sep=" ") if isinstance(value, datetime) else value
        alerts.append({"rule_name": rule, "title": title, "severity": severity, "source_ip": ip,
                       "description": description, "first_seen": selected[0]["event_time"],
                       "last_seen": stamp(selected[-1]["event_time"]), "occurrences": len(selected),
                       "event_ids": [x["id"] for x in selected]})
        alerts[-1]["first_seen"] = stamp(alerts[-1]["first_seen"])

    for ip, group in _windows(events, lambda e: e["status"] == "Failed" and e["event_type"] in {"Login", "Windows Login"}, FAILED_LOGIN_THRESHOLD):
        add("brute_force", "Possible Brute Force", "High", ip, group, f"{FAILED_LOGIN_THRESHOLD} محاولات دخول فاشلة أو أكثر خلال دقيقة واحدة.")
    for ip, group in _windows(events, lambda e: e["event_type"] == "Invalid User", 3, 5):
        add("username_enumeration", "Username Enumeration", "Medium", ip, group, "تكرار أسماء مستخدمين غير صالحة من نفس العنوان.")
    for ip, group in _windows(events, lambda e: e["http_status"] in ERROR_CODES, 8):
        add("web_scanning", "Suspicious Web Scanning", "Medium", ip, group, "عدد كبير من أخطاء 401/403/404 خلال دقيقة.")
    for ip, group in _windows(events, lambda e: e["event_type"] == "HTTP Request", 51):
        add("high_request_rate", "High Request Rate", "High", ip, group, "أكثر من 50 طلب HTTP خلال دقيقة واحدة.")
    for ip, group in _windows(events, lambda e: e["http_status"] in {401,403}, 5):
        add("web_login_burst", "Possible Web Login Brute Force", "High", ip, group, "تكرار أخطاء 401 أو 403 من نفس العنوان خلال دقيقة.")
    for ip, group in _windows(events, lambda e: e["http_status"] == 500, 5):
        add("http_500_burst", "Repeated HTTP 500 Errors", "Medium", ip, group, "خمسة أخطاء HTTP 500 أو أكثر خلال دقيقة.")

    # قاعدة إضافية لسجلات Windows المحلية: أخطاء النظام تستحق لفت الانتباه فورًا.
    windows_errors = [e for e in events if e["source"] == "Windows System" and e["status"] in {"Error", "Critical"}]
    if windows_errors:
        windows_errors.sort(key=lambda x: x["event_time"] or __import__("datetime").datetime.min)
        add("windows_system_error", "Windows System Error", "High", None, windows_errors,
            "تم العثور على حدث أو أكثر بمستوى Error أو Critical في سجل Windows System.")
    windows_warnings = [e for e in events if e["source"] == "Windows System" and e["status"] == "Warning"]
    if len(windows_warnings) >= 5:
        windows_warnings.sort(key=lambda x: x["event_time"] or __import__("datetime").datetime.min)
        add("windows_system_warning", "Windows System Warning", "Medium", None, windows_warnings,
            "تم العثور على أحداث بمستوى Warning في سجل Windows System؛ راجعيها عند توفر الوقت.")
    # الأحداث المعلوماتية العادية لا تُحوّل إلى Alerts؛ تبقى قابلة للبحث في صفحة الأحداث.

    windows_information = [e for e in events if e["source"] == "Windows System" and e["status"] in {"Information", "Info"}]
    if windows_information:
        windows_information.sort(key=lambda x: x["event_time"] or __import__("datetime").datetime.min)
        add("windows_system_information", "Windows System Information", "Low", None, windows_information,
            "Informational Windows System events retained for educational review.")

    for event in events:
        eid = str(event.get("event_id") or "")
        if eid == "1102":
            add("audit_log_cleared", "Windows Audit Log Cleared", "Critical", event.get("source_ip"), [event], "تم مسح سجل التدقيق في Windows ويحتاج ذلك إلى تحقق فوري.")
        elif eid == "7045":
            add("service_installed", "Windows Service Installed", "High", event.get("source_ip"), [event], "تم تثبيت خدمة Windows جديدة؛ راجع اسم الخدمة والجهة المنفذة.")
        elif event.get("event_type") == "PowerShell Encoded Command":
            add("powershell_encoded", "PowerShell Encoded Command", "High", event.get("source_ip"), [event], "ظهر أمر PowerShell مشفر. قد يكون مشروعًا لكنه يستحق التحقق من السياق.")

    by_ip = defaultdict(list)
    for event in events:
        if event["source_ip"]:
            by_ip[event["source_ip"]].append(event)
        if event["path"] and any(marker in event["path"].lower() for marker in SUSPICIOUS_PATHS):
            title = "WordPress Login Request" if "/wp-login.php" in event["path"].lower() else "Sensitive Path Request"
            severity = "High" if "/etc/passwd" in event["path"].lower() else "Medium"
            add("suspicious_path", title, severity, event["source_ip"], [event],
                f"تم طلب مسار حساس: {event['path']}")
    for ip, group in by_ip.items():
        group.sort(key=lambda x: x["event_time"] or __import__("datetime").datetime.min)
        success_positions = [i for i, e in enumerate(group) if e["event_type"] in {"Login", "Windows Login"} and e["status"] == "Success"]
        for pos in success_positions:
            prior = [e for e in group[:pos] if e["event_type"] in {"Login", "Windows Login"} and e["status"] == "Failed"]
            if len(prior) >= 3:
                add("success_after_failure", "Suspicious Login Success", "High", ip, prior[-3:] + [group[pos]],
                    "نجاح تسجيل دخول بعد ثلاث محاولات فاشلة أو أكثر من نفس العنوان.")
                break
    return alerts
