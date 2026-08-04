"""طبقة SQLite صغيرة وواضحة للمشروع التعليمي."""
import json
import sqlite3
from config import DATABASE_PATH, INSTANCE_DIR


def connection():
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DATABASE_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA busy_timeout = 10000")
    return db


def init_db():
    with connection() as db:
        db.execute("PRAGMA journal_mode = WAL")
        db.executescript("""
        CREATE TABLE IF NOT EXISTS uploaded_files (
            id INTEGER PRIMARY KEY, original_name TEXT NOT NULL, log_type TEXT,
            lines_read INTEGER DEFAULT 0, events_extracted INTEGER DEFAULT 0,
            alerts_created INTEGER DEFAULT 0, uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY, file_id INTEGER, event_time TEXT, source TEXT,
            source_ip TEXT, username TEXT, event_type TEXT, status TEXT, severity TEXT DEFAULT 'Low',
            port INTEGER, method TEXT, path TEXT, http_status INTEGER, response_size INTEGER, raw_line TEXT,
            FOREIGN KEY(file_id) REFERENCES uploaded_files(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY, file_id INTEGER, rule_name TEXT, title TEXT, description TEXT,
            severity TEXT, source_ip TEXT, first_seen TEXT, last_seen TEXT, occurrences INTEGER,
            event_ids TEXT, state TEXT DEFAULT 'New', created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(file_id) REFERENCES uploaded_files(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS detection_rules (
            id INTEGER PRIMARY KEY, rule_key TEXT UNIQUE, name TEXT, description TEXT, enabled INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY, value TEXT NOT NULL, ioc_type TEXT NOT NULL, source TEXT,
            file_id INTEGER, raw_line TEXT, first_seen TEXT, last_seen TEXT, occurrences INTEGER DEFAULT 1,
            ti_service TEXT, checked_at TEXT, classification TEXT DEFAULT 'Unknown', reason TEXT,
            malicious_count INTEGER, abuse_score INTEGER, UNIQUE(value,ioc_type)
        );
        CREATE TABLE IF NOT EXISTS ioc_events (ioc_id INTEGER,event_id INTEGER,UNIQUE(ioc_id,event_id));
        CREATE TABLE IF NOT EXISTS ioc_alerts (ioc_id INTEGER,alert_id INTEGER,UNIQUE(ioc_id,alert_id));
        """)
        rules = [
            ("brute_force", "Possible Brute Force", "5 محاولات دخول فاشلة خلال دقيقة"),
            ("username_enumeration", "Username Enumeration", "3 مستخدمين غير صالحين من نفس IP"),
            ("success_after_failure", "Suspicious Login Success", "نجاح بعد محاولات فاشلة"),
            ("web_scanning", "Suspicious Web Scanning", "8 أخطاء ويب خلال دقيقة"),
            ("suspicious_path", "Suspicious Path Request", "مسار ويب حساس"),
            ("high_request_rate", "High Request Rate", "أكثر من 50 طلبًا خلال دقيقة"),
            ("windows_system_error", "Windows System Error", "أخطاء أو أحداث حرجة في سجل Windows المحلي"),
            ("windows_system_warning", "Windows System Warning", "تحذيرات في سجل Windows المحلي"),
            ("windows_system_information", "Windows System Information", "ملخص أحداث المعلومات في سجل Windows المحلي"),
        ]
        db.executemany("INSERT OR IGNORE INTO detection_rules(rule_key,name,description) VALUES (?,?,?)", rules)
        _ensure_columns(db, "events", {
            "provider": "TEXT", "event_id": "TEXT", "computer": "TEXT", "line_number": "INTEGER"
        })
        _ensure_columns(db, "uploaded_files", {
            "rejected_lines": "INTEGER DEFAULT 0", "parse_errors": "TEXT"
        })
        db.executescript("""
        CREATE INDEX IF NOT EXISTS idx_events_time ON events(event_time);
        CREATE INDEX IF NOT EXISTS idx_events_ip ON events(source_ip);
        CREATE INDEX IF NOT EXISTS idx_events_user ON events(username);
        CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
        CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
        CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
        UPDATE iocs SET ti_service=NULL, checked_at=NULL, classification='Observed',
            reason='Local observation only; no external verdict was requested.'
            WHERE classification='Not configured';
        """)


def _ensure_columns(db, table, columns):
    existing = {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
    for name, definition in columns.items():
        if name not in existing:
            db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


def create_upload(filename, log_type):
    with connection() as db:
        cur = db.execute("INSERT INTO uploaded_files(original_name,log_type) VALUES (?,?)", (filename, log_type))
        return cur.lastrowid


def save_events(file_id, events):
    rows = []
    for e in events:
        rows.append((file_id, e.timestamp.isoformat(sep=" ") if e.timestamp else None, e.source, e.source_ip,
                     e.username, e.event_type, e.status, e.severity, e.port, e.method, e.path,
                     e.http_status, e.response_size, e.raw_line, e.provider, e.event_id, e.computer, e.line_number))
    with connection() as db:
        db.executemany("""INSERT INTO events(file_id,event_time,source,source_ip,username,event_type,status,severity,port,method,path,http_status,response_size,raw_line,provider,event_id,computer,line_number)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", rows)
        return db.execute("SELECT * FROM events WHERE file_id=? ORDER BY id", (file_id,)).fetchall()


def save_alerts(file_id, alerts):
    with connection() as db:
        for alert in alerts:
            db.execute("""INSERT INTO alerts(file_id,rule_name,title,description,severity,source_ip,first_seen,last_seen,occurrences,event_ids)
                          VALUES (?,?,?,?,?,?,?,?,?,?)""", (file_id, alert["rule_name"], alert["title"], alert["description"],
                          alert["severity"], alert["source_ip"], alert["first_seen"], alert["last_seen"], alert["occurrences"],
                          json.dumps(alert["event_ids"])))


def finish_upload(file_id, lines, events, alerts, rejected=0, parse_errors=None):
    with connection() as db:
        db.execute("UPDATE uploaded_files SET lines_read=?,events_extracted=?,alerts_created=?,rejected_lines=?,parse_errors=? WHERE id=?", (lines, events, alerts, rejected, json.dumps(parse_errors or [], ensure_ascii=False), file_id))


def dashboard_data(days=0):
    with connection() as db:
        days = days if days in {0,1,7,30} else 0
        ef="(?=0 OR datetime(event_time)>=datetime('now','-'||?||' days'))"; af="(?=0 OR datetime(created_at)>=datetime('now','-'||?||' days'))"
        args=(days,days); scalar=lambda q,p=():db.execute(q,p).fetchone()[0]
        summary = {"files": scalar("SELECT COUNT(*) FROM uploaded_files"), "events": scalar("SELECT COUNT(*) FROM events WHERE "+ef,args), "alerts": scalar("SELECT COUNT(*) FROM alerts WHERE "+af,args),
                   "critical": scalar("SELECT COUNT(*) FROM alerts WHERE severity='Critical' AND "+af,args),
                   "high": scalar("SELECT COUNT(*) FROM alerts WHERE severity='High' AND "+af,args),
                   "medium": scalar("SELECT COUNT(*) FROM alerts WHERE severity='Medium' AND "+af,args),
                   "low": scalar("SELECT COUNT(*) FROM alerts WHERE severity='Low' AND "+af,args),
                   "ips": scalar("SELECT COUNT(DISTINCT source_ip) FROM events WHERE source_ip IS NOT NULL AND "+ef,args),
                   "failed": scalar("SELECT COUNT(*) FROM events WHERE event_type IN ('Login','Windows Login') AND status='Failed' AND "+ef,args),
                   "success": scalar("SELECT COUNT(*) FROM events WHERE event_type IN ('Login','Windows Login') AND status='Success' AND "+ef,args),
                   "iocs": scalar("SELECT COUNT(*) FROM iocs")}
        charts = {
            "timeline": [dict(r) for r in db.execute("SELECT substr(event_time,1,16) label,COUNT(*) value FROM events WHERE event_time IS NOT NULL AND "+ef+" GROUP BY label ORDER BY label",args)],
            "severity": [dict(r) for r in db.execute("SELECT severity label,COUNT(*) value FROM alerts WHERE "+af+" GROUP BY severity",args)],
            "ips": [dict(r) for r in db.execute("SELECT source_ip label,COUNT(*) value FROM events WHERE source_ip IS NOT NULL AND "+ef+" GROUP BY source_ip ORDER BY value DESC LIMIT 8",args)],
            "users": [dict(r) for r in db.execute("SELECT username label,COUNT(*) value FROM events WHERE username IS NOT NULL AND "+ef+" GROUP BY username ORDER BY value DESC LIMIT 8",args)],
            "http": [dict(r) for r in db.execute("SELECT CAST(http_status AS TEXT) label,COUNT(*) value FROM events WHERE http_status IS NOT NULL AND "+ef+" GROUP BY http_status ORDER BY http_status",args)],
        }
        recent = db.execute("SELECT * FROM alerts WHERE "+af+" ORDER BY id DESC LIMIT 5",args).fetchall()
        return summary, charts, recent

def cleanup_data(days):
    """Delete complete uploads older than the selected retention window."""
    days=max(1,min(int(days),3650))
    with connection() as db:
        ids=[r[0] for r in db.execute("SELECT id FROM uploaded_files WHERE datetime(uploaded_at)<datetime('now',?)",(f"-{days} days",))]
        for file_id in ids: db.execute("DELETE FROM uploaded_files WHERE id=?",(file_id,))
        db.execute("DELETE FROM iocs WHERE file_id NOT IN (SELECT id FROM uploaded_files)")
        db.execute("DELETE FROM ioc_events WHERE ioc_id NOT IN (SELECT id FROM iocs) OR event_id NOT IN (SELECT id FROM events)")
        db.execute("DELETE FROM ioc_alerts WHERE ioc_id NOT IN (SELECT id FROM iocs) OR alert_id NOT IN (SELECT id FROM alerts)")
        return len(ids)

def clear_all_data():
    with connection() as db:
        for table in ("ioc_alerts","ioc_events","iocs","alerts","events","uploaded_files"):
            db.execute(f"DELETE FROM {table}")


def list_events(filters, page, per_page=20, sort="time_desc"):
    clauses, values = [], []
    for column, key in (("source_ip", "ip"), ("event_type", "type"), ("severity", "severity")):
        if filters.get(key): clauses.append(f"{column}=?"); values.append(filters[key])
    if filters.get("search"):
        clauses.append("(source_ip LIKE ? OR username LIKE ? OR path LIKE ? OR raw_line LIKE ?)")
        values.extend([f"%{filters['search']}%"] * 4)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    order_by = {"time_asc":"event_time ASC,id ASC", "severity_desc":"CASE severity WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 ELSE 1 END DESC,event_time DESC", "severity_asc":"CASE severity WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 ELSE 1 END ASC,event_time DESC"}.get(sort,"event_time DESC,id DESC")
    with connection() as db:
        total = db.execute("SELECT COUNT(*) FROM events" + where, values).fetchone()[0]
        rows = db.execute("SELECT * FROM events" + where + " ORDER BY " + order_by + " LIMIT ? OFFSET ?", values + [per_page, (page-1)*per_page]).fetchall()
        types = db.execute("SELECT DISTINCT event_type FROM events ORDER BY event_type").fetchall()
    return rows, total, [x[0] for x in types]

def get_event(event_id):
    with connection() as db:
        return db.execute("SELECT events.*,uploaded_files.original_name FROM events LEFT JOIN uploaded_files ON uploaded_files.id=events.file_id WHERE events.id=?", (event_id,)).fetchone()


def list_alerts():
    with connection() as db: return db.execute("SELECT * FROM alerts ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END,id DESC").fetchall()

def get_alert(alert_id):
    with connection() as db:
        alert = db.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if not alert: return None, []
        ids = json.loads(alert["event_ids"] or "[]")
        if not ids: return alert, []
        marks = ",".join("?" * len(ids))
        return alert, db.execute(f"SELECT * FROM events WHERE id IN ({marks}) ORDER BY event_time", ids).fetchall()

def update_alert_state(alert_id, state):
    with connection() as db: db.execute("UPDATE alerts SET state=? WHERE id=?", (state, alert_id))

def save_iocs(file_id, events, extract):
    with connection() as db:
        for e in events:
            for value,kind in extract(e['raw_line'] or '', e['source_ip']):
                row=db.execute('SELECT id FROM iocs WHERE value=? AND ioc_type=?',(value,kind)).fetchone()
                if row:
                    iid=row['id']; db.execute("UPDATE iocs SET last_seen=?,occurrences=occurrences+1 WHERE id=?",(e['event_time'],iid))
                else:
                    iid=db.execute("INSERT INTO iocs(value,ioc_type,source,file_id,raw_line,first_seen,last_seen) VALUES(?,?,?,?,?,?,?)",(value,kind,e['source'],file_id,(e['raw_line'] or '')[:2000],e['event_time'],e['event_time'])).lastrowid
                db.execute('INSERT OR IGNORE INTO ioc_events(ioc_id,event_id) VALUES(?,?)',(iid,e['id']))

def list_iocs():
    with connection() as db:return db.execute('SELECT * FROM iocs ORDER BY last_seen DESC,id DESC').fetchall()

def enrich_iocs():
    """يستعمل الكاش 24 ساعة؛ عند غياب المفتاح/الخدمة تبقى النتيجة Unknown."""
    from datetime import datetime, timedelta
    from threat_intelligence import abuse, vt, env
    hours=int(env('TI_CACHE_HOURS','24') or 24); cutoff=(datetime.utcnow()-timedelta(hours=hours)).isoformat()
    with connection() as db:
        rows=db.execute("SELECT * FROM iocs WHERE checked_at IS NULL OR checked_at<?",(cutoff,)).fetchall()
        for row in rows:
            result=abuse(row['value']) if row['ioc_type']=='ip' else vt(row['value'],row['ioc_type'])
            db.execute("UPDATE iocs SET ti_service=?,checked_at=?,classification=?,reason=?,malicious_count=?,abuse_score=? WHERE id=?",(result['service'],datetime.utcnow().isoformat(),result['classification'],result['reason'],result.get('malicious_count'),result.get('abuse_score'),row['id']))
