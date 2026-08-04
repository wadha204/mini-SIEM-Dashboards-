import csv
import io
import ipaddress
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(
    os.environ.get("DATA_DIR")
    or os.environ.get("RAILWAY_VOLUME_MOUNT_PATH")
    or BASE_DIR / "instance"
)
DATABASE = DATA_DIR / "siem.db"
SAMPLE_LOGS = BASE_DIR / "sample_logs.csv"

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024


def get_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_db() as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL CHECK(severity IN ('Low', 'Medium', 'High', 'Critical')),
                status TEXT NOT NULL CHECK(status IN ('Allowed', 'Blocked', 'Investigating')),
                message TEXT NOT NULL
            )
            """
        )
        count = db.execute("SELECT COUNT(*) FROM security_logs").fetchone()[0]
        if count == 0 and SAMPLE_LOGS.exists():
            with SAMPLE_LOGS.open(encoding="utf-8-sig", newline="") as file:
                rows = csv.DictReader(file)
                db.executemany(
                    """
                    INSERT INTO security_logs
                    (timestamp, source_ip, destination_ip, event_type, severity, status, message)
                    VALUES (:timestamp, :source_ip, :destination_ip, :event_type, :severity, :status, :message)
                    """,
                    rows,
                )
        db.commit()


def filtered_logs_query():
    clauses, params = [], []
    severity = request.args.get("severity", "").strip()
    status = request.args.get("status", "").strip()
    search = request.args.get("search", "").strip()

    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if status:
        clauses.append("status = ?")
        params.append(status)
    if search:
        clauses.append(
            "(source_ip LIKE ? OR destination_ip LIKE ? OR event_type LIKE ? OR message LIKE ?)"
        )
        params.extend([f"%{search}%"] * 4)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return where, params


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.route("/")
def dashboard():
    return render_template("index.html")


@app.route("/health")
def health():
    with get_db() as db:
        db.execute("SELECT 1").fetchone()
    return jsonify(status="ok")


@app.route("/api/summary")
def summary():
    with get_db() as db:
        total = db.execute("SELECT COUNT(*) FROM security_logs").fetchone()[0]
        threats = db.execute(
            "SELECT COUNT(*) FROM security_logs WHERE severity IN ('High', 'Critical')"
        ).fetchone()[0]
        blocked = db.execute(
            "SELECT COUNT(*) FROM security_logs WHERE status = 'Blocked'"
        ).fetchone()[0]
        sources = db.execute(
            "SELECT COUNT(DISTINCT source_ip) FROM security_logs"
        ).fetchone()[0]
    return jsonify(total_events=total, active_threats=threats, blocked=blocked, unique_sources=sources)


@app.route("/api/charts")
def charts():
    with get_db() as db:
        severity = db.execute(
            "SELECT severity AS label, COUNT(*) AS value FROM security_logs GROUP BY severity"
        ).fetchall()
        timeline = db.execute(
            """
            SELECT substr(timestamp, 1, 10) AS label, COUNT(*) AS value
            FROM security_logs GROUP BY substr(timestamp, 1, 10) ORDER BY label
            """
        ).fetchall()
        event_types = db.execute(
            """
            SELECT event_type AS label, COUNT(*) AS value FROM security_logs
            GROUP BY event_type ORDER BY value DESC LIMIT 6
            """
        ).fetchall()
    return jsonify(
        severity=[dict(row) for row in severity],
        timeline=[dict(row) for row in timeline],
        event_types=[dict(row) for row in event_types],
    )


@app.route("/api/logs")
def logs():
    where, params = filtered_logs_query()
    try:
        limit = min(max(int(request.args.get("limit", 100)), 1), 500)
    except ValueError:
        limit = 100
    with get_db() as db:
        rows = db.execute(
            f"SELECT * FROM security_logs {where} ORDER BY timestamp DESC, id DESC LIMIT ?",
            [*params, limit],
        ).fetchall()
    return jsonify([dict(row) for row in rows])


@app.route("/api/logs/export")
def export_logs():
    where, params = filtered_logs_query()
    with get_db() as db:
        rows = db.execute(
            f"SELECT * FROM security_logs {where} ORDER BY timestamp DESC, id DESC", params
        ).fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "timestamp", "source_ip", "destination_ip", "event_type", "severity", "status", "message"])
    writer.writerows([tuple(row) for row in rows])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=siem-logs.csv"},
    )


@app.route("/api/logs", methods=["POST"])
def create_log():
    data = request.get_json(silent=True) or {}
    required = ["source_ip", "destination_ip", "event_type", "severity", "status", "message"]
    values = {field: str(data.get(field, "")).strip() for field in required}
    missing = [field for field, value in values.items() if not value]
    if missing:
        return jsonify(error="Missing required fields", fields=missing), 400
    if values["severity"] not in {"Low", "Medium", "High", "Critical"}:
        return jsonify(error="Invalid severity"), 400
    if values["status"] not in {"Allowed", "Blocked", "Investigating"}:
        return jsonify(error="Invalid status"), 400
    try:
        ipaddress.ip_address(values["source_ip"])
        ipaddress.ip_address(values["destination_ip"])
    except ValueError:
        return jsonify(error="Invalid IP address"), 400
    if len(values["event_type"]) > 100 or len(values["message"]) > 1000:
        return jsonify(error="Event type or message is too long"), 400

    timestamp = str(data.get("timestamp") or datetime.now(timezone.utc).isoformat(timespec="seconds"))
    with get_db() as db:
        cursor = db.execute(
            """
            INSERT INTO security_logs
            (timestamp, source_ip, destination_ip, event_type, severity, status, message)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                values["source_ip"],
                values["destination_ip"],
                values["event_type"],
                values["severity"],
                values["status"],
                values["message"],
            ),
        )
        db.commit()
    return jsonify(id=cursor.lastrowid, message="Log created"), 201


init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
