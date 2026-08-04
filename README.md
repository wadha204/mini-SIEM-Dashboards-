# Sentinel Mini SIEM Dashboard

An educational SIEM dashboard built with Python, Flask, SQLite, HTML, CSS, JavaScript, and Chart.js.

> It uses synthetic sample data and is intended for learning, not production monitoring.

## Features

- Summary metrics and responsive dark interface
- Timeline, severity, and event-category charts
- Search plus severity/status filters
- CSV export of filtered results
- JSON API and demonstration event ingestion
- Automatic SQLite setup and sample-data import
- Railway-ready Gunicorn command, dynamic `$PORT`, and health endpoint

## Run locally

Python 3.11 or newer is recommended.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`. The database is created at `instance/siem.db`.

## API

- `GET /health` — application health
- `GET /api/summary` — metric totals
- `GET /api/charts` — chart data
- `GET /api/logs?search=&severity=&status=` — filtered events
- `GET /api/logs/export` — filtered CSV export
- `POST /api/logs` — add a demonstration event as JSON

Example POST body:

```json
{
  "source_ip": "203.0.113.10",
  "destination_ip": "10.0.0.4",
  "event_type": "Port Scan",
  "severity": "High",
  "status": "Blocked",
  "message": "Synthetic scan event for training"
}
```

## Deploy to Railway from GitHub

1. Extract the ZIP and upload all contents of the project folder to a new GitHub repository.
2. In Railway, choose **New Project → Deploy from GitHub repo**, then select it.
3. Railway installs `requirements.txt` and runs the `Procfile` command.
4. In **Settings → Networking**, choose **Generate Domain**.
5. Open `/health` on that domain to verify the deployment.

### Persist SQLite data

Railway service files are ephemeral. For data to survive deployments, add a Volume to the web service with a mount path such as `/data`. The app detects `RAILWAY_VOLUME_MOUNT_PATH` automatically and stores `siem.db` there. Without a Volume, it still works, but newly added events may reset on deployment.

## Notes

- Chart.js and Google Fonts load from public CDNs.
- Log text is escaped before being placed into the table.
- A real SIEM also needs authentication, authorization, encrypted transport, production storage, retention and audit policies, and a proper ingestion pipeline.
