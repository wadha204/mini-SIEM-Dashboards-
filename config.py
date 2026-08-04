from pathlib import Path
import os
import secrets

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(
    os.environ.get("MINI_SIEM_DATA_DIR")
    or os.environ.get("RAILWAY_VOLUME_MOUNT_PATH")
    or BASE_DIR
)
INSTANCE_DIR = DATA_DIR / "instance"
UPLOAD_DIR = DATA_DIR / "uploads"
DATABASE_PATH = INSTANCE_DIR / "mini_siem.db"

def _load_env_file():
    """Load simple KEY=VALUE entries without overriding real environment variables."""
    path = BASE_DIR / ".env"
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))

_load_env_file()

ALLOWED_EXTENSIONS = {"log", "txt", "csv", "json", "xml", "evtx"}
MAX_CONTENT_LENGTH = int(os.environ.get("MINI_SIEM_MAX_UPLOAD_BYTES", 5 * 1024 * 1024))

def _secret_key():
    configured = os.environ.get("MINI_SIEM_SECRET_KEY")
    if configured:
        return configured
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    key_file = INSTANCE_DIR / ".secret_key"
    if not key_file.exists():
        key_file.write_text(secrets.token_urlsafe(48), encoding="utf-8")
    return key_file.read_text(encoding="utf-8").strip()

SECRET_KEY = _secret_key()
ADMIN_USERNAME = os.environ.get("MINI_SIEM_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = os.environ.get("MINI_SIEM_ADMIN_PASSWORD_HASH", "")
UPLOAD_RATE_LIMIT = int(os.environ.get("MINI_SIEM_UPLOAD_RATE_LIMIT", "10"))
DEV_TOOLS = os.environ.get("MINI_SIEM_DEV_TOOLS", "0") == "1"
HOSTED_MODE = os.environ.get(
    "MINI_SIEM_HOSTED_MODE",
    "1" if (
        os.environ.get("PYTHONANYWHERE_SITE")
        or os.environ.get("PYTHONANYWHERE_DOMAIN")
        or os.environ.get("RAILWAY_PROJECT_ID")
        or os.environ.get("RAILWAY_ENVIRONMENT")
    ) else "0",
) == "1"
LOCAL_SOURCES_ENABLED = os.environ.get("MINI_SIEM_LOCAL_SOURCES", "0" if HOSTED_MODE else "1") == "1"
