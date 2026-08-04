"""نقطة تشغيل WSGI لـ PythonAnywhere وغيرها من استضافات Python."""
from app import app
from database import init_db

init_db()
application = app
