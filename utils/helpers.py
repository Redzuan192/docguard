import os
import uuid
from datetime import datetime
from werkzeug.utils import secure_filename
from config import Config


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS


def unique_filename(filename):
    name = secure_filename(filename)
    ext = name.rsplit('.', 1)[1].lower() if '.' in name else ''
    return f"{uuid.uuid4().hex}.{ext}" if ext else uuid.uuid4().hex


def generate_share_token():
    return uuid.uuid4().hex + uuid.uuid4().hex[:8]


def now_str():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def ensure_directories():
    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(Config.SHARED_FOLDER, exist_ok=True)