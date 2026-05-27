import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'docguard-super-secret-key-change-this')
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
    SHARED_FOLDER = os.path.join(os.getcwd(), 'shared')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'png', 'jpg', 'jpeg'}
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=60)

    DB_HOST = os.environ.get('DB_HOST', '127.0.0.1')
    DB_USER = os.environ.get('DB_USER', 'root')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', '')
    DB_NAME = os.environ.get('DB_NAME', 'docguard_db')
    DB_PORT = int(os.environ.get('DB_PORT', 3307))