import os
import uuid
import mysql.connector
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta
from collections import defaultdict
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, abort, Response
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'docguard-super-secret-key-2026')
csrf = CSRFProtect(app)

# =====================
# CSRF ERROR HANDLER
# =====================
@app.errorhandler(400)
def csrf_error(e):
    if 'CSRF' in str(e):
        flash('CSRF token missing or invalid. Please try again.', 'danger')
        return redirect(request.referrer or url_for('home'))
    return e

# =====================
# AES-256 ENCRYPTION SETUP
# =====================
KEY_FILE = 'encryption_key.key'

def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
        print(f"🔐 New encryption key created: {KEY_FILE}")
        return key

ENCRYPTION_KEY = load_or_create_key()
cipher = Fernet(ENCRYPTION_KEY)

def encrypt_file(data):
    return cipher.encrypt(data)

def decrypt_file(data):
    return cipher.decrypt(data)

# =====================
# RATE LIMITING
# =====================
login_attempts = defaultdict(list)

def is_rate_limited(ip):
    now = datetime.now()
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < timedelta(minutes=5)]
    return len(login_attempts[ip]) >= 5

def record_failed_attempt(ip):
    login_attempts[ip].append(datetime.now())

def reset_login_attempts(ip):
    if ip in login_attempts:
        del login_attempts[ip]

# =====================
# KONFIGURASI
# =====================
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'png', 'jpg', 'jpeg'}
MAX_FILE_SIZE = 16 * 1024 * 1024

app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# =====================
# DATABASE CONNECTION (Auto-detect Railway PostgreSQL or Local MySQL)
# =====================
def get_connection():
    database_url = os.environ.get('DATABASE_URL')
    
    if database_url:
        # Railway PostgreSQL
        return psycopg2.connect(database_url, cursor_factory=RealDictCursor)
    else:
        # Local MySQL (development)
        return mysql.connector.connect(
            host='127.0.0.1',
            user='root',
            password='',
            database='docguard_db',
            port=3307
        )

def fetch_one(query, params=None):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(query, params or ())
        row = cursor.fetchone()
        return row
    finally:
        cursor.close()
        conn.close()

def fetch_all(query, params=None):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(query, params or ())
        rows = cursor.fetchall()
        return rows
    finally:
        cursor.close()
        conn.close()

def execute_query(query, params=None):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(query, params or ())
        conn.commit()
        
        # Try to get last inserted id for PostgreSQL with RETURNING
        if 'RETURNING' in query.upper():
            try:
                result = cursor.fetchone()
                if result:
                    return result[0] if isinstance(result, tuple) else result.get('id')
            except:
                pass
        
        # For MySQL
        if hasattr(cursor, 'lastrowid'):
            return cursor.lastrowid
        return None
    finally:
        cursor.close()
        conn.close()

# =====================
# FUNGSI PEMBANTU
# =====================
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_token():
    return uuid.uuid4().hex + uuid.uuid4().hex[:8]

def unique_filename(filename):
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    return f"{uuid.uuid4().hex}.{ext}" if ext else uuid.uuid4().hex

def is_logged_in():
    return 'user_id' in session

def is_admin():
    return session.get('role') == 'admin'

def add_log(user_id, file_id, action, description, ip_address):
    # Handle None values
    if file_id is None:
        execute_query(
            "INSERT INTO audit_logs (user_id, file_id, action, description, ip_address) VALUES (%s, %s, %s, %s, %s)",
            (user_id, None, action, description, ip_address)
        )
    else:
        execute_query(
            "INSERT INTO audit_logs (user_id, file_id, action, description, ip_address) VALUES (%s, %s, %s, %s, %s)",
            (user_id, file_id, action, description, ip_address)
        )

# =====================
# ROUTES - AUTHENTICATION
# =====================
@app.route('/reset-admin')
def reset_admin():
    password_hash = generate_password_hash('admin123', method='pbkdf2:sha256:600000')
    
    database_url = os.environ.get('DATABASE_URL')
    if database_url:
        # PostgreSQL syntax
        execute_query("""INSERT INTO users (full_name, email, password_hash, role, is_active)
                         VALUES (%s,%s,%s,%s,%s)
                         ON CONFLICT (email) DO UPDATE SET 
                         password_hash=EXCLUDED.password_hash, 
                         is_active=1, 
                         role='admin'""",
                      ('Admin DocGuard', 'admin@docguard.com', password_hash, 'admin', 1))
    else:
        # MySQL syntax
        execute_query("""INSERT INTO users (full_name, email, password_hash, role, is_active)
                         VALUES (%s,%s,%s,%s,%s)
                         ON DUPLICATE KEY UPDATE 
                         password_hash=VALUES(password_hash), 
                         is_active=1, 
                         role='admin'""",
                      ('Admin DocGuard', 'admin@docguard.com', password_hash, 'admin', 1))
    
    return "✅ Admin reset successful! Login with: admin@docguard.com / admin123"

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['full_name'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        
        existing = fetch_one("SELECT id FROM users WHERE email = %s", (email,))
        if existing:
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))
        
        password_hash = generate_password_hash(password, method='pbkdf2:sha256:600000')
        
        execute_query(
            "INSERT INTO users (full_name, email, password_hash, role, is_active) VALUES (%s, %s, %s, 'user', 1)",
            (full_name, email, password_hash)
        )
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    if is_logged_in():
        add_log(session['user_id'], None, 'LOGOUT', 'User logged out.', request.remote_addr)
        session.clear()
        flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        ip = request.remote_addr

        if is_rate_limited(ip):
            flash('Too many failed attempts. Try again after 5 minutes.', 'danger')
            return redirect(url_for('login'))

        user = fetch_one("SELECT * FROM users WHERE email=%s", (email,))
        if not user or int(user.get('is_active', 0)) != 1:
            record_failed_attempt(ip)
            flash('Invalid email or password.', 'danger')
            return redirect(url_for('login'))

        if check_password_hash(user['password_hash'], password):
            reset_login_attempts(ip)
            session['user_id'] = user['id']
            session['full_name'] = user['full_name']
            session['role'] = user['role']
            add_log(user['id'], None, 'LOGIN_SUCCESS', 'User logged in successfully.', ip)
            
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))

        record_failed_attempt(ip)
        flash('Invalid email or password.', 'danger')

    return render_template('login.html')

@app.route('/')
def home():
    if is_logged_in():
        if is_admin():
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# =====================
# ROUTES - USER DASHBOARD & FILES
# =====================
@app.route('/dashboard')
def dashboard():
    if not is_logged_in() or is_admin():
        return redirect(url_for('home'))

    stats = {
        'my_files': fetch_one("SELECT COUNT(*) AS total FROM files WHERE uploaded_by = %s", (session['user_id'],)),
        'my_links': fetch_one("SELECT COUNT(*) AS total FROM share_links WHERE created_by = %s", (session['user_id'],)),
        'my_views': fetch_one("""
            SELECT COALESCE(SUM(used_views), 0) AS total 
            FROM share_links 
            WHERE created_by = %s
        """, (session['user_id'],))
    }
    
    recent_files = fetch_all(
        "SELECT * FROM files WHERE uploaded_by = %s ORDER BY created_at DESC LIMIT 5",
        (session['user_id'],)
    )
    
    recent_links = fetch_all("""
        SELECT sl.*, f.original_filename 
        FROM share_links sl 
        JOIN files f ON f.id = sl.file_id 
        WHERE sl.created_by = %s 
        ORDER BY sl.created_at DESC 
        LIMIT 5
    """, (session['user_id'],))

    return render_template('dashboard.html', stats=stats, recent_files=recent_files, recent_links=recent_links)

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if not is_logged_in(): 
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        file = request.files.get('document')
        title = request.form.get('title', '').strip()

        if not file or not file.filename or not allowed_file(file.filename):
            flash('Invalid file type.', 'danger')
            return redirect(url_for('upload_file'))

        file_data = file.read()
        if len(file_data) > MAX_FILE_SIZE:
            flash('File too large (max 16MB).', 'danger')
            return redirect(url_for('upload_file'))

        encrypted_data = encrypt_file(file_data)
        
        stored_filename = unique_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, stored_filename)

        with open(file_path, 'wb') as f:
            f.write(encrypted_data)

        # For PostgreSQL, use RETURNING id
        database_url = os.environ.get('DATABASE_URL')
        if database_url:
            file_id = execute_query(
                "INSERT INTO files (title, original_filename, stored_filename, file_path, uploaded_by) VALUES (%s,%s,%s,%s,%s) RETURNING id",
                (title or file.filename, file.filename, stored_filename, file_path, session['user_id'])
            )
        else:
            file_id = execute_query(
                "INSERT INTO files (title, original_filename, stored_filename, file_path, uploaded_by) VALUES (%s,%s,%s,%s,%s)",
                (title or file.filename, file.filename, stored_filename, file_path, session['user_id'])
            )
        
        add_log(session['user_id'], file_id, 'FILE_UPLOAD', f'Uploaded (encrypted): {file.filename}', request.remote_addr)
        flash('File uploaded and encrypted successfully.', 'success')
        return redirect(url_for('my_files'))

    return render_template('upload.html')

@app.route('/my-files')
def my_files():
    if not is_logged_in(): 
        return redirect(url_for('login'))
    
    files = fetch_all("SELECT * FROM files WHERE uploaded_by = %s ORDER BY created_at DESC", (session['user_id'],))
    return render_template('my_files.html', files=files)

@app.route('/delete-file/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    if not is_logged_in(): 
        return redirect(url_for('login'))
    
    file = fetch_one("SELECT * FROM files WHERE id = %s AND uploaded_by = %s", (file_id, session['user_id']))
    if not file:
        flash('File not found.', 'danger')
        return redirect(url_for('my_files'))

    add_log(session['user_id'], file_id, 'FILE_DELETE', f'Deleted: {file["original_filename"]}', request.remote_addr)
    
    if os.path.exists(file['file_path']):
        os.remove(file['file_path'])
    
    execute_query("DELETE FROM files WHERE id = %s", (file_id,))
    flash('File deleted successfully.', 'success')
    return redirect(url_for('my_files'))

# =====================
# ROUTES - SHARING
# =====================
@app.route('/share/<int:file_id>', methods=['GET', 'POST'])
def share_file(file_id):
    if not is_logged_in(): 
        return redirect(url_for('login'))
    
    file = fetch_one("SELECT * FROM files WHERE id = %s AND uploaded_by = %s", (file_id, session['user_id']))
    if not file:
        flash('File not found.', 'danger')
        return redirect(url_for('my_files'))

    if request.method == 'POST':
        expiry_date = request.form['expiry_date']
        max_views = int(request.form.get('max_views', 5))
        allow_download = 1 if request.form.get('allow_download') else 0
        password = request.form.get('password', '').strip()
        token = generate_token()
        password_hash = generate_password_hash(password, method='pbkdf2:sha256:600000') if password else None

        execute_query("""INSERT INTO share_links 
            (file_id, token, expiry_date, max_views, used_views, allow_download, password_hash, is_active, created_by)
            VALUES (%s, %s, %s, %s, 0, %s, %s, 1, %s)""",
            (file_id, token, expiry_date, max_views, allow_download, password_hash, session['user_id']))
        
        add_log(session['user_id'], file_id, 'LINK_CREATED', f'Created share link for: {file["original_filename"]}', request.remote_addr)
        
        # Use production domain
        host = request.host
        link_url = f"https://{host}/shared/{token}"
        
        if password:
            flash(f'🔗 Share link created (password protected): {link_url}', 'success')
        else:
            flash(f'🔗 Share link created: {link_url}', 'success')
            
        return redirect(url_for('my_files'))

    return render_template('share_file.html', file=file)

@app.route('/shared/<token>', methods=['GET', 'POST'])
def shared_access(token):
    link = fetch_one("""SELECT sl.*, f.* FROM share_links sl JOIN files f ON f.id = sl.file_id WHERE sl.token = %s""", (token,))
    
    if not link or int(link.get('is_active', 0)) != 1:
        return render_template('shared_access.html', error='Link Invalid or Expired', link=None)
    
    if datetime.now() > link['expiry_date']:
        return render_template('shared_access.html', error='Link has Expired', link=None)

    if int(link['used_views']) >= int(link['max_views']):
        return render_template('shared_access.html', error='Maximum Views Reached', link=None)

    password_hash = link.get('password_hash')
    if password_hash:
        if request.method == 'POST':
            if not check_password_hash(password_hash, request.form.get('link_password', '')):
                flash('Incorrect password.', 'danger')
                return render_template('shared_access.html', link=link, error=None, require_password=True)
            
            new_views = link['used_views'] + 1
            execute_query("UPDATE share_links SET used_views = %s WHERE id = %s", (new_views, link['id']))
            add_log(None, link['file_id'], 'FILE_VIEW', f'Viewed: {link["original_filename"]}', request.remote_addr)
            
            link = fetch_one("""SELECT sl.*, f.* FROM share_links sl JOIN files f ON f.id = sl.file_id WHERE sl.token = %s""", (token,))
            return render_template('shared_access.html', link=link, error=None, require_password=False)
        else:
            return render_template('shared_access.html', link=link, error=None, require_password=True)
    
    new_views = link['used_views'] + 1
    execute_query("UPDATE share_links SET used_views = %s WHERE id = %s", (new_views, link['id']))
    add_log(None, link['file_id'], 'FILE_VIEW', f'Viewed: {link["original_filename"]}', request.remote_addr)
    
    link = fetch_one("""SELECT sl.*, f.* FROM share_links sl JOIN files f ON f.id = sl.file_id WHERE sl.token = %s""", (token,))

    return render_template('shared_access.html', link=link, error=None, require_password=False)

@app.route('/download/<token>')
def download_shared_file(token):
    link = fetch_one("""SELECT sl.*, f.* FROM share_links sl JOIN files f ON f.id = sl.file_id WHERE sl.token = %s""", (token,))
    
    if not link or not link.get('allow_download'):
        abort(403)

    with open(link['file_path'], 'rb') as f:
        encrypted_data = f.read()

    decrypted_data = decrypt_file(encrypted_data)

    temp_path = os.path.join(UPLOAD_FOLDER, "temp_download_" + link['stored_filename'])
    with open(temp_path, 'wb') as f:
        f.write(decrypted_data)

    add_log(None, link['file_id'], 'FILE_DOWNLOAD', f'Downloaded: {link["original_filename"]}', request.remote_addr)

    response = send_from_directory(UPLOAD_FOLDER, "temp_download_" + link['stored_filename'], 
                                 as_attachment=True, download_name=link['original_filename'])
    
    @response.call_on_close
    def cleanup():
        try:
            os.remove(temp_path)
        except:
            pass
    
    return response

# =====================
# ROUTES - MANAGE SHARE LINKS
# =====================
@app.route('/my-links')
def my_links():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    links = fetch_all("""
        SELECT sl.*, f.original_filename, f.id as file_id
        FROM share_links sl
        JOIN files f ON f.id = sl.file_id
        WHERE sl.created_by = %s
        ORDER BY sl.created_at DESC
    """, (session['user_id'],))
    
    return render_template('my_links.html', links=links)

@app.route('/edit-link/<int:link_id>', methods=['GET', 'POST'])
def edit_link(link_id):
    if not is_logged_in():
        return redirect(url_for('login'))
    
    link = fetch_one("""
        SELECT sl.*, f.original_filename 
        FROM share_links sl
        JOIN files f ON f.id = sl.file_id
        WHERE sl.id = %s AND sl.created_by = %s
    """, (link_id, session['user_id']))
    
    if not link:
        flash('Link not found.', 'danger')
        return redirect(url_for('my_links'))
    
    if request.method == 'POST':
        expiry_date = request.form['expiry_date']
        max_views = int(request.form.get('max_views', 5))
        allow_download = 1 if request.form.get('allow_download') else 0
        is_active = 1 if request.form.get('is_active') else 0
        
        execute_query("""
            UPDATE share_links 
            SET expiry_date = %s, max_views = %s, allow_download = %s, is_active = %s
            WHERE id = %s
        """, (expiry_date, max_views, allow_download, is_active, link_id))
        
        add_log(session['user_id'], link['file_id'], 'LINK_EDITED', 
                f'Edited share link for: {link["original_filename"]}', request.remote_addr)
        
        flash('Share link updated successfully.', 'success')
        return redirect(url_for('my_links'))
    
    return render_template('edit_link.html', link=link)

@app.route('/cancel-link/<int:link_id>', methods=['POST'])
def cancel_link(link_id):
    if not is_logged_in():
        return redirect(url_for('login'))
    
    link = fetch_one("""
        SELECT sl.*, f.original_filename 
        FROM share_links sl
        JOIN files f ON f.id = sl.file_id
        WHERE sl.id = %s AND sl.created_by = %s
    """, (link_id, session['user_id']))
    
    if not link:
        flash('Link not found.', 'danger')
        return redirect(url_for('my_links'))
    
    execute_query("UPDATE share_links SET is_active = 0 WHERE id = %s", (link_id,))
    
    add_log(session['user_id'], link['file_id'], 'LINK_CANCELLED', 
            f'Cancelled share link for: {link["original_filename"]}', request.remote_addr)
    
    flash('Share link has been revoked/cancelled.', 'success')
    return redirect(url_for('my_links'))

# =====================
# ROUTES - EXPORT
# =====================
@app.route('/admin/export-logs')
def export_logs():
    if not is_logged_in() or not is_admin():
        return redirect(url_for('home'))
    
    import csv
    from io import StringIO
    
    keyword = request.args.get('keyword', '')
    action_filter = request.args.get('action', '')
    
    query = """
        SELECT al.created_at, u.full_name, f.original_filename, al.action, al.description, al.ip_address
        FROM audit_logs al
        LEFT JOIN users u ON u.id = al.user_id
        LEFT JOIN files f ON f.id = al.file_id
        WHERE 1=1
    """
    params = []
    
    if keyword:
        query += " AND (al.description LIKE %s OR u.full_name LIKE %s OR f.original_filename LIKE %s)"
        params.extend([f'%{keyword}%', f'%{keyword}%', f'%{keyword}%'])
    
    if action_filter:
        query += " AND al.action = %s"
        params.append(action_filter)
    
    query += " ORDER BY al.created_at DESC"
    
    logs = fetch_all(query, params)
    
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['Date & Time', 'User', 'File', 'Action', 'Description', 'IP Address'])
    
    for log in logs:
        writer.writerow([
            log['created_at'],
            log['full_name'] or 'Public/Unknown',
            log['original_filename'] or '-',
            log['action'],
            log['description'],
            log['ip_address'] or '-'
        ])
    
    output = si.getvalue()
    response = Response(output, mimetype='text/csv')
    filename = f"audit_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    response.headers.set('Content-Disposition', 'attachment', filename=filename)
    
    add_log(session['user_id'], None, 'EXPORT_LOGS', f'Exported logs to CSV', request.remote_addr)
    
    return response

# =====================
# ROUTES - ADMIN
# =====================
@app.route('/admin')
def admin_dashboard():
    if not is_logged_in() or not is_admin(): 
        return redirect(url_for('home'))
    
    total_users = fetch_one("SELECT COUNT(*) AS total FROM users")
    total_files = fetch_one("SELECT COUNT(*) AS total FROM files")
    total_links = fetch_one("SELECT COUNT(*) AS total FROM share_links")
    total_logs = fetch_one("SELECT COUNT(*) AS total FROM audit_logs")
    
    recent_logs = fetch_all("""
        SELECT al.*, u.full_name, f.original_filename
        FROM audit_logs al
        LEFT JOIN users u ON u.id = al.user_id
        LEFT JOIN files f ON f.id = al.file_id
        ORDER BY al.created_at DESC
        LIMIT 10
    """)
    
    return render_template('admin_dashboard.html',
        total_users=total_users,
        total_files=total_files,
        total_links=total_links,
        total_logs=total_logs,
        recent_logs=recent_logs
    )

@app.route('/admin/users')
def admin_users():
    if not is_logged_in() or not is_admin(): 
        return redirect(url_for('home'))
    
    users = fetch_all("SELECT * FROM users ORDER BY created_at DESC")
    return render_template('admin_users.html', users=users)

@app.route('/admin/toggle-user/<int:user_id>', methods=['POST'])
def toggle_user(user_id):
    if not is_logged_in() or not is_admin():
        return redirect(url_for('home'))
    
    if user_id == session['user_id']:
        flash('You cannot deactivate your own account.', 'danger')
        return redirect(url_for('admin_users'))
    
    user = fetch_one("SELECT is_active FROM users WHERE id = %s", (user_id,))
    if user:
        new_status = 0 if user['is_active'] else 1
        execute_query("UPDATE users SET is_active = %s WHERE id = %s", (new_status, user_id))
        add_log(session['user_id'], None, 'USER_STATUS_CHANGE', 
                f'Toggled user {user_id} to {"active" if new_status else "inactive"}', request.remote_addr)
        flash('User status updated.', 'success')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/logs')
def admin_logs():
    if not is_logged_in() or not is_admin():
        return redirect(url_for('home'))
    
    keyword = request.args.get('keyword', '')
    action_filter = request.args.get('action', '')
    
    query = """
        SELECT al.*, u.full_name, f.original_filename
        FROM audit_logs al
        LEFT JOIN users u ON u.id = al.user_id
        LEFT JOIN files f ON f.id = al.file_id
        WHERE 1=1
    """
    params = []
    
    if keyword:
        query += " AND (al.description LIKE %s OR u.full_name LIKE %s OR f.original_filename LIKE %s)"
        params.extend([f'%{keyword}%', f'%{keyword}%', f'%{keyword}%'])
    
    if action_filter:
        query += " AND al.action = %s"
        params.append(action_filter)
    
    query += " ORDER BY al.created_at DESC LIMIT 200"
    
    logs = fetch_all(query, params)
    return render_template('admin_logs.html', logs=logs, keyword=keyword, action=action_filter)

@app.route('/admin/reports')
def admin_reports():
    if not is_logged_in() or not is_admin():
        return redirect(url_for('home'))
    
    top_files = fetch_all("""
        SELECT f.original_filename, sl.used_views AS total_views
        FROM files f
        JOIN share_links sl ON sl.file_id = f.id
        ORDER BY total_views DESC
        LIMIT 10
    """)
    
    action_stats = fetch_all("""
        SELECT action, COUNT(*) AS total
        FROM audit_logs
        GROUP BY action
        ORDER BY total DESC
    """)
    
    return render_template('admin_reports.html', top_files=top_files, action_stats=action_stats)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)