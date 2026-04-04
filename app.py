from flask import Flask, flash, g, jsonify, redirect, render_template, request, send_from_directory, session, url_for
import csv
import base64
import hashlib
import ipaddress
import json
import mimetypes
import os
import re
import secrets
import socket
import sqlite3
import time
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from urllib import error as url_error
from urllib import parse as url_parse
from urllib import request as url_request
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None
try:
    from openai import OpenAI
except Exception:
    OpenAI = None
try:
    import stripe
except Exception:
    stripe = None
try:
    import requests
except Exception:
    requests = None

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / 'cybersecurity.db'
CSV_PATH = BASE_DIR / 'dataset.csv'
if load_dotenv is not None:
    load_dotenv(BASE_DIR / '.env')
AUTHOR_NAME = 'Al Momna Umar Daraz'
APP_BRAND_NAME = 'AI Cybersecurity Assistant'
DEFAULT_ADMIN_EMAIL = 'admin@cybershield.local'
DEFAULT_ADMIN_PASSWORD = os.getenv('DEFAULT_ADMIN_PASSWORD', '').strip()
DEFAULT_ADMIN_NAME = 'Admin User'
HIBP_API_KEY = os.getenv('HIBP_API_KEY', '').strip()
HIBP_BASE_URL = 'https://haveibeenpwned.com'
HIBP_USER_AGENT = 'CyberShield-AI-Breach-Module'
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '').strip()
OPENAI_MODEL = os.getenv('OPENAI_MODEL', 'gpt-5.4')
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID', '').strip()
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET', '').strip()
GOOGLE_REDIRECT_URI = os.getenv('GOOGLE_REDIRECT_URI', '').strip()
GOOGLE_OAUTH_SCOPE = 'openid email profile'
STRIPE_SECRET_KEY = os.getenv('STRIPE_SECRET_KEY', '').strip()
STRIPE_PUBLISHABLE_KEY = os.getenv('STRIPE_PUBLISHABLE_KEY', '').strip()
STRIPE_WEBHOOK_SECRET = os.getenv('STRIPE_WEBHOOK_SECRET', '').strip()
ADSENSE_CLIENT = os.getenv('ADSENSE_CLIENT', '').strip()
FACECHECK_API_TOKEN = os.getenv('FACECHECK_API_TOKEN', '').strip()
FACECHECK_DEMO = os.getenv('FACECHECK_DEMO', '1').strip() == '1'
FACECHECK_BASE_URL = 'https://facecheck.id'
UBL_BANK_NAME = os.getenv('UBL_BANK_NAME', 'United Bank Limited (UBL)').strip()
UBL_ACCOUNT_TITLE = os.getenv('UBL_ACCOUNT_TITLE', '').strip()
UBL_ACCOUNT_NUMBER = os.getenv('UBL_ACCOUNT_NUMBER', '').strip()
UBL_IBAN = os.getenv('UBL_IBAN', '').strip()
PK_BANK_NAME = os.getenv('PK_BANK_NAME', UBL_BANK_NAME or 'Pakistan Bank').strip()
PK_ACCOUNT_TITLE = os.getenv('PK_ACCOUNT_TITLE', UBL_ACCOUNT_TITLE).strip()
PK_ACCOUNT_NUMBER = os.getenv('PK_ACCOUNT_NUMBER', UBL_ACCOUNT_NUMBER).strip()
PK_IBAN = os.getenv('PK_IBAN', UBL_IBAN).strip()
BANK_TRANSFER_AUTO_APPROVE = os.getenv('BANK_TRANSFER_AUTO_APPROVE', '0').strip() == '1'
DANGEROUS_PORTS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    135: 'RPC',
    139: 'NetBIOS',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    1433: 'MSSQL',
    1521: 'Oracle',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    8080: 'HTTP-Alt',
}
LINUX_LAB_RULES = {
    'pwd': {'safe': True, 'tip': 'Print working directory.'},
    'ls': {'safe': True, 'tip': 'List files. Try: ls -la'},
    'cd': {'safe': True, 'tip': 'Change directory carefully.'},
    'cat': {'safe': True, 'tip': 'View file contents.'},
    'grep': {'safe': True, 'tip': 'Search text patterns in files.'},
    'find': {'safe': True, 'tip': 'Find files by name/type.'},
    'head': {'safe': True, 'tip': 'Preview first lines.'},
    'tail': {'safe': True, 'tip': 'Preview last lines.'},
    'chmod': {'safe': True, 'tip': 'Set proper permissions, avoid 777.'},
    'chown': {'safe': True, 'tip': 'Change file owner cautiously.'},
    'ps': {'safe': True, 'tip': 'Inspect running processes.'},
    'top': {'safe': True, 'tip': 'Monitor system usage.'},
    'kill': {'safe': False, 'tip': 'Can terminate critical processes.'},
    'sudo': {'safe': False, 'tip': 'Elevated privileges, high impact.'},
    'rm': {'safe': False, 'tip': 'Deletion command; very risky with -rf.'},
    'dd': {'safe': False, 'tip': 'Raw disk writes can destroy data.'},
    'mkfs': {'safe': False, 'tip': 'Formats filesystem; destructive.'},
    'shutdown': {'safe': False, 'tip': 'System availability impact.'},
}
COMMAND_GUIDE = [
    {
        'key': 'pwd',
        'command': 'pwd',
        'risk': 'SAFE',
        'what_happens': 'Prints the current working directory.',
        'how_to_use': 'Use it to confirm where you are before running file operations.',
        'example': 'pwd',
        'output_example': '/home/user/project',
    },
    {
        'key': 'ls',
        'command': 'ls -la',
        'risk': 'SAFE',
        'what_happens': 'Lists files and folders including hidden entries and permissions.',
        'how_to_use': 'Use it to inspect directory content safely.',
        'example': 'ls -la /var/log',
        'output_example': 'drwxr-xr-x logs\n-rw-r--r-- app.conf\n-rw-r--r-- access.log',
    },
    {
        'key': 'cd',
        'command': 'cd',
        'risk': 'SAFE',
        'what_happens': 'Changes the current directory.',
        'how_to_use': 'Pass an absolute or relative path.',
        'example': 'cd /etc/nginx',
        'output_example': 'Directory changed successfully.',
    },
    {
        'key': 'cat',
        'command': 'cat',
        'risk': 'SAFE',
        'what_happens': 'Displays file content.',
        'how_to_use': 'Use it to read text/config files.',
        'example': 'cat /etc/hosts',
        'output_example': '127.0.0.1 localhost\n::1 localhost',
    },
    {
        'key': 'grep',
        'command': 'grep',
        'risk': 'SAFE',
        'what_happens': 'Filters lines that match a pattern.',
        'how_to_use': 'Use it to search logs and files for keywords.',
        'example': "grep -i 'error' /var/log/syslog",
        'output_example': 'Jun 10 app[123]: error connection timeout',
    },
    {
        'key': 'find',
        'command': 'find',
        'risk': 'SAFE',
        'what_happens': 'Searches files/directories in a path.',
        'how_to_use': 'Use filters like name/type for precise results.',
        'example': 'find /var/www -name "*.conf"',
        'output_example': '/var/www/nginx.conf',
    },
    {
        'key': 'chmod',
        'command': 'chmod',
        'risk': 'WARNING',
        'what_happens': 'Changes file permissions.',
        'how_to_use': 'Apply least privilege; avoid 777 permissions.',
        'example': 'chmod 640 /etc/secret.conf',
        'output_example': 'Permissions updated.',
    },
    {
        'key': 'chown',
        'command': 'chown',
        'risk': 'WARNING',
        'what_happens': 'Changes file owner/group.',
        'how_to_use': 'Use for correct service account ownership.',
        'example': 'chown www-data:www-data /var/www/app',
        'output_example': 'Ownership updated.',
    },
    {
        'key': 'ps',
        'command': 'ps aux',
        'risk': 'SAFE',
        'what_happens': 'Shows running processes.',
        'how_to_use': 'Use it to inspect suspicious processes.',
        'example': 'ps aux | grep nginx',
        'output_example': 'root 101 nginx\nwww 222 gunicorn\nuser 333 python',
    },
    {
        'key': 'sudo',
        'command': 'sudo',
        'risk': 'DANGEROUS',
        'what_happens': 'Runs command with elevated privileges.',
        'how_to_use': 'Use only for verified admin tasks.',
        'example': 'sudo systemctl restart nginx',
        'output_example': 'Command executed with elevated privileges.',
    },
    {
        'key': 'rm',
        'command': 'rm -rf',
        'risk': 'DANGEROUS',
        'what_happens': 'Recursively and permanently deletes files/folders.',
        'how_to_use': 'Use extreme caution and verify target path first.',
        'example': 'rm -rf /tmp/test-data',
        'output_example': 'Target files removed permanently.',
    },
    {
        'key': 'shutdown',
        'command': 'shutdown',
        'risk': 'DANGEROUS',
        'what_happens': 'Shuts down or restarts the system.',
        'how_to_use': 'Run only during approved maintenance windows.',
        'example': 'shutdown -r now',
        'output_example': 'System restart initiated.',
    },
]
CREDIT_PACKS = {
    'starter_100': {'title': 'Starter 100 Credits', 'credits': 100, 'price_usd': 5},
    'pro_500': {'title': 'Pro 500 Credits', 'credits': 500, 'price_usd': 19},
    'business_2000': {'title': 'Business 2000 Credits', 'credits': 2000, 'price_usd': 59},
}
ASSISTANT_SYSTEM_PROMPT = (
    'You are a cybersecurity assistant for a practical security training web app. '
    'Give concise, actionable, and safe guidance. '
    'Do not provide instructions for illegal hacking or malware.'
)
UPLOAD_FOLDER = BASE_DIR / 'static' / 'uploads'
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}

app = Flask(__name__, template_folder='static/templates', static_folder='static')
app.secret_key = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.getenv(
        'SESSION_COOKIE_SECURE',
        '1' if os.getenv('ENFORCE_HTTPS', '0') == '1' else '0',
    ) == '1',
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)

ENFORCE_HTTPS = os.getenv('ENFORCE_HTTPS', '0') == '1'
API_RATE_LIMIT = int(os.getenv('API_RATE_LIMIT', '120'))
API_RATE_WINDOW = int(os.getenv('API_RATE_WINDOW', '60'))
AUTH_RATE_LIMIT = int(os.getenv('AUTH_RATE_LIMIT', '20'))
AUTH_RATE_WINDOW = int(os.getenv('AUTH_RATE_WINDOW', '600'))
LOGIN_MAX_FAILURES = int(os.getenv('LOGIN_MAX_FAILURES', '5'))
LOGIN_LOCK_SECONDS = int(os.getenv('LOGIN_LOCK_SECONDS', '900'))
DEFAULT_CURRENCY = 'usd'
HIBP_BREACHES_CACHE_SECONDS = 6 * 60 * 60
HIBP_BREACHES_FAIL_CACHE_SECONDS = 5 * 60
_hibp_breaches_cache = {'fetched_at': 0, 'data': [], 'failed_at': 0, 'fail_message': ''}


def build_static_version():
    files = [
        BASE_DIR / 'static' / 'script.js',
        BASE_DIR / 'static' / 'style.css',
        BASE_DIR / 'static' / 'sw.js',
    ]
    latest = 0
    for p in files:
        try:
            latest = max(latest, int(p.stat().st_mtime))
        except Exception:
            continue
    return str(latest or int(time.time()))


STATIC_VERSION = build_static_version()

UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
if stripe is not None and STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY


def get_db_connection():
    global DB_PATH
    try:
        conn = sqlite3.connect(DB_PATH)
    except sqlite3.Error:
        DB_PATH = BASE_DIR / 'cybersecurity_runtime.db'
        conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_client_ip():
    forwarded = (request.headers.get('X-Forwarded-For') or '').strip()
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or 'unknown'


def get_csrf_token():
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['_csrf_token'] = token
    return token


def is_valid_csrf():
    expected = session.get('_csrf_token')
    supplied = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
    return bool(expected and supplied and secrets.compare_digest(str(expected), str(supplied)))


def record_security_event(event_type, event_key):
    now_ts = int(time.time())
    conn = None
    try:
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO security_events (event_type, event_key, created_at) VALUES (?, ?, ?)',
            (str(event_type), str(event_key), now_ts),
        )
        conn.execute('DELETE FROM security_events WHERE created_at < ?', (now_ts - 86400,))
        conn.commit()
    except sqlite3.Error:
        return False
    finally:
        if conn is not None:
            conn.close()
    return True


def count_security_events(event_type, event_key, window_seconds):
    now_ts = int(time.time())
    conn = None
    try:
        conn = get_db_connection()
        row = conn.execute(
            '''
            SELECT COUNT(*) AS count
            FROM security_events
            WHERE event_type = ? AND event_key = ? AND created_at >= ?
            ''',
            (str(event_type), str(event_key), now_ts - int(window_seconds)),
        ).fetchone()
        return int(row['count'] if row else 0)
    except sqlite3.Error:
        return 0
    finally:
        if conn is not None:
            conn.close()


def check_rate_limit(event_type, event_key, limit, window_seconds):
    try:
        current = count_security_events(event_type, event_key, window_seconds)
    except Exception:
        return True
    if current >= int(limit):
        return False
    try:
        record_security_event(event_type, event_key)
    except Exception:
        return True
    return True


def set_login_lock(lock_key, lock_until_ts):
    conn = get_db_connection()
    try:
        conn.execute(
            '''
            INSERT INTO login_locks (lock_key, lock_until)
            VALUES (?, ?)
            ON CONFLICT(lock_key) DO UPDATE SET lock_until = excluded.lock_until
            ''',
            (str(lock_key), int(lock_until_ts)),
        )
        conn.commit()
    finally:
        conn.close()


def get_login_lock_seconds(lock_key):
    now_ts = int(time.time())
    conn = get_db_connection()
    try:
        row = conn.execute('SELECT lock_until FROM login_locks WHERE lock_key = ?', (str(lock_key),)).fetchone()
        if not row:
            return 0
        lock_until = int(row['lock_until'] or 0)
        if lock_until <= now_ts:
            conn.execute('DELETE FROM login_locks WHERE lock_key = ?', (str(lock_key),))
            conn.commit()
            return 0
        return lock_until - now_ts
    finally:
        conn.close()


def get_login_lock_state(email, ip):
    for key in (f'email:{email}', f'ip:{ip}'):
        seconds = get_login_lock_seconds(key)
        if seconds > 0:
            return True, int(seconds)
    return False, 0


def record_login_failure(email, ip):
    now_ts = int(time.time())
    for key in (f'email:{email}', f'ip:{ip}'):
        record_security_event('login_fail', key)
        fail_count = count_security_events('login_fail', key, LOGIN_LOCK_SECONDS)
        if fail_count >= LOGIN_MAX_FAILURES:
            set_login_lock(key, now_ts + LOGIN_LOCK_SECONDS)


def clear_login_failures(email, ip):
    conn = get_db_connection()
    try:
        for key in (f'email:{email}', f'ip:{ip}'):
            conn.execute('DELETE FROM security_events WHERE event_type = ? AND event_key = ?', ('login_fail', key))
            conn.execute('DELETE FROM login_locks WHERE lock_key = ?', (key,))
        conn.commit()
    finally:
        conn.close()


def is_google_oauth_enabled():
    return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)


def get_google_redirect_uri():
    if GOOGLE_REDIRECT_URI:
        return GOOGLE_REDIRECT_URI
    return url_for('google_auth_callback', _external=True)


def google_exchange_code_for_token(code):
    payload = url_parse.urlencode(
        {
            'code': code,
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'redirect_uri': get_google_redirect_uri(),
            'grant_type': 'authorization_code',
        }
    ).encode('utf-8')
    req = url_request.Request(
        'https://oauth2.googleapis.com/token',
        data=payload,
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
        method='POST',
    )
    with url_request.urlopen(req, timeout=12) as resp:
        body = resp.read().decode('utf-8')
        return json.loads(body) if body else {}


def google_get_userinfo(access_token):
    req = url_request.Request(
        'https://openidconnect.googleapis.com/v1/userinfo',
        headers={'Authorization': f'Bearer {access_token}'},
        method='GET',
    )
    with url_request.urlopen(req, timeout=12) as resp:
        body = resp.read().decode('utf-8')
        return json.loads(body) if body else {}


def normalize_phone(value):
    raw = str(value or '').strip()
    digits = ''.join(ch for ch in raw if ch.isdigit())
    if raw.startswith('+'):
        digits = '+' + digits
    return digits


def is_valid_phone(value):
    phone = normalize_phone(value)
    return bool(re.match(r'^\+?\d{10,15}$', phone))


def is_allowed_image(filename):
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    return ext in ALLOWED_IMAGE_EXTENSIONS


def save_profile_image(file_storage, user_id):
    if not file_storage or not file_storage.filename:
        return None, None
    if not is_allowed_image(file_storage.filename):
        return None, 'Invalid image type. Use png, jpg, jpeg, or webp.'

    original = secure_filename(file_storage.filename)
    ext = original.rsplit('.', 1)[-1].lower()
    name = f'profile_{int(user_id)}_{secrets.token_hex(6)}.{ext}'
    path = UPLOAD_FOLDER / name
    file_storage.save(path)
    return name, None


def parse_dataset_csv(csv_path):
    if not csv_path.exists():
        return []

    records = []
    current_type = None

    with csv_path.open('r', encoding='utf-8', newline='') as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or len(row) < 2:
                continue

            left = row[0].strip().lower()
            right = row[1].strip().lower()

            if left in {'command', 'password', 'url'} and right == 'threat_level':
                current_type = left
                continue

            if current_type is None:
                continue

            pattern_text = row[0].strip().strip('"')
            try:
                threat_level = int(row[1])
            except ValueError:
                continue

            records.append((current_type, pattern_text, threat_level))

    return records


def set_setting(conn, user_id, key, value):
    conn.execute(
        '''
        INSERT INTO user_settings (user_id, setting_key, setting_value)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id, setting_key) DO UPDATE SET setting_value = excluded.setting_value
        ''',
        (int(user_id), key, str(value)),
    )


def ensure_user_default_settings(conn, user_id):
    default_settings = {
        'dark_mode': '0',
        'threat_alerts': '1',
        'scan_complete': '1',
        'auto_refresh': '1',
    }
    for key, value in default_settings.items():
        set_setting(conn, int(user_id), key, value)


def ensure_scan_reports_user_column(conn):
    cols = conn.execute('PRAGMA table_info(scan_reports)').fetchall()
    column_names = {row['name'] for row in cols}
    if 'user_id' not in column_names:
        conn.execute('ALTER TABLE scan_reports ADD COLUMN user_id INTEGER')


def ensure_users_extra_columns(conn):
    cols = conn.execute('PRAGMA table_info(users)').fetchall()
    column_names = {row['name'] for row in cols}
    if 'phone' not in column_names:
        conn.execute('ALTER TABLE users ADD COLUMN phone TEXT')
    if 'profile_image' not in column_names:
        conn.execute('ALTER TABLE users ADD COLUMN profile_image TEXT')


def is_ads_enabled():
    return bool(is_real_config_value(ADSENSE_CLIENT))


def is_real_config_value(value):
    text = str(value or '').strip()
    if not text:
        return False
    lowered = text.lower()
    blocked_prefixes = (
        'replace_with_',
        'ca-pub-xxxxxxxx',
        'pk00demo',
    )
    return not lowered.startswith(blocked_prefixes)


def is_stripe_enabled():
    return bool(
        stripe is not None
        and is_real_config_value(STRIPE_SECRET_KEY)
        and is_real_config_value(STRIPE_PUBLISHABLE_KEY)
    )


def is_facecheck_enabled():
    return bool(requests is not None and is_real_config_value(FACECHECK_API_TOKEN))


def is_ubl_payout_configured():
    return bool(
        is_real_config_value(UBL_ACCOUNT_TITLE)
        and (is_real_config_value(UBL_ACCOUNT_NUMBER) or is_real_config_value(UBL_IBAN))
    )


def is_pk_bank_payout_configured():
    return bool(
        is_real_config_value(PK_ACCOUNT_TITLE)
        and (is_real_config_value(PK_ACCOUNT_NUMBER) or is_real_config_value(PK_IBAN))
    )


def ensure_user_wallet(conn, user_id):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn.execute(
        '''
        INSERT INTO user_wallet (user_id, balance, updated_at)
        VALUES (?, 0, ?)
        ON CONFLICT(user_id) DO NOTHING
        ''',
        (int(user_id), now),
    )


def create_default_user(conn):
    if not DEFAULT_ADMIN_PASSWORD:
        return None

    row = conn.execute('SELECT id FROM users WHERE email = ?', (DEFAULT_ADMIN_EMAIL,)).fetchone()
    if row:
        return int(row['id'])

    cur = conn.execute(
        'INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)',
        (
            DEFAULT_ADMIN_NAME,
            DEFAULT_ADMIN_EMAIL,
            generate_password_hash(DEFAULT_ADMIN_PASSWORD),
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        ),
    )
    return int(cur.lastrowid)


def init_db():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            phone TEXT,
            profile_image TEXT,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        '''
    )
    ensure_users_extra_columns(conn)

    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS threat_patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern_type TEXT NOT NULL,
            pattern_text TEXT NOT NULL,
            threat_level INTEGER NOT NULL
        )
        '''
    )

    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS scan_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            input_text TEXT NOT NULL,
            input_type TEXT NOT NULL,
            score INTEGER NOT NULL,
            status TEXT NOT NULL,
            threats_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        '''
    )

    ensure_scan_reports_user_column(conn)

    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS user_settings (
            user_id INTEGER NOT NULL,
            setting_key TEXT NOT NULL,
            setting_value TEXT NOT NULL
            ,
            PRIMARY KEY (user_id, setting_key),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        '''
    )
    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            event_key TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
        '''
    )
    cur.execute(
        '''
        CREATE INDEX IF NOT EXISTS idx_security_events_type_key_time
        ON security_events (event_type, event_key, created_at)
        '''
    )
    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS login_locks (
            lock_key TEXT PRIMARY KEY,
            lock_until INTEGER NOT NULL
        )
        '''
    )
    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS user_wallet (
            user_id INTEGER PRIMARY KEY,
            balance INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        '''
    )
    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS credit_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            tx_type TEXT NOT NULL,
            reference TEXT,
            meta_json TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        '''
    )
    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS payment_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_token TEXT NOT NULL UNIQUE,
            user_id INTEGER NOT NULL,
            pack_key TEXT NOT NULL,
            credits INTEGER NOT NULL,
            amount_cents INTEGER NOT NULL,
            currency TEXT NOT NULL DEFAULT 'usd',
            provider TEXT NOT NULL,
            provider_session_id TEXT,
            status TEXT NOT NULL DEFAULT 'created',
            created_at TEXT NOT NULL,
            paid_at TEXT,
            credited_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        '''
    )
    cur.execute(
        '''
        CREATE INDEX IF NOT EXISTS idx_payment_sessions_user_status
        ON payment_sessions (user_id, status)
        '''
    )

    cur.execute('SELECT COUNT(*) AS count FROM threat_patterns')
    has_data = cur.fetchone()['count'] > 0
    if not has_data:
        records = parse_dataset_csv(CSV_PATH)
        if not records:
            records = [
                ('command', 'rm -rf /', 100),
                ('command', 'del *.*', 95),
                ('command', 'format c:', 98),
                ('command', 'net user hacker', 90),
                ('password', '123456', 80),
                ('password', 'password', 85),
                ('password', 'qwerty', 75),
                ('password', 'abc123', 70),
                ('url', 'bit.ly/suspicious', 90),
                ('url', 'tinyurl.com/phish', 85),
                ('url', 'suspicious.tk', 95),
            ]
        cur.executemany(
            'INSERT INTO threat_patterns (pattern_type, pattern_text, threat_level) VALUES (?, ?, ?)',
            records,
        )

    admin_user_id = create_default_user(conn)
    if admin_user_id:
        ensure_user_default_settings(conn, admin_user_id)

    existing_users = conn.execute('SELECT id FROM users').fetchall()
    for u in existing_users:
        ensure_user_default_settings(conn, int(u['id']))
        ensure_user_wallet(conn, int(u['id']))

    cur.execute('SELECT COUNT(*) AS count FROM scan_reports')
    has_reports = cur.fetchone()['count'] > 0
    if (not has_reports) and admin_user_id:
        now = datetime.now()
        sample_reports = [
            ('rm -rf /tmp', 'command', 92, 'DANGEROUS', ['Malicious command detected: rm -rf /'], now - timedelta(hours=6)),
            ('password123', 'password', 88, 'DANGEROUS', ['Common weak password pattern: password'], now - timedelta(hours=5)),
            ('https://suspicious.tk/login', 'url', 95, 'DANGEROUS', ['Phishing pattern found: suspicious.tk'], now - timedelta(hours=4)),
            ('dir /a', 'command', 10, 'SAFE', [], now - timedelta(hours=3)),
            ('StrongP@ssw0rd2026', 'password', 5, 'SAFE', [], now - timedelta(hours=2)),
            ('https://openai.com', 'url', 0, 'SAFE', [], now - timedelta(hours=1)),
        ]
        cur.executemany(
            '''
            INSERT INTO scan_reports (user_id, input_text, input_type, score, status, threats_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''',
            [
                (
                    admin_user_id,
                    r[0],
                    r[1],
                    r[2],
                    r[3],
                    json.dumps(r[4]),
                    r[5].strftime('%Y-%m-%d %H:%M:%S'),
                )
                for r in sample_reports
            ],
        )

    conn.commit()
    conn.close()


def get_user_by_email(email):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email.lower().strip(),)).fetchone()
    conn.close()
    return user


def get_user_by_phone(phone):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE phone = ?', (normalize_phone(phone),)).fetchone()
    conn.close()
    return user


def get_user_by_id(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return user


def get_user_by_identifier(identifier):
    ident = str(identifier or '').strip()
    if not ident:
        return None
    if '@' in ident:
        return get_user_by_email(ident.lower())
    return get_user_by_phone(ident)


def create_user(name, email, phone, password):
    conn = get_db_connection()
    try:
        cur = conn.execute(
            'INSERT INTO users (name, email, phone, password_hash, created_at) VALUES (?, ?, ?, ?, ?)',
            (
                name.strip(),
                email.lower().strip(),
                normalize_phone(phone),
                generate_password_hash(password),
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            ),
        )
        ensure_user_default_settings(conn, int(cur.lastrowid))
        ensure_user_wallet(conn, int(cur.lastrowid))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get_credit_packs():
    packs = []
    for key, details in CREDIT_PACKS.items():
        packs.append(
            {
                'key': key,
                'title': details['title'],
                'credits': int(details['credits']),
                'price_usd': float(details['price_usd']),
                'price_cents': int(round(float(details['price_usd']) * 100)),
            }
        )
    return packs


def get_credit_pack(pack_key):
    if pack_key not in CREDIT_PACKS:
        return None
    details = CREDIT_PACKS[pack_key]
    return {
        'key': pack_key,
        'title': details['title'],
        'credits': int(details['credits']),
        'price_usd': float(details['price_usd']),
        'price_cents': int(round(float(details['price_usd']) * 100)),
    }


def get_user_credit_balance(user_id):
    conn = get_db_connection()
    try:
        ensure_user_wallet(conn, int(user_id))
        row = conn.execute('SELECT balance FROM user_wallet WHERE user_id = ?', (int(user_id),)).fetchone()
        conn.commit()
        return int(row['balance'] if row else 0)
    finally:
        conn.close()


def add_user_credits(user_id, amount, tx_type, reference='', metadata=None):
    delta = int(amount)
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = get_db_connection()
    try:
        ensure_user_wallet(conn, int(user_id))
        row = conn.execute('SELECT balance FROM user_wallet WHERE user_id = ?', (int(user_id),)).fetchone()
        current_balance = int(row['balance'] if row else 0)
        new_balance = max(0, current_balance + delta)
        conn.execute(
            'UPDATE user_wallet SET balance = ?, updated_at = ? WHERE user_id = ?',
            (new_balance, now, int(user_id)),
        )
        conn.execute(
            '''
            INSERT INTO credit_transactions (user_id, amount, tx_type, reference, meta_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ''',
            (
                int(user_id),
                delta,
                str(tx_type),
                str(reference or ''),
                json.dumps(metadata or {}),
                now,
            ),
        )
        conn.commit()
        return new_balance
    finally:
        conn.close()


def create_payment_session(user_id, pack, provider):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    token = secrets.token_urlsafe(24)
    conn = get_db_connection()
    try:
        conn.execute(
            '''
            INSERT INTO payment_sessions (
                session_token, user_id, pack_key, credits, amount_cents, currency, provider, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                token,
                int(user_id),
                pack['key'],
                int(pack['credits']),
                int(pack['price_cents']),
                DEFAULT_CURRENCY,
                str(provider),
                'created',
                now,
            ),
        )
        conn.commit()
        return token
    finally:
        conn.close()


def update_payment_provider_session(local_token, provider_session_id):
    conn = get_db_connection()
    try:
        conn.execute(
            'UPDATE payment_sessions SET provider_session_id = ? WHERE session_token = ?',
            (str(provider_session_id), str(local_token)),
        )
        conn.commit()
    finally:
        conn.close()


def get_payment_session_for_user(user_id, local_token):
    conn = get_db_connection()
    try:
        return conn.execute(
            'SELECT * FROM payment_sessions WHERE user_id = ? AND session_token = ?',
            (int(user_id), str(local_token)),
        ).fetchone()
    finally:
        conn.close()


def mark_payment_failed(local_token):
    conn = get_db_connection()
    try:
        conn.execute(
            "UPDATE payment_sessions SET status = 'failed' WHERE session_token = ? AND status = 'created'",
            (str(local_token),),
        )
        conn.commit()
    finally:
        conn.close()


def mark_bank_transfer_pending(local_token, transfer_reference):
    conn = get_db_connection()
    try:
        conn.execute(
            '''
            UPDATE payment_sessions
            SET status = 'pending_verification', provider_session_id = ?
            WHERE session_token = ? AND status = 'created'
            ''',
            (str(transfer_reference or ''), str(local_token)),
        )
        conn.commit()
    finally:
        conn.close()


def finalize_paid_session(user_id, local_token, payment_reference):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = get_db_connection()
    try:
        row = conn.execute(
            'SELECT * FROM payment_sessions WHERE user_id = ? AND session_token = ?',
            (int(user_id), str(local_token)),
        ).fetchone()
        if not row:
            return {'ok': False, 'message': 'Payment session not found.'}

        if row['credited_at']:
            bal = conn.execute('SELECT balance FROM user_wallet WHERE user_id = ?', (int(user_id),)).fetchone()
            return {'ok': True, 'already_credited': True, 'balance': int(bal['balance'] if bal else 0)}

        ensure_user_wallet(conn, int(user_id))
        conn.execute(
            '''
            UPDATE payment_sessions
            SET status = 'paid', paid_at = COALESCE(paid_at, ?), credited_at = ?
            WHERE id = ?
            ''',
            (now, now, int(row['id'])),
        )
        wallet_row = conn.execute('SELECT balance FROM user_wallet WHERE user_id = ?', (int(user_id),)).fetchone()
        current_balance = int(wallet_row['balance'] if wallet_row else 0)
        new_balance = max(0, current_balance + int(row['credits']))
        conn.execute(
            'UPDATE user_wallet SET balance = ?, updated_at = ? WHERE user_id = ?',
            (new_balance, now, int(user_id)),
        )
        conn.execute(
            '''
            INSERT INTO credit_transactions (user_id, amount, tx_type, reference, meta_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ''',
            (
                int(user_id),
                int(row['credits']),
                'credit_purchase',
                str(payment_reference or ''),
                json.dumps({'pack_key': row['pack_key'], 'provider': row['provider']}),
                now,
            ),
        )
        conn.commit()
        return {'ok': True, 'already_credited': False, 'balance': new_balance}
    finally:
        conn.close()


def update_user_profile(user_id, name, email, phone, profile_image=None):
    conn = get_db_connection()
    try:
        if profile_image:
            conn.execute(
                'UPDATE users SET name = ?, email = ?, phone = ?, profile_image = ? WHERE id = ?',
                (name.strip(), email.lower().strip(), normalize_phone(phone), profile_image, int(user_id)),
            )
        else:
            conn.execute(
                'UPDATE users SET name = ?, email = ?, phone = ? WHERE id = ?',
                (name.strip(), email.lower().strip(), normalize_phone(phone), int(user_id)),
            )
        conn.commit()
    finally:
        conn.close()


def login_required(view_fn):
    @wraps(view_fn)
    def wrapped(*args, **kwargs):
        if g.user is None:
            next_url = request.path
            return redirect(url_for('login', next=next_url))
        return view_fn(*args, **kwargs)

    return wrapped


def api_login_required(view_fn):
    @wraps(view_fn)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return jsonify({'error': 'Unauthorized'}), 401
        return view_fn(*args, **kwargs)

    return wrapped


def get_patterns_by_type(pattern_type):
    conn = get_db_connection()
    rows = conn.execute(
        'SELECT pattern_text, threat_level FROM threat_patterns WHERE pattern_type = ?',
        (pattern_type,),
    ).fetchall()
    conn.close()
    return rows


def build_breach_safety_notes(breach_count, mode, domain, status):
    notes = []
    if mode == 'live':
        if breach_count == 0:
            notes.append('No public breach record was returned for this email at this time.')
            notes.append('Use a unique password and enable MFA to stay protected.')
            notes.append('Keep monitoring periodically because new breaches can appear later.')
        else:
            notes.append(f'This email appears in {breach_count} public breach record(s).')
            notes.append('Change passwords immediately on breached services and any reused accounts.')
            notes.append('Enable MFA and review account recovery settings to reduce takeover risk.')
    else:
        notes.append('Live breach API is currently unavailable; this is a local risk estimate.')
        notes.append('Without live data, exact breach count cannot be confirmed right now.')
        if status == 'SAFE':
            notes.append('Current domain pattern looks lower risk, but continue using MFA and unique passwords.')
        elif status == 'WARNING':
            notes.append('Domain pattern indicates moderate risk. Rotate password and review account activity.')
        else:
            notes.append('Domain pattern indicates higher risk. Change password now and secure linked accounts.')

    if domain:
        notes.append(f'Email domain analyzed: {domain}')
    return notes[:6]


def build_email_breach_fallback(email_clean, account_link, reason):
    domain = ''
    if '@' in email_clean:
        domain = email_clean.split('@', 1)[1].strip().lower()

    score = 20
    if domain in {'gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'icloud.com', 'proton.me', 'protonmail.com'}:
        score = 18
    risky_suffixes = ('.ru', '.tk', '.xyz', '.top', '.click')
    if any(domain.endswith(sfx) for sfx in risky_suffixes):
        score = 72
    elif '-' in domain or domain.count('.') >= 3:
        score = 45

    status = 'SAFE' if score < 30 else 'WARNING' if score < 70 else 'DANGEROUS'
    notes = build_breach_safety_notes(0, 'fallback', domain, status)

    msg = 'Live breach lookup unavailable. Showing local safety estimate.'
    if reason:
        msg = f'{msg} {reason}'

    return {
        'ok': True,
        'score': int(score),
        'status': status,
        'message': msg,
        'breaches': [],
        'account_link': account_link,
        'mode': 'fallback',
        'live_available': False,
        'safety_notes': notes,
    }


def check_hibp_breaches(email):
    email_clean = (email or '').strip().lower()
    account_link = f'{HIBP_BASE_URL}/account/{url_parse.quote(email_clean)}'
    domain = email_clean.split('@', 1)[1] if '@' in email_clean else ''

    if not HIBP_API_KEY:
        return build_email_breach_fallback(
            email_clean,
            account_link,
            'HIBP API key is missing on server.'
        )

    endpoint = f'{HIBP_BASE_URL}/api/v3/breachedaccount/{url_parse.quote(email_clean)}?truncateResponse=false'
    req = url_request.Request(
        endpoint,
        headers={
            'hibp-api-key': HIBP_API_KEY,
            'user-agent': HIBP_USER_AGENT,
        },
        method='GET',
    )

    try:
        with url_request.urlopen(req, timeout=12) as resp:
            body = resp.read().decode('utf-8')
            data = json.loads(body) if body else []
            breaches = []
            for item in data:
                breaches.append(
                    {
                        'name': item.get('Name', ''),
                        'title': item.get('Title', ''),
                        'domain': item.get('Domain', ''),
                        'breach_date': item.get('BreachDate', ''),
                        'added_date': item.get('AddedDate', ''),
                        'pwn_count': item.get('PwnCount', 0),
                        'data_classes': item.get('DataClasses', []),
                    }
                )

            breach_count = len(breaches)
            score = min(100, breach_count * 25)
            status = 'SAFE' if breach_count == 0 else 'DANGEROUS'
            message = 'No known breaches found.' if breach_count == 0 else f'{breach_count} breach record(s) found.'
            return {
                'ok': True,
                'score': score,
                'status': status,
                'message': message,
                'breaches': breaches,
                'account_link': account_link,
                'mode': 'live',
                'live_available': True,
                'safety_notes': build_breach_safety_notes(breach_count, 'live', domain, status),
            }
    except url_error.HTTPError as ex:
        if ex.code == 404:
            return {
                'ok': True,
                'score': 0,
                'status': 'SAFE',
                'message': 'No known breaches found.',
                'breaches': [],
                'account_link': account_link,
                'mode': 'live',
                'live_available': True,
                'safety_notes': build_breach_safety_notes(0, 'live', domain, 'SAFE'),
            }
        if ex.code in (401, 403):
            msg = 'HIBP authentication failed. Verify HIBP_API_KEY.'
        elif ex.code == 429:
            msg = 'HIBP rate limit reached. Please retry shortly.'
        else:
            msg = f'HIBP request failed with status {ex.code}.'
        return build_email_breach_fallback(email_clean, account_link, msg)
    except Exception:
        return build_email_breach_fallback(email_clean, account_link, 'Unable to reach HIBP right now.')


def normalize_url_input(raw_url):
    value = (raw_url or '').strip()
    if not value:
        return {'ok': False, 'message': 'URL is required.', 'url': '', 'domain': ''}

    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', value):
        value = 'https://' + value

    try:
        parsed = url_parse.urlparse(value)
    except Exception:
        return {'ok': False, 'message': 'Invalid URL format.', 'url': '', 'domain': ''}

    host = (parsed.hostname or '').strip().lower()
    if not host:
        return {'ok': False, 'message': 'Invalid URL: hostname not found.', 'url': '', 'domain': ''}

    is_ip_host = False
    try:
        ipaddress.ip_address(host)
        is_ip_host = True
    except Exception:
        is_ip_host = False

    if (not is_ip_host) and ('.' not in host):
        return {'ok': False, 'message': 'Invalid URL/domain format.', 'url': '', 'domain': ''}

    if host in {'localhost', '127.0.0.1'}:
        return {'ok': False, 'message': 'Localhost URLs are not allowed for scan.', 'url': '', 'domain': ''}

    return {'ok': True, 'url': value, 'domain': host, 'scheme': parsed.scheme.lower()}


def normalize_host_input(raw_host):
    value = (raw_host or '').strip()
    if not value:
        return {'ok': False, 'host': '', 'message': 'Host is required.'}

    try:
        parsed = url_parse.urlparse(value if '://' in value else ('//' + value), scheme='http')
        host = (parsed.hostname or '').strip().lower()
    except Exception:
        host = ''

    if not host:
        host = value.strip().lower()

    if host.endswith('.'):
        host = host[:-1]

    if not host:
        return {'ok': False, 'host': '', 'message': 'Invalid host format.'}

    return {'ok': True, 'host': host, 'message': 'ok'}


def get_hibp_breaches_catalog():
    now_ts = int(time.time())
    if _hibp_breaches_cache['data'] and (now_ts - int(_hibp_breaches_cache['fetched_at'])) < HIBP_BREACHES_CACHE_SECONDS:
        return {'ok': True, 'data': _hibp_breaches_cache['data'], 'cached': True}
    if _hibp_breaches_cache.get('failed_at') and (now_ts - int(_hibp_breaches_cache.get('failed_at', 0))) < HIBP_BREACHES_FAIL_CACHE_SECONDS:
        return {'ok': False, 'message': _hibp_breaches_cache.get('fail_message') or 'Breach catalog unavailable.'}

    if not HIBP_API_KEY:
        return {'ok': False, 'message': 'HIBP API key missing.'}

    req = url_request.Request(
        f'{HIBP_BASE_URL}/api/v3/breaches',
        headers={
            'hibp-api-key': HIBP_API_KEY,
            'user-agent': HIBP_USER_AGENT,
        },
        method='GET',
    )
    try:
        with url_request.urlopen(req, timeout=8) as resp:
            body = resp.read().decode('utf-8')
            data = json.loads(body) if body else []
            if not isinstance(data, list):
                data = []
            _hibp_breaches_cache['fetched_at'] = now_ts
            _hibp_breaches_cache['data'] = data
            _hibp_breaches_cache['failed_at'] = 0
            _hibp_breaches_cache['fail_message'] = ''
            return {'ok': True, 'data': data, 'cached': False}
    except url_error.HTTPError as ex:
        msg = f'HIBP request failed with status {ex.code}.'
        _hibp_breaches_cache['failed_at'] = now_ts
        _hibp_breaches_cache['fail_message'] = msg
        return {'ok': False, 'message': msg}
    except Exception:
        msg = 'Unable to reach HIBP breach catalog right now.'
        _hibp_breaches_cache['failed_at'] = now_ts
        _hibp_breaches_cache['fail_message'] = msg
        return {'ok': False, 'message': msg}


def count_breaches_for_domain(domain):
    catalog = get_hibp_breaches_catalog()
    if not catalog.get('ok'):
        return {'ok': False, 'count': None, 'message': catalog.get('message', 'Breach catalog unavailable.')}

    count = 0
    domain_clean = (domain or '').strip().lower()
    for item in catalog.get('data', []):
        item_domain = str(item.get('Domain') or '').strip().lower()
        if not item_domain:
            continue
        if domain_clean == item_domain or domain_clean.endswith('.' + item_domain):
            count += 1
    return {'ok': True, 'count': int(count), 'message': 'ok'}


def run_url_scan(url_input):
    normalized = normalize_url_input(url_input)
    if not normalized.get('ok'):
        return {'ok': False, 'message': normalized.get('message', 'Invalid URL.')}

    target_url = normalized['url']
    domain = normalized['domain']
    scheme = normalized['scheme']

    score, threats = calculate_threat_score(target_url, 'url')
    findings = list(threats)

    if scheme != 'https':
        score += 20
        findings.append('URL is not using HTTPS.')

    if domain.count('-') >= 3:
        score += 10
        findings.append('Domain has many hyphens, which can be suspicious.')

    if 'xn--' in domain:
        score += 20
        findings.append('Punycode domain detected (possible homograph risk).')

    breach_info = count_breaches_for_domain(domain)
    breach_count = int(breach_info.get('count', 0) or 0)
    if breach_info.get('ok') and breach_count > 0:
        score += min(35, breach_count * 5)
        findings.append(f'Domain appears in {breach_count} known breach record(s).')

    score = min(int(score), 100)
    status = 'SAFE' if score < 30 else 'WARNING' if score < 70 else 'DANGEROUS'
    safe_percent = max(0, 100 - score)

    if not breach_info.get('ok'):
        breach_message = 'Breach data unavailable (API key missing or remote service issue).'
    elif breach_count == 0:
        breach_message = 'No known breaches for this domain.'
    else:
        breach_message = f'{breach_count} known breach record(s) for this domain.'

    return {
        'ok': True,
        'url': target_url,
        'domain': domain,
        'score': score,
        'safe_percent': safe_percent,
        'status': status,
        'breach_count': breach_count,
        'hibp_available': breach_info.get('ok', False),
        'breach_message': breach_message,
        'message': 'URL scan completed.',
        'threats': findings or ['No major threat indicators detected.'],
    }


def parse_port_list(port_input):
    if not port_input:
        return [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080]

    ports = []
    raw = str(port_input).split(',')
    for item in raw:
        part = item.strip()
        if not part:
            continue
        if '-' in part:
            start, end = part.split('-', 1)
            if start.isdigit() and end.isdigit():
                s, e = int(start), int(end)
                if 1 <= s <= 65535 and 1 <= e <= 65535 and s <= e:
                    ports.extend(range(s, e + 1))
        elif part.isdigit():
            p = int(part)
            if 1 <= p <= 65535:
                ports.append(p)
    return sorted(list(dict.fromkeys(ports)))[:200]


def validate_scan_target(host):
    target = (host or '').strip()
    if not target:
        return False, 'Host is required.', ''

    if target.lower() in {'localhost', 'localhost.localdomain'}:
        return False, 'Localhost scanning is blocked for safety.', ''

    try:
        infos = socket.getaddrinfo(target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = sorted({info[4][0] for info in infos if info and info[4]})
    except Exception:
        return False, 'Could not resolve host.', ''

    if not ips:
        return False, 'Could not resolve host.', ''

    for ip_text in ips:
        ip_obj = ipaddress.ip_address(ip_text)
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            return False, 'Target resolves to private/internal address. Scan blocked for safety.', ''

    return True, '', ips[0]


def run_port_scan(host, ports):
    results = []
    open_ports = []
    is_allowed, reason, resolved_ip = validate_scan_target(host)
    if not is_allowed:
        return {
            'ok': False,
            'status': 'UNKNOWN',
            'score': 0,
            'message': reason,
            'target_ip': '',
            'results': [],
        }

    for port in ports:
        is_open = False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.45)
            code = sock.connect_ex((resolved_ip, int(port)))
            is_open = code == 0
        except Exception:
            is_open = False
        finally:
            try:
                sock.close()
            except Exception:
                pass

        service = DANGEROUS_PORTS.get(int(port), 'Unknown')
        results.append({'port': int(port), 'open': bool(is_open), 'service': service})
        if is_open:
            open_ports.append(int(port))

    risky_open = [p for p in open_ports if p in DANGEROUS_PORTS]
    score = min(100, len(risky_open) * 12 + max(0, len(open_ports) - len(risky_open)) * 5)
    status = 'SAFE' if score < 30 else 'WARNING' if score < 70 else 'DANGEROUS'
    msg = f'Open ports: {len(open_ports)}. Risky service ports: {len(risky_open)}.'

    return {
        'ok': True,
        'status': status,
        'score': score,
        'message': msg,
        'target_ip': resolved_ip,
        'results': results,
    }


def run_network_risk_scan(target):
    value = (target or '').strip().lower()
    findings = []
    score = 0

    suspicious_tokens = [
        ('free-gift', 20),
        ('verify-account', 25),
        ('login-secure', 20),
        ('bank-update', 30),
        ('crypto-double', 25),
        ('bit.ly', 20),
        ('tinyurl', 20),
        ('.tk', 30),
        ('.ru', 20),
        ('.xyz', 18),
        ('@', 15),
    ]

    for token, weight in suspicious_tokens:
        if token in value:
            score += weight
            findings.append(f'Suspicious indicator found: {token}')

    if re.match(r'^\\d+\\.\\d+\\.\\d+\\.\\d+$', value):
        score += 15
        findings.append('Direct IP usage can indicate suspicious infrastructure.')

    if 'https://' not in value and 'http://' in value:
        score += 20
        findings.append('Non-HTTPS link detected.')

    status = 'SAFE' if score < 30 else 'WARNING' if score < 70 else 'DANGEROUS'
    return {
        'ok': True,
        'status': status,
        'score': min(100, score),
        'message': 'AI heuristic scan complete.',
        'findings': findings or ['No high-risk indicators found.'],
    }


def evaluate_linux_command(command_text):
    command = (command_text or '').strip()
    if not command:
        return {
            'ok': False,
            'status': 'UNKNOWN',
            'score': 0,
            'message': 'Please enter a Linux command.',
            'feedback': [],
        }

    primary = command.split()[0].lower()
    rule = LINUX_LAB_RULES.get(primary)
    feedback = []
    score = 10

    if rule:
        if rule['safe']:
            feedback.append(f'Command "{primary}" is generally safe for practice.')
            feedback.append(rule['tip'])
            score = 15
        else:
            feedback.append(f'Command "{primary}" is high-risk in real environments.')
            feedback.append(rule['tip'])
            score = 85
    else:
        feedback.append('Unknown command for this lab profile; verify before running on real systems.')
        score = 45

    risky_patterns = ['rm -rf', 'mkfs', 'dd if=', 'chmod 777', ':(){:|:&};:']
    for pattern in risky_patterns:
        if pattern in command.lower():
            score = max(score, 95)
            feedback.append(f'Critical risk pattern detected: {pattern}')

    status = 'SAFE' if score < 30 else 'WARNING' if score < 70 else 'DANGEROUS'
    return {
        'ok': True,
        'status': status,
        'score': min(score, 100),
        'message': 'Linux command safety review complete.',
        'feedback': feedback,
    }


def build_local_assistant_fallback(user_message):
    text = str(user_message or '').strip().lower()
    if 'password' in text:
        reply = 'Use at least 12 chars with uppercase, lowercase, number, and symbol. Avoid reused passwords.'
    elif 'url' in text or 'link' in text:
        reply = 'Verify domain spelling, HTTPS certificate, and avoid shortened unknown links.'
    elif 'port' in text:
        reply = 'Close unused ports, restrict admin ports with firewall, and monitor repeated scan attempts.'
    elif 'linux' in text or 'command' in text:
        reply = 'Test commands in sandbox first and avoid destructive flags like rm -rf on unknown paths.'
    else:
        reply = (
            'Assistant is in local fallback mode. Configure OPENAI_API_KEY for advanced responses. '
            'I can still guide you on secure setup and module usage.'
        )
    return {'ok': True, 'message': 'fallback_mode', 'reply': reply}


def generate_assistant_reply(history, user_message):
    if not OPENAI_API_KEY:
        return build_local_assistant_fallback(user_message)
    if OpenAI is None:
        return build_local_assistant_fallback(user_message)

    client = OpenAI(api_key=OPENAI_API_KEY)
    cleaned_history = []
    if isinstance(history, list):
        for item in history[-12:]:
            if not isinstance(item, dict):
                continue
            role = str(item.get('role', '')).strip().lower()
            content = str(item.get('content', '')).strip()
            if role in {'user', 'assistant'} and content:
                cleaned_history.append({'role': role, 'content': content[:2000]})

    prompt_messages = [{'role': 'system', 'content': ASSISTANT_SYSTEM_PROMPT}]
    prompt_messages.extend(cleaned_history)
    prompt_messages.append({'role': 'user', 'content': str(user_message).strip()[:3000]})

    try:
        if hasattr(client, 'responses'):
            resp = client.responses.create(model=OPENAI_MODEL, input=prompt_messages)
            text = getattr(resp, 'output_text', None)
            if text and str(text).strip():
                return {'ok': True, 'message': 'ok', 'reply': str(text).strip()}

        chat = client.chat.completions.create(model=OPENAI_MODEL, messages=prompt_messages, temperature=0.3)
        text = chat.choices[0].message.content if chat and chat.choices else ''
        return {'ok': True, 'message': 'ok', 'reply': (text or '').strip()}
    except Exception as ex:
        fallback = build_local_assistant_fallback(user_message)
        fallback['message'] = f"fallback_after_error: {str(ex)}"
        return fallback


def run_facecheck_search(file_storage):
    if not file_storage or not file_storage.filename:
        return {'ok': False, 'message': 'Image file is required.'}
    if not is_allowed_image(file_storage.filename):
        return {'ok': False, 'message': 'Invalid image type. Use png, jpg, jpeg, or webp.'}

    filename = secure_filename(file_storage.filename) or 'image.jpg'
    mime_type = file_storage.mimetype or mimetypes.guess_type(filename)[0] or 'application/octet-stream'
    image_bytes = file_storage.read()
    if not image_bytes:
        return {'ok': False, 'message': 'Uploaded file is empty.'}
    file_storage.stream.seek(0)

    if (requests is None or not FACECHECK_API_TOKEN) and FACECHECK_DEMO:
        digest = hashlib.sha256(image_bytes).hexdigest()[:12]
        return {
            'ok': True,
            'status': 'WARNING',
            'score': 35,
            'message': 'FaceCheck live token missing. Demo mode active; live internet search not performed.',
            'matches': [],
            'findings': [f'Demo fingerprint: {digest}', 'Set FACECHECK_API_TOKEN for live face search.'],
            'id_search': f'demo-{digest}',
            'search_url': FACECHECK_BASE_URL,
        }

    if requests is None:
        return {'ok': False, 'message': 'requests library missing. Install requirements first.'}
    if not FACECHECK_API_TOKEN:
        return {'ok': False, 'message': 'FaceCheck API token missing. Set FACECHECK_API_TOKEN in server env.'}

    headers = {'accept': 'application/json', 'Authorization': FACECHECK_API_TOKEN}
    try:
        upload_resp = requests.post(
            f'{FACECHECK_BASE_URL}/api/upload_pic',
            headers=headers,
            files={'images': (filename, image_bytes, mime_type)},
            data={'id_search': ''},
            timeout=30,
        )
        upload_resp.raise_for_status()
        upload_data = upload_resp.json()
    except Exception:
        return {'ok': False, 'message': 'FaceCheck upload failed. Verify token/network and try again.'}

    id_search = str(upload_data.get('id_search', '')).strip()
    if not id_search:
        return {'ok': False, 'message': upload_data.get('error') or 'FaceCheck did not return a valid search ID.'}

    search_payload = {
        'id_search': id_search,
        'with_progress': True,
        'status_only': False,
        'demo': FACECHECK_DEMO,
    }

    raw_items = []
    status_text = 'searching'
    error_message = ''
    for _ in range(45):
        try:
            search_resp = requests.post(
                f'{FACECHECK_BASE_URL}/api/search',
                headers={**headers, 'Content-Type': 'application/json'},
                json=search_payload,
                timeout=25,
            )
            search_resp.raise_for_status()
            search_data = search_resp.json()
        except Exception:
            return {'ok': False, 'message': 'FaceCheck search request failed during polling.'}

        if search_data.get('error'):
            error_message = str(search_data.get('error'))
            break

        status_text = str(search_data.get('message') or '').lower()
        output = search_data.get('output')
        if isinstance(output, dict):
            items = output.get('items')
            if isinstance(items, list):
                raw_items = items
                break
        if status_text in {'finished', 'completed', 'done'}:
            break
        if status_text.startswith('not found'):
            break
        time.sleep(1)

    if error_message:
        return {'ok': False, 'message': error_message}

    matches = []
    top_score = 0
    for item in raw_items[:20]:
        if not isinstance(item, dict):
            continue
        score = float(item.get('score') or 0)
        top_score = max(top_score, score)
        matches.append(
            {
                'score': round(score, 2),
                'url': item.get('url') or '',
                'base64': item.get('base64') or '',
            }
        )

    if not matches:
        score = 5
        status = 'SAFE'
        message = 'No public face matches found.'
        findings = ['No indexed face matches found in this scan.']
    else:
        if top_score >= 90:
            score = 88
            status = 'DANGEROUS'
        elif top_score >= 70:
            score = 68
            status = 'WARNING'
        else:
            score = 45
            status = 'WARNING'
        message = f'Found {len(matches)} potential match(es). Review links carefully.'
        findings = [f"Face match score {m['score']} at {m['url'] or 'unknown source'}" for m in matches[:5]]

    return {
        'ok': True,
        'status': status,
        'score': int(score),
        'message': message,
        'matches': matches,
        'findings': findings,
        'id_search': id_search,
        'search_url': f'{FACECHECK_BASE_URL}',
    }


def save_scan_report(user_id, input_text, input_type, score, status, threats):
    conn = None
    try:
        conn = get_db_connection()
        conn.execute(
            '''
            INSERT INTO scan_reports (user_id, input_text, input_type, score, status, threats_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                user_id,
                input_text,
                input_type,
                score,
                status,
                json.dumps(threats),
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            ),
        )
        conn.commit()
        return True
    except sqlite3.Error:
        return False
    finally:
        if conn is not None:
            conn.close()


def build_report_query_parts(user_id, filter_key='all', keyword=''):
    where = ['user_id = ?']
    params = [user_id]

    if filter_key == 'today':
        where.append("date(created_at) = date('now', 'localtime')")
    elif filter_key == 'week':
        where.append("datetime(created_at) >= datetime('now', 'localtime', '-7 days')")

    if keyword:
        where.append('(LOWER(input_text) LIKE ? OR LOWER(input_type) LIKE ? OR LOWER(status) LIKE ?)')
        kw = f'%{keyword.lower()}%'
        params.extend([kw, kw, kw])

    where_sql = (' WHERE ' + ' AND '.join(where)) if where else ''
    return where_sql, params


def get_scan_reports(user_id, filter_key='all', keyword=''):
    conn = get_db_connection()
    where_sql, params = build_report_query_parts(user_id, filter_key, keyword)
    rows = conn.execute(
        f'SELECT * FROM scan_reports{where_sql} ORDER BY datetime(created_at) DESC LIMIT 200',
        params,
    ).fetchall()
    conn.close()

    reports = []
    for row in rows:
        reports.append({
            'id': row['id'],
            'input_text': row['input_text'],
            'input_type': row['input_type'],
            'score': row['score'],
            'status': row['status'],
            'threats': json.loads(row['threats_json']) if row['threats_json'] else [],
            'created_at': row['created_at'],
        })
    return reports


def get_analysis_summary(user_id, filter_key='all', keyword=''):
    conn = get_db_connection()
    where_sql, params = build_report_query_parts(user_id, filter_key, keyword)

    total_row = conn.execute(
        f'SELECT COUNT(*) AS total, COALESCE(AVG(score), 0) AS avg_score FROM scan_reports{where_sql}',
        params,
    ).fetchone()

    status_rows = conn.execute(
        f'SELECT status, COUNT(*) AS count FROM scan_reports{where_sql} GROUP BY status',
        params,
    ).fetchall()

    type_rows = conn.execute(
        f'SELECT input_type, COUNT(*) AS count FROM scan_reports{where_sql} GROUP BY input_type',
        params,
    ).fetchall()
    type_risk_rows = conn.execute(
        f'SELECT input_type, COALESCE(AVG(score), 0) AS avg_risk FROM scan_reports{where_sql} GROUP BY input_type',
        params,
    ).fetchall()

    trend_rows = conn.execute(
        f'''
        SELECT date(created_at) AS day, COUNT(*) AS count
        FROM scan_reports{where_sql}
        GROUP BY date(created_at)
        ORDER BY day ASC
        ''',
        params,
    ).fetchall()
    conn.close()

    total = int(total_row['total'])
    avg_score = round(float(total_row['avg_score'] or 0), 1)

    status_counts = {'SAFE': 0, 'WARNING': 0, 'DANGEROUS': 0}
    for row in status_rows:
        status_counts[row['status']] = row['count']

    type_counts = {
        'command': 0,
        'password': 0,
        'url': 0,
        'breach': 0,
        'portscan': 0,
        'network': 0,
        'encryption': 0,
        'linux': 0,
        'facecheck': 0,
    }
    for row in type_rows:
        if row['input_type'] in type_counts:
            type_counts[row['input_type']] = row['count']

    type_risk = {
        'command': 0,
        'password': 0,
        'url': 0,
        'breach': 0,
        'portscan': 0,
        'network': 0,
        'encryption': 0,
        'linux': 0,
        'facecheck': 0,
    }
    for row in type_risk_rows:
        if row['input_type'] in type_risk:
            type_risk[row['input_type']] = round(float(row['avg_risk'] or 0), 1)

    safe_pct = round((status_counts['SAFE'] / total) * 100, 1) if total else 0
    warning_pct = round((status_counts['WARNING'] / total) * 100, 1) if total else 0
    dangerous_pct = round((status_counts['DANGEROUS'] / total) * 100, 1) if total else 0

    trend_map = {row['day']: row['count'] for row in trend_rows}
    labels = []
    values = []
    for i in range(6, -1, -1):
        d = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        labels.append(d)
        values.append(int(trend_map.get(d, 0)))

    return {
        'total_scans': total,
        'avg_threat_score': avg_score,
        'safe_percent': safe_pct,
        'warning_percent': warning_pct,
        'dangerous_percent': dangerous_pct,
        'status_counts': status_counts,
        'type_counts': type_counts,
        'type_risk': type_risk,
        'trend': {
            'labels': labels,
            'values': values,
        },
    }


def get_settings_dict(user_id):
    conn = get_db_connection()
    rows = conn.execute(
        'SELECT setting_key, setting_value FROM user_settings WHERE user_id = ?',
        (int(user_id),),
    ).fetchall()
    conn.close()
    settings = {row['setting_key']: row['setting_value'] for row in rows}
    return {
        'dark_mode': settings.get('dark_mode', '0') == '1',
        'threat_alerts': settings.get('threat_alerts', '1') == '1',
        'scan_complete': settings.get('scan_complete', '1') == '1',
        'auto_refresh': settings.get('auto_refresh', '1') == '1',
    }


def calculate_threat_score(input_text, input_type):
    score = 0
    threats = []
    text = input_text or ''
    normalized = text.lower()

    if input_type == 'command':
        for row in get_patterns_by_type('command'):
            pattern = row['pattern_text']
            level = row['threat_level']
            if pattern.lower() in normalized:
                score += level
                threats.append(f'Malicious command detected: {pattern}')

    elif input_type == 'password':
        if len(text) < 8:
            score += 30
            threats.append('Password is too short (minimum 8 characters).')
        if re.search(r'[a-z]', text) is None:
            score += 20
            threats.append('Missing lowercase letter.')
        if re.search(r'[A-Z]', text) is None:
            score += 20
            threats.append('Missing uppercase letter.')
        if re.search(r'\d', text) is None:
            score += 20
            threats.append('Missing number.')

        for row in get_patterns_by_type('password'):
            pattern = row['pattern_text']
            level = row['threat_level']
            if pattern.lower() in normalized:
                score += level
                threats.append(f'Common weak password pattern: {pattern}')

    elif input_type == 'url':
        for row in get_patterns_by_type('url'):
            pattern = row['pattern_text']
            level = row['threat_level']
            if pattern.lower() in normalized:
                score += level
                threats.append(f'Phishing pattern found: {pattern}')

    return min(score, 100), threats


@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    g.user = None
    if user_id:
        try:
            user = get_user_by_id(user_id)
            if user:
                g.user = user
                session['user_name'] = str(user['name'] or '')
                session['user_email'] = str(user['email'] or '')
                session['user_phone'] = str(user['phone'] or '')
                session['user_profile_image'] = str(user['profile_image'] or '')
            else:
                g.user = None
        except sqlite3.Error:
            g.user = {
                'id': int(user_id),
                'name': session.get('user_name', 'User'),
                'email': session.get('user_email', ''),
                'phone': session.get('user_phone', ''),
                'profile_image': session.get('user_profile_image', ''),
            }
    g.csp_nonce = secrets.token_urlsafe(16)


@app.before_request
def enforce_https_and_limits():
    if ENFORCE_HTTPS:
        forwarded_proto = (request.headers.get('X-Forwarded-Proto') or '').lower()
        is_secure_request = request.is_secure or forwarded_proto == 'https'
        host = (request.host or '').split(':')[0].lower()
        if (not is_secure_request) and host not in {'127.0.0.1', 'localhost'}:
            return redirect(request.url.replace('http://', 'https://', 1), code=301)

    ip = get_client_ip()
    if request.path.startswith('/api/'):
        key = f'api:{ip}:{request.endpoint or request.path}'
        if not check_rate_limit('api', key, API_RATE_LIMIT, API_RATE_WINDOW):
            return jsonify({'error': 'Too many requests. Please try again shortly.'}), 429

    if request.endpoint in {'login', 'register'} and request.method == 'POST':
        key = f'auth:{ip}:{request.endpoint}'
        if not check_rate_limit('auth', key, AUTH_RATE_LIMIT, AUTH_RATE_WINDOW):
            flash('Too many attempts. Please try again later.', 'error')
            return redirect(url_for(request.endpoint))


@app.before_request
def csrf_protect():
    if request.method not in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        return
    if request.endpoint == 'static':
        return
    if not is_valid_csrf():
        if request.path.startswith('/api/'):
            return jsonify({'error': 'CSRF token missing or invalid.'}), 400
        flash('Security token invalid. Please try again.', 'error')
        return redirect(request.referrer or url_for('home'))


@app.after_request
def apply_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    nonce = getattr(g, 'csp_nonce', '')
    script_src = f"script-src 'self' 'unsafe-inline' 'nonce-{nonce}' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com"
    connect_src = "connect-src 'self'"
    img_src = "img-src 'self' data: https:"
    frame_src = "frame-src 'self'"
    if is_ads_enabled():
        script_src += ' https://pagead2.googlesyndication.com https://googleads.g.doubleclick.net'
        connect_src += ' https://pagead2.googlesyndication.com https://googleads.g.doubleclick.net'
        img_src += ' https://tpc.googlesyndication.com https://googleads.g.doubleclick.net'
        frame_src += ' https://googleads.g.doubleclick.net https://tpc.googlesyndication.com'

    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        + script_src
        + '; '
        + connect_src
        + '; '
        + "style-src 'self' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
        + "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        + img_src
        + '; '
        + frame_src
        + ';'
    )
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


@app.errorhandler(404)
def handle_404(err):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'API endpoint not found.'}), 404
    return err


@app.errorhandler(405)
def handle_405(err):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Method not allowed for this API endpoint.'}), 405
    return err


@app.errorhandler(500)
def handle_500(err):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error. Please retry.'}), 500
    return err


@app.context_processor
def inject_globals():
    avatar_path = ''
    if g.user and g.user['profile_image']:
        avatar_path = url_for('static', filename=f"uploads/{g.user['profile_image']}")
    return {
        'current_year': datetime.now().year,
        'app_brand_name': APP_BRAND_NAME,
        'author_name': AUTHOR_NAME,
        'logged_in': g.user is not None,
        'current_user_name': g.user['name'] if g.user else '',
        'current_user_email': g.user['email'] if g.user else '',
        'current_user_phone': g.user['phone'] if g.user and 'phone' in g.user.keys() else '',
        'current_user_avatar': avatar_path,
        'google_oauth_enabled': is_google_oauth_enabled(),
        'stripe_enabled': is_stripe_enabled(),
        'stripe_publishable_key': STRIPE_PUBLISHABLE_KEY,
        'ads_enabled': is_ads_enabled(),
        'adsense_client': ADSENSE_CLIENT,
        'facecheck_enabled': is_facecheck_enabled(),
        'facecheck_base_url': FACECHECK_BASE_URL,
        'ubl_payout_configured': is_ubl_payout_configured(),
        'ubl_bank_name': UBL_BANK_NAME,
        'ubl_account_title': UBL_ACCOUNT_TITLE,
        'ubl_account_number': UBL_ACCOUNT_NUMBER,
        'ubl_iban': UBL_IBAN,
        'pk_bank_payout_configured': is_pk_bank_payout_configured(),
        'pk_bank_name': PK_BANK_NAME,
        'pk_account_title': PK_ACCOUNT_TITLE,
        'pk_account_number': PK_ACCOUNT_NUMBER,
        'pk_iban': PK_IBAN,
        'csp_nonce': getattr(g, 'csp_nonce', ''),
        'csrf_token': get_csrf_token(),
        'static_version': build_static_version(),
    }


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if g.user is not None:
        return redirect(url_for('analysis'))

    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        phone = (request.form.get('phone') or '').strip()
        password = request.form.get('password') or ''
        profile_file = request.files.get('profile_image')

        if not name or not email or not phone or not password:
            flash('Please fill all required fields.', 'error')
            return render_template('register.html')

        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
            flash('Please enter a valid email address.', 'error')
            return render_template('register.html')

        if not is_valid_phone(phone):
            flash('Please enter a valid phone number (10-15 digits).', 'error')
            return render_template('register.html')

        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('register.html')

        if get_user_by_email(email):
            flash('Email already exists. Please login.', 'error')
            return redirect(url_for('login'))

        if get_user_by_phone(phone):
            flash('Phone already exists. Please login.', 'error')
            return redirect(url_for('login'))

        if profile_file and profile_file.filename and (not is_allowed_image(profile_file.filename)):
            flash('Invalid image type. Use png, jpg, jpeg, or webp.', 'error')
            return render_template('register.html')

        user_id = create_user(name, email, phone, password)
        saved_image, image_error = save_profile_image(profile_file, user_id)
        if image_error:
            flash(image_error, 'error')
            return render_template('register.html')
        if saved_image:
            update_user_profile(user_id, name, email, phone, saved_image)
        session['user_id'] = int(user_id)
        session['user_name'] = name
        session['user_email'] = email
        session['user_phone'] = normalize_phone(phone)
        session['user_profile_image'] = saved_image or ''
        flash('Account created successfully.', 'success')
        return redirect(url_for('analysis'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user is not None:
        return redirect(url_for('analysis'))

    if request.method == 'POST':
        identifier = (request.form.get('identifier') or '').strip().lower()
        password = request.form.get('password') or ''
        next_url = request.form.get('next') or ''
        ip = get_client_ip()

        locked, wait_seconds = get_login_lock_state(identifier, ip)
        if locked:
            flash(f'Too many failed logins. Try again in {wait_seconds} seconds.', 'error')
            return render_template('login.html', next_url=next_url), 429

        user = get_user_by_identifier(identifier)
        if not user or not check_password_hash(user['password_hash'], password):
            record_login_failure(identifier, ip)
            flash('Invalid phone/email or password.', 'error')
            return render_template('login.html', next_url=next_url)

        clear_login_failures(identifier, ip)
        session['user_id'] = int(user['id'])
        session['user_name'] = str(user['name'] or '')
        session['user_email'] = str(user['email'] or '')
        session['user_phone'] = str(user['phone'] or '')
        session['user_profile_image'] = str(user['profile_image'] or '')
        flash('Logged in successfully.', 'success')
        if next_url.startswith('/'):
            return redirect(next_url)
        return redirect(url_for('analysis'))

    next_url = request.args.get('next', '')
    return render_template('login.html', next_url=next_url)


@app.route('/auth/google/login')
def google_auth_login():
    if not is_google_oauth_enabled():
        flash('Google Sign-In is not configured yet.', 'error')
        return redirect(url_for('login'))

    next_url = request.args.get('next', '') or request.referrer or ''
    if next_url.startswith('/'):
        session['oauth_next'] = next_url
    else:
        session['oauth_next'] = url_for('analysis')

    state = secrets.token_urlsafe(24)
    session['google_oauth_state'] = state

    query = url_parse.urlencode(
        {
            'client_id': GOOGLE_CLIENT_ID,
            'redirect_uri': get_google_redirect_uri(),
            'response_type': 'code',
            'scope': GOOGLE_OAUTH_SCOPE,
            'state': state,
            'prompt': 'select_account',
            'access_type': 'online',
        }
    )
    return redirect(f'https://accounts.google.com/o/oauth2/v2/auth?{query}')


@app.route('/auth/google/callback')
def google_auth_callback():
    if not is_google_oauth_enabled():
        flash('Google Sign-In is not configured yet.', 'error')
        return redirect(url_for('login'))

    state = request.args.get('state', '')
    code = request.args.get('code', '')
    expected = session.pop('google_oauth_state', '')
    next_url = session.pop('oauth_next', url_for('analysis'))

    if not state or not expected or state != expected:
        flash('Google Sign-In state validation failed.', 'error')
        return redirect(url_for('login'))
    if not code:
        flash('Google Sign-In did not return authorization code.', 'error')
        return redirect(url_for('login'))

    try:
        token_data = google_exchange_code_for_token(code)
        access_token = token_data.get('access_token', '')
        if not access_token:
            flash('Google token exchange failed.', 'error')
            return redirect(url_for('login'))

        profile = google_get_userinfo(access_token)
        email = (profile.get('email') or '').strip().lower()
        email_verified = bool(profile.get('email_verified', False))
        name = (profile.get('name') or '').strip() or email.split('@')[0]
        if not email:
            flash('Google account email not available.', 'error')
            return redirect(url_for('login'))
        if not email_verified:
            flash('Google account email is not verified.', 'error')
            return redirect(url_for('login'))

        user = get_user_by_email(email)
        if not user:
            user_id = create_user(name, email, '', secrets.token_urlsafe(32))
            user = get_user_by_id(int(user_id))

        session['user_id'] = int(user['id'])
        session['user_name'] = str(user['name'] or name or '')
        session['user_email'] = str(user['email'] or email or '')
        session['user_phone'] = str(user['phone'] or '')
        session['user_profile_image'] = str(user['profile_image'] or '')
        flash('Google Sign-In successful.', 'success')
        return redirect(next_url if str(next_url).startswith('/') else url_for('analysis'))
    except Exception:
        flash('Google Sign-In failed. Please try again.', 'error')
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.clear()
    flash('You are logged out.', 'success')
    return redirect(url_for('home'))


@app.route('/features/command')
@login_required
def command_analyzer():
    return render_template('features/command.html', command_guide=COMMAND_GUIDE)


@app.route('/features/password')
@login_required
def password_checker():
    return render_template('features/password.html')


@app.route('/features/url')
@login_required
def url_scanner():
    return render_template('features/url.html')


@app.route('/features/breach')
@login_required
def breach_checker():
    return render_template('features/breach.html')


@app.route('/features/port-scan')
@login_required
def port_scanner():
    return render_template('features/port_scan.html')


@app.route('/features/network-scan')
@login_required
def network_scanner():
    return render_template('features/network_scan.html')


@app.route('/features/encryption')
@login_required
def encryption_tools():
    return render_template('features/encryption.html')


@app.route('/features/linux-lab')
@login_required
def linux_lab():
    return render_template('features/linux_lab.html')


@app.route('/features/assistant')
@login_required
def ai_assistant():
    return render_template('features/assistant.html')


@app.route('/features/chatbot')
@login_required
def chatbot():
    return render_template('features/chatbot.html')


@app.route('/features/attack')
@login_required
def attack_simulator():
    return render_template('features/attack.html')


@app.route('/features/face-intel')
@login_required
def face_intel():
    return render_template('features/face_intel.html')


@app.route('/analysis')
@login_required
def analysis():
    report_filter = request.args.get('filter', 'all').lower()
    keyword = request.args.get('q', '').strip()
    if report_filter not in {'all', 'today', 'week'}:
        report_filter = 'all'

    summary = get_analysis_summary(int(g.user['id']), report_filter, keyword)
    return render_template('analysis.html', summary=summary, report_filter=report_filter, keyword=keyword)


@app.route('/reports')
@login_required
def reports():
    report_filter = request.args.get('filter', 'all').lower()
    keyword = request.args.get('q', '').strip()
    if report_filter not in {'all', 'today', 'week'}:
        report_filter = 'all'

    reports_data = get_scan_reports(int(g.user['id']), report_filter, keyword)
    return render_template('reports.html', reports=reports_data, report_filter=report_filter, keyword=keyword)


@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html', settings_data=get_settings_dict(int(g.user['id'])))


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        phone = (request.form.get('phone') or '').strip()
        profile_file = request.files.get('profile_image')

        if not name or not email or not phone:
            flash('Name, email, and phone are required.', 'error')
            return redirect(url_for('profile'))
        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
            flash('Please enter a valid email address.', 'error')
            return redirect(url_for('profile'))
        if not is_valid_phone(phone):
            flash('Please enter a valid phone number (10-15 digits).', 'error')
            return redirect(url_for('profile'))

        existing_email = get_user_by_email(email)
        if existing_email and int(existing_email['id']) != int(g.user['id']):
            flash('This email is already used by another account.', 'error')
            return redirect(url_for('profile'))
        existing_phone = get_user_by_phone(phone)
        if existing_phone and int(existing_phone['id']) != int(g.user['id']):
            flash('This phone number is already used by another account.', 'error')
            return redirect(url_for('profile'))

        saved_image, image_error = save_profile_image(profile_file, int(g.user['id']))
        if image_error:
            flash(image_error, 'error')
            return redirect(url_for('profile'))
        update_user_profile(int(g.user['id']), name, email, phone, saved_image)
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html')


@app.route('/monetization')
@login_required
def monetization():
    return render_template(
        'monetization.html',
        credit_packs=get_credit_packs(),
        credit_balance=get_user_credit_balance(int(g.user['id'])),
        stripe_enabled=is_stripe_enabled(),
    )


@app.route('/payment/success')
@login_required
def payment_success():
    local_token = (request.args.get('token') or '').strip()
    stripe_session_id = (request.args.get('stripe_session_id') or '').strip()
    if not local_token:
        flash('Payment confirmation token is missing.', 'error')
        return redirect(url_for('monetization'))

    payment_row = get_payment_session_for_user(int(g.user['id']), local_token)
    if not payment_row:
        flash('Payment session not found for this user.', 'error')
        return redirect(url_for('monetization'))

    if payment_row['provider'] == 'stripe':
        if not is_stripe_enabled():
            flash('Stripe is not configured on server.', 'error')
            return redirect(url_for('monetization'))
        if not stripe_session_id:
            flash('Stripe session id is missing.', 'error')
            return redirect(url_for('monetization'))
        if payment_row['provider_session_id'] and payment_row['provider_session_id'] != stripe_session_id:
            flash('Stripe session mismatch detected.', 'error')
            return redirect(url_for('monetization'))
        try:
            session_obj = stripe.checkout.Session.retrieve(stripe_session_id)
            is_paid = str(getattr(session_obj, 'payment_status', '')).lower() == 'paid'
            metadata = getattr(session_obj, 'metadata', {}) or {}
            if str(metadata.get('local_token', '')) != local_token:
                flash('Payment metadata validation failed.', 'error')
                return redirect(url_for('monetization'))
            if not is_paid:
                flash('Payment is not completed yet.', 'error')
                return redirect(url_for('monetization'))
            result = finalize_paid_session(int(g.user['id']), local_token, stripe_session_id)
            if result.get('ok'):
                flash(f"Payment successful. Credits added. Balance: {result.get('balance', 0)}", 'success')
            else:
                flash(result.get('message', 'Payment finalization failed.'), 'error')
            return redirect(url_for('monetization'))
        except Exception:
            flash('Unable to verify Stripe payment right now.', 'error')
            return redirect(url_for('monetization'))

    result = finalize_paid_session(int(g.user['id']), local_token, 'manual')
    if result.get('ok'):
        flash(f"Payment successful. Credits added. Balance: {result.get('balance', 0)}", 'success')
    else:
        flash(result.get('message', 'Payment finalization failed.'), 'error')
    return redirect(url_for('monetization'))


@app.route('/manifest.webmanifest')
def manifest():
    return send_from_directory(app.static_folder, 'manifest.webmanifest')


@app.route('/sw.js')
def service_worker():
    response = send_from_directory(app.static_folder, 'sw.js')
    response.headers['Service-Worker-Allowed'] = '/'
    return response


@app.route('/api/db-status', methods=['GET'])
@api_login_required
def db_status():
    conn = get_db_connection()
    summary_rows = conn.execute(
        'SELECT pattern_type, COUNT(*) AS count FROM threat_patterns GROUP BY pattern_type'
    ).fetchall()
    summary = {row['pattern_type']: row['count'] for row in summary_rows}
    total_reports = conn.execute(
        'SELECT COUNT(*) AS count FROM scan_reports WHERE user_id = ?',
        (int(g.user['id']),),
    ).fetchone()['count']
    conn.close()

    return jsonify({
        'database': str(DB_PATH),
        'exists': DB_PATH.exists(),
        'summary': summary,
        'saved_reports': total_reports,
    })


@app.route('/api/credit-packs', methods=['GET'])
@api_login_required
def credit_packs_api():
    return jsonify(
        {
            'ok': True,
            'stripe_enabled': is_stripe_enabled(),
            'packs': get_credit_packs(),
            'balance': get_user_credit_balance(int(g.user['id'])),
        }
    )


@app.route('/api/create-payment', methods=['POST'])
@api_login_required
def create_payment_api():
    payload = request.json or {}
    pack_key = (payload.get('pack_key') or '').strip()
    pack = get_credit_pack(pack_key)
    if not pack:
        return jsonify({'ok': False, 'message': 'Invalid credit pack.'}), 400

    if not is_stripe_enabled():
        return jsonify(
            {
                'ok': False,
                'message': 'Stripe is not configured. Use test/simulated payment for now.',
                'stripe_enabled': False,
            }
        ), 400

    local_token = create_payment_session(int(g.user['id']), pack, 'stripe')
    try:
        success_url = (
            url_for('payment_success', _external=True)
            + f'?token={url_parse.quote(local_token)}&stripe_session_id={{CHECKOUT_SESSION_ID}}'
        )
        cancel_url = url_for('monetization', _external=True) + '?payment=cancelled'
        checkout = stripe.checkout.Session.create(
            mode='payment',
            success_url=success_url,
            cancel_url=cancel_url,
            metadata={
                'user_id': str(int(g.user['id'])),
                'pack_key': pack['key'],
                'local_token': local_token,
            },
            line_items=[
                {
                    'price_data': {
                        'currency': DEFAULT_CURRENCY,
                        'unit_amount': int(pack['price_cents']),
                        'product_data': {
                            'name': pack['title'],
                            'description': f"{pack['credits']} credits for {APP_BRAND_NAME}",
                        },
                    },
                    'quantity': 1,
                }
            ],
        )
        update_payment_provider_session(local_token, str(checkout.id))
        return jsonify({'ok': True, 'checkout_url': checkout.url})
    except Exception:
        mark_payment_failed(local_token)
        return jsonify({'ok': False, 'message': 'Unable to create Stripe checkout session right now.'}), 503


@app.route('/api/simulate-payment', methods=['POST'])
@api_login_required
def simulate_payment_api():
    payload = request.json or {}
    pack_key = (payload.get('pack_key') or '').strip()
    pack = get_credit_pack(pack_key)
    if not pack:
        return jsonify({'ok': False, 'message': 'Invalid credit pack.'}), 400

    local_token = create_payment_session(int(g.user['id']), pack, 'simulated')
    result = finalize_paid_session(int(g.user['id']), local_token, f'simulated:{local_token[:8]}')
    if not result.get('ok'):
        return jsonify({'ok': False, 'message': result.get('message', 'Simulated payment failed.')}), 500

    return jsonify(
        {
            'ok': True,
            'message': 'Simulated payment completed and credits were added.',
            'balance': int(result.get('balance', 0)),
        }
    )


@app.route('/api/create-bank-transfer', methods=['POST'])
@api_login_required
def create_bank_transfer_api():
    payload = request.json or {}
    pack_key = (payload.get('pack_key') or '').strip()
    transfer_ref = (payload.get('transfer_ref') or '').strip()
    pack = get_credit_pack(pack_key)
    if not pack:
        return jsonify({'ok': False, 'message': 'Invalid credit pack.'}), 400
    if len(transfer_ref) < 4:
        return jsonify({'ok': False, 'message': 'Please provide a valid bank transfer reference.'}), 400
    if not is_pk_bank_payout_configured():
        return jsonify({'ok': False, 'message': 'Pakistan bank payout details are not configured on server.'}), 400

    local_token = create_payment_session(int(g.user['id']), pack, 'pk_bank')
    mark_bank_transfer_pending(local_token, transfer_ref)

    if BANK_TRANSFER_AUTO_APPROVE:
        result = finalize_paid_session(int(g.user['id']), local_token, f'ubl:{transfer_ref}')
        if result.get('ok'):
            return jsonify(
                {
                    'ok': True,
                    'message': 'Bank transfer auto-approved in demo mode. Credits added.',
                    'balance': int(result.get('balance', 0)),
                }
            )
        return jsonify({'ok': False, 'message': result.get('message', 'Unable to process transfer.')}), 500

    return jsonify(
        {
            'ok': True,
            'message': 'Bank transfer request submitted. Credits will be added after manual verification.',
            'status': 'pending_verification',
        }
    )


@app.route('/api/face-intel', methods=['POST'])
@api_login_required
def face_intel_api():
    consent = (request.form.get('consent') or '').strip().lower()
    if consent not in {'yes', 'true', '1'}:
        return jsonify(
            {
                'ok': False,
                'message': 'Consent required: only scan images you are authorized to analyze.',
            }
        ), 400

    image = request.files.get('image')
    result = run_facecheck_search(image)
    if not result.get('ok'):
        return jsonify(result), 400

    save_scan_report(
        int(g.user['id']),
        f"facecheck:{(image.filename if image else 'unknown')[:80]}",
        'facecheck',
        int(result.get('score', 0)),
        result.get('status', 'UNKNOWN'),
        result.get('findings', []),
    )
    return jsonify(result)


@app.route('/api/analysis-summary', methods=['GET'])
@api_login_required
def analysis_summary_api():
    report_filter = request.args.get('filter', 'all').lower()
    keyword = request.args.get('q', '').strip()
    if report_filter not in {'all', 'today', 'week'}:
        report_filter = 'all'
    return jsonify(get_analysis_summary(int(g.user['id']), report_filter, keyword))


@app.route('/api/settings', methods=['GET', 'POST'])
@api_login_required
def settings_api():
    if request.method == 'GET':
        return jsonify(get_settings_dict(int(g.user['id'])))

    payload = request.json or {}
    data = {
        'dark_mode': bool(payload.get('dark_mode', False)),
        'threat_alerts': bool(payload.get('threat_alerts', True)),
        'scan_complete': bool(payload.get('scan_complete', True)),
        'auto_refresh': bool(payload.get('auto_refresh', True)),
    }

    conn = get_db_connection()
    user_id = int(g.user['id'])
    set_setting(conn, user_id, 'dark_mode', '1' if data['dark_mode'] else '0')
    set_setting(conn, user_id, 'threat_alerts', '1' if data['threat_alerts'] else '0')
    set_setting(conn, user_id, 'scan_complete', '1' if data['scan_complete'] else '0')
    set_setting(conn, user_id, 'auto_refresh', '1' if data['auto_refresh'] else '0')
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'settings': data})


@app.route('/api/reports/reset', methods=['POST'])
@api_login_required
def reset_reports_api():
    conn = get_db_connection()
    conn.execute('DELETE FROM scan_reports WHERE user_id = ?', (int(g.user['id']),))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/analyze', methods=['POST'])
@api_login_required
def analyze():
    data = request.json or {}
    input_text = data.get('input', '')
    input_type = data.get('type', '')

    score, threats = calculate_threat_score(input_text, input_type)
    status = 'SAFE' if score < 30 else 'WARNING' if score < 70 else 'DANGEROUS'
    save_scan_report(int(g.user['id']), input_text, input_type, score, status, threats)

    return jsonify({
        'score': score,
        'status': status,
        'threats': threats,
        'input_type': input_type,
    })


@app.route('/api/url-scan', methods=['POST'])
@api_login_required
def url_scan_api():
    try:
        payload = request.json or {}
        target = (payload.get('url') or '').strip()
        result = run_url_scan(target)
        if not result.get('ok'):
            return jsonify(result), 400

        save_scan_report(
            int(g.user['id']),
            result.get('url', target)[:300],
            'url',
            int(result.get('score', 0)),
            result.get('status', 'UNKNOWN'),
            result.get('threats', []),
        )
        return jsonify(result)
    except Exception:
        return jsonify({'ok': False, 'message': 'URL scanner service temporarily unavailable. Please retry.'}), 500


@app.route('/api/breach-check', methods=['POST'])
@api_login_required
def breach_check():
    data = request.json or {}
    email = (data.get('email') or '').strip().lower()

    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return jsonify({'ok': False, 'message': 'Please enter a valid email address.'}), 400

    result = check_hibp_breaches(email)
    if not isinstance(result, dict):
        result = build_email_breach_fallback(email, f'{HIBP_BASE_URL}/account/{url_parse.quote(email)}', 'Invalid breach response.')

    # Normalize response so frontend always gets consistent mode/status fields.
    message_text = str(result.get('message') or '').lower()
    mode = str(result.get('mode') or '').lower()
    live_available = bool(result.get('live_available', mode == 'live'))
    if ('api key is missing' in message_text) or ('unable to reach hibp' in message_text):
        live_available = False
        mode = 'fallback'
    if mode not in {'live', 'fallback'}:
        mode = 'live' if live_available else 'fallback'

    if not result.get('status') or str(result.get('status')).upper() == 'UNKNOWN':
        score_guess = int(result.get('score', 0) or 0)
        result['status'] = 'SAFE' if score_guess < 30 else 'WARNING' if score_guess < 70 else 'DANGEROUS'
    if not isinstance(result.get('safety_notes'), list):
        domain = email.split('@', 1)[1] if '@' in email else ''
        breach_count = len(result.get('breaches') or [])
        result['safety_notes'] = build_breach_safety_notes(breach_count, mode, domain, result.get('status', 'UNKNOWN'))

    result['mode'] = mode
    result['live_available'] = live_available
    result['ok'] = True

    # Save a report entry so this module appears in reports/analysis.
    if result.get('ok'):
        threats = [f"Breach: {b.get('title') or b.get('name')}" for b in result.get('breaches', [])]
        save_scan_report(
            int(g.user['id']),
            email,
            'breach',
            int(result.get('score', 0)),
            result.get('status', 'UNKNOWN'),
            threats,
        )

    return jsonify(result)


@app.route('/api/port-scan', methods=['POST'])
@api_login_required
def port_scan_api():
    try:
        data = request.json or {}
        host_raw = (data.get('host') or '').strip()
        ports_raw = data.get('ports', '')
        normalized = normalize_host_input(host_raw)
        if not normalized.get('ok'):
            return jsonify({'ok': False, 'message': normalized.get('message', 'Host is required.')}), 400
        host = normalized.get('host', '')

        ports = parse_port_list(ports_raw)
        if not ports:
            return jsonify({'ok': False, 'message': 'No valid ports provided.'}), 400

        result = run_port_scan(host, ports)
        if result.get('ok'):
            open_ports = [r['port'] for r in result.get('results', []) if r.get('open')]
            threats = [f'Open port {p} ({DANGEROUS_PORTS.get(p, "Unknown")})' for p in open_ports[:25]]
            save_scan_report(
                int(g.user['id']),
                f'{host} | ports={",".join(map(str, ports[:20]))}',
                'portscan',
                int(result.get('score', 0)),
                result.get('status', 'UNKNOWN'),
                threats,
            )
        return jsonify(result)
    except Exception:
        return jsonify({'ok': False, 'message': 'Port scanner temporarily unavailable. Please retry.'}), 500


@app.route('/api/network-scan', methods=['POST'])
@api_login_required
def network_scan_api():
    try:
        data = request.json or {}
        target = (data.get('target') or '').strip()
        if not target:
            return jsonify({'ok': False, 'message': 'Target is required.'}), 400

        normalized = normalize_url_input(target)
        if not normalized.get('ok'):
            return jsonify({'ok': False, 'message': normalized.get('message', 'Invalid target format.')}), 400

        normalized_target = normalized.get('url', target)
        result = run_network_risk_scan(normalized_target)
        # Extra fields for richer frontend cards.
        result['target'] = normalized_target
        try:
            parsed = url_parse.urlparse(normalized_target)
            result['domain'] = parsed.hostname or ''
        except Exception:
            result['domain'] = ''
        result['mode'] = 'live'
        result['checked_at'] = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

        save_scan_report(
            int(g.user['id']),
            normalized_target,
            'network',
            int(result.get('score', 0)),
            result.get('status', 'UNKNOWN'),
            result.get('findings', []),
        )
        return jsonify(result)
    except Exception:
        return jsonify({'ok': False, 'message': 'Network scanner temporarily unavailable. Please retry.'}), 500


@app.route('/api/encryption-tool', methods=['POST'])
@api_login_required
def encryption_tool_api():
    data = request.json or {}
    text = data.get('text', '')
    action = (data.get('action') or '').strip().lower()
    if not action:
        return jsonify({'ok': False, 'message': 'Action is required.'}), 400

    try:
        if action == 'sha256':
            output = hashlib.sha256(str(text).encode('utf-8')).hexdigest()
            score = 5
            threats = ['Generated SHA-256 hash.']
        elif action == 'base64_encode':
            output = base64.b64encode(str(text).encode('utf-8')).decode('utf-8')
            score = 10
            threats = ['Encoded text with Base64.']
        elif action == 'base64_decode':
            output = base64.b64decode(str(text).encode('utf-8'), validate=True).decode('utf-8')
            score = 20
            threats = ['Decoded Base64 data. Verify source trust before use.']
        else:
            return jsonify({'ok': False, 'message': 'Unsupported action.'}), 400
    except Exception:
        return jsonify({'ok': False, 'message': 'Encryption tool operation failed for given input.'}), 400

    save_scan_report(
        int(g.user['id']),
        f'{action}: {str(text)[:80]}',
        'encryption',
        score,
        'SAFE' if score < 30 else 'WARNING',
        threats,
    )

    return jsonify({'ok': True, 'status': 'SAFE', 'score': score, 'output': output, 'message': 'Operation complete.'})


@app.route('/api/linux-lab', methods=['POST'])
@api_login_required
def linux_lab_api():
    data = request.json or {}
    command_text = (data.get('command') or '').strip()
    result = evaluate_linux_command(command_text)
    if not result.get('ok'):
        return jsonify(result), 400

    save_scan_report(
        int(g.user['id']),
        command_text[:120],
        'linux',
        int(result.get('score', 0)),
        result.get('status', 'UNKNOWN'),
        result.get('feedback', []),
    )
    return jsonify(result)


@app.route('/api/assistant-chat', methods=['POST'])
@api_login_required
def assistant_chat_api():
    data = request.json or {}
    user_message = (data.get('message') or '').strip()
    history = data.get('history') or []

    if not user_message:
        return jsonify({'ok': False, 'message': 'Message is required.', 'reply': ''}), 400

    result = generate_assistant_reply(history, user_message)
    code = 200 if result.get('ok') else 503
    return jsonify(result), code


@app.route('/api/chat', methods=['POST'])
@api_login_required
def chat():
    user_message = (request.json or {}).get('message', '').lower().strip()

    responses = {
        'command': 'I will analyze that command for you. Use the Command Analyzer tool.',
        'password': 'Check password strength in Password Checker module.',
        'url': 'Scan URLs using URL Scanner. Stay safe.',
        'attack': 'Attack simulations are available in Attack Simulator (safe mode only).',
        'default': 'I can help with cybersecurity analysis. Try Command Analyzer, Password Checker, or URL Scanner.',
    }

    response = responses.get(user_message, responses['default'])
    return jsonify({'response': response})


try:
    init_db()
except sqlite3.Error:
    DB_PATH = BASE_DIR / 'cybersecurity_runtime.db'
    try:
        init_db()
    except sqlite3.Error:
        print('Warning: SQLite initialization failed. Running in degraded mode without persistent storage.')

if __name__ == '__main__':
    app.run(debug=True)


