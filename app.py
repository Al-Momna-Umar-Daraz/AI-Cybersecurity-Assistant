from flask import Flask, flash, g, jsonify, redirect, render_template, request, send_from_directory, session, url_for
import csv
import base64
import hashlib
import hmac
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
from werkzeug.middleware.proxy_fix import ProxyFix
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
try:
    import wikipedia as wikipedia_lib
except Exception:
    wikipedia_lib = None

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / 'cybersecurity.db'
CSV_PATH = BASE_DIR / 'dataset.csv'
CHATBOT_DATA_PATH = BASE_DIR / 'data.json'
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
OPENAI_TIMEOUT_SECONDS = max(3.0, float(os.getenv('OPENAI_TIMEOUT_SECONDS', '8')))
OPENAI_FAIL_CACHE_SECONDS = max(15, int(os.getenv('OPENAI_FAIL_CACHE_SECONDS', '180')))
USE_OLLAMA_CHATBOT = os.getenv('USE_OLLAMA_CHATBOT', '0').strip() == '1'
OLLAMA_MODEL = os.getenv('OLLAMA_MODEL', 'llama3').strip() or 'llama3'
OLLAMA_URL = os.getenv('OLLAMA_URL', 'http://localhost:11434/api/generate').strip() or 'http://localhost:11434/api/generate'
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
ENABLE_SIMULATED_PAYMENTS = os.getenv('ENABLE_SIMULATED_PAYMENTS', '0').strip() == '1'
OTP_DEBUG_MODE = os.getenv('OTP_DEBUG_MODE', '0').strip() == '1'
ADS_ONLY_MONETIZATION = os.getenv('ADS_ONLY_MONETIZATION', '1').strip() == '1'
TRUST_PROXY_HEADERS = os.getenv('TRUST_PROXY_HEADERS', '0').strip() == '1'
SESSION_TTL_HOURS = max(1, int(os.getenv('SESSION_TTL_HOURS', '12')))
MIN_PASSWORD_LENGTH = max(10, int(os.getenv('MIN_PASSWORD_LENGTH', '12')))
UPLOAD_BYTES_LIMIT = 2 * 1024 * 1024
ENFORCE_HTTPS = os.getenv('ENFORCE_HTTPS', '0') == '1'
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
    'You are the in-app ChatGPT-style cybersecurity assistant for a practical security training web app. '
    'Answer like a helpful, clear, professional assistant. '
    'Start with the direct answer, then give practical next steps. '
    'Use short sections or bullets when they improve readability, but do not sound robotic. '
    'Adapt to the user question instead of giving generic filler. '
    'If the user asks for help with security, defense, hardening, incident response, phishing, passwords, SOC, or safe configuration, '
    'provide actionable defensive guidance. '
    'Do not provide instructions for illegal hacking, malware, credential theft, or evasion.'
)
FIXED_CHATBOT_RESPONSES = [
    {
        'question': 'what is phishing',
        'keywords': ['phishing', 'fake email', 'suspicious email', 'credential theft'],
        'answer': 'Phishing is a social-engineering attack where an attacker tricks someone into revealing passwords, OTP codes, banking details, or other sensitive information through fake messages, login pages, or calls.',
    },
    {
        'question': 'what is malware',
        'keywords': ['malware', 'virus', 'trojan', 'spyware', 'worm'],
        'answer': 'Malware is malicious software designed to damage systems, steal data, spy on users, or give attackers unauthorized access. Common types include viruses, worms, trojans, spyware, and ransomware.',
    },
    {
        'question': 'strong password',
        'keywords': ['strong password', 'secure password', 'password create', 'password policy'],
        'answer': 'A strong password should be long, unique, and hard to guess. Use at least 12 to 16 characters, mix letters, numbers, and symbols, avoid personal details, and do not reuse it across sites.',
    },
    {
        'question': 'what is port scanning',
        'keywords': ['port scanning', 'open ports', 'scan ports', 'nmap'],
        'answer': 'Port scanning is the process of checking which network ports are open on a host. Attackers use it to discover exposed services, while defenders use it to identify unnecessary or risky internet-facing services.',
    },
    {
        'question': 'what is a firewall',
        'keywords': ['firewall', 'network firewall', 'allow ports', 'block traffic'],
        'answer': 'A firewall filters inbound and outbound network traffic based on rules. It helps block unauthorized connections, restrict exposed services, and reduce the attack surface of a device or network.',
    },
    {
        'question': 'what is a data breach',
        'keywords': ['data breach', 'data leak', 'stolen data', 'breach disclosure'],
        'answer': 'A data breach happens when sensitive information is accessed, exposed, stolen, or shared without authorization. This can include passwords, personal data, business records, or payment information.',
    },
    {
        'question': 'what is ransomware',
        'keywords': ['ransomware', 'files encrypted', 'ransom attack', 'crypto malware'],
        'answer': 'Ransomware is malware that encrypts files or locks systems and demands payment for restoration. Good backups, patching, endpoint protection, and phishing resistance are key defenses.',
    },
    {
        'question': 'what is social engineering',
        'keywords': ['social engineering', 'human hacking', 'manipulation attack', 'pretexting'],
        'answer': 'Social engineering is the use of deception or manipulation to convince people to reveal secrets, transfer money, install malware, or bypass security controls.',
    },
    {
        'question': 'what is two factor authentication',
        'keywords': ['2fa', 'mfa', 'two factor', 'multi factor', 'otp'],
        'answer': 'Two-factor or multi-factor authentication adds an extra verification step beyond the password, such as an authenticator app, hardware key, or biometric check. It greatly reduces account takeover risk.',
    },
    {
        'question': 'what is vpn',
        'keywords': ['vpn', 'virtual private network', 'secure tunnel'],
        'answer': 'A VPN encrypts traffic between your device and a trusted VPN server. It can reduce exposure on untrusted networks, but it is not a substitute for patching, MFA, and secure account practices.',
    },
    {
        'question': 'what is sql injection',
        'keywords': ['sql injection', 'sqli', 'database injection'],
        'answer': 'SQL injection is a vulnerability where unsafe user input is interpreted as part of a database query. It can lead to unauthorized data access, modification, or deletion if queries are not parameterized.',
    },
    {
        'question': 'what is xss',
        'keywords': ['xss', 'cross site scripting', 'script injection'],
        'answer': 'Cross-site scripting, or XSS, happens when untrusted input is rendered as executable script in a browser. It can steal session data, modify page content, or perform actions as the victim user.',
    },
    {
        'question': 'what is ddos',
        'keywords': ['ddos', 'denial of service', 'traffic flood', 'bot traffic'],
        'answer': 'A DDoS attack overwhelms a service with large volumes of traffic or requests so legitimate users cannot access it. Common defenses include rate limiting, CDN protection, autoscaling, and WAF rules.',
    },
    {
        'question': 'what is encryption',
        'keywords': ['encryption', 'encrypt data', 'cipher text'],
        'answer': 'Encryption converts readable data into unreadable ciphertext using a key. It protects sensitive information in transit and at rest so unauthorized parties cannot easily read it.',
    },
    {
        'question': 'what is hashing',
        'keywords': ['hashing', 'hash function', 'sha256', 'password hash'],
        'answer': 'Hashing transforms input data into a fixed-length value. It is commonly used for integrity checks and secure password storage, but hashing is one-way and is not the same as encryption.',
    },
    {
        'question': 'what is brute force',
        'keywords': ['brute force', 'password guessing', 'credential attack'],
        'answer': 'A brute-force attack tries many passwords or keys until one works. Strong unique passwords, account lockouts, MFA, and rate limiting help defend against this type of attack.',
    },
    {
        'question': 'what is patch management',
        'keywords': ['patch management', 'security updates', 'update software', 'patching'],
        'answer': 'Patch management is the process of identifying, testing, and applying software updates to fix security vulnerabilities and bugs. Delayed patching leaves systems exposed to known exploits.',
    },
    {
        'question': 'what is least privilege',
        'keywords': ['least privilege', 'minimum access', 'limited permissions'],
        'answer': 'Least privilege means giving users, apps, and services only the permissions they truly need. This limits damage if an account or system is compromised.',
    },
    {
        'question': 'what is incident response',
        'keywords': ['incident response', 'security incident', 'respond to attack'],
        'answer': 'Incident response is the structured process of preparing for, detecting, containing, investigating, recovering from, and documenting cybersecurity incidents.',
    },
    {
        'question': 'what is a botnet',
        'keywords': ['botnet', 'infected devices', 'zombie network'],
        'answer': 'A botnet is a group of compromised devices controlled by an attacker. Botnets are often used for DDoS attacks, spam campaigns, malware delivery, or credential attacks.',
    },
    {
        'question': 'what is zero day',
        'keywords': ['zero day', '0day', 'unknown vulnerability'],
        'answer': 'A zero-day vulnerability is a security flaw that is unknown to the vendor or has no patch available yet. It is especially dangerous because defenders have limited time to react.',
    },
    {
        'question': 'what is https',
        'keywords': ['https', 'ssl', 'tls', 'secure website'],
        'answer': 'HTTPS protects web traffic with TLS encryption so attackers cannot easily read or modify the connection in transit. It improves trust, but a malicious website can still use HTTPS.',
    },
    {
        'question': 'what is backup',
        'keywords': ['backup', 'restore data', 'recovery copy'],
        'answer': 'A backup is a separate copy of important data used for recovery after accidental deletion, hardware failure, ransomware, or other incidents. Good backups should be tested and isolated.',
    },
    {
        'question': 'what is ids ips',
        'keywords': ['ids', 'ips', 'intrusion detection', 'intrusion prevention'],
        'answer': 'An IDS monitors traffic or system events and alerts on suspicious activity, while an IPS can actively block or stop malicious traffic based on detected patterns or rules.',
    },
]
UPLOAD_FOLDER = BASE_DIR / 'static' / 'uploads'
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}

app = Flask(__name__, template_folder='static/templates', static_folder='static')
if TRUST_PROXY_HEADERS:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.secret_key = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.getenv(
        'SESSION_COOKIE_SECURE',
        '1' if os.getenv('ENFORCE_HTTPS', '0') == '1' else '0',
    ) == '1',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=SESSION_TTL_HOURS),
    PREFERRED_URL_SCHEME='https' if ENFORCE_HTTPS else 'http',
    MAX_CONTENT_LENGTH=UPLOAD_BYTES_LIMIT,
    MAX_FORM_MEMORY_SIZE=UPLOAD_BYTES_LIMIT,
)

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
_assistant_live_fail_cache = {'failed_at': 0, 'message': ''}
_chatbot_kb_cache = {'loaded_at': 0, 'mtime': 0, 'data': []}


def build_static_version():
    files = [
        BASE_DIR / 'static' / 'script.js',
        BASE_DIR / 'static' / 'style.css',
        BASE_DIR / 'static' / 'sw.js',
        CHATBOT_DATA_PATH,
    ]
    latest = 0
    for p in files:
        try:
            latest = max(latest, int(p.stat().st_mtime))
        except Exception:
            continue
    return str(latest or int(time.time()))


def load_chatbot_knowledge_base():
    try:
        mtime = int(CHATBOT_DATA_PATH.stat().st_mtime)
    except Exception:
        return []

    if _chatbot_kb_cache['data'] and _chatbot_kb_cache['mtime'] == mtime:
        return list(_chatbot_kb_cache['data'])

    try:
        with CHATBOT_DATA_PATH.open('r', encoding='utf-8') as fh:
            payload = json.load(fh)
    except Exception:
        return []

    entries = []
    if isinstance(payload, list):
        for item in payload:
            if not isinstance(item, dict):
                continue
            keywords = item.get('keywords') or []
            answer = str(item.get('answer') or '').strip()
            if not answer or not isinstance(keywords, list):
                continue
            cleaned_keywords = [str(k or '').strip().lower() for k in keywords if str(k or '').strip()]
            if cleaned_keywords:
                entries.append({'keywords': cleaned_keywords, 'answer': answer})

    _chatbot_kb_cache['mtime'] = mtime
    _chatbot_kb_cache['loaded_at'] = int(time.time())
    _chatbot_kb_cache['data'] = entries
    return list(entries)


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
    return request.remote_addr or 'unknown'


def is_disallowed_ip_address(ip_obj):
    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )


def is_safe_relative_url(target):
    value = str(target or '').strip()
    if not value or not value.startswith('/') or value.startswith('//'):
        return False
    parsed = url_parse.urlsplit(value)
    return not parsed.scheme and not parsed.netloc


def get_safe_redirect_target(target, fallback_endpoint='analysis'):
    value = str(target or '').strip()
    if is_safe_relative_url(value):
        return value
    return url_for(fallback_endpoint)


def rotate_csrf_token():
    token = secrets.token_urlsafe(32)
    session['_csrf_token'] = token
    return token


def start_user_session(user):
    session.clear()
    session.permanent = True
    rotate_csrf_token()
    session['user_id'] = int(user['id'])
    session['user_name'] = str(user['name'] or '')
    session['user_email'] = str(user['email'] or '')
    session['user_phone'] = str(user['phone'] or '')
    session['user_profile_image'] = str(user['profile_image'] or '')


def password_policy_error(password):
    value = str(password or '')
    if len(value) < MIN_PASSWORD_LENGTH:
        return f'Password must be at least {MIN_PASSWORD_LENGTH} characters.'
    if re.search(r'[a-z]', value) is None:
        return 'Password must include at least one lowercase letter.'
    if re.search(r'[A-Z]', value) is None:
        return 'Password must include at least one uppercase letter.'
    if re.search(r'\d', value) is None:
        return 'Password must include at least one number.'
    if re.search(r'[^A-Za-z0-9]', value) is None:
        return 'Password must include at least one symbol.'
    return ''


def is_strong_password(password):
    return not password_policy_error(password)


def sniff_image_extension(data):
    if data.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'png'
    if data[:3] == b'\xff\xd8\xff':
        return 'jpg'
    if data.startswith(b'RIFF') and data[8:12] == b'WEBP':
        return 'webp'
    return ''


def read_image_upload(file_storage, required=False):
    if not file_storage or not file_storage.filename:
        if required:
            return {'ok': False, 'message': 'Image file is required.'}
        return {'ok': True, 'empty': True}

    original = secure_filename(file_storage.filename or '')
    if not original or not is_allowed_image(original):
        return {'ok': False, 'message': 'Invalid image type. Use png, jpg, jpeg, or webp.'}

    image_bytes = file_storage.read(UPLOAD_BYTES_LIMIT + 1)
    file_storage.stream.seek(0)
    if not image_bytes:
        return {'ok': False, 'message': 'Uploaded file is empty.'}
    if len(image_bytes) > UPLOAD_BYTES_LIMIT:
        return {'ok': False, 'message': 'Image is too large. Maximum size is 2 MB.'}

    detected_ext = sniff_image_extension(image_bytes)
    expected_ext = original.rsplit('.', 1)[-1].lower()
    if expected_ext == 'jpeg':
        expected_ext = 'jpg'
    if not detected_ext:
        return {'ok': False, 'message': 'Uploaded file does not appear to be a valid PNG, JPEG, or WebP image.'}
    if detected_ext != expected_ext:
        return {'ok': False, 'message': 'Image content does not match the file extension.'}

    mime_map = {
        'png': 'image/png',
        'jpg': 'image/jpeg',
        'webp': 'image/webp',
    }
    return {
        'ok': True,
        'empty': False,
        'filename': original,
        'ext': detected_ext,
        'data': image_bytes,
        'mime_type': mime_map.get(detected_ext, 'application/octet-stream'),
    }


def get_csrf_token():
    token = session.get('_csrf_token')
    if not token:
        token = rotate_csrf_token()
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


def save_profile_image(file_storage, user_id, prepared_image=None):
    image_info = prepared_image or read_image_upload(file_storage)
    if not image_info.get('ok'):
        return None, image_info.get('message', 'Invalid image upload.')
    if image_info.get('empty'):
        return None, None

    ext = image_info['ext']
    name = f'profile_{int(user_id)}_{secrets.token_hex(6)}.{ext}'
    path = UPLOAD_FOLDER / name
    try:
        path.write_bytes(image_info['data'])
    except OSError:
        return None, 'Unable to save uploaded image right now. Please retry.'
    return name, None


def mask_email(value):
    email = str(value or '').strip()
    if '@' not in email:
        return email
    left, right = email.split('@', 1)
    if len(left) <= 2:
        masked = left[0] + '*' if left else '*'
    else:
        masked = left[:2] + '*' * max(2, len(left) - 2)
    return f'{masked}@{right}'


def mask_phone(value):
    phone = normalize_phone(value)
    if not phone:
        return ''
    digits = ''.join(ch for ch in phone if ch.isdigit())
    if len(digits) <= 4:
        return '*' * len(digits)
    return '*' * (len(digits) - 4) + digits[-4:]


def build_password_code(channel):
    code = ''.join(secrets.choice('0123456789') for _ in range(6))
    salt = secrets.token_hex(8)
    hashed = hashlib.sha256(f'{salt}:{code}'.encode('utf-8')).hexdigest()
    return {'code': code, 'salt': salt, 'hash': hashed, 'channel': channel}


def _b64url_encode(data):
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def _b64url_decode(text):
    value = str(text or '').strip()
    padding = '=' * ((4 - (len(value) % 4)) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _derive_secret_key(secret, salt):
    return hashlib.pbkdf2_hmac('sha256', str(secret).encode('utf-8'), salt, 120000, dklen=32)


def _xor_stream(data_bytes, key_bytes):
    output = bytearray()
    counter = 0
    while len(output) < len(data_bytes):
        block = hashlib.sha256(key_bytes + counter.to_bytes(4, 'big')).digest()
        output.extend(block)
        counter += 1
    return bytes(a ^ b for a, b in zip(data_bytes, output[: len(data_bytes)]))


def _payload_mac(key_bytes, salt_token, cipher_token):
    message = f'v2|{salt_token}|{cipher_token}'.encode('utf-8')
    digest = hmac.new(key_bytes, message, hashlib.sha256).digest()
    return _b64url_encode(digest)


def encrypt_text_payload(plain_text, secret):
    salt = secrets.token_bytes(16)
    key = _derive_secret_key(secret, salt)
    cipher = _xor_stream(str(plain_text).encode('utf-8'), key)
    salt_token = _b64url_encode(salt)
    cipher_token = _b64url_encode(cipher)
    mac_token = _payload_mac(key, salt_token, cipher_token)
    return f"v2.{salt_token}.{cipher_token}.{mac_token}"


def decrypt_text_payload(token, secret):
    value = str(token or '').strip()
    parts = value.split('.')
    if len(parts) == 4 and parts[0] == 'v2':
        salt = _b64url_decode(parts[1])
        cipher = _b64url_decode(parts[2])
        key = _derive_secret_key(secret, salt)
        expected_mac = _payload_mac(key, parts[1], parts[2])
        provided_mac = str(parts[3] or '')
        if not hmac.compare_digest(expected_mac, provided_mac):
            raise ValueError('Invalid secret key or tampered encrypted payload.')
        plain = _xor_stream(cipher, key)
        try:
            return plain.decode('utf-8')
        except Exception as exc:
            raise ValueError('Unable to decrypt payload. Secret key may be incorrect.') from exc

    if len(parts) == 3 and parts[0] == 'v1':
        salt = _b64url_decode(parts[1])
        cipher = _b64url_decode(parts[2])
        key = _derive_secret_key(secret, salt)
        plain = _xor_stream(cipher, key)
        try:
            return plain.decode('utf-8')
        except Exception as exc:
            raise ValueError('Unable to decrypt payload. Secret key may be incorrect.') from exc

    raise ValueError('Invalid encrypted payload format.')


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
        'dark_mode': '1',
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
    if not is_strong_password(DEFAULT_ADMIN_PASSWORD):
        print(
            f'Warning: DEFAULT_ADMIN_PASSWORD ignored because it does not meet the minimum password policy '
            f'({MIN_PASSWORD_LENGTH}+ chars with uppercase, lowercase, number, and symbol).'
        )
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


def update_user_password(user_id, new_password):
    conn = get_db_connection()
    try:
        conn.execute(
            'UPDATE users SET password_hash = ? WHERE id = ?',
            (generate_password_hash(str(new_password)), int(user_id)),
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

    if is_ip_host:
        if is_disallowed_ip_address(ipaddress.ip_address(host)):
            return {'ok': False, 'message': 'Private/internal IP addresses are not allowed for scan.', 'url': '', 'domain': ''}
    elif host in {'localhost', 'localhost.localdomain'} or not re.match(r'^[a-z0-9.-]+$', host):
        return {'ok': False, 'message': 'Invalid or local hostname for scan.', 'url': '', 'domain': ''}

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

    try:
        ip_obj = ipaddress.ip_address(host)
        if is_disallowed_ip_address(ip_obj):
            return {'ok': False, 'host': '', 'message': 'Private/internal IP addresses are blocked for safety.'}
    except Exception:
        if host in {'localhost', 'localhost.localdomain'} or not re.match(r'^[a-z0-9.-]+$', host):
            return {'ok': False, 'host': '', 'message': 'Invalid or local hostname.'}

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
        if is_disallowed_ip_address(ip_obj):
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


def format_chat_style_reply(intro, bullet_points=None, closing=''):
    parts = [str(intro or '').strip()]
    bullets = [str(item).strip() for item in (bullet_points or []) if str(item or '').strip()]
    if bullets:
        parts.append('\n'.join(f'- {item}' for item in bullets))
    if str(closing or '').strip():
        parts.append(str(closing).strip())
    return '\n\n'.join(part for part in parts if part)


def find_fixed_chatbot_answer(user_message):
    lowered = re.sub(r'\s+', ' ', str(user_message or '').strip().lower())
    if not lowered:
        return None

    knowledge_base = load_chatbot_knowledge_base()
    if not knowledge_base:
        return None

    best_entry = None
    best_score = 0
    for entry in knowledge_base:
        score = 0
        for keyword in entry.get('keywords', []):
            token = str(keyword or '').strip().lower()
            if not token:
                continue
            if ' ' in token:
                if token in lowered:
                    score += 3
                continue

            pattern = r'(?<![a-z0-9])' + re.escape(token) + r'(?![a-z0-9])'
            if re.search(pattern, lowered):
                score += 2

        if score > best_score:
            best_score = score
            best_entry = entry

    if not best_entry or best_score <= 0:
        return None

    return {
        'ok': True,
        'message': 'knowledge_base',
        'reply': str(best_entry.get('answer') or '').strip(),
        'matched_keywords': list(best_entry.get('keywords') or []),
    }


def build_contextual_generic_reply(user_message):
    text = str(user_message or '').strip()
    lowered = text.lower()
    words = set(re.findall(r'[a-z0-9]+', lowered))

    intro = f'I understood your question as: "{text[:140]}". Here is practical cybersecurity guidance based on that topic.'
    bullets = []
    closing = 'If you want, ask a more specific follow-up and I will narrow this down further.'

    if words & {'account', 'login', 'signin', 'gmail', 'email', 'mfa', '2fa', 'otp'}:
        bullets = [
            'Protect the account first with a strong unique password and MFA.',
            'Review recent sign-in activity, recovery settings, and connected apps.',
            'Remove suspicious forwarding rules, filters, or unknown sessions.',
            'Treat unexpected login alerts, OTP prompts, or password reset emails as potential abuse.',
        ]
    elif words & {'server', 'linux', 'ubuntu', 'ssh', 'hardening', 'vps'}:
        bullets = [
            'Patch the system and remove unused packages or services.',
            'Restrict SSH access, prefer keys over passwords, and limit sudo rights.',
            'Allow only required ports through the firewall.',
            'Enable logging, backups, and regular configuration review.',
        ]
    elif words & {'website', 'web', 'app', 'sql', 'xss', 'csrf', 'api'}:
        bullets = [
            'Validate and sanitize user input on both frontend and backend.',
            'Use parameterized queries and safe output encoding.',
            'Protect sessions with CSRF defenses, secure cookies, and least privilege.',
            'Log security-relevant actions and test the app for common web vulnerabilities.',
        ]
    elif words & {'network', 'port', 'firewall', 'router', 'traffic', 'scan'}:
        bullets = [
            'Close unused ports and document every internet-facing service.',
            'Restrict administrative access by IP where possible.',
            'Monitor unusual inbound scans and outbound traffic patterns.',
            'Keep exposed services patched and behind filtering controls.',
        ]
    elif words & {'breach', 'incident', 'compromise', 'hacked', 'attack', 'malware', 'ransomware'}:
        bullets = [
            'Start with containment so the issue cannot spread further.',
            'Preserve evidence such as timestamps, alerts, screenshots, and affected hosts.',
            'Reset exposed credentials and verify privileged access paths.',
            'Document impact, recovery actions, and lessons learned.',
        ]
    elif words & {'password', 'authentication', 'auth', 'credential'}:
        bullets = [
            'Use long unique passwords and store them in a password manager.',
            'Enable MFA on important systems so a stolen password alone is not enough.',
            'Block password reuse and review failed-login patterns.',
            'Protect reset and recovery flows as carefully as the login flow itself.',
        ]
    elif words & {'data', 'privacy', 'backup', 'encryption', 'hashing', 'files'}:
        bullets = [
            'Classify sensitive data so protections match business impact.',
            'Encrypt data in transit and at rest where appropriate.',
            'Use tested backups and keep at least one recovery copy isolated.',
            'Limit who can access sensitive data and monitor export activity.',
        ]
    else:
        bullets = [
            'Identify what asset or system is involved and what risk you are trying to reduce.',
            'Apply basic controls first: patching, MFA, least privilege, logging, and backups.',
            'Check whether the issue is about account security, network exposure, web security, or incident response.',
            'Break the problem into prevention, detection, and recovery steps.',
        ]

    return format_chat_style_reply(intro, bullets, closing)


def fetch_wikipedia_summary(query_text):
    text = str(query_text or '').strip()
    if not text or wikipedia_lib is None:
        return None

    cleaned = re.sub(r'[^a-z0-9\s-]+', ' ', text.lower())
    cleaned = re.sub(r'^(what is|what are|tell me about|explain|define|how does|how do|what does)\s+', '', cleaned).strip()
    query_options = []
    for candidate in [text, cleaned.title() if cleaned else '', cleaned]:
        value = str(candidate or '').strip()
        if value and value not in query_options:
            query_options.append(value)

    wikipedia_lib.set_lang('en')
    for candidate in query_options:
        try:
            summary = wikipedia_lib.summary(candidate, sentences=3, auto_suggest=True)
            summary_text = str(summary or '').strip()
            if not summary_text:
                continue
            return {
                'ok': True,
                'message': 'wikipedia',
                'reply': "Sorry, I couldn't find an exact answer, but here's something helpful:\n\n" + summary_text,
                'notice': 'Answer source: Wikipedia summary.',
            }
        except wikipedia_lib.exceptions.DisambiguationError as exc:
            options = [str(opt).strip() for opt in (getattr(exc, 'options', []) or []) if str(opt).strip()][:3]
            if not options:
                continue
            return {
                'ok': True,
                'message': 'wikipedia',
                'reply': format_chat_style_reply(
                    "Sorry, I couldn't find an exact answer, but here's something helpful:",
                    [f'Wikipedia found multiple meanings for "{candidate}".', 'Try one of these more specific topics: ' + ', '.join(options)],
                    'Ask again with one of the specific topics and I will narrow it down.'
                ),
                'notice': 'Wikipedia returned multiple possible topics.',
            }
        except Exception:
            continue
    return None


def run_ollama_chat_reply(history, user_message):
    if not USE_OLLAMA_CHATBOT or requests is None:
        return None

    try:
        history_lines = []
        for item in sanitize_chat_history(history, max_items=6, max_chars=300):
            role = 'User' if item.get('role') == 'user' else 'Assistant'
            history_lines.append(f'{role}: {item.get("content")}')
        prompt = (
            'You are a beginner-friendly cybersecurity assistant. '
            'Give practical, defensive, safe answers only.\n\n'
            + ('\n'.join(history_lines) + '\n' if history_lines else '')
            + f'User: {str(user_message or "").strip()}\nAssistant:'
        )
        resp = requests.post(
            OLLAMA_URL,
            json={
                'model': OLLAMA_MODEL,
                'prompt': prompt,
                'stream': False,
            },
            timeout=25,
        )
        resp.raise_for_status()
        payload = resp.json() if hasattr(resp, 'json') else {}
        answer = str((payload or {}).get('response') or '').strip()
        if not answer:
            return None
        return {
            'ok': True,
            'message': 'ollama',
            'reply': answer,
            'notice': f'Answer source: local Ollama model ({OLLAMA_MODEL}).',
        }
    except Exception:
        return None


def build_local_assistant_fallback(user_message):
    fixed_match = find_fixed_chatbot_answer(user_message)
    if fixed_match:
        return fixed_match

    text = str(user_message or '').strip()
    lowered = text.lower()

    if any(term in lowered for term in {'gmail', 'phishing', 'fake login', 'suspicious email'}):
        reply = format_chat_style_reply(
            'To secure Gmail from phishing, focus on account hardening first and then tighten your email habits.',
            [
                'Enable 2-Step Verification and keep your recovery phone/email updated.',
                'Use Gmail Security Checkup and review recent login activity for unknown devices.',
                'Do not sign in through links sent in email or chat; open Gmail directly yourself.',
                'Check the full sender address, not just the display name.',
                'Remove suspicious forwarding rules, filters, or third-party app access.',
            ],
            'If you already clicked a suspicious link, change the password immediately, sign out other sessions, and review recovery settings.'
        )
    elif any(term in lowered for term in {'incident response', 'suspicious login', 'account compromised', 'hacked account'}):
        reply = format_chat_style_reply(
            'Start with containment so the attacker loses access as quickly as possible.',
            [
                'Change the password and force sign-out from other active sessions.',
                'Enable MFA immediately if it is not already enabled.',
                'Review recent login history, connected devices, and third-party app access.',
                'Check recovery email, phone number, inbox rules, and forwarding settings.',
                'Preserve evidence such as timestamps, screenshots, alert emails, and suspicious IPs.',
            ],
            'After containment, assess impact, reset any reused passwords, and document the incident timeline.'
        )
    elif any(term in lowered for term in {'soc checklist', 'security operations center', 'soc'}):
        reply = format_chat_style_reply(
            'A small-company SOC checklist should cover visibility, alerting, ownership, and response.',
            [
                'Inventory critical assets, users, servers, endpoints, and internet-facing apps.',
                'Centralize logs from authentication, endpoints, firewall, and cloud services.',
                'Define alert severity levels and clear escalation owners.',
                'Monitor failed logins, suspicious sign-ins, malware alerts, and unusual outbound traffic.',
                'Maintain an incident response playbook for phishing, compromised account, malware, and data exposure.',
                'Review backups, patching status, and privileged account activity regularly.',
            ],
            'If you want, I can also turn this into a 1-page SOC checklist for your project or company.'
        )
    elif 'password' in lowered:
        reply = format_chat_style_reply(
            'A strong password policy should reduce reuse and make credential attacks harder.',
            [
                'Use at least 12 characters with uppercase, lowercase, numbers, and symbols.',
                'Do not reuse passwords across websites or company systems.',
                'Use a password manager to generate and store unique passwords.',
                'Enable MFA for important accounts so password theft alone is not enough.',
            ],
            'If you want, I can also suggest a good password policy for this app specifically.'
        )
    elif any(term in lowered for term in {'url', 'link', 'domain'}):
        reply = format_chat_style_reply(
            'When checking a suspicious URL, verify trust before you click or sign in anywhere.',
            [
                'Check the exact domain spelling and watch for lookalike characters or extra subdomains.',
                'Prefer HTTPS, but remember HTTPS alone does not guarantee safety.',
                'Be careful with shortened links that hide the final destination.',
                'Never enter credentials after opening a suspicious link from email, SMS, or chat.',
            ],
            'If you paste the exact URL, I can help you assess what looks suspicious about it.'
        )
    elif any(term in lowered for term in {'linux', 'server harden', 'hardening', 'ubuntu', 'ssh'}):
        reply = format_chat_style_reply(
            'For Linux hardening, reduce attack surface first and then improve monitoring.',
            [
                'Keep the OS and packages updated.',
                'Disable password SSH login where possible and use key-based auth.',
                'Allow only required ports in the firewall.',
                'Remove unused services and packages.',
                'Use least-privileged accounts and limit sudo access.',
                'Enable logging, audit review, and regular backups.',
            ],
            'If you want, I can give you a Linux hardening checklist specifically for Ubuntu or for a cloud VPS.'
        )
    elif any(term in lowered for term in {'port', 'firewall', 'open port'}):
        reply = format_chat_style_reply(
            'Open ports should be treated as exposed services, so only keep what is truly needed.',
            [
                'Close unused ports and remove services you do not need.',
                'Restrict admin ports like SSH or RDP to trusted IP addresses.',
                'Put public apps behind a firewall, reverse proxy, or WAF where possible.',
                'Patch the software listening on exposed ports.',
                'Monitor repeated scans or connection attempts in logs.',
            ]
        )
    elif any(term in lowered for term in {'malware', 'virus', 'trojan', 'ransomware'}):
        reply = format_chat_style_reply(
            'If malware is suspected, containment matters more than normal productivity in the first few minutes.',
            [
                'Isolate the affected device from the network.',
                'Do not keep logging into sensitive accounts from that device.',
                'Scan with trusted security tools and collect indicators of compromise.',
                'Rotate important passwords from a clean device.',
                'Restore only from known-good backups if recovery is needed.',
            ]
        )
    else:
        reply = build_contextual_generic_reply(user_message)

    return {'ok': True, 'message': 'fallback_mode', 'reply': reply}


def generate_free_chatbot_reply(history, user_message):
    fixed_match = find_fixed_chatbot_answer(user_message)
    if fixed_match:
        fixed_match['notice'] = 'Answer source: local cybersecurity knowledge base.'
        return fixed_match

    wiki_match = fetch_wikipedia_summary(user_message)
    if wiki_match:
        return wiki_match

    ollama_match = run_ollama_chat_reply(history, user_message)
    if ollama_match:
        return ollama_match

    fallback = build_local_assistant_fallback(user_message)
    if fallback.get('message') == 'knowledge_base':
        fallback['notice'] = 'Answer source: local cybersecurity knowledge base.'
        return fallback

    fallback['message'] = 'fallback'
    fallback['notice'] = ''
    return fallback


def build_assistant_service_notice(error_text):
    message = str(error_text or '').strip().lower()
    if 'insufficient_quota' in message or 'quota' in message or 'rate limit' in message:
        return 'Live AI temporarily unavailable: OpenAI quota exceeded. Update billing/quota in OpenAI dashboard.'
    if 'invalid_api_key' in message or 'incorrect api key' in message or 'authentication' in message:
        return 'Live AI temporarily unavailable: OpenAI API key is invalid. Update OPENAI_API_KEY and restart server.'
    if 'model_not_found' in message or 'does not exist' in message:
        return 'Live AI temporarily unavailable: configured model is not available for this API key.'
    if 'connection error' in message or 'timed out' in message:
        return 'Live AI temporarily unavailable: network/connectivity issue while reaching OpenAI.'
    return 'Live AI temporarily unavailable right now. Showing local guidance mode.'


def get_chat_runtime_status():
    kb_entries = len(load_chatbot_knowledge_base())
    if USE_OLLAMA_CHATBOT:
        detail = f'Local knowledge base ({kb_entries} entries), Wikipedia, and Ollama ({OLLAMA_MODEL}) are enabled.'
    else:
        detail = f'Local knowledge base ({kb_entries} entries) and Wikipedia are enabled. Ollama is optional and currently off.'

    return {
        'label': 'Free Hybrid',
        'headline': 'Free chatbot mode is ready: local knowledge base first, then Wikipedia, then optional local AI.',
        'detail': detail,
        'class': 'live',
        'model_label': 'FREE AI',
    }


def sanitize_chat_history(history, max_items=12, max_chars=2000):
    cleaned_history = []
    if isinstance(history, list):
        for item in history[-int(max_items):]:
            if not isinstance(item, dict):
                continue
            role = str(item.get('role', '')).strip().lower()
            content = str(item.get('content', '')).strip()
            if role in {'user', 'assistant'} and content:
                cleaned_history.append({'role': role, 'content': content[: int(max_chars)]})
    return cleaned_history


def run_openai_chat_completion(prompt_messages):
    client = OpenAI(api_key=OPENAI_API_KEY, timeout=OPENAI_TIMEOUT_SECONDS, max_retries=0)
    if hasattr(client, 'responses'):
        resp = client.responses.create(model=OPENAI_MODEL, input=prompt_messages)
        text = getattr(resp, 'output_text', None)
        if text and str(text).strip():
            return str(text).strip()

    chat = client.chat.completions.create(model=OPENAI_MODEL, messages=prompt_messages, temperature=0.3)
    text = chat.choices[0].message.content if chat and chat.choices else ''
    return (text or '').strip()


def generate_assistant_reply(history, user_message):
    return generate_free_chatbot_reply(history, user_message)


def run_facecheck_search(file_storage):
    image_info = read_image_upload(file_storage, required=True)
    if not image_info.get('ok'):
        return {'ok': False, 'message': image_info.get('message', 'Invalid image upload.')}

    filename = image_info.get('filename') or 'image.jpg'
    mime_type = image_info.get('mime_type') or mimetypes.guess_type(filename)[0] or 'application/octet-stream'
    image_bytes = image_info.get('data') or b''

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
        'dark_mode': settings.get('dark_mode', '1') == '1',
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
        session.permanent = g.user is not None
    g.csp_nonce = secrets.token_urlsafe(16)


@app.before_request
def enforce_https_and_limits():
    if ENFORCE_HTTPS:
        is_secure_request = request.is_secure
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
        return redirect(get_safe_redirect_target(request.referrer, fallback_endpoint='home'))


@app.after_request
def apply_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    response.headers['Origin-Agent-Cluster'] = '?1'
    response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
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
        + "; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; manifest-src 'self'; worker-src 'self';"
    )
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        if ENFORCE_HTTPS:
            response.headers['Content-Security-Policy'] += ' upgrade-insecure-requests;'
    if (
        request.path.startswith('/api/')
        or request.endpoint in {'login', 'register', 'google_auth_login', 'google_auth_callback', 'logout', 'profile', 'settings'}
        or g.user is not None
    ):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
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


@app.errorhandler(413)
def handle_413(err):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Uploaded file is too large. Maximum size is 2 MB.'}), 413
    flash('Uploaded file is too large. Maximum size is 2 MB.', 'error')
    return redirect(get_safe_redirect_target(request.referrer, fallback_endpoint='home'))


@app.errorhandler(500)
def handle_500(err):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error. Please retry.'}), 500
    return err


@app.context_processor
def inject_globals():
    avatar_path = ''
    current_dark_mode = True
    chat_runtime = get_chat_runtime_status()
    if g.user and g.user['profile_image']:
        avatar_path = url_for('static', filename=f"uploads/{g.user['profile_image']}")
    if g.user:
        try:
            current_dark_mode = bool(get_settings_dict(int(g.user['id'])).get('dark_mode', False))
            session['dark_mode'] = '1' if current_dark_mode else '0'
        except Exception:
            current_dark_mode = session.get('dark_mode', '0') == '1'
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
        'current_dark_mode': current_dark_mode,
        'chat_model_name': OPENAI_MODEL,
        'live_ai_ready': bool(OPENAI_API_KEY and OpenAI is not None),
        'chat_model_label': chat_runtime['model_label'],
        'chat_status_label': chat_runtime['label'],
        'chat_status_headline': chat_runtime['headline'],
        'chat_status_detail': chat_runtime['detail'],
        'chat_status_class': chat_runtime['class'],
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

        password_error = password_policy_error(password)
        if password_error:
            flash(password_error, 'error')
            return render_template('register.html')

        if get_user_by_email(email):
            flash('Email already exists. Please login.', 'error')
            return redirect(url_for('login'))

        if get_user_by_phone(phone):
            flash('Phone already exists. Please login.', 'error')
            return redirect(url_for('login'))

        prepared_image = read_image_upload(profile_file)
        if not prepared_image.get('ok'):
            flash(prepared_image.get('message', 'Invalid image upload.'), 'error')
            return render_template('register.html')

        user_id = create_user(name, email, phone, password)
        saved_image, image_error = save_profile_image(profile_file, user_id, prepared_image=prepared_image)
        if image_error:
            flash(image_error, 'error')
            return render_template('register.html')
        if saved_image:
            update_user_profile(user_id, name, email, phone, saved_image)
        start_user_session(
            {
                'id': user_id,
                'name': name,
                'email': email,
                'phone': normalize_phone(phone),
                'profile_image': saved_image or '',
            }
        )
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
        next_url = get_safe_redirect_target(request.form.get('next') or '', fallback_endpoint='analysis')
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
        start_user_session(user)
        flash('Logged in successfully.', 'success')
        return redirect(next_url)

    next_url = get_safe_redirect_target(request.args.get('next', ''), fallback_endpoint='analysis')
    return render_template('login.html', next_url=next_url)


@app.route('/auth/google/login')
def google_auth_login():
    if not is_google_oauth_enabled():
        flash('Google Sign-In is not configured yet.', 'error')
        return redirect(url_for('login'))

    next_url = request.args.get('next', '') or request.referrer or ''
    session['oauth_next'] = get_safe_redirect_target(next_url, fallback_endpoint='analysis')

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

    if not state or not expected or not secrets.compare_digest(state, expected):
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

        start_user_session(user)
        flash('Google Sign-In successful.', 'success')
        return redirect(get_safe_redirect_target(next_url, fallback_endpoint='analysis'))
    except Exception:
        flash('Google Sign-In failed. Please try again.', 'error')
        return redirect(url_for('login'))


@app.route('/logout', methods=['POST'])
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
    return redirect(url_for('chatbot'))


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
    try:
        summary = get_analysis_summary(int(g.user['id']), report_filter, keyword)
    except Exception:
        summary = {
            'total_scans': 0,
            'avg_threat_score': 0,
            'safe_percent': 0,
            'warning_percent': 0,
            'dangerous_percent': 0,
            'status_counts': {'SAFE': 0, 'WARNING': 0, 'DANGEROUS': 0},
            'type_counts': {'command': 0, 'password': 0, 'url': 0, 'breach': 0, 'portscan': 0, 'network': 0, 'encryption': 0, 'linux': 0, 'facecheck': 0},
            'type_risk': {'command': 0, 'password': 0, 'url': 0, 'breach': 0, 'portscan': 0, 'network': 0, 'encryption': 0, 'linux': 0, 'facecheck': 0},
            'trend': {'labels': [], 'values': []},
        }
    return render_template('analysis.html', summary=summary, report_filter=report_filter, keyword=keyword)


@app.route('/reports')
@login_required
def reports():
    report_filter = request.args.get('filter', 'all').lower()
    keyword = request.args.get('q', '').strip()
    if report_filter not in {'all', 'today', 'week'}:
        report_filter = 'all'

    try:
        reports_data = get_scan_reports(int(g.user['id']), report_filter, keyword)
    except Exception:
        reports_data = []
    return render_template('reports.html', reports=reports_data, report_filter=report_filter, keyword=keyword)


@app.route('/settings')
@login_required
def settings():
    try:
        settings_data = get_settings_dict(int(g.user['id']))
    except Exception:
        settings_data = {'dark_mode': True, 'threat_alerts': True, 'scan_complete': True, 'auto_refresh': True}
    return render_template('settings.html', settings_data=settings_data)


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
    if ADS_ONLY_MONETIZATION:
        return render_template(
            'monetization.html',
            credit_packs=[],
            credit_balance=0,
            stripe_enabled=False,
            ads_only_mode=True,
        )
    return render_template(
        'monetization.html',
        credit_packs=get_credit_packs(),
        credit_balance=get_user_credit_balance(int(g.user['id'])),
        stripe_enabled=is_stripe_enabled(),
        ads_only_mode=False,
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
    if ADS_ONLY_MONETIZATION:
        return jsonify({'ok': False, 'message': 'Credit purchase is disabled in Ads-only mode.'}), 403
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
    if not ENABLE_SIMULATED_PAYMENTS:
        return jsonify({'ok': False, 'message': 'Simulated payments are disabled on this server.'}), 403
    if ADS_ONLY_MONETIZATION:
        return jsonify({'ok': False, 'message': 'Simulated purchase is disabled in Ads-only mode.'}), 403
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
    if ADS_ONLY_MONETIZATION:
        return jsonify({'ok': False, 'message': 'Bank transfer purchase is disabled in Ads-only mode.'}), 403
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
    try:
        return jsonify(get_analysis_summary(int(g.user['id']), report_filter, keyword))
    except Exception:
        return jsonify({
            'total_scans': 0,
            'avg_threat_score': 0,
            'safe_percent': 0,
            'warning_percent': 0,
            'dangerous_percent': 0,
            'status_counts': {'SAFE': 0, 'WARNING': 0, 'DANGEROUS': 0},
            'type_counts': {'command': 0, 'password': 0, 'url': 0, 'breach': 0, 'portscan': 0, 'network': 0, 'encryption': 0, 'linux': 0, 'facecheck': 0},
            'type_risk': {'command': 0, 'password': 0, 'url': 0, 'breach': 0, 'portscan': 0, 'network': 0, 'encryption': 0, 'linux': 0, 'facecheck': 0},
            'trend': {'labels': [], 'values': []},
        })


@app.route('/api/settings', methods=['GET', 'POST'])
@api_login_required
def settings_api():
    if request.method == 'GET':
        try:
            return jsonify(get_settings_dict(int(g.user['id'])))
        except Exception:
            return jsonify({'dark_mode': True, 'threat_alerts': True, 'scan_complete': True, 'auto_refresh': True})

    payload = request.json or {}
    data = {
        'dark_mode': bool(payload.get('dark_mode', False)),
        'threat_alerts': bool(payload.get('threat_alerts', True)),
        'scan_complete': bool(payload.get('scan_complete', True)),
        'auto_refresh': bool(payload.get('auto_refresh', True)),
    }

    try:
        conn = get_db_connection()
        user_id = int(g.user['id'])
        set_setting(conn, user_id, 'dark_mode', '1' if data['dark_mode'] else '0')
        set_setting(conn, user_id, 'threat_alerts', '1' if data['threat_alerts'] else '0')
        set_setting(conn, user_id, 'scan_complete', '1' if data['scan_complete'] else '0')
        set_setting(conn, user_id, 'auto_refresh', '1' if data['auto_refresh'] else '0')
        conn.commit()
        conn.close()
    except Exception:
        # Keep UI preference functional even if DB is temporarily unavailable.
        pass
    session['dark_mode'] = '1' if data['dark_mode'] else '0'
    return jsonify({'success': True, 'settings': data})


@app.route('/api/theme', methods=['POST'])
@api_login_required
def theme_api():
    payload = request.json or {}
    dark_mode = bool(payload.get('dark_mode', True))
    try:
        conn = get_db_connection()
        set_setting(conn, int(g.user['id']), 'dark_mode', '1' if dark_mode else '0')
        conn.commit()
        conn.close()
    except Exception:
        pass
    session['dark_mode'] = '1' if dark_mode else '0'
    return jsonify({'ok': True, 'dark_mode': dark_mode})


@app.route('/api/request-password-code', methods=['POST'])
@api_login_required
def request_password_code_api():
    payload = request.json or {}
    channel = str(payload.get('channel') or '').strip().lower()
    if channel not in {'email', 'phone'}:
        return jsonify({'ok': False, 'message': 'Choose email or phone for code delivery.'}), 400

    destination = ''
    masked = ''
    if channel == 'email':
        destination = str(g.user['email'] or '').strip().lower()
        if not destination or '@' not in destination:
            return jsonify({'ok': False, 'message': 'No valid email found on profile.'}), 400
        masked = mask_email(destination)
    else:
        destination = normalize_phone(g.user['phone'] or '')
        if not destination:
            return jsonify({'ok': False, 'message': 'No valid phone found on profile.'}), 400
        masked = mask_phone(destination)

    bundle = build_password_code(channel)
    session['pwd_reset'] = {
        'channel': channel,
        'destination': destination,
        'salt': bundle['salt'],
        'hash': bundle['hash'],
        'attempts': 0,
        'expires_at': int(time.time()) + 10 * 60,
    }

    message = f'Code sent to your {channel}: {masked}.'
    if OTP_DEBUG_MODE:
        message += f' Demo code: {bundle["code"]}'

    return jsonify({'ok': True, 'message': message, 'channel': channel})


@app.route('/api/change-password-with-code', methods=['POST'])
@api_login_required
def change_password_with_code_api():
    payload = request.json or {}
    code = str(payload.get('code') or '').strip()
    new_password = str(payload.get('new_password') or '')
    confirm_password = str(payload.get('confirm_password') or '')

    flow = session.get('pwd_reset') or {}
    if not flow:
        return jsonify({'ok': False, 'message': 'Request a verification code first.'}), 400

    now_ts = int(time.time())
    if int(flow.get('expires_at', 0)) < now_ts:
        session.pop('pwd_reset', None)
        return jsonify({'ok': False, 'message': 'Code expired. Request a new code.'}), 400

    attempts = int(flow.get('attempts', 0))
    if attempts >= 6:
        session.pop('pwd_reset', None)
        return jsonify({'ok': False, 'message': 'Too many attempts. Request a new code.'}), 429

    if len(code) != 6 or not code.isdigit():
        flow['attempts'] = attempts + 1
        session['pwd_reset'] = flow
        return jsonify({'ok': False, 'message': 'Invalid code format. Enter 6 digits.'}), 400

    if new_password != confirm_password:
        return jsonify({'ok': False, 'message': 'New password and confirm password do not match.'}), 400
    password_error = password_policy_error(new_password)
    if password_error:
        return jsonify({'ok': False, 'message': password_error}), 400

    expected = str(flow.get('hash') or '')
    salt = str(flow.get('salt') or '')
    provided = hashlib.sha256(f'{salt}:{code}'.encode('utf-8')).hexdigest()
    if not expected or not hmac.compare_digest(expected, provided):
        flow['attempts'] = attempts + 1
        session['pwd_reset'] = flow
        return jsonify({'ok': False, 'message': 'Incorrect verification code.'}), 400

    update_user_password(int(g.user['id']), new_password)
    session.pop('pwd_reset', None)
    return jsonify({'ok': True, 'message': 'Password changed successfully.'})


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
    input_text = str(data.get('input', '') or '')
    input_type = str(data.get('type', '') or '').strip().lower()
    if input_type not in {'command', 'password', 'url'}:
        return jsonify({'error': 'Invalid analysis type.'}), 400
    if not input_text.strip():
        return jsonify({'error': 'Input is required.'}), 400
    if len(input_text) > 4000:
        return jsonify({'error': 'Input is too long. Maximum allowed is 4000 characters.'}), 400

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
    text = str(data.get('text', ''))
    secret = str(data.get('secret', ''))
    action = (data.get('action') or '').strip().lower()
    if not action:
        return jsonify({'ok': False, 'message': 'Action is required.'}), 400
    if not text.strip():
        return jsonify({'ok': False, 'message': 'Input text is required.'}), 400
    if len(text) > 20000:
        return jsonify({'ok': False, 'message': 'Input is too long. Maximum allowed is 20,000 characters.'}), 400

    try:
        if action == 'sha256':
            output = hashlib.sha256(text.encode('utf-8')).hexdigest()
            score = 5
            operation_label = 'SHA-256 Hash'
            message = 'SHA-256 hash generated successfully.'
            notes = [
                'SHA-256 is one-way hashing and cannot be reversed.',
                'For passwords, always use strong salted password hashing on backend.',
            ]
        elif action == 'base64_encode':
            output = base64.b64encode(text.encode('utf-8')).decode('utf-8')
            score = 10
            operation_label = 'Base64 Encode'
            message = 'Base64 encoding completed.'
            notes = [
                'Base64 is encoding only, not encryption.',
                'Use proper encryption for sensitive data.',
            ]
        elif action == 'base64_decode':
            cleaned_text = re.sub(r'\s+', '', text)
            output = base64.b64decode(cleaned_text.encode('utf-8'), validate=True).decode('utf-8')
            score = 20
            operation_label = 'Base64 Decode'
            message = 'Base64 decoding completed.'
            notes = [
                'Decoded output may contain unsafe content. Review before use.',
                'Only decode data from trusted sources.',
            ]
        elif action == 'encrypt_text':
            if not secret.strip():
                return jsonify({'ok': False, 'message': 'Secret key is required for encryption.'}), 400
            if len(secret.strip()) < 6:
                return jsonify({'ok': False, 'message': 'Secret key must be at least 6 characters.'}), 400
            output = encrypt_text_payload(text, secret)
            score = 12
            operation_label = 'Encrypt Text'
            message = 'Text encrypted successfully.'
            notes = [
                'Store secret keys securely and never expose them in frontend logs.',
                'Use separate secrets per environment and rotate keys periodically.',
            ]
        elif action == 'decrypt_text':
            if not secret.strip():
                return jsonify({'ok': False, 'message': 'Secret key is required for decryption.'}), 400
            if len(secret.strip()) < 6:
                return jsonify({'ok': False, 'message': 'Secret key must be at least 6 characters.'}), 400
            output = decrypt_text_payload(text, secret)
            score = 18
            operation_label = 'Decrypt Text'
            message = 'Text decrypted successfully.'
            notes = [
                'If output is unreadable, verify token format and secret key.',
                'Treat decrypted sensitive data carefully and avoid logging it.',
            ]
        else:
            return jsonify({'ok': False, 'message': 'Unsupported action.'}), 400
    except ValueError as exc:
        return jsonify({'ok': False, 'message': str(exc) or 'Invalid encryption input.'}), 400
    except Exception:
        return jsonify({'ok': False, 'message': 'Encryption tool operation failed for given input.'}), 400

    status = 'SAFE' if score < 30 else 'WARNING'
    safe_percent = max(0, min(100, 100 - int(score)))

    save_scan_report(
        int(g.user['id']),
        f'{operation_label}: {text[:80]}',
        'encryption',
        score,
        status,
        notes,
    )

    return jsonify(
        {
            'ok': True,
            'status': status,
            'score': score,
            'safe_percent': safe_percent,
            'output': output,
            'output_length': len(str(output)),
            'message': message,
            'action': action,
            'operation_label': operation_label,
            'notes': notes,
            'processed_at': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
        }
    )


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


@app.route('/chat', methods=['POST'])
@app.route('/api/chat', methods=['POST'])
@api_login_required
def chat():
    data = request.json or {}
    user_message = str(data.get('message') or '').strip()
    history = data.get('history') or []
    if not user_message:
        return jsonify({'ok': False, 'message': 'Message is required.', 'reply': ''}), 400
    if len(user_message) > 3000:
        return jsonify({'ok': False, 'message': 'Message too long. Limit is 3000 characters.', 'reply': ''}), 400

    started = time.time()
    result = generate_assistant_reply(history, user_message)
    latency_ms = int((time.time() - started) * 1000)
    reply = str(result.get('reply') or '').strip()[:4000]
    chat_runtime = get_chat_runtime_status()
    if result.get('message') == 'knowledge_base':
        chat_runtime = {
            'label': 'Knowledge Base',
            'headline': 'Matched your question with the local cybersecurity knowledge base.',
            'detail': 'Instant local answer delivered from data.json before using Wikipedia or local AI.',
            'class': 'live',
            'model_label': 'LOCAL KB',
        }
    elif result.get('message') == 'wikipedia':
        chat_runtime = {
            'label': 'Wikipedia',
            'headline': 'A related Wikipedia summary was used for this answer.',
            'detail': 'No local match was found, so the chatbot used Wikipedia as the next free source.',
            'class': 'live',
            'model_label': 'WIKIPEDIA',
        }
    elif result.get('message') == 'ollama':
        chat_runtime = {
            'label': 'Local AI',
            'headline': f'Local Ollama model {OLLAMA_MODEL} generated this answer.',
            'detail': 'The chatbot used your local AI runtime instead of any paid API.',
            'class': 'live',
            'model_label': 'OLLAMA',
        }
    elif result.get('message') in {'fallback', 'fallback_mode'}:
        chat_runtime = {
            'label': 'Local Guide',
            'headline': 'CyberBot generated a local cybersecurity answer.',
            'detail': 'Answer generated from built-in cybersecurity guidance.',
            'class': 'live',
            'model_label': 'CYBERBOT',
        }

    return jsonify(
        {
            'ok': bool(result.get('ok', False)),
            'reply': reply,
            'response': reply,
            'mode': result.get('message', 'ok'),
            'notice': str(result.get('notice') or '').strip(),
            'latency_ms': latency_ms,
            'model': (
                'knowledge-base'
                if result.get('message') == 'knowledge_base'
                else 'wikipedia'
                if result.get('message') == 'wikipedia'
                else OLLAMA_MODEL
                if result.get('message') == 'ollama'
                else 'local-fallback'
            ),
            'model_label': chat_runtime['model_label'],
            'status_label': chat_runtime['label'],
            'status_text': chat_runtime['headline'],
            'status_detail': chat_runtime['detail'],
            'status_class': chat_runtime['class'],
        }
    )


try:
    init_db()
except sqlite3.Error:
    DB_PATH = BASE_DIR / 'cybersecurity_runtime.db'
    try:
        init_db()
    except sqlite3.Error:
        print('Warning: SQLite initialization failed. Running in degraded mode without persistent storage.')

if __name__ == '__main__':
    app.run(debug=False)


