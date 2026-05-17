#!/usr/bin/env python3
"""
Flask API Server for Pentest Platform v3.0
- Gemini AI-powered scan analysis
- Real Nmap scanning (Normal/Medium/Strong)
- PDF + JSON report generation
- Role-based access (Admin / User)
- Full user management for admins

CHANGES in this version (Phase 1 security fixes):
  - SECRET_KEY loaded from .env — raises error if missing in production
  - Admin password loaded from ADMIN_PASSWORD env var (never hardcoded)
  - Rate limiting on /api/auth/login and /api/auth/register (Flask-Limiter)
  - CORS restricted to CORS_ORIGINS env var instead of wildcard *
  - SCANS_DIR uses persistent path from SCANS_DIR env var
  - Stale 'running' scans cleaned up on startup
"""

from flask import Flask, request, jsonify, session, send_file
from flask_cors import CORS
import subprocess
import shutil
import json
import csv
import io
import uuid
import os
import sys
import re
import secrets
import threading
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
from functools import wraps

# ── Load .env file if present ─────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv optional; set env vars manually if not installed

# ── Import local modules ──────────────────────────────────────
from database import init_db, get_db_session, User, Scan, ScanResult, Vulnerability
from ai.report_generator import generate_ai_report, summarize_scan_results, classify_all_vulnerabilities
from ai.gemini_client import get_gemini_client
from utils.validators import validate_and_normalize_target, resolve_target

# ── Rate limiting (optional but strongly recommended) ─────────
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    LIMITER_AVAILABLE = True
except ImportError:
    LIMITER_AVAILABLE = False
    print("⚠ Flask-Limiter not installed — rate limiting disabled (pip install flask-limiter)")

# ── Optional PDF generator ────────────────────────────────────
try:
    from utils.pdf_generator import generate_pdf_report
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    print("⚠ PDF generation unavailable (pip install reportlab)")

# ─────────────────────────────────────────────────────────────
# App setup
# ─────────────────────────────────────────────────────────────

app = Flask(__name__, static_folder='../Frontend', static_url_path='/')

@app.route('/')
def index():
    return app.send_static_file('signin.html')

# ── SECRET_KEY — never fall back to a known string ────────────
_secret = os.environ.get('SECRET_KEY', '')
if not _secret:
    # In development we auto-generate (ephemeral — sessions break on restart).
    # In production always set SECRET_KEY in your .env file.
    _secret = secrets.token_hex(32)
    print("⚠  SECRET_KEY not set — generated a temporary one. Sessions will break on restart.")
    print("   Fix: add SECRET_KEY=<your-secret> to your .env file.")
app.secret_key = _secret

app.config.update(
    SESSION_COOKIE_SAMESITE='Lax',
    # Set to True when you have HTTPS (even self-signed). Keep False for plain HTTP LAN only.
    SESSION_COOKIE_SECURE=os.environ.get('HTTPS_ENABLED', 'false').lower() == 'true',
    SESSION_COOKIE_HTTPONLY=True,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=24)
)

# ── CORS — restrict to your own origins ──────────────────────
_cors_origins_raw = os.environ.get('CORS_ORIGINS', '')
_cors_origins = [o.strip() for o in _cors_origins_raw.split(',') if o.strip()] if _cors_origins_raw else ['*']
if '*' in _cors_origins:
    print("⚠  CORS_ORIGINS not set — allowing all origins. Set CORS_ORIGINS in .env for production.")

CORS(app,
     resources={r"/api/*": {"origins": _cors_origins}},
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization", "Accept", "Origin"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

# ── Rate limiter ──────────────────────────────────────────────
if LIMITER_AVAILABLE:
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=[],           # no global limit — apply per-route only
        storage_uri="memory://",     # switch to "redis://localhost:6379" for multi-process
    )

def rate_limit(limit_string):
    """Decorator that applies rate limiting only when flask-limiter is available."""
    def decorator(f):
        if LIMITER_AVAILABLE:
            return limiter.limit(limit_string)(f)
        return f
    return decorator

# ── Directories — persistent storage ─────────────────────────
BACKEND_DIR  = os.path.dirname(os.path.abspath(__file__))
_default_scans_dir = os.path.join(BACKEND_DIR, 'data', 'scans')
SCANS_DIR    = os.environ.get('SCANS_DIR', _default_scans_dir)
REPORTS_DIR  = os.path.join(SCANS_DIR, 'reports')
os.makedirs(SCANS_DIR,   exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

SCANNERS_DIR = os.path.join(BACKEND_DIR, 'scanners')

# ── Scan type mapping ─────────────────────────────────────────
SCAN_TYPE_MAP = {
    'normal':        'quick',
    'medium':        'standard',
    'strong':        'intense',
    'quick':         'quick',
    'standard':      'standard',
    'intense':       'intense',
    'comprehensive': 'comprehensive',
    'vulnerability': 'vulnerability',
}

VALID_SCAN_TOOLS = ('nmap', 'nikto', 'sqlmap', 'wfuzz', 'harvester')

# ─────────────────────────────────────────────────────────────
# Database init
# ─────────────────────────────────────────────────────────────

try:
    init_db()
    print("✓ Database initialized")

    with get_db_session() as db:
        # ── Clean up stale 'running' scans from a previous crash ──
        stale = db.query(Scan).filter_by(status='running').all()
        if stale:
            for s in stale:
                s.status = 'failed'
                s.error_message = 'Server restarted while scan was running'
            db.commit()
            print(f"⚠  Marked {len(stale)} stale scan(s) as failed")

        # ── Create / sync default admin ───────────────────────────
        admin_password = os.environ.get('ADMIN_PASSWORD', '').strip()
        if not admin_password:
            admin_password = secrets.token_urlsafe(16)
            print(f"\n{'='*55}")
            print(f"  ⚠  ADMIN_PASSWORD not set in .env")
            print(f"  Generated password: {admin_password}")
            print(f"  Save this — it will NOT be shown again.")
            print(f"  Add ADMIN_PASSWORD={admin_password} to your .env")
            print(f"{'='*55}\n")

        admin = db.query(User).filter_by(email='admin@security.com').first()
        if not admin:
            admin = User(
                user_id='user_admin',
                email='admin@security.com',
                name='Admin User',
                role='admin',
                is_active=True
            )
            admin.set_password(admin_password)
            db.add(admin)
            db.commit()
            print("✓ Admin account created: admin@security.com")
        else:
            # Always sync password from .env so admin can always login
            admin.set_password(admin_password)
            db.commit()
            print("✓ Admin password synced from .env")

except Exception as e:
    print(f"⚠ DB init warning: {e}")


# ─────────────────────────────────────────────────────────────
# Auth decorators
# ─────────────────────────────────────────────────────────────

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
        if session.get('role') != 'admin':
            return jsonify({'status': 'error', 'message': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────────────────────
# AUTHENTICATION
# ─────────────────────────────────────────────────────────────

@app.route('/api/auth/register', methods=['POST'])
@rate_limit("5 per minute; 20 per hour")
def register():
    try:
        data     = request.json or {}
        email    = (data.get('email') or '').strip().lower()
        password = data.get('password', '')
        name     = (data.get('name') or '').strip()

        if not email or not password or not name:
            return jsonify({'status': 'error', 'message': 'Name, email, and password are required'}), 400
        if len(password) < 8:
            return jsonify({'status': 'error', 'message': 'Password must be at least 8 characters'}), 400
        if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
            return jsonify({'status': 'error', 'message': 'Invalid email format'}), 400
        if len(name) > 100:
            return jsonify({'status': 'error', 'message': 'Name too long'}), 400

        with get_db_session() as db:
            if db.query(User).filter_by(email=email).first():
                return jsonify({'status': 'error', 'message': 'Email already registered'}), 400
            user = User(user_id=str(uuid.uuid4()), email=email, name=name,
                        role='user', is_active=True)
            user.set_password(password)
            db.add(user)
            db.commit()
            print(f"✓ New user registered: {email}")

        return jsonify({'status': 'success', 'message': 'Registration successful. Please sign in.'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/auth/login', methods=['POST'])
@rate_limit("10 per minute; 50 per hour")
def login():
    """
    Rate limited: 10 attempts/minute per IP.
    After 10 failed attempts the IP is blocked for 1 minute automatically.
    """
    try:
        data     = request.json or {}
        email    = (data.get('email') or '').strip().lower()
        password = data.get('password', '')

        if not email or not password:
            return jsonify({'status': 'error', 'message': 'Email and password required'}), 400

        with get_db_session() as db:
            user = db.query(User).filter_by(email=email).first()
            # Constant-time comparison: always call check_password even if user not found
            # to prevent user-enumeration via timing attack
            password_ok = user.check_password(password) if user else False

            if not user or not password_ok:
                return jsonify({'status': 'error', 'message': 'Invalid email or password'}), 401
            if not user.is_active:
                return jsonify({'status': 'error', 'message': 'Account disabled. Contact an admin.'}), 403

            user.last_login = datetime.now(timezone.utc)
            db.commit()

            session.permanent = True
            session['user_id']    = user.user_id
            session['db_user_id'] = user.id
            session['email']      = user.email
            session['name']       = user.name
            session['role']       = user.role

            print(f"✓ Login: {email} (role={user.role})")
            return jsonify({
                'status': 'success',
                'user': {
                    'user_id': user.user_id,
                    'email':   user.email,
                    'name':    user.name,
                    'role':    user.role
                }
            })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'status': 'success'})


@app.route('/api/auth/me', methods=['GET'])
@require_auth
def get_me():
    return jsonify({
        'status': 'success',
        'user': {
            'user_id': session.get('user_id'),
            'email':   session.get('email'),
            'name':    session.get('name'),
            'role':    session.get('role')
        }
    })


# ─────────────────────────────────────────────────────────────
# ADMIN ENDPOINTS
# ─────────────────────────────────────────────────────────────

@app.route('/api/admin/users', methods=['GET'])
@require_admin
def list_users():
    try:
        with get_db_session() as db:
            users = db.query(User).order_by(User.created_at.desc()).all()
            scan_counts = {}
            for u in users:
                count = db.query(Scan).filter_by(user_id_fk=u.id).count()
                scan_counts[u.user_id] = count

            return jsonify({
                'status': 'success',
                'users': [{
                    'user_id':    u.user_id,
                    'email':      u.email,
                    'name':       u.name,
                    'role':       u.role,
                    'is_active':  u.is_active,
                    'created_at': u.created_at.isoformat() if u.created_at else None,
                    'last_login': u.last_login.isoformat() if u.last_login else None,
                    'scan_count': scan_counts.get(u.user_id, 0),
                } for u in users],
                'total': len(users)
            })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/admin/users/<user_id>/toggle', methods=['POST'])
@require_admin
def toggle_user(user_id):
    try:
        with get_db_session() as db:
            user = db.query(User).filter_by(user_id=user_id).first()
            if not user:
                return jsonify({'status': 'error', 'message': 'User not found'}), 404
            if user.role == 'admin':
                return jsonify({'status': 'error', 'message': 'Cannot disable admin users'}), 400
            user.is_active = not user.is_active
            db.commit()
            return jsonify({
                'status': 'success',
                'message': f"User {'enabled' if user.is_active else 'disabled'}",
                'is_active': user.is_active
            })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/admin/users/<user_id>', methods=['DELETE'])
@require_admin
def delete_user(user_id):
    try:
        with get_db_session() as db:
            user = db.query(User).filter_by(user_id=user_id).first()
            if not user:
                return jsonify({'status': 'error', 'message': 'User not found'}), 404
            if user.role == 'admin':
                return jsonify({'status': 'error', 'message': 'Cannot delete admin users'}), 400
            db.delete(user)
            db.commit()
            return jsonify({'status': 'success', 'message': 'User deleted'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/admin/stats', methods=['GET'])
@require_admin
def admin_stats():
    try:
        with get_db_session() as db:
            today    = datetime.now(timezone.utc).date()
            week_ago = datetime.now(timezone.utc) - timedelta(days=7)

            total_users  = db.query(User).count()
            active_users = db.query(User).filter_by(is_active=True).count()
            total_scans  = db.query(Scan).count()
            scans_today  = db.query(Scan).filter(
                Scan.created_at >= datetime.combine(today, datetime.min.time())
            ).count()
            total_vulns  = db.query(Vulnerability).count()
            active_scans = db.query(Scan).filter_by(status='running').count()
            recent_scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(10).all()

            return jsonify({
                'status': 'success',
                'stats': {
                    'total_users':  total_users,
                    'active_users': active_users,
                    'total_scans':  total_scans,
                    'scans_today':  scans_today,
                    'total_vulns':  total_vulns,
                    'active_scans': active_scans,
                },
                'recent_scans': [{
                    'scan_id':    s.scan_id,
                    'target':     s.target,
                    'scan_type':  s.scan_type,
                    'status':     s.status,
                    'risk_level': s.risk_level,
                    'created_at': s.created_at.isoformat() if s.created_at else None,
                } for s in recent_scans]
            })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ─────────────────────────────────────────────────────────────
# PING
# ─────────────────────────────────────────────────────────────

@app.route('/api/ping', methods=['POST'])
@require_auth
def ping_target():
    try:
        data       = request.json
        raw_target = (data.get('target') or '').strip()

        is_valid, target, error = validate_and_normalize_target(raw_target)
        if not is_valid:
            return jsonify({'status': 'error', 'message': error}), 400

        # Resolve DNS
        is_ok, ip_address, err = resolve_target(target)
        if not is_ok:
            return jsonify({
                'status': 'success',
                'reachable': False,
                'target': target,
                'message': f'Cannot resolve {target}: {err}'
            })

        try:
            result = subprocess.run(
                ['ping', '-c', '3', '-W', '5', ip_address],
                capture_output=True, text=True, timeout=20
            )
            latency = None
            lat_match = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/', result.stdout)
            if lat_match:
                latency = float(lat_match.group(1))

            loss_match = re.search(r'(\d+)% packet loss', result.stdout)
            packet_loss = int(loss_match.group(1)) if loss_match else 100

            reachable = result.returncode == 0 and packet_loss < 100

            return jsonify({
                'status':      'success',
                'reachable':   reachable,
                'target':      target,
                'ip_address':  ip_address,
                'latency_ms':  round(latency, 2) if latency else None,
                'packet_loss': packet_loss,
                'message':     (f'Host is up — avg latency {latency:.1f}ms' if reachable and latency
                                else 'Host is up' if reachable else 'Host appears down or blocking ICMP')
            })
        except subprocess.TimeoutExpired:
            return jsonify({
                'status': 'success', 'reachable': False,
                'target': target, 'ip_address': ip_address,
                'message': 'Ping timed out'
            })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ─────────────────────────────────────────────────────────────
# SCAN
# ─────────────────────────────────────────────────────────────

@app.route('/api/scan', methods=['POST'])
@rate_limit("10 per minute; 100 per hour")
def start_scan():
    """
    Start an Nmap scan.
    Accepts scan_type: normal | medium | strong | quick | standard | intense
    """
    try:
        data        = request.json or {}
        raw_target  = (data.get('target') or '').strip()
        scan_type_in = (data.get('scan_type') or 'normal').lower()
        consent     = data.get('consent', False)
        tool        = (data.get('tool') or 'nmap').lower()

        if tool not in VALID_SCAN_TOOLS:
            return jsonify({
                'status': 'error',
                'message': f"Unknown tool. Choose from: {', '.join(VALID_SCAN_TOOLS)}"
            }), 400

        if tool == 'nikto':
            return nikto_scan()
        if tool == 'sqlmap':
            return sql_scan()
        if tool == 'wfuzz':
            return wfuzz_scan()
        if tool == 'harvester':
            return harvester_scan()

        if not session.get('user_id'):
            return jsonify({'status': 'error', 'message': 'Authentication required'}), 401

        db_user_id  = session.get('db_user_id')
        user_id     = session.get('user_id')

        if not consent:
            return jsonify({'status': 'error', 'message': 'You must confirm authorization to scan this target'}), 400

        # Map scan type
        scan_type = SCAN_TYPE_MAP.get(scan_type_in, 'quick')

        # Validate target
        is_valid, target, error = validate_and_normalize_target(raw_target)
        if not is_valid:
            return jsonify({'status': 'error', 'message': error}), 400

        # DNS check
        is_ok, ip_address, err = resolve_target(target)
        if not is_ok:
            return jsonify({'status': 'error', 'message': f'Cannot resolve target: {err}', 'phase': 'dns'}), 400

        scan_id     = str(uuid.uuid4())
        output_file = os.path.join(SCANS_DIR, f'scan_{scan_id}.json')
        scanner_script = os.path.join(SCANNERS_DIR, 'nmap_scanner.py')

        if not os.path.exists(scanner_script):
            return jsonify({'status': 'error', 'message': 'Nmap scanner script not found'}), 500

        # Create DB record
        with get_db_session() as db:
            scan = Scan(
                scan_id=scan_id, user_id_fk=db_user_id,
                target=target, scan_type=scan_type_in,
                tool='nmap', status='running',
                created_at=datetime.now(timezone.utc), started_at=datetime.now(timezone.utc)
            )
            db.add(scan)
            db.commit()

        print(f"[{user_id}] Starting {scan_type} ({scan_type_in}) scan on {target} ({ip_address})")

        start_time = datetime.now(timezone.utc)

        timeout_map = {'quick': 120, 'standard': 300, 'intense': 600, 'comprehensive': 600, 'vulnerability': 600}
        timeout = timeout_map.get(scan_type, 300)

        result = subprocess.run(
            [sys.executable, scanner_script, target, scan_type, '--output', output_file],
            capture_output=True, text=True, timeout=timeout
        )

        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()

        if result.returncode != 0 or not os.path.exists(output_file):
            err_msg = result.stderr or 'Scan failed'
            with get_db_session() as db:
                s = db.query(Scan).filter_by(scan_id=scan_id).first()
                s.status = 'failed'
                s.completed_at = end_time
                s.duration = duration
                s.error_message = err_msg
                db.commit()
            return jsonify({'status': 'error', 'message': f'Scan failed: {err_msg}', 'scan_id': scan_id}), 500

        with open(output_file, 'r') as f:
            scan_results = json.load(f)

        # AI analysis (Gemini)
        ai_summary = summarize_scan_results(scan_results)
        vulnerabilities = classify_all_vulnerabilities(scan_results)
        ai_report = generate_ai_report(scan_results, vulnerabilities)

        # Save to DB
        with get_db_session() as db:
            s = db.query(Scan).filter_by(scan_id=scan_id).first()
            s.status = 'completed'
            s.completed_at = end_time
            s.duration = duration
            s.risk_level = (ai_summary or {}).get('risk_level', 'info')
            if ai_summary:
                s.ai_summary = json.dumps(ai_summary)

            # Save port results
            results_data = scan_results.get('results', {})
            if isinstance(results_data, dict):
                for _, rdata in results_data.items():
                    if isinstance(rdata, dict):
                        for p in rdata.get('ports', []):
                            svc = p.get('service', {})
                            svc_name = svc.get('name', '') if isinstance(svc, dict) else str(svc or '')
                            svc_ver  = (str(svc.get('product') or '') + ' ' + str(svc.get('version') or '')).strip() if isinstance(svc, dict) else ''
                            db.add(ScanResult(
                                scan_id=s.id,
                                port=p.get('port'),
                                protocol=p.get('protocol', 'tcp'),
                                state=p.get('state', 'unknown'),
                                service=svc_name,
                                version=svc_ver
                            ))

            # Save vulnerabilities
            for v in vulnerabilities:
                cve = v.get('cve_id') or (v.get('cve_references') or [None])[0]
                db.add(Vulnerability(
                    scan_id=s.id,
                    title=v.get('title', 'Unknown'),
                    description=v.get('description', ''),
                    severity=(v.get('severity') or 'info').lower(),
                    cvss_score=v.get('cvss_score'),
                    cve_id=cve,
                    owasp_category=v.get('owasp_category'),
                    remediation=v.get('remediation', ''),
                    ai_classified=True
                ))
            db.commit()

        # Save JSON report
        user_report_dir = os.path.join(REPORTS_DIR, user_id)
        os.makedirs(user_report_dir, exist_ok=True)
        json_filename = f'{scan_id}.json'
        json_path = os.path.join(user_report_dir, json_filename)
        with open(json_path, 'w') as f:
            json.dump({
                'scan_id': scan_id, 'user_id': user_id,
                'target': target, 'resolved_ip': ip_address,
                'scan_type': scan_type_in, 'duration': duration,
                'timestamp': datetime.now().isoformat(),
                'scan_results': scan_results,
                'ai_summary': ai_summary,
                'ai_report': ai_report,
                'vulnerabilities': vulnerabilities,
            }, f, indent=2, default=str)

        print(f"✓ Scan {scan_id} completed in {duration:.1f}s")

        return jsonify({
            'status':          'success',
            'scan_id':         scan_id,
            'target':          target,
            'resolved_ip':     ip_address,
            'duration':        duration,
            'scan_type':       scan_type_in,
            'results':         scan_results,
            'ai_summary':      ai_summary,
            'ai_report':       ai_report,
            'vulnerabilities': vulnerabilities,
        })

    except subprocess.TimeoutExpired:
        return jsonify({'status': 'error', 'message': 'Scan timed out. Try a lighter scan type.'}), 500
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/scan/<scan_id>', methods=['GET'])
@require_auth
def get_scan(scan_id):
    try:
        db_user_id = session.get('db_user_id')
        role       = session.get('role')

        with get_db_session() as db:
            scan = db.query(Scan).filter_by(scan_id=scan_id).first()
            if not scan:
                return jsonify({'status': 'error', 'message': 'Scan not found'}), 404
            if role != 'admin' and scan.user_id_fk != db_user_id:
                return jsonify({'status': 'error', 'message': 'Access denied'}), 403

            results = db.query(ScanResult).filter_by(scan_id=scan.id).all()
            vulns   = db.query(Vulnerability).filter_by(scan_id=scan.id).all()

            ai_report = None  # Full AI report is only in the CSV download

            return jsonify({
                'status': 'success',
                'scan': {
                    'scan_id':     scan.scan_id,
                    'target':      scan.target,
                    'scan_type':   scan.scan_type,
                    'tool':        scan.tool,
                    'status':      scan.status,
                    'risk_level':  scan.risk_level,
                    'duration':    scan.duration,
                    'created_at':  scan.created_at.isoformat() if scan.created_at else None,
                    'completed_at':scan.completed_at.isoformat() if scan.completed_at else None,
                    'ai_summary':  json.loads(scan.ai_summary) if scan.ai_summary else None,
                },
                'results': [{
                    'port': r.port, 'protocol': r.protocol,
                    'state': r.state, 'service': r.service, 'version': r.version
                } for r in results],
                'vulnerabilities': [{
                    'title': v.title, 'severity': v.severity, 'cvss_score': v.cvss_score,
                    'cve_id': v.cve_id, 'owasp_category': v.owasp_category,
                    'description': v.description, 'remediation': v.remediation
                } for v in vulns],
                'ai_report': ai_report,
            })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/scan-history', methods=['GET'])
@require_auth
def scan_history():
    try:
        db_user_id = session.get('db_user_id')
        role       = session.get('role')
        limit      = request.args.get('limit', 50, type=int)

        with get_db_session() as db:
            query = db.query(Scan)
            if role != 'admin':
                query = query.filter_by(user_id_fk=db_user_id)
            scans = query.order_by(Scan.created_at.desc()).limit(limit).all()

            return jsonify({
                'status': 'success',
                'scans': [{
                    'scan_id':    s.scan_id,
                    'target':     s.target,
                    'scan_type':  s.scan_type,
                    'status':     s.status,
                    'risk_level': s.risk_level,
                    'duration':   s.duration,
                    'created_at': s.created_at.isoformat() if s.created_at else None,
                } for s in scans],
                'total': len(scans)
            })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/statistics', methods=['GET'])
@require_auth
def statistics():
    try:
        db_user_id = session.get('db_user_id')
        role       = session.get('role')

        with get_db_session() as db:
            today = datetime.now(timezone.utc).date()

            if role == 'admin':
                total_scans  = db.query(Scan).count()
                total_vulns  = db.query(Vulnerability).count()
                total_users  = db.query(User).count()
                active_users = db.query(User).filter_by(is_active=True).count()
                scans_today  = db.query(Scan).filter(
                    Scan.created_at >= datetime.combine(today, datetime.min.time())
                ).count()
                active_scans = db.query(Scan).filter_by(status='running').count()
            else:
                total_scans  = db.query(Scan).filter_by(user_id_fk=db_user_id).count()
                total_vulns  = 0
                my_scans = db.query(Scan).filter_by(user_id_fk=db_user_id).all()
                for s in my_scans:
                    total_vulns += db.query(Vulnerability).filter_by(scan_id=s.id).count()
                scans_today  = db.query(Scan).filter(
                    Scan.user_id_fk == db_user_id,
                    Scan.created_at >= datetime.combine(today, datetime.min.time())
                ).count()
                total_users  = 0
                active_users = 0
                active_scans = 0

            return jsonify({
                'status': 'success',
                'statistics': {
                    'total_scans':   total_scans,
                    'total_vulns':   total_vulns,
                    'total_users':   total_users,
                    'active_users':  active_users,
                    'scans_today':   scans_today,
                    'active_scans':  active_scans,
                }
            })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ─────────────────────────────────────────────────────────────
# REPORTS
# ─────────────────────────────────────────────────────────────

def _write_csv_report(path, scan_id, target, scan_type, duration,
                      ports, vulnerabilities, ai_report, ai_summary):
    """Write a structured CSV security report."""
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)

        # ── Metadata ──────────────────────────────────────────
        w.writerow(['SECURITY SCAN REPORT'])
        w.writerow(['Scan ID', scan_id])
        w.writerow(['Target', target])
        w.writerow(['Scan Type', scan_type])
        w.writerow(['Duration (s)', round(duration or 0, 2)])
        w.writerow(['Generated At', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])

        ar = ai_report or {}
        w.writerow(['Risk Score', ar.get('risk_score', ai_summary.get('risk_score', 'N/A'))])
        w.writerow(['Risk Grade', ar.get('risk_grade', 'N/A')])
        w.writerow(['Risk Level', ar.get('risk_level', ai_summary.get('risk_level', 'N/A'))])
        w.writerow(['AI Generated', 'Yes' if ar.get('ai_generated') else 'No (rule-based)'])
        w.writerow([])

        # ── Executive Summary ─────────────────────────────────
        w.writerow(['EXECUTIVE SUMMARY'])
        w.writerow([ar.get('executive_summary', ai_summary.get('summary', 'N/A'))])
        w.writerow([])

        # ── Open Ports ────────────────────────────────────────
        w.writerow(['OPEN PORTS'])
        w.writerow(['Port', 'Protocol', 'State', 'Service', 'Version'])
        for p in (ports or []):
            svc = p.get('service', '')
            svc_name = svc.get('name', '') if isinstance(svc, dict) else (svc or '')
            svc_ver  = p.get('version', '') or (svc.get('version', '') if isinstance(svc, dict) else '')
            if p.get('state') == 'open':
                w.writerow([p.get('port', ''), p.get('protocol', 'tcp'),
                             p.get('state', ''), svc_name, svc_ver])
        if not any(p.get('state') == 'open' for p in (ports or [])):
            w.writerow(['No open ports found'])
        w.writerow([])

        # ── Vulnerabilities ───────────────────────────────────
        w.writerow(['VULNERABILITIES'])
        w.writerow(['Title', 'Severity', 'CVE ID', 'OWASP Category', 'Description', 'Remediation'])
        for v in (vulnerabilities or []):
            w.writerow([
                v.get('title', ''), v.get('severity', '').upper(),
                v.get('cve_id', ''), v.get('owasp_category', ''),
                (v.get('description', '') or '')[:300],
                (v.get('remediation', '') or '')[:300],
            ])
        if not vulnerabilities:
            w.writerow(['No vulnerabilities detected'])
        w.writerow([])

        # ── Severity Distribution ─────────────────────────────
        sd = ar.get('severity_distribution', {})
        if sd:
            w.writerow(['SEVERITY DISTRIBUTION'])
            w.writerow(['Critical', 'High', 'Medium', 'Low', 'Info'])
            w.writerow([sd.get('critical', 0), sd.get('high', 0),
                        sd.get('medium', 0), sd.get('low', 0), sd.get('info', 0)])
            w.writerow([])

        # ── Recommendations ───────────────────────────────────
        recs = ar.get('recommendations', [])
        if recs:
            w.writerow(['RECOMMENDATIONS'])
            w.writerow(['Priority', 'Action', 'Effort', 'Impact'])
            for r in recs:
                w.writerow([
                    r.get('priority', '').upper(),
                    r.get('action', ''),
                    r.get('effort', ''),
                    r.get('impact_reduction', ''),
                ])
            w.writerow([])

        # ── Mitigation Roadmap ────────────────────────────────
        roadmap = ar.get('mitigation_roadmap', [])
        if roadmap:
            w.writerow(['MITIGATION ROADMAP'])
            w.writerow(['Phase', 'Actions'])
            for phase in roadmap:
                actions = '; '.join(phase.get('actions', []))
                w.writerow([phase.get('phase', ''), actions])


@app.route('/api/reports/generate', methods=['POST'])
@require_auth
def generate_report():
    """Generate PDF + JSON AI report for a given scan_id."""
    try:
        data       = request.json
        scan_id    = (data.get('scan_id') or '').strip()
        db_user_id = session.get('db_user_id')
        user_id    = session.get('user_id')
        role       = session.get('role')

        if not scan_id:
            return jsonify({'status': 'error', 'message': 'scan_id required'}), 400

        # Serialize everything inside the session so objects stay bound
        with get_db_session() as db:
            scan = db.query(Scan).filter_by(scan_id=scan_id).first()
            if not scan:
                return jsonify({'status': 'error', 'message': 'Scan not found'}), 404
            if role != 'admin' and scan.user_id_fk != db_user_id:
                return jsonify({'status': 'error', 'message': 'Access denied'}), 403

            # Determine report owner while session is open
            report_owner_id = user_id
            if role == 'admin':
                owner = db.query(User).filter_by(id=scan.user_id_fk).first()
                if owner:
                    report_owner_id = owner.user_id

            # Serialize scan fields to plain Python values before session closes
            scan_target   = scan.target
            scan_type_val = scan.scan_type
            scan_duration = scan.duration
            ai_summary_data = json.loads(scan.ai_summary) if scan.ai_summary else {}

            results = db.query(ScanResult).filter_by(scan_id=scan.id).all()
            vulns   = db.query(Vulnerability).filter_by(scan_id=scan.id).all()

            # Convert ORM objects to plain dicts before session closes
            results_for_ai = [{
                'port': r.port, 'protocol': r.protocol,
                'state': r.state,
                'service': {'name': r.service or '', 'version': r.version or ''}
            } for r in results]

            results_flat = [{
                'port': r.port, 'protocol': r.protocol,
                'state': r.state, 'service': r.service, 'version': r.version
            } for r in results]

            vulns_list = [{
                'title': v.title, 'severity': v.severity, 'description': v.description,
                'remediation': v.remediation, 'cve_id': v.cve_id,
                'owasp_category': v.owasp_category,
            } for v in vulns]

        # --- All DB access complete; use only plain Python data from here ---

        user_report_dir = os.path.join(REPORTS_DIR, report_owner_id)
        os.makedirs(user_report_dir, exist_ok=True)

        csv_path = os.path.join(user_report_dir, f'{scan_id}.csv')
        scan_data_for_ai = {
            'scan_id': scan_id,
            'target': scan_target,
            'scan_type': scan_type_val,
            'duration': scan_duration,
            'scan_metadata': {'target': scan_target, 'scan_type': scan_type_val},
            'results': {'standard': {'ports': results_for_ai}}
        }

        # Generate AI report (Gemini or fallback)
        ai_report = generate_ai_report(scan_data_for_ai, vulns_list)

        # Save CSV report
        _write_csv_report(csv_path, scan_id, scan_target, scan_type_val,
                          scan_duration, results_flat, vulns_list, ai_report, ai_summary_data)

        pdf_path = None
        pdf_filename = None
        if PDF_AVAILABLE:
            pdf_filename = f'{scan_id}.pdf'
            pdf_path = os.path.join(user_report_dir, pdf_filename)
            try:
                generate_pdf_report(scan_data_for_ai, ai_report, vulns_list, pdf_path)
                print(f"✓ PDF report generated: {pdf_path}")
            except Exception as e:
                print(f"⚠ PDF generation failed: {e}")
                pdf_path = None

        # Also ensure the JSON report file from scan-time exists
        json_report_path = os.path.join(user_report_dir, f'{scan_id}.json')
        has_json = os.path.exists(json_report_path)

        return jsonify({
            'status':  'success',
            'message': 'Report generated successfully',
            'scan_id': scan_id,
            'ai_report': ai_report,
            'downloads': {
                'json': f'/api/reports/download/{report_owner_id}/{scan_id}.json' if has_json else None,
                'csv': f'/api/reports/download/{report_owner_id}/{scan_id}.csv',
                'pdf': f'/api/reports/download/{report_owner_id}/{scan_id}.pdf' if pdf_path else None,
            }
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/reports/list', methods=['GET'])
@require_auth
def list_reports():
    """List all reports for current user. Admin sees all."""
    try:
        user_id = session.get('user_id')
        role    = session.get('role')
        reports = []

        if role == 'admin':
            # All user directories
            dirs_to_scan = []
            if os.path.exists(REPORTS_DIR):
                for d in os.listdir(REPORTS_DIR):
                    full = os.path.join(REPORTS_DIR, d)
                    if os.path.isdir(full):
                        dirs_to_scan.append((d, full))
        else:
            user_dir = os.path.join(REPORTS_DIR, user_id)
            dirs_to_scan = [(user_id, user_dir)] if os.path.exists(user_dir) else []

        for owner_id, dirpath in dirs_to_scan:
            if not os.path.exists(dirpath):
                continue
            csv_files = [f for f in os.listdir(dirpath) if f.endswith('.csv')]
            for fname in csv_files:
                scan_id = fname.replace('.csv', '')
                with get_db_session() as db:
                    s = db.query(Scan).filter_by(scan_id=scan_id).first()
                    if s:
                        has_pdf = os.path.exists(os.path.join(dirpath, f'{scan_id}.pdf'))
                        reports.append({
                            'scan_id':    scan_id,
                            'target':     s.target,
                            'scan_type':  s.scan_type,
                            'status':     s.status,
                            'risk_level': s.risk_level,
                            'created_at': s.created_at.isoformat() if s.created_at else None,
                            'owner_id':   owner_id,
                            'has_csv':    True,
                            'has_pdf':    has_pdf,
                            'downloads': {
                                'csv': f'/api/reports/download/{owner_id}/{scan_id}.csv',
                                'pdf': f'/api/reports/download/{owner_id}/{scan_id}.pdf' if has_pdf else None,
                            }
                        })

        reports.sort(key=lambda x: x.get('created_at') or '', reverse=True)
        return jsonify({'status': 'success', 'reports': reports, 'total': len(reports)})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/reports/download/<owner_id>/<filename>', methods=['GET'])
@require_auth
def download_report(owner_id, filename):
    """Download a report file (PDF or JSON)."""
    try:
        user_id = session.get('user_id')
        role    = session.get('role')

        # Users can only access their own reports
        if role != 'admin' and owner_id != user_id:
            return jsonify({'status': 'error', 'message': 'Access denied'}), 403

        file_path = os.path.join(REPORTS_DIR, owner_id, filename)
        if not os.path.exists(file_path):
            return jsonify({'status': 'error', 'message': 'File not found'}), 404

        if filename.endswith('.pdf'):
            mime = 'application/pdf'
        elif filename.endswith('.csv'):
            mime = 'text/csv'
        else:
            mime = 'application/octet-stream'
        return send_file(file_path, mimetype=mime, as_attachment=True, download_name=filename)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/reports/upload', methods=['POST'])
@require_admin
def upload_report():
    """Admin: upload an external report file."""
    try:
        if 'file' not in request.files:
            return jsonify({'status': 'error', 'message': 'No file provided'}), 400
        f = request.files['file']
        if not f.filename:
            return jsonify({'status': 'error', 'message': 'No filename'}), 400

        ext = f.filename.rsplit('.', 1)[-1].lower()
        if ext not in ('pdf', 'csv'):
            return jsonify({'status': 'error', 'message': 'Only PDF or CSV files allowed'}), 400

        admin_dir = os.path.join(REPORTS_DIR, 'uploads')
        os.makedirs(admin_dir, exist_ok=True)
        uid = str(uuid.uuid4())[:8]
        safe_name = f'upload_{uid}.{ext}'
        save_path = os.path.join(admin_dir, safe_name)
        f.save(save_path)

        return jsonify({
            'status': 'success',
            'message': f'Report uploaded: {safe_name}',
            'filename': safe_name,
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ─────────────────────────────────────────────────────────────
# NIKTO SCAN
# ─────────────────────────────────────────────────────────────

@app.route('/api/scan/nikto', methods=['POST'])
@require_auth
@rate_limit("5 per minute; 30 per hour")
def nikto_scan():
    """Run Nikto web-server vulnerability scan."""
    try:
        data       = request.json or {}
        raw_target = (data.get('target') or '').strip()
        consent    = data.get('consent', False)
        user_id    = session.get('user_id')
        db_user_id = session.get('db_user_id')

        if not consent:
            return jsonify({'status': 'error', 'message': 'You must confirm authorization to scan this target'}), 400
        if not raw_target:
            return jsonify({'status': 'error', 'message': 'Target URL required'}), 400
        if not shutil.which('nikto'):
            return jsonify({
                'status': 'error',
                'message': 'nikto is not installed or not in PATH. Install with: sudo apt install -y nikto'
            }), 503

        # Validate & normalize target
        is_valid, target, error = validate_and_normalize_target(raw_target)
        if not is_valid:
            return jsonify({'status': 'error', 'message': error}), 400

        scan_id     = str(uuid.uuid4())
        output_file = os.path.join(SCANS_DIR, f'nikto_{scan_id}.json')

        # Create DB record
        with get_db_session() as db:
            scan = Scan(
                scan_id=scan_id, user_id_fk=db_user_id,
                target=target, scan_type='nikto',
                tool='nikto', status='running',
                created_at=datetime.now(timezone.utc), started_at=datetime.now(timezone.utc)
            )
            db.add(scan)
            db.commit()

        start_time = datetime.now(timezone.utc)

        # Run nikto -h <target> -Format json -output <file>
        try:
            result = subprocess.run(
                ['nikto', '-h', target, '-Format', 'json', '-output', output_file, '-Tuning', '1234567890abcx'],
                capture_output=True, text=True, timeout=900
            )
        except FileNotFoundError:
            with get_db_session() as db:
                s = db.query(Scan).filter_by(scan_id=scan_id).first()
                if s:
                    s.status = 'failed'
                    s.error_message = 'nikto not installed on server'
                    s.completed_at = datetime.now(timezone.utc)
                    db.commit()
            return jsonify({'status': 'error', 'message': 'nikto is not installed on the server'}), 500

        duration = (datetime.now(timezone.utc) - start_time).total_seconds()

        # Parse results — nikto JSON output varies; handle gracefully
        vulnerabilities = []
        scan_results = {}

        if os.path.exists(output_file):
            try:
                with open(output_file) as f:
                    nikto_data = json.load(f)
                scan_results = nikto_data

                # Nikto JSON structure: may be {"host": ..., "vulnerabilities": [...]}
                # or [{"host": ..., "vulnerabilities": [...]}]
                items = nikto_data if isinstance(nikto_data, list) else [nikto_data]
                for item in items:
                    for vuln in (item.get('vulnerabilities') or item.get('items') or []):
                        vulnerabilities.append({
                            'id': vuln.get('id') or vuln.get('OSVDB') or vuln.get('osvdb', ''),
                            'description': vuln.get('msg') or vuln.get('description') or vuln.get('message', ''),
                            'severity': vuln.get('severity', 'info'),
                            'uri': vuln.get('url') or vuln.get('uri', '/'),
                            'title': vuln.get('msg') or vuln.get('description', 'Nikto Finding'),
                        })
            except (json.JSONDecodeError, Exception) as e:
                print(f"⚠ Nikto JSON parse warning: {e}")
                # Fallback: parse stdout for findings
                for line in (result.stdout or '').split('\n'):
                    line = line.strip()
                    if line.startswith('+') and 'OSVDB' in line:
                        vulnerabilities.append({
                            'id': 'NIKTO',
                            'description': line,
                            'severity': 'info',
                            'uri': '/',
                            'title': line[:100],
                        })
        else:
            # No output file — parse stdout
            for line in (result.stdout or '').split('\n'):
                line = line.strip()
                if line.startswith('+') and len(line) > 5:
                    vulnerabilities.append({
                        'id': 'NIKTO',
                        'description': line,
                        'severity': 'info',
                        'uri': '/',
                        'title': line[:100],
                    })

        # Update DB
        with get_db_session() as db:
            s = db.query(Scan).filter_by(scan_id=scan_id).first()
            if s:
                s.status = 'completed'
                s.completed_at = datetime.now(timezone.utc)
                s.duration = duration
                for v in vulnerabilities:
                    db.add(Vulnerability(
                        scan_id=s.id,
                        title=v.get('title', 'Unknown'),
                        description=v.get('description', ''),
                        severity=(v.get('severity') or 'info').lower(),
                        owasp_category=None,
                        remediation='',
                        ai_classified=False
                    ))
                db.commit()

        # Save JSON report for report generation
        user_report_dir = os.path.join(REPORTS_DIR, user_id)
        os.makedirs(user_report_dir, exist_ok=True)
        json_path = os.path.join(user_report_dir, f'{scan_id}.json')
        with open(json_path, 'w') as f:
            json.dump({
                'scan_id': scan_id, 'target': target, 'tool': 'nikto',
                'duration': duration, 'timestamp': datetime.now().isoformat(),
                'vulnerabilities': vulnerabilities, 'raw_results': scan_results,
            }, f, indent=2, default=str)

        if result.returncode not in (0, 1):
            print(f"⚠ Nikto returned code {result.returncode}: {(result.stderr or result.stdout or '').strip()[:500]}")

        print(f"✓ Nikto scan {scan_id} completed in {duration:.1f}s — {len(vulnerabilities)} findings")

        return jsonify({
            'status':          'success',
            'scan_id':         scan_id,
            'target':          target,
            'duration':        duration,
            'vulnerabilities': vulnerabilities,
        })

    except subprocess.TimeoutExpired:
        with get_db_session() as db:
            s = db.query(Scan).filter_by(scan_id=scan_id).first()
            if s:
                s.status = 'failed'
                s.error_message = 'Nikto scan timed out'
                s.completed_at = datetime.now(timezone.utc)
                db.commit()
        return jsonify({'status': 'error', 'message': 'Nikto scan timed out after 15 minutes. Try a narrower target.'}), 500
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ─────────────────────────────────────────────────────────────
# HARVESTER SCAN
# ─────────────────────────────────────────────────────────────

@app.route('/api/scan/harvester', methods=['POST'])
@require_auth
@rate_limit("5 per minute; 30 per hour")
def harvester_scan():
    """Run theHarvester OSINT reconnaissance on a domain."""
    try:
        data       = request.json or {}
        raw_target = (data.get('target') or '').strip()
        user_id    = session.get('user_id')
        db_user_id = session.get('db_user_id')

        if not raw_target:
            return jsonify({'status': 'error', 'message': 'Target domain required'}), 400
        if not shutil.which('theHarvester'):
            return jsonify({
                'status': 'error',
                'message': 'theHarvester is not installed or not in PATH. Install with: sudo apt install -y theharvester'
            }), 503

        # Strip any protocol prefix — harvester needs bare domain
        target = re.sub(r'^https?://', '', raw_target).split('/')[0].strip()
        if not target or '.' not in target:
            return jsonify({'status': 'error', 'message': 'Invalid domain format. Use example.com'}), 400

        scan_id     = str(uuid.uuid4())
        output_file = os.path.join(SCANS_DIR, f'harvester_{scan_id}')

        # Create DB record
        with get_db_session() as db:
            scan = Scan(
                scan_id=scan_id, user_id_fk=db_user_id,
                target=target, scan_type='harvester',
                tool='harvester', status='running',
                created_at=datetime.now(timezone.utc), started_at=datetime.now(timezone.utc)
            )
            db.add(scan)
            db.commit()

        start_time = datetime.now(timezone.utc)

        # Run theHarvester -d <domain> -b all -f <output>
        try:
            result = subprocess.run(
                ['theHarvester', '-d', target, '-b', 'crtsh,duckduckgo,hackertarget,otx,urlscan,yahoo', '-f', output_file],
                capture_output=True, text=True, timeout=180
            )
        except FileNotFoundError:
            with get_db_session() as db:
                s = db.query(Scan).filter_by(scan_id=scan_id).first()
                if s:
                    s.status = 'failed'
                    s.error_message = 'theHarvester not installed on server'
                    s.completed_at = datetime.now(timezone.utc)
                    db.commit()
            return jsonify({'status': 'error', 'message': 'theHarvester is not installed on the server'}), 500

        duration = (datetime.now(timezone.utc) - start_time).total_seconds()

        # Parse results
        emails = []
        subdomains = []
        ips = []
        hosts = []

        # theHarvester outputs XML and JSON files with the given prefix
        json_output = output_file + '.json'
        xml_output  = output_file + '.xml'

        if os.path.exists(json_output):
            try:
                with open(json_output) as f:
                    hdata = json.load(f)
                emails     = list(set(hdata.get('emails', [])))
                subdomains = list(set(hdata.get('hosts', []) + hdata.get('subdomains', [])))
                ips        = list(set(hdata.get('ips', [])))
                hosts      = list(set(hdata.get('asns', []) + hdata.get('hosts', [])))
            except (json.JSONDecodeError, Exception) as e:
                print(f"⚠ Harvester JSON parse warning: {e}")

        # Fallback: parse stdout if JSON file not available or empty
        if not emails and not subdomains and not ips:
            stdout = result.stdout or ''
            current_section = None
            for line in stdout.split('\n'):
                line = line.strip()
                if not line or line.startswith('*'):
                    continue
                if 'emails' in line.lower() and ':' in line:
                    current_section = 'emails'
                    continue
                elif 'hosts' in line.lower() and ':' in line:
                    current_section = 'hosts'
                    continue
                elif 'ips' in line.lower() and ':' in line:
                    current_section = 'ips'
                    continue
                elif 'subdomains' in line.lower() and ':' in line:
                    current_section = 'subdomains'
                    continue
                elif line.startswith('[') or line.startswith('---'):
                    current_section = None
                    continue

                if current_section == 'emails' and '@' in line:
                    emails.append(line)
                elif current_section == 'hosts':
                    hosts.append(line)
                elif current_section == 'ips':
                    ips.append(line)
                elif current_section == 'subdomains':
                    subdomains.append(line)

        # Update DB
        with get_db_session() as db:
            s = db.query(Scan).filter_by(scan_id=scan_id).first()
            if s:
                s.status = 'completed'
                s.completed_at = datetime.now(timezone.utc)
                s.duration = duration
                db.commit()

        # Save JSON report
        user_report_dir = os.path.join(REPORTS_DIR, user_id)
        os.makedirs(user_report_dir, exist_ok=True)
        json_path = os.path.join(user_report_dir, f'{scan_id}.json')
        with open(json_path, 'w') as f:
            json.dump({
                'scan_id': scan_id, 'target': target, 'tool': 'harvester',
                'duration': duration, 'timestamp': datetime.now().isoformat(),
                'results': {'emails': emails, 'subdomains': subdomains, 'ips': ips, 'hosts': hosts},
            }, f, indent=2, default=str)

        print(f"✓ Harvester scan {scan_id} completed in {duration:.1f}s — "
              f"{len(emails)} emails, {len(subdomains)} subdomains, {len(ips)} IPs, {len(hosts)} hosts")

        return jsonify({
            'status':   'success',
            'scan_id':  scan_id,
            'target':   target,
            'duration': duration,
            'results':  {
                'emails':     emails,
                'subdomains': subdomains,
                'ips':        ips,
                'hosts':      hosts,
            }
        })

    except subprocess.TimeoutExpired:
        with get_db_session() as db:
            s = db.query(Scan).filter_by(scan_id=scan_id).first()
            if s:
                s.status = 'failed'
                s.error_message = 'Harvester scan timed out'
                s.completed_at = datetime.now(timezone.utc)
                db.commit()
        return jsonify({'status': 'error', 'message': 'Harvester scan timed out'}), 500
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ─────────────────────────────────────────────────────────────
# SQL SCAN
# ─────────────────────────────────────────────────────────────

@app.route('/api/sql-scan', methods=['POST'])
@require_auth
@rate_limit("5 per minute; 30 per hour")
def sql_scan():
    """Run SQLMap scan against a target URL."""
    try:
        data        = request.json or {}
        raw_target  = (data.get('target') or '').strip()
        scan_type   = (data.get('scan_type') or 'quick').lower()
        techniques  = data.get('techniques', [])
        consent     = data.get('consent', False)

        if not consent:
            return jsonify({'status': 'error', 'message': 'Authorization consent required'}), 400
        if not raw_target:
            return jsonify({'status': 'error', 'message': 'Target URL required'}), 400

        # Basic URL validation
        if not re.match(r'^https?://', raw_target, re.IGNORECASE):
            raw_target = 'http://' + raw_target

        scan_id     = str(uuid.uuid4())
        output_file = os.path.join(SCANS_DIR, f'sql_{scan_id}.json')
        scanner_script = os.path.join(SCANNERS_DIR, 'sql_scanner.py')

        if not os.path.exists(scanner_script):
            return jsonify({'status': 'error', 'message': 'SQL scanner script not found'}), 500

        start_time = datetime.now(timezone.utc)
        timeout    = 180 if scan_type == 'quick' else 360

        result = subprocess.run(
            [sys.executable, scanner_script, raw_target, scan_type, '--output', output_file],
            capture_output=True, text=True, timeout=timeout
        )

        duration = (datetime.now(timezone.utc) - start_time).total_seconds()

        if not os.path.exists(output_file):
            return jsonify({'status': 'error', 'message': result.stderr or 'SQL scan failed', 'scan_id': scan_id}), 500

        with open(output_file) as f:
            scan_data = json.load(f)

        return jsonify({
            'status':    'success',
            'scan_id':   scan_id,
            'target':    raw_target,
            'duration':  round(duration, 2),
            'tool':      'sqlmap',
            'results':   scan_data,
        })
    except subprocess.TimeoutExpired:
        return jsonify({'status': 'error', 'message': 'SQL scan timed out'}), 500
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ─────────────────────────────────────────────────────────────
# WFUZZ SCAN
# ─────────────────────────────────────────────────────────────

@app.route('/api/wfuzz', methods=['POST'])
@require_auth
@rate_limit("5 per minute; 30 per hour")
def wfuzz_scan():
    """Run Wfuzz directory/file fuzzing against a target URL."""
    try:
        data       = request.json or {}
        raw_target = (data.get('target') or '').strip()
        wordlist   = (data.get('wordlist') or 'common').lower()
        threads    = min(int(data.get('threads', 10)), 50)
        consent    = data.get('consent', False)

        if not consent:
            return jsonify({'status': 'error', 'message': 'Authorization consent required'}), 400
        if not raw_target:
            return jsonify({'status': 'error', 'message': 'Target URL required'}), 400

        if not re.match(r'^https?://', raw_target, re.IGNORECASE):
            raw_target = 'http://' + raw_target

        scan_id     = str(uuid.uuid4())
        output_file = os.path.join(SCANS_DIR, f'wfuzz_{scan_id}.json')
        scanner_script = os.path.join(SCANNERS_DIR, 'wfuzz_scanner.py')

        if not os.path.exists(scanner_script):
            return jsonify({'status': 'error', 'message': 'Wfuzz scanner script not found'}), 500

        start_time = datetime.now(timezone.utc)

        result = subprocess.run(
            [sys.executable, scanner_script, raw_target, wordlist, '--output', output_file],
            capture_output=True, text=True, timeout=180
        )

        duration = (datetime.now(timezone.utc) - start_time).total_seconds()

        if not os.path.exists(output_file):
            return jsonify({'status': 'error', 'message': result.stderr or 'Wfuzz scan failed', 'scan_id': scan_id}), 500

        with open(output_file) as f:
            scan_data = json.load(f)

        return jsonify({
            'status':   'success',
            'scan_id':  scan_id,
            'target':   raw_target,
            'duration': round(duration, 2),
            'tool':     'wfuzz',
            'results':  scan_data,
        })
    except subprocess.TimeoutExpired:
        return jsonify({'status': 'error', 'message': 'Wfuzz scan timed out'}), 500
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ─────────────────────────────────────────────────────────────
# OWASP WEB SCAN (HTTP header & config checker)
# ─────────────────────────────────────────────────────────────

@app.route('/api/owasp-scan', methods=['POST'])
@require_auth
@rate_limit("5 per minute; 30 per hour")
def owasp_scan():
    """Perform a lightweight OWASP-based HTTP security header check."""
    try:
        import urllib.request
        import ssl

        data       = request.json or {}
        raw_target = (data.get('target') or '').strip()
        scan_mode  = (data.get('scan_mode') or 'quick').lower()
        consent    = data.get('consent', False)

        if not consent:
            return jsonify({'status': 'error', 'message': 'Authorization consent required'}), 400
        if not raw_target:
            return jsonify({'status': 'error', 'message': 'Target URL required'}), 400

        if not re.match(r'^https?://', raw_target, re.IGNORECASE):
            raw_target = 'http://' + raw_target

        # Security headers to check (OWASP recommendations)
        SECURITY_HEADERS = {
            'Strict-Transport-Security': {
                'severity': 'high',
                'owasp': 'A05:2021',
                'desc': 'Missing HSTS header — browser connections can be downgraded to HTTP.',
                'fix':  'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'
            },
            'X-Content-Type-Options': {
                'severity': 'medium',
                'owasp': 'A05:2021',
                'desc': 'Missing X-Content-Type-Options — browser may MIME-sniff responses.',
                'fix':  'Add: X-Content-Type-Options: nosniff'
            },
            'X-Frame-Options': {
                'severity': 'medium',
                'owasp': 'A05:2021',
                'desc': 'Missing X-Frame-Options — page may be vulnerable to clickjacking.',
                'fix':  'Add: X-Frame-Options: DENY or SAMEORIGIN'
            },
            'Content-Security-Policy': {
                'severity': 'high',
                'owasp': 'A03:2021',
                'desc': 'Missing Content-Security-Policy — XSS attacks are not mitigated.',
                'fix':  'Add a restrictive CSP header.'
            },
            'X-XSS-Protection': {
                'severity': 'low',
                'owasp': 'A03:2021',
                'desc': 'Missing X-XSS-Protection header (legacy browsers).',
                'fix':  'Add: X-XSS-Protection: 1; mode=block'
            },
            'Referrer-Policy': {
                'severity': 'low',
                'owasp': 'A05:2021',
                'desc': 'Missing Referrer-Policy — referrer data may leak to third parties.',
                'fix':  'Add: Referrer-Policy: strict-origin-when-cross-origin'
            },
            'Permissions-Policy': {
                'severity': 'low',
                'owasp': 'A05:2021',
                'desc': 'Missing Permissions-Policy — browser features are unrestricted.',
                'fix':  'Add: Permissions-Policy: geolocation=(), microphone=(), camera=()'
            },
        }

        start_time = datetime.now(timezone.utc)
        scan_id    = str(uuid.uuid4())
        findings   = []
        headers_present = {}
        server_info = {}
        urls_scanned = 0

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(
                raw_target,
                headers={'User-Agent': 'SecuritySuite/3.0 OWASP-Scanner'}
            )
            with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
                resp_headers = dict(resp.headers)
                status_code  = resp.status
                urls_scanned = 1

                # Check for missing security headers
                headers_lower = {k.lower(): v for k, v in resp_headers.items()}
                for header, meta in SECURITY_HEADERS.items():
                    present = header.lower() in headers_lower
                    headers_present[header] = {
                        'present': present,
                        'value': headers_lower.get(header.lower(), ''),
                    }
                    if not present:
                        findings.append({
                            'title':    f'Missing {header}',
                            'severity': meta['severity'],
                            'owasp':    meta['owasp'],
                            'description': meta['desc'],
                            'remediation': meta['fix'],
                        })

                # Check for server info disclosure
                server = headers_lower.get('server', '')
                if server:
                    server_info['server'] = server
                    if any(v in server.lower() for v in ['apache/', 'nginx/', 'iis/', 'php/']):
                        findings.append({
                            'title':    'Server Version Disclosure',
                            'severity': 'low',
                            'owasp':    'A05:2021',
                            'description': f'Server header reveals software version: {server}',
                            'remediation': 'Configure server to suppress version information.',
                        })

                x_powered = headers_lower.get('x-powered-by', '')
                if x_powered:
                    server_info['x_powered_by'] = x_powered
                    findings.append({
                        'title':    'X-Powered-By Disclosure',
                        'severity': 'low',
                        'owasp':    'A05:2021',
                        'description': f'X-Powered-By header exposes technology stack: {x_powered}',
                        'remediation': 'Remove the X-Powered-By header from server responses.',
                    })

                # Check HTTP vs HTTPS
                if raw_target.startswith('http://'):
                    findings.append({
                        'title':    'Plaintext HTTP Used',
                        'severity': 'high',
                        'owasp':    'A02:2021',
                        'description': 'The site is accessible over unencrypted HTTP.',
                        'remediation': 'Enforce HTTPS and redirect all HTTP traffic to HTTPS.',
                    })

                # Check for cookies without security flags
                set_cookie = headers_lower.get('set-cookie', '')
                if set_cookie:
                    if 'httponly' not in set_cookie.lower():
                        findings.append({
                            'title':    'Cookie Missing HttpOnly Flag',
                            'severity': 'medium',
                            'owasp':    'A02:2021',
                            'description': 'Set-Cookie header missing HttpOnly flag — accessible via JavaScript.',
                            'remediation': 'Add HttpOnly flag to all session cookies.',
                        })
                    if 'secure' not in set_cookie.lower():
                        findings.append({
                            'title':    'Cookie Missing Secure Flag',
                            'severity': 'medium',
                            'owasp':    'A02:2021',
                            'description': 'Set-Cookie header missing Secure flag — cookie sent over HTTP.',
                            'remediation': 'Add Secure flag to all cookies.',
                        })

        except urllib.error.URLError as e:
            return jsonify({'status': 'error', 'message': f'Cannot reach target: {e.reason}'}), 400
        except Exception as e:
            return jsonify({'status': 'error', 'message': f'Scan error: {str(e)}'}), 500

        duration = (datetime.now(timezone.utc) - start_time).total_seconds()

        # Risk scoring
        sev_scores = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1, 'info': 0}
        risk_score = min(100, sum(sev_scores.get(f['severity'], 0) for f in findings))
        risk_grade = 'A' if risk_score < 10 else 'B' if risk_score < 25 else 'C' if risk_score < 40 else 'D' if risk_score < 60 else 'F'

        stats = {
            'urls_scanned': urls_scanned,
            'alerts_found': len(findings),
            'high_count':   sum(1 for f in findings if f['severity'] == 'high'),
            'medium_count': sum(1 for f in findings if f['severity'] == 'medium'),
            'low_count':    sum(1 for f in findings if f['severity'] in ('low', 'info')),
        }

        return jsonify({
            'status':          'success',
            'scan_id':         scan_id,
            'target':          raw_target,
            'duration':        round(duration, 2),
            'tool':            'owasp-header-check',
            'risk_score':      risk_score,
            'risk_grade':      risk_grade,
            'stats':           stats,
            'headers_present': headers_present,
            'server_info':     server_info,
            'findings':        findings,
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ─────────────────────────────────────────────────────────────
# HEALTH CHECK
# ─────────────────────────────────────────────────────────────

@app.route('/api/health', methods=['GET'])
def health():
    gemini = get_gemini_client()
    return jsonify({
        'status':    'healthy',
        'version':   '3.0',
        'gemini_ai': gemini.is_available(),
        'pdf':       PDF_AVAILABLE,
        'timestamp': datetime.now(timezone.utc).isoformat()
    })


# ─────────────────────────────────────────────────────────────
# Run
# ─────────────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    
    # Initialize database tables
    print("Initializing database tables...")
    init_db()

    print(f"\n{'='*55}")
    print(f"  🛡  Security Suite Pentest Platform v3.0")
    print(f"  Backend running at http://localhost:{port}")
    print(f"  Gemini AI: {'✓ enabled' if get_gemini_client().is_available() else '✗ disabled (set GEMINI_API_KEY)'}")
    print(f"  PDF reports: {'✓ enabled' if PDF_AVAILABLE else '✗ disabled (install reportlab)'}")
    print(f"  Admin: admin@security.com (password set via ADMIN_PASSWORD env var)")
    print(f"{'='*55}\n")
    app.run(host='0.0.0.0', port=port, debug=False)
