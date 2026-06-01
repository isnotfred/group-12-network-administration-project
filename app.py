import os
import json
import threading
import time
import secrets
import hashlib
import hmac
from datetime import datetime, timezone, timedelta
from functools import wraps

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from flask import (Flask, Response, redirect, render_template, request,
                   session, url_for, jsonify, abort)
from flask_sock import Sock
from dotenv import load_dotenv
import simple_websocket
import psycopg2
import psycopg2.extras
import requests as http_requests

load_dotenv()

app  = Flask(__name__)
sock = Sock(app)

app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-production")

# ── Session / cookie hardening ────────────────────────────────────────────────
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
)

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
INGEST_KEY     = os.environ.get("INGEST_KEY", "")
DATABASE_URL   = os.environ.get("DATABASE_URL", "")

# ── Email / alert config ───────────────────────────────────────────────────────
ALERT_EMAIL_TO = os.environ.get("ALERT_EMAIL_TO")
SMTP_HOST      = os.environ.get("SMTP_HOST")
SMTP_PORT      = int(os.environ.get("SMTP_PORT"))
SMTP_USER      = os.environ.get("SMTP_USER")        # sender Gmail address
SMTP_PASSWORD  = os.environ.get("SMTP_PASSWORD")    # Gmail App Password

# Philippine Standard Time (UTC+8)
PHT = timezone(timedelta(hours=8))

# ── Thread-safe frame buffer ───────────────────────────────────────────────────
_frame_lock      = threading.Lock()
_latest_frame: bytes | None = None
_last_push_time: float      = 0.0

# ── Viewer registry ────────────────────────────────────────────────────────────
_viewers_lock = threading.Lock()
_viewers: set = set()

# ── Brute-force tracker (in-memory, keyed by IP) ──────────────────────────────
_bf_lock    = threading.Lock()
_bf_attempts: dict[str, dict] = {}  # ip -> {count, blocked_until}
BF_MAX_ATTEMPTS = 5
BF_BLOCK_SECONDS = 900  # 15 minutes


def _pht_now() -> datetime:
    return datetime.now(PHT)


def _pht_iso() -> str:
    return _pht_now().isoformat()


# ── DB helpers ─────────────────────────────────────────────────────────────────

def _get_db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set")
    return psycopg2.connect(DATABASE_URL, connect_timeout=5)


def _ensure_schema():
    conn = _get_db()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS devices (
                        ip          TEXT PRIMARY KEY,
                        mac         TEXT,
                        hostname    TEXT,
                        vendor      TEXT,
                        open_ports  JSONB,
                        last_seen   TIMESTAMPTZ DEFAULT NOW(),
                        updated_at  TIMESTAMPTZ DEFAULT NOW()
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS logs (
                        id          BIGSERIAL PRIMARY KEY,
                        type        TEXT NOT NULL,
                        message     TEXT NOT NULL,
                        ip          TEXT,
                        username    TEXT,
                        success     BOOLEAN,
                        meta        JSONB,
                        created_at  TIMESTAMPTZ DEFAULT NOW()
                    )
                """)
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS logs_created_at_idx
                        ON logs (created_at DESC)
                """)
                # ── Users table ───────────────────────────────────────────────
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id          BIGSERIAL PRIMARY KEY,
                        username    TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        approved    BOOLEAN DEFAULT FALSE,
                        is_admin    BOOLEAN DEFAULT FALSE,
                        created_at  TIMESTAMPTZ DEFAULT NOW()
                    )
                """)
                # ── IP blocks table ───────────────────────────────────────────
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS ip_blocks (
                        ip              TEXT PRIMARY KEY,
                        attempts        INT DEFAULT 0,
                        blocked_until   TIMESTAMPTZ,
                        updated_at      TIMESTAMPTZ DEFAULT NOW()
                    )
                """)
        print("[DB] Schema ready")
    except Exception as exc:
        print(f"[DB] Schema error: {exc}")
    finally:
        conn.close()


# ── Log writer ─────────────────────────────────────────────────────────────────

def write_log(type_: str, message: str, ip: str = None, username: str = None,
              success: bool = None, meta: dict = None):
    """Insert a log row. Fails silently so it never breaks a request."""
    try:
        conn = _get_db()
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO logs (type, message, ip, username, success, meta, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (type_, message, ip, username, success,
                    json.dumps(meta) if meta else None,
                    _pht_now()))
        conn.close()
    except Exception as exc:
        print(f"[LOG] Failed to write log: {exc}")


# ── IP geolocation ─────────────────────────────────────────────────────────────

def _geolocate(ip: str) -> dict:
    """Return {city, region, country} for an IP. Returns {} on failure."""
    try:
        if ip in ("127.0.0.1", "::1", "localhost"):
            return {"city": "Localhost", "region": "", "country": ""}
        resp = http_requests.get(
            f"https://ipapi.co/{ip}/json/",
            timeout=3,
            headers={"User-Agent": "NetworkAdmin/1.0"}
        )
        if resp.status_code == 200:
            data = resp.json()
            return {
                "city":      data.get("city", ""),
                "region":    data.get("region", ""),
                "country":   data.get("country_name", ""),
                "latitude":  data.get("latitude", "N/A"),
                "longitude": data.get("longitude", "N/A"),
            }
    except Exception:
        pass
    return {}


# ── Block alert email ─────────────────────────────────────────────────────────

def _send_block_alert(ip: str, geo: dict, device: dict | None):
    """Send an email alert when an IP is blocked. Fails silently."""
    if not SMTP_USER or not SMTP_PASSWORD:
        print("[EMAIL] SMTP credentials not configured; skipping alert.")
        return

    try:
        now_str   = _pht_now().strftime("%Y-%m-%d %H:%M:%S PHT")
        city      = geo.get("city", "")
        region    = geo.get("region", "")
        country   = geo.get("country", "")
        lat       = geo.get("latitude", "N/A")
        lon       = geo.get("longitude", "N/A")

        location_parts = [p for p in [city, region, country] if p]
        location_str   = ", ".join(location_parts) if location_parts else "Unknown"
        coords_str     = (f"{lat}, {lon}"
                          if lat != "N/A" and lon != "N/A"
                          else "Unavailable")

        hostname   = device.get("hostname",   "N/A") if device else "N/A"
        mac        = device.get("mac",        "N/A") if device else "N/A"
        vendor     = device.get("vendor",     "N/A") if device else "N/A"
        open_ports = device.get("open_ports", [])   if device else []
        ports_str  = (", ".join(str(p) for p in open_ports)
                      if open_ports else "None detected")

        subject = f"[Network Admin] IP Blocked: {ip}"

        html_body = f"""
<html><body style="font-family:Arial,sans-serif;color:#222;max-width:600px;margin:auto">
  <h2 style="background:#c0392b;color:#fff;padding:12px 16px;border-radius:4px;margin:0">
    ⚠️ IP Address Blocked
  </h2>
  <p style="margin:16px 0 4px">
    An IP was automatically blocked after <strong>{BF_MAX_ATTEMPTS}</strong> consecutive
    failed login attempts.
  </p>
  <table style="width:100%;border-collapse:collapse;margin-top:12px">
    <tr style="background:#f5f5f5">
      <th style="text-align:left;padding:8px 12px;border:1px solid #ddd;width:40%">Field</th>
      <th style="text-align:left;padding:8px 12px;border:1px solid #ddd">Value</th>
    </tr>
    <tr>
      <td style="padding:8px 12px;border:1px solid #ddd"><strong>Blocked IP</strong></td>
      <td style="padding:8px 12px;border:1px solid #ddd;font-family:monospace">{ip}</td>
    </tr>
    <tr style="background:#fafafa">
      <td style="padding:8px 12px;border:1px solid #ddd"><strong>Blocked At</strong></td>
      <td style="padding:8px 12px;border:1px solid #ddd">{now_str}</td>
    </tr>
    <tr>
      <td style="padding:8px 12px;border:1px solid #ddd"><strong>Block Duration</strong></td>
      <td style="padding:8px 12px;border:1px solid #ddd">{BF_BLOCK_SECONDS // 60} minutes</td>
    </tr>
    <tr style="background:#fafafa">
      <td style="padding:8px 12px;border:1px solid #ddd"><strong>Location</strong></td>
      <td style="padding:8px 12px;border:1px solid #ddd">{location_str}</td>
    </tr>
    <tr>
      <td style="padding:8px 12px;border:1px solid #ddd"><strong>Coordinates</strong></td>
      <td style="padding:8px 12px;border:1px solid #ddd">{coords_str}</td>
    </tr>
    <tr style="background:#fafafa">
      <td style="padding:8px 12px;border:1px solid #ddd"><strong>Hostname</strong></td>
      <td style="padding:8px 12px;border:1px solid #ddd">{hostname}</td>
    </tr>
    <tr>
      <td style="padding:8px 12px;border:1px solid #ddd"><strong>MAC Address</strong></td>
      <td style="padding:8px 12px;border:1px solid #ddd;font-family:monospace">{mac}</td>
    </tr>
    <tr style="background:#fafafa">
      <td style="padding:8px 12px;border:1px solid #ddd"><strong>Vendor</strong></td>
      <td style="padding:8px 12px;border:1px solid #ddd">{vendor}</td>
    </tr>
    <tr>
      <td style="padding:8px 12px;border:1px solid #ddd"><strong>Open Ports</strong></td>
      <td style="padding:8px 12px;border:1px solid #ddd">{ports_str}</td>
    </tr>
  </table>
  <p style="margin-top:20px;font-size:12px;color:#888">
    Sent by Network Administration Dashboard &bull; {now_str}
  </p>
</body></html>
"""

        plain_body = (
            f"IP BLOCKED ALERT\n"
            f"================\n"
            f"Blocked IP      : {ip}\n"
            f"Blocked At      : {now_str}\n"
            f"Block Duration  : {BF_BLOCK_SECONDS // 60} minutes\n"
            f"Location        : {location_str}\n"
            f"Coordinates     : {coords_str}\n"
            f"Hostname        : {hostname}\n"
            f"MAC Address     : {mac}\n"
            f"Vendor          : {vendor}\n"
            f"Open Ports      : {ports_str}\n"
        )

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = SMTP_USER
        msg["To"]      = ALERT_EMAIL_TO
        msg.attach(MIMEText(plain_body, "plain"))
        msg.attach(MIMEText(html_body,  "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, ALERT_EMAIL_TO, msg.as_string())

        print(f"[EMAIL] Block alert sent for {ip} → {ALERT_EMAIL_TO}")

    except Exception as exc:
        print(f"[EMAIL] Failed to send block alert: {exc}")


# ── Brute-force helpers ────────────────────────────────────────────────────────

def _is_blocked(ip: str) -> bool:
    """Check both in-memory and DB for active block."""
    now = time.time()
    with _bf_lock:
        state = _bf_attempts.get(ip)
        if state and state.get("blocked_until", 0) > now:
            return True
    # also check DB as authoritative source
    try:
        conn = _get_db()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT blocked_until FROM ip_blocks
                WHERE ip = %s AND blocked_until > NOW()
            """, (ip,))
            row = cur.fetchone()
        conn.close()
        return row is not None
    except Exception:
        return False


def _record_failed_attempt(ip: str):
    """Increment failure counter; block after BF_MAX_ATTEMPTS."""
    now = time.time()
    blocked_until_ts = None

    with _bf_lock:
        state = _bf_attempts.setdefault(ip, {"count": 0, "blocked_until": 0})
        state["count"] += 1
        if state["count"] >= BF_MAX_ATTEMPTS:
            state["blocked_until"] = now + BF_BLOCK_SECONDS
            blocked_until_ts = state["blocked_until"]

    # persist to DB
    try:
        conn = _get_db()
        blocked_dt = (datetime.utcfromtimestamp(blocked_until_ts)
                      .replace(tzinfo=timezone.utc)) if blocked_until_ts else None
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO ip_blocks (ip, attempts, blocked_until, updated_at)
                    VALUES (%s, 1, %s, NOW())
                    ON CONFLICT (ip) DO UPDATE SET
                        attempts      = ip_blocks.attempts + 1,
                        blocked_until = COALESCE(%s, ip_blocks.blocked_until),
                        updated_at    = NOW()
                """, (ip, blocked_dt, blocked_dt))
        conn.close()
    except Exception as exc:
        print(f"[BF] DB error: {exc}")

    if blocked_until_ts:
        write_log(
            type_="security",
            message=f"IP {ip} blocked after {BF_MAX_ATTEMPTS} failed login attempts",
            ip=ip,
            success=False,
            meta={"reason": "brute_force", "blocked_for_seconds": BF_BLOCK_SECONDS}
        )
        # Look up geo + any known device record, then email the alert
        def _alert_async(blocked_ip: str):
            geo    = _geolocate(blocked_ip)
            device = _get_device_by_ip(blocked_ip)
            _send_block_alert(blocked_ip, geo, device)
        threading.Thread(target=_alert_async, args=(ip,), daemon=True).start()


def _reset_attempts(ip: str):
    with _bf_lock:
        _bf_attempts.pop(ip, None)
    try:
        conn = _get_db()
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE ip_blocks SET attempts=0, blocked_until=NULL WHERE ip=%s",
                    (ip,)
                )
        conn.close()
    except Exception:
        pass


# ── CSRF helpers ───────────────────────────────────────────────────────────────

def _get_csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def csrf_protected(f):
    """Decorator: verify CSRF token on POST/PUT/PATCH/DELETE."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            token = (request.form.get("csrf_token")
                     or request.headers.get("X-CSRF-Token", ""))
            expected = session.get("csrf_token", "")
            if not token or not expected or not hmac.compare_digest(token, expected):
                write_log(
                    type_="security",
                    message="CSRF validation failed",
                    ip=request.headers.get("X-Forwarded-For",
                                           request.remote_addr or "").split(",")[0].strip(),
                    username=session.get("user"),
                    success=False,
                )
                abort(403)
        return f(*args, **kwargs)
    return decorated


# ── Password helpers ───────────────────────────────────────────────────────────

def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{h}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        salt, h = stored.split(":", 1)
        return hmac.compare_digest(
            hashlib.sha256((salt + password).encode()).hexdigest(), h
        )
    except Exception:
        return False


# ── User helpers ───────────────────────────────────────────────────────────────

def _get_user(username: str) -> dict | None:
    try:
        conn = _get_db()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM users WHERE username=%s", (username,))
            row = cur.fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception:
        return None


def _create_user(username: str, password: str) -> bool:
    try:
        conn = _get_db()
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO users (username, password_hash, approved, is_admin)
                    VALUES (%s, %s, FALSE, FALSE)
                """, (username, _hash_password(password)))
        conn.close()
        return True
    except psycopg2.errors.UniqueViolation:
        return False
    except Exception as exc:
        print(f"[USER] Create error: {exc}")
        return False


def _get_client_ip() -> str:
    return (request.headers.get("X-Forwarded-For", request.remote_addr or "")
            .split(",")[0].strip())


# ── Device helpers ─────────────────────────────────────────────────────────────

def _upsert_devices(devices: list[dict]):
    conn = _get_db()
    try:
        with conn:
            with conn.cursor() as cur:
                for d in devices:
                    ip = d["ip"]
                    cur.execute("SELECT 1 FROM devices WHERE ip = %s", (ip,))
                    is_new = cur.fetchone() is None

                    cur.execute("""
                        INSERT INTO devices (ip, mac, hostname, vendor, open_ports, last_seen, updated_at)
                        VALUES (%s, %s, %s, %s, %s, to_timestamp(%s), NOW())
                        ON CONFLICT (ip) DO UPDATE SET
                            mac        = EXCLUDED.mac,
                            hostname   = EXCLUDED.hostname,
                            vendor     = EXCLUDED.vendor,
                            open_ports = EXCLUDED.open_ports,
                            last_seen  = EXCLUDED.last_seen,
                            updated_at = NOW()
                    """, (
                        ip,
                        d.get("mac", "N/A"),
                        d.get("hostname", ip),
                        d.get("vendor", "Unknown"),
                        json.dumps(d.get("open_ports", [])),
                        d.get("last_seen", int(time.time())),
                    ))

                    if is_new:
                        ports = d.get("open_ports", [])
                        write_log(
                            type_="new_device",
                            message=f"New device discovered: {d.get('hostname', ip)} ({ip})",
                            ip=ip,
                            meta={
                                "mac": d.get("mac", "N/A"),
                                "hostname": d.get("hostname", ip),
                                "vendor": d.get("vendor", "Unknown"),
                                "open_ports": ports,
                            }
                        )
        print(f"[DB] Upserted {len(devices)} devices")
    finally:
        conn.close()


def _fetch_devices() -> list[dict]:
    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT ip, mac, hostname, vendor, open_ports,
                       EXTRACT(EPOCH FROM last_seen)::bigint AS last_seen_ts,
                       EXTRACT(EPOCH FROM (NOW() - last_seen)) AS seconds_ago
                FROM devices
                ORDER BY inet(ip)
            """)
            return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def _get_device_by_ip(ip: str) -> dict | None:
    """Return the device row for a given IP, or None if not found."""
    try:
        conn = _get_db()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT ip, mac, hostname, vendor, open_ports FROM devices WHERE ip = %s",
                (ip,)
            )
            row = cur.fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception:
        return None


def _fetch_recent_logs(limit: int = 10) -> list[dict]:
    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT id, type, message, ip, username, success, meta,
                       created_at AT TIME ZONE 'Asia/Manila' AS created_at
                FROM logs
                ORDER BY created_at DESC
                LIMIT %s
            """, (limit,))
            rows = []
            for r in cur.fetchall():
                row = dict(r)
                row["created_at"] = r["created_at"].isoformat()
                rows.append(row)
            return rows
    finally:
        conn.close()


# ── Auth helpers ───────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        if not session.get("is_admin"):
            abort(403)
        return f(*args, **kwargs)
    return decorated


def _check_ingest_key() -> bool:
    key = request.headers.get("X-Ingest-Key", "")
    return bool(INGEST_KEY) and key == INGEST_KEY


# ── Template context ───────────────────────────────────────────────────────────

@app.context_processor
def inject_csrf():
    return {"csrf_token": _get_csrf_token()}


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("login"))


# ── Login ──────────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
@csrf_protected
def login():
    error = None
    if request.method == "POST":
        username  = request.form.get("username", "").strip()
        password  = request.form.get("password", "").strip()
        client_ip = _get_client_ip()
        ua        = request.headers.get("User-Agent", "")

        # Brute-force check
        if _is_blocked(client_ip):
            error = "Too many failed attempts. Your IP is temporarily blocked. Please try again later."
            write_log(
                type_="security",
                message=f"Blocked IP {client_ip} attempted login",
                ip=client_ip,
                username=username or None,
                success=False,
                meta={"user_agent": ua, "reason": "ip_blocked"}
            )
            return render_template("login.html", error=error)

        # Check env-var admin first (legacy support)
        admin_match = (
            username and password
            and username == ADMIN_USERNAME
            and password == ADMIN_PASSWORD
        )

        # Check DB users
        db_user = _get_user(username) if not admin_match else None
        db_match = (
            db_user is not None
            and _verify_password(password, db_user["password_hash"])
            and db_user["approved"]
        )

        geo = _geolocate(client_ip)

        if admin_match or db_match:
            _reset_attempts(client_ip)
            session.clear()
            session["logged_in"] = True
            session["user"]     = username
            session["is_admin"] = True if admin_match else bool(db_user.get("is_admin"))
            _get_csrf_token()  # generate fresh token

            
            write_log(
                type_="login",
                message=f"Successful login for '{username}'",
                ip=client_ip,
                username=username,
                success=True,
                meta={
                    "user_agent": ua,
                    "city":    geo.get("city", ""),
                    "region":  geo.get("region", ""),
                    "country": geo.get("country", ""),
                }
            )
            return redirect(url_for("dashboard"))

        # Failed login
        _record_failed_attempt(client_ip)

        # Check if user exists but not approved
        if db_user and not db_user["approved"] and _verify_password(password, db_user["password_hash"]):
            error = "Your account is pending admin approval."
        elif db_user and not _verify_password(password, db_user["password_hash"]):
            error = "Invalid username or password."
        else:
            error = "Invalid username or password."

        write_log(
            type_="login",
            message=f"Failed login attempt for '{username or '(empty)'}'",
            ip=client_ip,
            username=username or None,
            success=False,
            meta={
                "user_agent": ua,
                "city":    geo.get("city", ""),
                "region":  geo.get("region", ""),
                "country": geo.get("country", ""),
            }
        )

    return render_template("login.html", error=error)


# ── Signup ─────────────────────────────────────────────────────────────────────

@app.route("/signup", methods=["GET", "POST"])
@csrf_protected
def signup():
    error = None
    success_msg = None
    if request.method == "POST":
        username  = request.form.get("username", "").strip()
        password  = request.form.get("password", "").strip()
        password2 = request.form.get("password2", "").strip()
        client_ip = _get_client_ip()
        ua        = request.headers.get("User-Agent", "")

        if not username or not password:
            error = "Username and password are required."
        elif len(username) < 3:
            error = "Username must be at least 3 characters."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        elif password != password2:
            error = "Passwords do not match."
        elif username == ADMIN_USERNAME:
            error = "That username is not available."
        else:
            created = _create_user(username, password)
            if created:
                write_log(
                    type_="signup",
                    message=f"New account registered: '{username}' (pending approval)",
                    ip=client_ip,
                    username=username,
                    success=True,
                    meta={"user_agent": ua}
                )
                success_msg = "Account created! An admin will review and approve your account."
            else:
                error = "Username is already taken."

    return render_template("signup.html", error=error, success=success_msg)


# ── Logout (POST only, CSRF protected) ────────────────────────────────────────

@app.route("/logout", methods=["POST"])
@csrf_protected
def logout():
    user      = session.get("user")
    client_ip = _get_client_ip()
    if user:
        write_log(
            type_="logout",
            message=f"User '{user}' logged out",
            ip=client_ip,
            username=user,
            success=True,
        )
    session.clear()
    return redirect(url_for("login"))


# ── Dashboard ──────────────────────────────────────────────────────────────────

def _fetch_alerts() -> dict:
    """Return counts of things that need admin attention."""
    result = {"blocked_ips": 0, "pending_users": 0, "total": 0}
    try:
        conn = _get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM ip_blocks WHERE blocked_until > NOW()")
            result["blocked_ips"] = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM users WHERE approved = FALSE")
            result["pending_users"] = cur.fetchone()[0]
        conn.close()
        result["total"] = result["blocked_ips"] + result["pending_users"]
    except Exception as exc:
        print(f"[ALERTS] Failed to fetch: {exc}")
    return result


@app.route("/dashboard")
@login_required
def dashboard():
    user        = session.get("user", "Admin")
    is_admin    = session.get("is_admin", False)
    agent_live  = (time.time() - _last_push_time) < 10
    devices     = _fetch_devices()      if is_admin else []
    recent_logs = _fetch_recent_logs(limit=8) if is_admin else []
    alerts      = _fetch_alerts()       if is_admin else {"total": 0, "blocked_ips": 0, "pending_users": 0}
    write_log(
        type_="page_view",
        message=f"User '{user}' viewed Dashboard",
        ip=_get_client_ip(),
        username=user,
        success=True,
    )
    return render_template("dashboard.html", user=user, is_admin=is_admin,
                           agent_live=agent_live, devices=devices,
                           recent_logs=recent_logs, alerts=alerts)


# ── Logs page ──────────────────────────────────────────────────────────────────

@app.route("/logs")
@admin_required
def logs_page():
    user     = session.get("user", "Admin")
    is_admin = session.get("is_admin", False)
    write_log(
        type_="page_view",
        message=f"User '{user}' viewed Logs",
        ip=_get_client_ip(),
        username=user,
        success=True,
    )
    return render_template("logs.html", user=user, is_admin=is_admin)


# ── Admin: User Management ─────────────────────────────────────────────────────

@app.route("/admin/users")
@admin_required
def admin_users():
    user     = session.get("user", "Admin")
    is_admin = True
    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT id, username, approved, is_admin,
                       created_at AT TIME ZONE 'Asia/Manila' AS created_at
                FROM users ORDER BY created_at DESC
            """)
            users = [dict(r) for r in cur.fetchall()]
            for u in users:
                u["created_at"] = u["created_at"].isoformat() if u["created_at"] else ""
    finally:
        conn.close()

    write_log(
        type_="page_view",
        message=f"Admin '{user}' viewed User Management",
        ip=_get_client_ip(),
        username=user,
        success=True,
    )
    return render_template("admin_users.html", user=user, is_admin=is_admin, users=users)


@app.route("/admin/users/<int:user_id>/approve", methods=["POST"])
@admin_required
@csrf_protected
def admin_approve_user(user_id):
    admin     = session.get("user")
    client_ip = _get_client_ip()
    action    = request.form.get("action", "approve")  # "approve" or "reject"

    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT username FROM users WHERE id=%s", (user_id,))
            row = cur.fetchone()
            if not row:
                return jsonify({"error": "User not found"}), 404
            target_username = row["username"]

        with conn:
            with conn.cursor() as cur:
                if action == "approve":
                    cur.execute("UPDATE users SET approved=TRUE WHERE id=%s", (user_id,))
                    msg = f"Admin '{admin}' approved user '{target_username}'"
                    log_type = "user_approved"
                else:
                    cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
                    msg = f"Admin '{admin}' rejected/deleted user '{target_username}'"
                    log_type = "user_rejected"
    finally:
        conn.close()

    write_log(type_=log_type, message=msg, ip=client_ip, username=admin, success=True,
              meta={"target_user": target_username, "action": action})
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/toggle_admin", methods=["POST"])
@admin_required
@csrf_protected
def admin_toggle_admin(user_id):
    admin     = session.get("user")
    client_ip = _get_client_ip()
    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT username, is_admin FROM users WHERE id=%s", (user_id,))
            row = cur.fetchone()
            if not row:
                return jsonify({"error": "User not found"}), 404
            new_admin = not row["is_admin"]
            target_username = row["username"]
        with conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET is_admin=%s WHERE id=%s", (new_admin, user_id))
    finally:
        conn.close()

    write_log(
        type_="user_role_change",
        message=f"Admin '{admin}' {'granted' if new_admin else 'revoked'} admin for '{target_username}'",
        ip=client_ip, username=admin, success=True,
        meta={"target_user": target_username, "is_admin": new_admin}
    )
    return redirect(url_for("admin_users"))


# ── Logs API (cursor-based pagination) ────────────────────────────────────────

@app.route("/api/logs")
@admin_required
def api_logs():
    limit       = min(int(request.args.get("limit", 25)), 100)
    before_id   = request.args.get("before_id", type=int)
    after_id    = request.args.get("after_id",  type=int)
    type_filter = request.args.get("type", "").strip() or None

    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            if type_filter:
                cur.execute("SELECT COUNT(*) FROM logs WHERE type = %s", (type_filter,))
            else:
                cur.execute("SELECT COUNT(*) FROM logs")
            total = cur.fetchone()["count"]

            conditions = []
            params: list = []
            if type_filter:
                conditions.append("type = %s")
                params.append(type_filter)
            if before_id:
                conditions.append("id < %s")
                params.append(before_id)
            if after_id:
                conditions.append("id > %s")
                params.append(after_id)

            where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
            order = "DESC" if not after_id else "ASC"

            cur.execute(f"""
                SELECT id, type, message, ip, username, success, meta,
                       created_at AT TIME ZONE 'Asia/Manila' AS created_at
                FROM logs
                {where}
                ORDER BY id {order}
                LIMIT %s
            """, params + [limit + 1])

            rows = cur.fetchall()
            if after_id:
                rows = list(reversed(rows))

            has_more = len(rows) > limit
            if has_more:
                rows = rows[:limit]

            result = []
            for r in rows:
                row = dict(r)
                row["created_at"] = r["created_at"].isoformat()
                result.append(row)

            next_cursor = result[-1]["id"] if has_more else None
            prev_cursor = result[0]["id"] if result else None

            return jsonify({
                "logs":        result,
                "next_cursor": next_cursor,
                "prev_cursor": prev_cursor,
                "total":       total,
                "limit":       limit,
            })
    finally:
        conn.close()


# ── Device ingest ──────────────────────────────────────────────────────────────

@app.route("/ingest/devices", methods=["POST"])
def ingest_devices():
    if not _check_ingest_key():
        return jsonify({"error": "Unauthorized"}), 401
    payload = request.get_json(force=True, silent=True)
    if not payload or "devices" not in payload:
        return jsonify({"error": "Missing 'devices' key"}), 400
    devices = payload["devices"]
    if not isinstance(devices, list):
        return jsonify({"error": "'devices' must be a list"}), 400
    _upsert_devices(devices)
    return jsonify({"ok": True, "count": len(devices)})


# ── Device list API ────────────────────────────────────────────────────────────

@app.route("/api/devices")
@login_required
def api_devices():
    return jsonify(_fetch_devices())


# ── WebSocket: agent ingest ────────────────────────────────────────────────────

@sock.route("/ws/ingest")
def ws_ingest(ws):
    global _latest_frame, _last_push_time, _viewers

    if not INGEST_KEY:
        ws.close(message="INGEST_KEY not configured")
        return

    try:
        key = ws.receive(timeout=5)
    except Exception:
        ws.close(message="Auth timeout")
        return

    if key != INGEST_KEY:
        ws.close(message="Unauthorized")
        return

    ws.send("OK")
    print("[INFO] Agent connected via WebSocket")

    try:
        while True:
            data = ws.receive()
            if data is None:
                break
            if not isinstance(data, bytes):
                continue
            with _frame_lock:
                _latest_frame   = data
                _last_push_time = time.time()
            with _viewers_lock:
                dead = set()
                for viewer_ws in _viewers:
                    try:
                        viewer_ws.send(data)
                    except Exception:
                        dead.add(viewer_ws)
                _viewers -= dead
    except simple_websocket.ConnectionClosed:
        pass

    print("[INFO] Agent disconnected")


# ── WebSocket: browser viewer ──────────────────────────────────────────────────

@sock.route("/ws/view")
def ws_view(ws):
    if not session.get("logged_in"):
        ws.close(message="Unauthorized")
        return

    with _viewers_lock:
        _viewers.add(ws)

    try:
        with _frame_lock:
            if _latest_frame:
                ws.send(_latest_frame)
        while True:
            ws.receive(timeout=30)
    except simple_websocket.ConnectionClosed:
        pass
    finally:
        with _viewers_lock:
            _viewers.discard(ws)


# ── Debug ──────────────────────────────────────────────────────────────────────

@app.route("/ingest/status")
def ingest_status():
    age = round(time.time() - _last_push_time, 1)
    return {"last_push_seconds_ago": age, "frame_available": _latest_frame is not None}


# ── Startup ────────────────────────────────────────────────────────────────────

with app.app_context():
    _ensure_schema()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, threaded=True)