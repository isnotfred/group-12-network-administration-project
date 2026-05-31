import os
import json
import threading
import time
from datetime import datetime

from flask import Flask, Response, redirect, render_template, request, session, url_for, jsonify
from flask_sock import Sock
from functools import wraps
from dotenv import load_dotenv
import simple_websocket

import psycopg2
import psycopg2.extras

load_dotenv()

app  = Flask(__name__)
sock = Sock(app)
app.secret_key = os.environ.get("SECRET_KEY")

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
INGEST_KEY     = os.environ.get("INGEST_KEY", "")
DATABASE_URL   = os.environ.get("DATABASE_URL", "")

# ── Thread-safe frame buffer ───────────────────────────────────────────────────
_frame_lock      = threading.Lock()
_latest_frame: bytes | None = None
_last_push_time: float      = 0.0

# ── Viewer registry ────────────────────────────────────────────────────────────
_viewers_lock = threading.Lock()
_viewers: set = set()


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
                    INSERT INTO logs (type, message, ip, username, success, meta)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (type_, message, ip, username, success,
                      json.dumps(meta) if meta else None))
        conn.close()
    except Exception as exc:
        print(f"[LOG] Failed to write log: {exc}")


# ── Device helpers ─────────────────────────────────────────────────────────────

def _upsert_devices(devices: list[dict]):
    conn = _get_db()
    try:
        with conn:
            with conn.cursor() as cur:
                for d in devices:
                    ip = d["ip"]

                    # Check if this is a brand-new device
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


def _fetch_recent_logs(limit: int = 10) -> list[dict]:
    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT id, type, message, ip, username, success, meta, created_at
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


def _check_ingest_key() -> bool:
    key = request.headers.get("X-Ingest-Key", "")
    return bool(INGEST_KEY) and key == INGEST_KEY


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
        ua = request.headers.get("User-Agent", "")

        if username and password and username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["logged_in"] = True
            session["user"] = username
            write_log(
                type_="login",
                message=f"Successful login for '{username}'",
                ip=client_ip,
                username=username,
                success=True,
                meta={"user_agent": ua}
            )
            return redirect(url_for("dashboard"))

        error = "Invalid username or password."
        write_log(
            type_="login",
            message=f"Failed login attempt for '{username or '(empty)'}'",
            ip=client_ip,
            username=username or None,
            success=False,
            meta={"user_agent": ua}
        )

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    user = session.get("user")
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
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


@app.route("/dashboard")
@login_required
def dashboard():
    user       = session.get("user", "Admin")
    agent_live = (time.time() - _last_push_time) < 10
    devices    = _fetch_devices()
    recent_logs = _fetch_recent_logs(limit=8)
    return render_template("dashboard.html", user=user, agent_live=agent_live,
                           devices=devices, recent_logs=recent_logs)


# ── Logs page ──────────────────────────────────────────────────────────────────

@app.route("/logs")
@login_required
def logs_page():
    user = session.get("user", "Admin")
    return render_template("logs.html", user=user)


# ── Logs API (cursor-based pagination) ────────────────────────────────────────

@app.route("/api/logs")
@login_required
def api_logs():
    """
    Query params:
      before_id  – return rows with id < before_id  (older, next page)
      after_id   – return rows with id > after_id   (newer, refresh)
      limit      – max rows (default 25, max 100)
      type       – filter by log type (login, new_device, logout, …)
    Returns:
      { logs: [...], next_cursor: <id|null>, prev_cursor: <id|null>, total_count }
    """
    limit     = min(int(request.args.get("limit", 25)), 100)
    before_id = request.args.get("before_id", type=int)
    after_id  = request.args.get("after_id",  type=int)
    type_filter = request.args.get("type", "").strip() or None

    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Total count (for display)
            if type_filter:
                cur.execute("SELECT COUNT(*) FROM logs WHERE type = %s", (type_filter,))
            else:
                cur.execute("SELECT COUNT(*) FROM logs")
            total = cur.fetchone()["count"]

            # Build query
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
                SELECT id, type, message, ip, username, success, meta, created_at
                FROM logs
                {where}
                ORDER BY id {order}
                LIMIT %s
            """, params + [limit + 1])  # fetch one extra to know if there's a next page

            rows = cur.fetchall()

            # If we queried ASC (after_id), reverse for consistent newest-first display
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
                "logs": result,
                "next_cursor": next_cursor,
                "prev_cursor": prev_cursor,
                "total": total,
                "limit": limit,
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