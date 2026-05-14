import os
import threading
import time

from flask import Flask, Response, redirect, render_template, request, session, url_for
from flask_sock import Sock
from functools import wraps
from dotenv import load_dotenv
import simple_websocket

load_dotenv()

app  = Flask(__name__)
sock = Sock(app)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-production")

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
INGEST_KEY     = os.environ.get("INGEST_KEY", "")

# ── Thread-safe frame buffer ───────────────────────────────────────────────────
_frame_lock      = threading.Lock()
_latest_frame: bytes | None = None
_last_push_time: float      = 0.0

# ── Viewer registry (browser WebSocket connections) ───────────────────────────
_viewers_lock = threading.Lock()
_viewers: set = set()


# ── Auth helpers ───────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if username and password and username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["logged_in"] = True
            session["user"] = username
            return redirect(url_for("dashboard"))
        error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    user       = session.get("user", "Admin")
    agent_live = (time.time() - _last_push_time) < 10
    return render_template("dashboard.html", user=user, agent_live=agent_live)


# ── Agent WebSocket (replaces /ingest POST) ───────────────────────────────────
@sock.route("/ws/ingest")
def ws_ingest(ws):
    """
    The local agent connects here and sends JPEG frames as binary messages.
    First message must be the INGEST_KEY as UTF-8 text for auth.
    """
    global _latest_frame, _last_push_time, _viewers

    if not INGEST_KEY:
        ws.close(message="INGEST_KEY not configured")
        return

    # Auth handshake — first message must be the key
    try:
        key = ws.receive(timeout=5)
    except Exception:
        ws.close(message="Auth timeout")
        return

    if key != INGEST_KEY:
        ws.close(message="Unauthorized")
        return

    ws.send("OK")  # acknowledge auth

    print("[INFO] Agent connected via WebSocket")

    try:
        while True:
            data = ws.receive()          # blocks until next frame arrives
            if data is None:
                break
            if not isinstance(data, bytes):
                continue                 # ignore unexpected text messages

            with _frame_lock:
                _latest_frame   = data
                _last_push_time = time.time()

            # Broadcast to all browser viewers
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


# ── Browser viewer WebSocket ───────────────────────────────────────────────────
@sock.route("/ws/view")
def ws_view(ws):
    """Browser connects here to receive JPEG frames as binary messages."""
    if not session.get("logged_in"):
        ws.close(message="Unauthorized")
        return

    with _viewers_lock:
        _viewers.add(ws)

    try:
        # Send the latest frame immediately so the canvas isn't blank
        with _frame_lock:
            if _latest_frame:
                ws.send(_latest_frame)

        # Keep the connection alive; frames are pushed from ws_ingest
        while True:
            ws.receive(timeout=30)   # ping-like: just wait
    except simple_websocket.ConnectionClosed:
        pass
    finally:
        with _viewers_lock:
            _viewers.discard(ws)


# ── Legacy ingest status (still useful for debugging) ─────────────────────────
@app.route("/ingest/status")
def ingest_status():
    age = round(time.time() - _last_push_time, 1)
    return {"last_push_seconds_ago": age, "frame_available": _latest_frame is not None}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, threaded=True)