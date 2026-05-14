import os
import threading
import time

from flask import Flask, Response, redirect, render_template, request, session, url_for
from functools import wraps
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-production")

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

# Shared secret the local agent must send in every push request.
# Set INGEST_KEY to a long random string in your Railway environment variables.
INGEST_KEY = os.environ.get("INGEST_KEY", "")

# ── Thread-safe frame buffer ───────────────────────────────────────────────────
_frame_lock  = threading.Lock()
_latest_frame: bytes | None = None
_last_push_time: float = 0.0


# ── Auth helpers ───────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ── MJPEG generator ────────────────────────────────────────────────────────────
def _mjpeg_generator():
    BOUNDARY      = b"--frame"
    HEADER        = b"Content-Type: image/jpeg\r\n\r\n"
    POLL_INTERVAL = 1 / 30

    while True:
        with _frame_lock:
            frame = _latest_frame

        if frame:
            yield BOUNDARY + b"\r\n" + HEADER + frame + b"\r\n"

        time.sleep(POLL_INTERVAL)


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
    agent_live = (time.time() - _last_push_time) < 10   # stale after 10 s
    return render_template("dashboard.html", user=user, agent_live=agent_live)


@app.route("/video_feed")
@login_required
def video_feed():
    """MJPEG stream consumed by the <img> tag in dashboard.html."""
    return Response(
        _mjpeg_generator(),
        mimetype="multipart/x-mixed-replace; boundary=frame",
    )


@app.route("/ingest", methods=["POST"])
def ingest():
    """
    Receives a single raw JPEG frame from the local Windows agent.

    Required headers:
        X-Ingest-Key: <INGEST_KEY>
        Content-Type: image/jpeg
    """
    global _latest_frame, _last_push_time

    if not INGEST_KEY:
        return "INGEST_KEY not configured on server", 500

    if request.headers.get("X-Ingest-Key", "") != INGEST_KEY:
        return "Unauthorized", 401

    if not request.content_type or "image/jpeg" not in request.content_type:
        return "Expected Content-Type: image/jpeg", 415

    data = request.get_data()
    if not data:
        return "Empty body", 400

    with _frame_lock:
        _latest_frame   = data
        _last_push_time = time.time()

    return "OK", 200


@app.route("/ingest/status")
def ingest_status():
    """Quick health-check — useful for debugging the agent."""
    age = round(time.time() - _last_push_time, 1)
    return {"last_push_seconds_ago": age, "frame_available": _latest_frame is not None}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, threaded=True)