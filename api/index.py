import os
import sqlite3
import time
import secrets

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, g, make_response
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), "..", "templates"), static_folder=os.path.join(os.path.dirname(__file__), "..", "static"))
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Vercel only allows writes to /tmp – SQLite DB lives there
DATABASE = os.environ.get("DATABASE", "/tmp/portal.db")
FLAG = os.environ.get("FLAG", "CTF{placeholder_set_via_env}")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "yNT2fww0ootUbukIwZbUKfEV8fk")

# ---------------------------------------------------------------------------
# Rate limiter (in‑memory, fine for a single‑instance deployment)
# ---------------------------------------------------------------------------
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

# ---------------------------------------------------------------------------
# Database helpers – initialise on first request if missing
# ---------------------------------------------------------------------------
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        os.makedirs(os.path.dirname(DATABASE), exist_ok=True)
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def init_db():
    """Create the users table and seed it if the file does not exist yet."""
    if os.path.exists(DATABASE):
        return
    con = sqlite3.connect(DATABASE)
    cur = con.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    cur.executemany(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
        [
            ("guest", "guestpass", 0),
            ("alice", "alicepw123", 0),
            ("admin", ADMIN_PASSWORD, 1),
        ],
    )
    con.commit()
    con.close()

# Ensure the DB is ready before the first request
@app.before_first_request
def ensure_db():
    init_db()

# ---------------------------------------------------------------------------
# Keyword blacklist (naïve, case‑insensitive)
# ---------------------------------------------------------------------------
BLACKLIST = ["union", "--", "#", " or ", "admin"]

def is_blocked(value: str) -> bool:
    lower = value.lower()
    return any(kw in lower for kw in BLACKLIST)

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("1 per 300 milliseconds")
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if is_blocked(username) or is_blocked(password):
            error = "Invalid username or password."
            return make_response(render_template("login.html", error=error))
        raw_query = (
            f"SELECT * FROM users "
            f"WHERE username = '{username}' AND password = '{password}'"
        )
        db = get_db()
        try:
            cur = db.execute(raw_query)
            row = cur.fetchone()
        except Exception:
            error = "Invalid username or password."
            return make_response(render_template("login.html", error=error))
        if row:
            time.sleep(0.35)  # timing side‑channel for TRUE condition
            session.clear()
            session["username"] = row["username"]
            session["is_admin"] = bool(row["is_admin"])
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid username or password."
    return make_response(render_template("login.html", error=error))

@app.route("/dashboard", methods=["GET"])
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    username = session.get("username", "")
    is_admin = session.get("is_admin", False)
    flag = FLAG if is_admin else None
    return render_template(
        "dashboard.html",
        username=username,
        is_admin=is_admin,
        flag=flag,
    )

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------------------------------------------------------------------------
# Organizer‑only backdoor – useful for verification (can be removed later)
# ---------------------------------------------------------------------------
ORGANIZER_TOKEN = os.environ.get("ORGANIZER_TOKEN", "organizer_secret_2024")

@app.route("/organizer-access", methods=["GET"])
def organizer_access():
    token = request.args.get("token", "")
    if token != ORGANIZER_TOKEN:
        return redirect(url_for("login"))
    session.clear()
    session["username"] = "admin"
    session["is_admin"] = True
    return redirect(url_for("dashboard"))

# ---------------------------------------------------------------------------
# Error handlers – always generic
# ---------------------------------------------------------------------------
@app.errorhandler(429)
def rate_limit_handler(e):
    return render_template("login.html", error="Invalid username or password."), 429

@app.errorhandler(404)
def not_found(e):
    return redirect(url_for("login"))

@app.errorhandler(500)
def server_error(e):
    return render_template("login.html", error="Invalid username or password."), 500

# ---------------------------------------------------------------------------
# Vercel entry point – expose a WSGI handler
# ---------------------------------------------------------------------------
def handler(request):
    """Vercel will call this function for every HTTP request."""
    return app(request.environ, request.start_response)
