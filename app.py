import os
import re
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
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

DATABASE = os.environ.get("DATABASE", "/data/portal.db")
FLAG     = os.environ.get("FLAG", "CTF{placeholder_set_via_env}")

# Admin password is seeded from env so Docker bakes it in
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "yNT2fww0ootUbukIwZbUKfEV8fk")

# ---------------------------------------------------------------------------
# Rate limiter  (~1 req / 300 ms per IP on /login)
# ---------------------------------------------------------------------------
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

# ---------------------------------------------------------------------------
# Database helpers
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
    """Create and seed the users table if it does not exist."""
    os.makedirs(os.path.dirname(DATABASE), exist_ok=True)
    con = sqlite3.connect(DATABASE)
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT    NOT NULL UNIQUE,
            password TEXT    NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        )
    """)
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
            [
                ("guest", "guestpass",    0),
                ("alice", "alicepw123",   0),
                ("admin", ADMIN_PASSWORD, 1),
            ]
        )
    con.commit()
    con.close()

# ---------------------------------------------------------------------------
# Keyword blacklist
# Naive, case-insensitive — inline comments / case tricks bypass it.
# ---------------------------------------------------------------------------
BLACKLIST = ["union", "--", "#", " or ", "admin"]

def is_blocked(value: str) -> bool:
    lower = value.lower()
    for kw in BLACKLIST:
        if kw in lower:
            return True
    return False

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

        # --- Blacklist check ---
        if is_blocked(username) or is_blocked(password):
            # Same generic message — no hint that filtering fired
            error = "Invalid username or password."
            return make_response(render_template("login.html", error=error))

        # --- Vulnerable query (intentional SQLi — DO NOT FIX) ---
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
            # TRUE branch — timing side-channel: sleep makes true distinguishable
            time.sleep(0.35)
            session.clear()
            session["username"] = row["username"]
            session["is_admin"] = bool(row["is_admin"])
            return redirect(url_for("dashboard"))
        else:
            # FALSE branch — no extra sleep
            error = "Invalid username or password."

    return make_response(render_template("login.html", error=error))


@app.route("/dashboard", methods=["GET"])
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session.get("username", "")
    is_admin = session.get("is_admin", False)
    flag     = FLAG if is_admin else None

    return render_template(
        "dashboard.html",
        username=username,
        is_admin=is_admin,
        flag=flag,
    )


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Organizer-only backdoor — not linked from any page; token required.
# Lets organizers verify the flag without needing to bypass the blacklist.
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
# Error handlers — never leak details
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
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
