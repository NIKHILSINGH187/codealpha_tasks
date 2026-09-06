"""
secure_app.py
--------------
Remediated version of vulnerable_app.py, produced as part of the
CodeAlpha Task 3: Secure Coding Review.

Every fix here maps to a numbered finding in CODE_REVIEW_REPORT.md.
"""

from flask import Flask, request, render_template_string, redirect, session, abort
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import secrets

app = Flask(__name__)

# --- FIX 1: Secret key loaded from environment, not hardcoded ---
# Generate one with: python -c "import secrets; print(secrets.token_hex(32))"
# and store it as an environment variable, never in source control.
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

DB_PATH = "users.db"
UPLOAD_DIR = os.path.abspath("uploads")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT)"
    )
    conn.commit()
    conn.close()


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        return "Username and password are required", 400

    # --- FIX 2: Strong, salted password hashing (PBKDF2 via Werkzeug) ---
    password_hash = generate_password_hash(password)

    conn = get_db()
    try:
        # --- FIX 3: Parameterized query — eliminates SQL injection ---
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return "Username already exists", 409
    finally:
        conn.close()
    return "Registered!"


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    conn = get_db()
    # --- FIX 3 (again): Parameterized query ---
    cursor = conn.execute(
        "SELECT password_hash FROM users WHERE username = ?", (username,)
    )
    row = cursor.fetchone()
    conn.close()

    # --- FIX 2 (again): Verify against the stored salted hash ---
    if row and check_password_hash(row[0], password):
        session.clear()
        session["user"] = username
        return redirect("/dashboard")

    # Same generic message whether the username or password was wrong,
    # so attackers can't use the response to enumerate valid usernames.
    return "Invalid credentials", 401


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")

    # --- FIX 4: Use Jinja2 templating with auto-escaping instead of
    # building HTML with an f-string. {{ name }} is escaped by default,
    # neutralizing script injection. ---
    return render_template_string(
        "<h1>Welcome, {{ name }}!</h1>", name=session["user"]
    )


@app.route("/load_preferences", methods=["POST"])
def load_preferences():
    # --- FIX 5: Use a safe serialization format (JSON) instead of pickle.
    # JSON cannot execute arbitrary code when parsed, unlike pickle. ---
    import json

    raw = request.form.get("data", "{}")
    try:
        preferences = json.loads(raw)
    except json.JSONDecodeError:
        return "Invalid preferences payload", 400
    return {"loaded_preferences": preferences}


@app.route("/download")
def download():
    filename = request.args.get("file", "")

    # --- FIX 6: Path traversal prevention ---
    # Resolve the final path and confirm it's still inside UPLOAD_DIR
    # before opening it, and reject empty or suspicious input outright.
    if not filename or "/" in filename or "\\" in filename or ".." in filename:
        abort(400)

    full_path = os.path.abspath(os.path.join(UPLOAD_DIR, filename))
    if not full_path.startswith(UPLOAD_DIR + os.sep):
        abort(403)

    if not os.path.isfile(full_path):
        abort(404)

    with open(full_path, "r") as f:
        return f.read()


if __name__ == "__main__":
    init_db()
    # --- FIX 7: Debug mode driven by an environment variable, defaulting
    # to OFF, so it can never accidentally ship on in production. ---
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode, host="127.0.0.1")
