"""
vulnerable_app.py
------------------
Sample Flask application used as the SUBJECT of a secure coding review.

INTENTIONALLY INSECURE — this file exists only to demonstrate common
vulnerability patterns for the CodeAlpha Task 3: Secure Coding Review.
Do NOT deploy this code. See CODE_REVIEW_REPORT.md for the full audit
and secure_app.py for the corrected version.
"""

from flask import Flask, request, render_template_string, redirect, session
import sqlite3
import hashlib
import pickle
import os

app = Flask(__name__)

# --- FINDING 1: Hardcoded secret key committed to source control ---
app.secret_key = "supersecret123"

DB_PATH = "users.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
    )
    conn.commit()
    conn.close()


@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]

    # --- FINDING 2: Weak, unsalted password hashing (MD5) ---
    hashed = hashlib.md5(password.encode()).hexdigest()

    conn = get_db()
    # --- FINDING 3: SQL Injection via string formatting ---
    query = f"INSERT INTO users (username, password) VALUES ('{username}', '{hashed}')"
    conn.execute(query)
    conn.commit()
    conn.close()
    return "Registered!"


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    hashed = hashlib.md5(password.encode()).hexdigest()

    conn = get_db()
    # --- FINDING 3 (again): SQL Injection via string formatting ---
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashed}'"
    cursor = conn.execute(query)
    user = cursor.fetchone()
    conn.close()

    if user:
        session["user"] = username
        return redirect("/dashboard")
    return "Invalid credentials"


@app.route("/dashboard")
def dashboard():
    # --- FINDING 4: Reflected XSS — user input rendered without escaping ---
    name = request.args.get("name", session.get("user", "Guest"))
    template = f"<h1>Welcome, {name}!</h1>"
    return render_template_string(template)


@app.route("/load_preferences", methods=["POST"])
def load_preferences():
    # --- FINDING 5: Insecure deserialization ---
    # Untrusted client-supplied data is unpickled directly, allowing
    # arbitrary code execution if the payload is crafted maliciously.
    raw = request.form["data"]
    preferences = pickle.loads(raw.encode("latin1"))
    return f"Loaded preferences: {preferences}"


@app.route("/download")
def download():
    # --- FINDING 6: Path traversal ---
    # No validation on the filename lets an attacker request
    # arbitrary files, e.g. ?file=../../etc/passwd
    filename = request.args.get("file")
    path = os.path.join("uploads", filename)
    with open(path, "r") as f:
        return f.read()


if __name__ == "__main__":
    init_db()
    # --- FINDING 7: Debug mode enabled in what could be a production run ---
    app.run(debug=True, host="0.0.0.0")
