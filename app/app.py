"""
DELIBERATELY VULNERABLE demo API for an AppSec / GHAS lab.
Every vulnerability below is intentional and tagged with its CWE so scanner
findings can be mapped back to the source. Do NOT deploy this anywhere.
"""
import hashlib
import os
import pickle
import base64
import sqlite3
import subprocess

import jwt
import requests
import yaml
from flask import Flask, request, render_template_string, send_file, jsonify

app = Flask(__name__)

# CWE-798: hard-coded credential (intentionally NOT a real provider token format)
app.config["SECRET_KEY"] = "lab-hardcoded-secret-do-not-use"
JWT_SECRET = "changeme"

DB_PATH = os.path.join(os.path.dirname(__file__), "lab.db")
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, password TEXT)")
    return conn


@app.route("/users")
def find_user():
    # CWE-89: SQL injection via string formatting
    name = request.args.get("name", "")
    rows = get_db().execute(f"SELECT id, name FROM users WHERE name = '{name}'").fetchall()
    return jsonify(rows)


@app.route("/register", methods=["POST"])
def register():
    # CWE-328: weak, unsalted hash for passwords
    name = request.form["name"]
    pw_hash = hashlib.md5(request.form["password"].encode()).hexdigest()
    conn = get_db()
    conn.execute("INSERT INTO users (name, password) VALUES (?, ?)", (name, pw_hash))
    conn.commit()
    return "ok"


@app.route("/ping")
def ping():
    # CWE-78: OS command injection
    host = request.args.get("host", "127.0.0.1")
    out = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return out


@app.route("/download")
def download():
    # CWE-22: path traversal
    filename = request.args.get("file", "")
    return send_file(os.path.join(UPLOAD_DIR, filename))


@app.route("/fetch")
def fetch():
    # CWE-918: server-side request forgery (think 169.254.169.254)
    url = request.args.get("url", "")
    return requests.get(url, timeout=5).text


@app.route("/greet")
def greet():
    # Fixed: keep template constant; pass user input as context data
    name = request.args.get("name", "world")
    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)


@app.route("/session")
def load_session():
    # CWE-502: insecure deserialization of attacker-controlled cookie
    blob = request.cookies.get("state", "")
    state = pickle.loads(base64.b64decode(blob))
    return jsonify(state)


@app.route("/config", methods=["POST"])
def load_config():
    # CWE-502: unsafe YAML load
    cfg = yaml.load(request.data, Loader=yaml.Loader)
    return jsonify(cfg)


@app.route("/me")
def me():
    # CWE-347: JWT signature never verified
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    claims = jwt.decode(token, options={"verify_signature": False})
    return jsonify(claims)


if __name__ == "__main__":
    # CWE-489: debug mode exposes the Werkzeug console
    app.run(host="0.0.0.0", port=5000, debug=True)
