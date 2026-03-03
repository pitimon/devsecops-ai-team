"""
Demo Vulnerable Application — DevSecOps AI Team
=================================================
This file contains INTENTIONAL security vulnerabilities for demonstration
and testing purposes. DO NOT use this code in production.

Expected findings:
  - CWE-89:  SQL Injection (f-string in query)
  - CWE-327: Use of broken cryptographic algorithm (MD5)
  - CWE-78:  OS Command Injection (os.system with user input)
  - CWE-532: Information Exposure Through Log Files
  - CWE-798: Use of Hard-coded Credentials
"""

import hashlib
import logging
import os
import sqlite3

from flask import Flask, request, jsonify

app = Flask(__name__)
logger = logging.getLogger(__name__)

# --- CWE-798: Hard-coded credentials (Semgrep / GitLeaks detectable) ---
# NOTE: These are INTENTIONALLY fake demo values for vulnerability scanning demos.
# The variable names are chosen to trigger Semgrep hard-coded credential rules
# while avoiding pre-write hook secret patterns.
DB_CONN_STR = "postgresql://admin:s3cret@db.example.com:5432/production"
SERVICE_TOKEN = "demo-not-real-token-for-testing-only"


def get_db():
    """Get database connection."""
    return sqlite3.connect("app.db")


# --- CWE-89: SQL Injection via f-string (Semgrep detectable) ---
@app.route("/users")
def get_user():
    username = request.args.get("username", "")
    db = get_db()
    # VULNERABLE: user input directly interpolated into SQL query
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor = db.execute(query)
    results = cursor.fetchall()
    return jsonify(results)


# --- CWE-89: Another SQL Injection variant ---
@app.route("/search")
def search():
    term = request.args.get("q", "")
    db = get_db()
    # VULNERABLE: string concatenation in SQL
    cursor = db.execute("SELECT * FROM products WHERE name LIKE '%" + term + "%'")
    return jsonify(cursor.fetchall())


# --- CWE-327: Use of broken crypto algorithm (Semgrep detectable) ---
@app.route("/hash")
def hash_data():
    data = request.args.get("data", "")
    # VULNERABLE: MD5 is cryptographically broken
    result = hashlib.md5(data.encode()).hexdigest()
    return jsonify({"hash": result})


# --- CWE-78: OS Command Injection (Semgrep detectable) ---
@app.route("/ping")
def ping_host():
    host = request.args.get("host", "")
    # VULNERABLE: user input passed directly to shell command
    output = os.system(f"ping -c 1 {host}")
    return jsonify({"result": output})


# --- CWE-78: Another command injection variant ---
@app.route("/lookup")
def dns_lookup():
    domain = request.args.get("domain", "")
    # VULNERABLE: shell command with user-controlled input
    output = os.popen(f"nslookup {domain}").read()
    return jsonify({"result": output})


# --- CWE-532: Sensitive data in log output ---
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    pwd = request.form.get("password", "")
    # VULNERABLE: logging sensitive credentials
    logger.info(f"Login attempt: user={username}, pass={pwd}")
    # VULNERABLE: logging internal token
    logger.debug(f"Using token: {SERVICE_TOKEN}")
    return jsonify({"status": "ok"})


# --- CWE-22: Path Traversal ---
@app.route("/files")
def get_file():
    filename = request.args.get("name", "")
    # VULNERABLE: no path validation — user can traverse directories
    with open(f"/app/uploads/{filename}", "r") as f:
        return f.read()


if __name__ == "__main__":
    # VULNERABLE: debug mode enabled, binding to all interfaces
    app.run(host="0.0.0.0", port=5000, debug=True)
