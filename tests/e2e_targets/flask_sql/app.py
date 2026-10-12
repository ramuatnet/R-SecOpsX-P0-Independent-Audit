import sqlite3
from flask import Flask, request

app = Flask(__name__)

# Hard-coded credential (CWE-798)
API_KEY = "sk-live-hardcoded-secret-0123456789"


@app.route("/query")
def query():
    user = request.args.get("u", "")  # taint source
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    # SQL injection (CWE-89): interpolated into the statement
    cur.execute("SELECT * FROM users WHERE name = '" + user + "'")
    rows = cur.fetchall()
    conn.close()
    return str(rows)
