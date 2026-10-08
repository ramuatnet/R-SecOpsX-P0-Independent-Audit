from flask import Flask, request, render_string
import sqlite3, subprocess, os, pickle

app = Flask(__name__)

# ----- Hard‑coded secret (CWE-798) -----
SECRET_KEY="***"

@app.route("/profile")
def profile():
    user = request.args.get("user", "")  # source
    # ----- SQL Injection (CWE-89) -----
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Vulnerable: string concatenation
    query = f"SELECT * FROM users WHERE username = '{user}'"
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return str(rows)

@app.route("/run")
def run_cmd():
    cmd = request.args.get("cmd", "")  # source
    # ----- Command Injection (CWE-78) -----
    # Vulnerable: shell=True + unsanitized input
    output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
    return output.decode()

@app.route("/load")
def load_obj():
    data = request.get_data()  # raw bytes from client
    # ----- Insecure Deserialization (CWE-502) -----
    obj = pickle.loads(data)  # dangerous!
    return f"Loaded object: {obj}"

@app.route("/template")
def tmpl():
    name = request.args.get("name", "")  # source
    # ----- Server‑Side Template Injection (CWE-94) -----
    tpl = f"Hello {name}"
    return render_string(tpl)  # Jinja2 auto‑escape is OFF in this example

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
