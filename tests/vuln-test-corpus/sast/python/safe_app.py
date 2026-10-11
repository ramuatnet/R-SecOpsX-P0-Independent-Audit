from flask import Flask, request, render_template_string
import sqlite3, subprocess, os, shlex

app = Flask(__name__)
# Secret from environment – no hard‑coded secret
SECRET_KEY = os.getenv("FLASK_SECRET", "")

@app.route("/profile")
def profile():
    user = request.args.get("user", "")
    # ----- Parameterised query (fixes CWE-89) -----
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (user,))
    rows = cursor.fetchall()
    conn.close()
    return str(rows)

@app.route("/run")
def run_cmd():
    cmd = request.args.get("cmd", "")
    # ----- Allow only a whitelist of commands (fixes CWE-78) -----
    allowed = ["ls", "pwd", "date"]
    parts = shlex.split(cmd)
    if not parts or parts[0] not in allowed:
        return "Invalid command", 400
    # Use subprocess without shell=True
    output = subprocess.check_output(parts, stderr=subprocess.STDOUT)
    return output.decode()

@app.route("/load")
def load_obj():
    # Disallow deserialization from untrusted data
    return "Deserialization disabled", 403

@app.route("/template")
def tmpl():
    name = request.args.get("name", "")
    # Auto‑escape is on by default in render_template_string
    return render_template_string("Hello {{ name }}", name=name)

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
