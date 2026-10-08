#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------
# 1️⃣  Create the folder structure
# -----------------------------------------------------------------
BASE="vuln-test-corpus"
rm -rf "$BASE"
mkdir -p "$BASE"/{java,go,python,php,rust,dotnet,cpp,ai_ml}

# -----------------------------------------------------------------
# 2️⃣  Helper to write a file (creates parent dirs if needed)
# -----------------------------------------------------------------
write_file() {
  local path="$1" content="$2"
  printf "%s\n" "$content" > "$path"
}

# -----------------------------------------------------------------
# 3️⃣  Java
# -----------------------------------------------------------------
write_file "$BASE/java/VulnerableServlet.java" "$(cat <<'EOF'
package test;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.*;
import java.sql.*;

public class VulnerableServlet extends HttpServlet {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/testdb";
    private static final String USER = "root";
    private static final String PASS="***"; // CWE-798: Hard‑coded Credentials

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        String userInput = req.getParameter("input"); // <-- source

        // ---- SQL Injection (CWE-89) ----
        String sql = "SELECT * FROM users WHERE name = '" + userInput + "'";
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            // process result …
        } catch (SQLException e) {
            resp.getWriter().println("DB error");
        }

        // ---- Command Injection (CWE-78) ----
        String cmd = "echo " + userInput; // concatenation without validation
        try {
            Process p = Runtime.getRuntime().exec(cmd);
            p.waitFor();
        } catch (Exception e) { /* ignore */ }

        // ---- Path Traversal (CWE-22) ----
        String fileName = req.getParameter("file");
        File f = new File("/var/www/uploads/" + fileName); // no validation
        try (FileInputStream fis = new FileInputStream(f)) {
            // read file …
        } catch (IOException e) {
            resp.getWriter().println("File error");
        }

        // ---- Insecure Deserialization (CWE-502) ----
        String serialized = req.getHeader("X-Serialized-Data");
        try {
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(
                    serialized.getBytes()));
            Object obj = ois.readObject(); // <-- dangerous
        } catch (Exception e) { /* ignore */ }

        resp.setContentType("text/plain");
        resp.getWriter().println("Done");
    }
}
EOF
)"

write_file "$BASE/java/SafeServlet.java" "$(cat <<'EOF'
package test;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.*;
import java.sql.*;

public class SafeServlet extends HttpServlet {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/testdb";
    private static final String USER = System.getenv("DB_USER"); // from env
    private static final String PASS=System...S"); // from env

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        String userInput = req.getParameter("input");

        // ---- Parameterised query (fixes CWE-89) ----
        String sql = "SELECT * FROM users WHERE name = ?";
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, userInput);
            try (ResultSet rs = ps.executeQuery()) {
                // process result …
            }
        } catch (SQLException e) {
            resp.getWriter().println("DB error");
        }

        // ---- Whitelist for command (fixes CWE-78) ----
        if (userInput.matches("[a-zA-Z0-9]+")) { // only alphanum allowed
            String cmd = "echo " + userInput;
            try {
                Process p = Runtime.getRuntime().exec(cmd);
                p.waitFor();
            } catch (Exception e) { /* ignore */ }
        } else {
            resp.getWriter().println("Invalid input");
            return;
        }

        // ---- Path validation (fixes CWE-22) ----
        String fileName = req.getParameter("file");
        if (fileName != null && !fileName.contains("..") && !fileName.startsWith("/")) {
            File f = new File("/var/www/uploads/" + fileName);
            try (FileInputStream fis = new FileInputStream(f)) {
                // read file …
            } catch (IOException e) {
                resp.getWriter().println("File error");
            }
        } else {
            resp.getWriter().println("Invalid file name");
            return;
        }

        // ---- Disallow deserialization from untrusted source (fixes CWE-502) ----
        String serialized = req.getHeader("X-Serialized-Data");
        // In a real app you would avoid deserializing user‑controlled data altogether.
        // Here we simply ignore the header.
        resp.setContentType("text/plain");
        resp.getWriter().println("Done");
    }
}
EOF
)"

# -----------------------------------------------------------------
# 4️⃣  Go
# -----------------------------------------------------------------
write_file "$BASE/go/vulnerable.go" "$(cat <<'EOF'
package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/query", queryHandler).Methods("GET")
	r.HandleFunc("/cmd", cmdHandler).Methods("GET")
	r.HandleFunc("/file", fileHandler).Methods("GET")
	log.Fatal(http.ListenAndServe(":8080", r))
}

// ----- SQL Injection (CWE-89) -----
func queryHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("mysql", "root:hardcoded_pass@tcp(127.0.0.1:3306)/test")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer db.Close()

	input := r.URL.Query().Get("name") // source
	// Vulnerable: concatenation
	q := "SELECT * FROM users WHERE name = '" + input + "'"
	rows, err := db.Query(q)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	fmt.Fprint(w, "query done")
}

// ----- Command Injection (CWE-78) -----
func cmdHandler(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("cmd") // source
	// Vulnerable: direct concatenation
	out, err := exec.Command("sh", "-c", "echo "+input).Output()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(out)
}

// ----- Path Traversal (CWE-22) -----
func fileHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file") // source
	// No validation
	path := "/var/www/uploads/" + name
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	w.Write(data)
}
EOF
)"

write_file "$BASE/go/safe.go" "$(cat <<'EOF'
package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/query", queryHandler).Methods("GET")
	r.HandleFunc("/cmd", cmdHandler).Methods("GET")
	r.HandleFunc("/file", fileHandler).Methods("GET")
	log.Fatal(http.ListenAndServe(":8080", r))
}

// ----- Fixed SQL (CWE-89) -----
func queryHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(127.0.0.1:3306)/test",
		os.Getenv("DB_USER"), os.Getenv("DB_PASS")))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer db.Close()

	input := r.URL.Query().Get("name")
	q := "SELECT * FROM users WHERE name = ?"
	rows, err := db.Query(q, input)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	fmt.Fprint(w, "query done")
}

// ----- Fixed Command (CWE-78) -----
func cmdHandler(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("cmd")
	// Allow only alphanumeric
	if matched, _ := regexp.MatchString(`^[a-zA-Z0-9]+$`, input); !matched {
		http.Error(w, "invalid input", 400)
		return
	}
	out, err := exec.Command("echo", input).Output()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(out)
}

// ----- Fixed Path Traversal (CWE-22) -----
func fileHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	if strings.Contains(name, "..") || strings.HasPrefix(name, "/") {
		http.Error(w, "invalid file name", 400)
		return
	}
	path := "/var/www/uploads/" + name
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	w.Write(data)
}
EOF
)"

# -----------------------------------------------------------------
# 5️⃣  Python
# -----------------------------------------------------------------
write_file "$BASE/python/vulnerable_app.py" "$(cat <<'EOF'
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
EOF
)"

write_file "$BASE/python/safe_app.py" "$(cat <<'EOF'
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
EOF
)"

# -----------------------------------------------------------------
# 6️⃣  PHP
# -----------------------------------------------------------------
write_file "$BASE/php/vulnerable.php" "$(cat <<'EOF'
<?php
// ----- Hard‑coded DB credentials (CWE-798) -----
$host = "localhost";
$user = "root";
$pass = "hardcoded_password";
$db   = "testdb";

$mysqli = new mysqli($host, $user, $pass, $db);
if ($mysqli->connect_error) {
    die("Connection failed: " . $mysqli->connect_error);
}

// ----- SQL Injection (CWE-89) -----
$userInput = $_GET['name'] ?? ''; // source
$sql = "SELECT * FROM users WHERE name = '$userInput'";
$result = $mysqli->query($sql);
while ($row = $result->fetch_assoc()) {
    echo $row['username'] . "<br>";
}

// ----- Command Injection (CWE-78) -----
$cmd = $_GET['cmd'] ?? '';
system("echo " . $cmd); // vulnerable

// ----- File Include (CWE-22) -----
$file = $_GET['file'] ?? '';
include("/var/www/includes/" . $file); // no validation

// ----- Unsafe eval (CWE-94) -----
$code = $_GET['code'] ?? '';
eval($code); // dangerous

$mysqli->close();
?>
EOF
)"

write_file "$BASE/php/safe.php" "$(cat <<'EOF'
<?php
// Credentials from environment – no hard‑coded secret
$host = getenv("DB_HOST") ?: "localhost";
$user = getenv("DB_USER") ?: "";
$pass = getenv("DB_PASS") ?: "";
$db   = getenv("DB_NAME") ?: "testdb";

$mysqli = new mysqli($host, $user, $pass, $db);
if ($mysqli->connect_error) {
    die("Connection failed: " . $mysqli->connect_error);
}

// ----- Parameterised query (fixes CWE-89) -----
$name = $_GET['name'] ?? '';
$stmt = $mysqli->prepare("SELECT * FROM users WHERE name = ?");
$stmt->bind_param("s", $name);
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    echo $row['username'] . "<br>";
}
$stmt->close();

// ----- Whitelist for command (fixes CWE-78) -----
$cmd = $_GET['cmd'] ?? '';
$allowed = ['ls', 'pwd', 'date'];
$parts = explode(' ', $cmd);
if (!in_array($parts[0] ?? '', $allowed, true)) {
    die("Invalid command");
}
// Use exec with escapeshellarg
$safeCmd = escapeshellcmd($parts[0]);
$output = shell_exec($safeCmd . " " . escapeshellarg(implode(' ', array_slice($parts,1))));
echo $output;

// ----- Path validation (fixes CWE-22) -----
$file = $_GET['file'] ?? '';
if (strpos($file, '..') !== false || strpos($file, '/') === 0) {
    die("Invalid file name");
}
include("/var/www/includes/" . $file);

// ----- Avoid eval altogether (fixes CWE-94) -----
// If dynamic code is truly needed, use a safe sandbox or whitelist.
// Here we simply reject the input.
$code = $_GET['code'] ?? '';
if ($code !== '') {
    die("Code evaluation disabled");
}

$mysqli->close();
?>
EOF
)"

# -----------------------------------------------------------------
# 7️⃣  Rust
# -----------------------------------------------------------------
write_file "$BASE/rust/vulnerable.rs" "$(cat <<'EOF'
use actix_web::{get, App, HttpResponse, HttpServer, Responder};
use rusqlite::{Connection, Result};
use std::process::Command;

#[get("/profile")]
async fn profile(info: actix_web::web::Query<std::collections::HashMap<String,String>>) -> impl Responder {
    let user = info.get("user").unwrap_or(&"".to_string());
    // ----- Hard‑coded secret (CWE-798) -----
    const DB_PASS: &str = "hardcoded_pass";

    // ----- SQL Injection (CWE-89) -----
    let conn = Connection::open("test.db").unwrap();
    let sql = format!("SELECT * FROM users WHERE name = '{}'", user);
    let mut stmt = conn.prepare(&sql).unwrap();
    let rows = stmt.query_map([], |row| {
        Ok(row.get::<_, String>(0)?)
    }).unwrap();
    let mut out = String::new();
    for name in rows {
        out.push_str(&name.unwrap());
        out.push('<');
        out.push('b');
        out.push('r');
        out.push('>');
    }
    HttpResponse::Ok().body(out)
}

#[get("/cmd")]
async fn cmd(info: actix_web::web::Query<std::collections::HashMap<String,String>>) -> impl Responder {
    let input = info.get("cmd").unwrap_or(&"".to_string());
    // ----- Command Injection (CWE-78) -----
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("echo {}", input))
        .output()
        .unwrap();
    HttpResponse::Ok().body(output.stdout)
}

#[get("/file")]
async fn file(info: actix_web::web::Query<std::collections::HashMap<String,String>>) -> impl Responder {
    let filename = info.get("file").unwrap_or(&"".to_string());
    // ----- Path Traversal (CWE-22) -----
    let path = format!("/var/www/uploads/{}", filename);
    let data = std::fs::read_to_string(path).unwrap_or_else(|_| "not found".to_string());
    HttpResponse::Ok().body(data)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new()
        .service(profile)
        .service(cmd)
        .service(file))
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}
EOF
)"

write_file "$BASE/rust/safe.rs" "$(cat <<'EOF'
use actix_web::{get, App, HttpResponse, HttpServer, Responder};
use rusqlite::{Connection, params};
use std::env;

#[get("/profile")]
async fn profile(info: actix_web::web::Query<std::collections::HashMap<String,String>>) -> impl Responder {
    let user = info.get("user").unwrap_or(&"".to_string());

    // Credentials from environment – no hard‑coded secret
    let db_pass = env::var("DB_PASS").unwrap_or_default();

    // ----- Parameterised query (fixes CWE-89) -----
    let conn = Connection::open("test.db").unwrap();
    let mut stmt = conn.prepare("SELECT * FROM users WHERE name = ?1").unwrap();
    let rows = stmt.query_map(params![user], |row| {
        Ok(row.get::<_, String>(0)?)
    }).unwrap();
    let mut out = String::new();
    for name in rows {
        out.push_str(&name.unwrap());
        out.push('<');
        out.push('b');
        out.push('r');
        out.push('>');
    }
    HttpResponse::Ok().body(out)
}

#[get("/cmd")]
async fn cmd(info: actix_web::web::Query<std::collections::HashMap<String,String>>) -> impl Responder {
    let input = info.get("cmd").unwrap_or(&"".to_string());
    // ----- Whitelist (fixes CWE-78) -----
    let allowed = vec!["ls", "pwd", "date"];
    let parts: Vec<&str> = input.split_whitespace().collect();
    if parts.is_empty() || !allowed.contains(&parts[0]) {
        return HttpResponse::BadRequest().body("Invalid command");
    }
    // Safe: no shell, use Command with args directly
    let output = Command::new(parts[0])
        .args(&parts[1..])
        .output()
        .unwrap();
    HttpResponse::Ok().body(output.stdout)
}

#[get("/file")]
async fn file(info: actix_web::web::Query<std::collections::HashMap<String,String>>) -> impl Responder {
    let filename = info.get("file").unwrap_or(&"".to_string());
    // ----- Path validation (fixes CWE-22) -----
    if filename.contains("..") || filename.starts_with('/') {
        return HttpResponse::BadRequest().body("Invalid file name");
    }
    let path = format!("/var/www/uploads/{}", filename);
    let data = std::fs::read_to_string(path).unwrap_or_else(|_| "not found".to_string());
    HttpResponse::Ok().body(data)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new()
        .service(profile)
        .service(cmd)
        .service(file))
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}
EOF
)"

# -----------------------------------------------------------------
# 8️⃣  .NET (C#)
# -----------------------------------------------------------------
write_file "$BASE/dotnet/VulnerableController.cs" "$(cat <<'EOF'
using Microsoft.AspNetCore.Mvc;
using System.Data.SqlClient;
using System.IO;

namespace TestApp.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class VulnerableController : ControllerBase
    {
        // ----- Hard‑coded connection string (CWE-798) -----
        private readonly string _connStr = "Server=localhost;Database=testdb;User Id=root;Password=hardcoded_password;";

        [HttpGet("profile")]
        public IActionResult Profile([FromQuery] string name)
        {
            // ----- SQL Injection (CWE-89) -----
            using var conn = new SqlConnection(_connStr);
            conn.Open();
            var cmd = new SqlCommand($"SELECT * FROM Users WHERE Name = '{name}'", conn);
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                return Ok(reader["Name"]);
            }
            return NotFound();
        }

        [HttpGet("run")]
        public IActionResult Run([FromQuery] string cmd)
        {
            // ----- Command Injection (CWE-78) -----
            var proc = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = "/c " + cmd,
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            proc.Start();
            string output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit();
            return Ok(output);
        }

        [HttpGet("file")]
        public IActionResult File([FromQuery] string filename)
        {
            // ----- Path Traversal (CWE-22) -----
            var path = Path.Combine(@"C:\Uploads", filename);
            if (System.IO.File.Exists(path))
            {
                var bytes = System.IO.File.ReadAllBytes(path);
                return File(bytes, "application/octet-stream");
            }
            return NotFound();
        }
    }
}
EOF
)"

write_file "$BASE/dotnet/SafeController.cs" "$(cat <<'EOF'
using Microsoft.AspNetCore.Mvc;
using System.Data.SqlClient;
using System.IO;
using Microsoft.Extensions.Configuration;

namespace TestApp.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class SafeController : ControllerBase
    {
        // Credentials from configuration / environment – no hard‑coded secret
        private readonly string _connStr;

        public SafeController(IConfiguration config)
        {
            _connStr = config.GetConnectionString("DefaultConnection"); // from appsettings.json / env vars
        }

        [HttpGet("profile")]
        public IActionResult Profile([FromQuery] string name)
        {
            // ----- Parameterised query (fixes CWE-89) -----
            using var conn = new SqlConnection(_connStr);
            conn.Open();
            var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = @pName", conn);
            cmd.Parameters.AddWithValue("@pName", name);
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                return Ok(reader["Name"]);
            }
            return NotFound();
        }

        [HttpGet("run")]
        public IActionResult Run([FromQuery] string cmd)
        {
            // ----- Whitelist (fixes CWE-78) -----
            var allowed = new[] { "ls", "pwd", "date" };
            var parts = cmd.Split(' ');
            if (parts.Length == 0 || !allowed.Contains(parts[0]))
                return BadRequest("Invalid command");

            var proc = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = parts[0],
                    Arguments = string.Join(" ", parts.Skip(1)),
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            proc.Start();
            string output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit();
            return Ok(output);
        }

        [HttpGet("file")]
        public IActionResult File([FromQuery] string filename)
        {
            // ----- Path validation (fixes CWE-22) -----
            if (filename.Contains("..") || Path.IsPathRooted(filename))
                return BadRequest("Invalid file name");

            var path = Path.Combine(@"C:\Uploads", filename);
            if (System.IO.File.Exists(path))
            {
                var bytes = System.IO.File.ReadAllBytes(path);
                return File(bytes, "application/octet-stream");
            }
            return NotFound();
        }
    }
}
EOF
)"

# -----------------------------------------------------------------
# 9️⃣  C++
# -----------------------------------------------------------------
write_file "$BASE/cpp/vulnerable.cpp" "$(cat <<'EOF'
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/wait.h>
#include <sqlite3.h>

int main(int argc, char* argv[])
{
    // ----- Hard‑coded secret (CWE-798) -----
    const char* db_pass = "hardcoded_password";

    sqlite3* db;
    sqlite3_open("test.db", &db);

    // Simulate a CGI‑style query string: QUERY_STRING="name=..."
    char* query = getenv("QUERY_STRING");
    if (query) {
        char* name = nullptr;
        // parse name=value
        char* token = strtok(query, "&");
        while (token) {
            if (strncmp(token, "name=", 5) == 0) {
                name = token + 5;
                break;
            }
            token = strtok(nullptr, "&");
        }
        if (name) {
            // ----- SQL Injection (CWE-89) -----
            char sql[512];
            snprintf(sql, sizeof(sql), "SELECT * FROM users WHERE name = '%s'", name);
            sqlite3_exec(db, sql, nullptr, nullptr, nullptr);
        }
    }

    // ----- Command Injection (CWE-78) -----
    char* cmd = getenv("CMD");
    if (cmd) {
        // Vulnerable: system() with unsanitized input
        std::system(cmd);
    }

    // ----- Path Traversal (CWE-22) -----
    char* file = getenv("FILE");
    if (file) {
        char path[260];
        snprintf(path, sizeof(path), "/var/www/uploads/%s", file);
        FILE* f = fopen(path, "r");
        if (f) {
            fclose(f);
        }
    }

    sqlite3_close(db);
    return 0;
}
EOF
)"

write_file "$BASE/cpp/safe.cpp" "$(cat <<'EOF'
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/wait.h>
#include <sqlite3.h>
#include <vector>
#include <string>

bool is_safe(const std::string& s) {
    // Allow only alphanumerics and underscores
    for (char c : s) {
        if (!isalnum(c) && c != '_') return false;
    }
    return true;
}

int main(int argc, char* argv[])
{
    // Credentials from environment – no hard‑coded secret
    const char* db_pass = getenv("DB_PASS"); // may be empty

    sqlite3* db;
    sqlite3_open("test.db", &db);

    char* query = getenv("QUERY_STRING");
    if (query) {
        char* name = nullptr;
        char* token = strtok(query, "&");
        while (token) {
            if (strncmp(token, "name=", 5) == 0) {
                name = token + 5;
                break;
            }
            token = strtok(nullptr, "&");
        }
        if (name && is_safe(name)) {
            // ----- Parameterised query via sqlite3_prepare (fixes CWE-89) -----
            const char* sql = "SELECT * FROM users WHERE name = ?";
            sqlite3_stmt* stmt;
            sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
            sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }

    // ----- Safe command execution (fixes CWE-78) -----
    char* cmd = getenv("CMD");
    if (cmd) {
        std::vector<std::string> args;
        char* saveptr = nullptr;
        char* tok = strtok_r(cmd, " ", &saveptr);
        while (tok) {
            args.push_back(tok);
            tok = strtok_r(nullptr, " ", &saveptr);
        }
        // whitelist
        std::vector<std::string> allowed = {"ls", "pwd", "date"};
        if (!args.empty() && std::find(allowed.begin(), allowed.end(), args[0]) != allowed.end()) {
            pid_t pid = fork();
            if (pid == 0) {
                std::vector<char*> cargs;
                for (auto& a : args) cargs.push_back(const_cast<char*>(a.c_str()));
                cargs.push_back(nullptr);
                execvp(cargs[0], cargs.data());
                _exit(127);
            } else if (pid > 0) {
                int status;
                waitpid(pid, &status, 0);
            }
        }
    }

    // ----- Path validation (fixes CWE-22) -----
    char* file = getenv("FILE");
    if (file) {
        if (std::string(file).find("..") != std::string::npos ||
            file[0] == '/') {
            // reject
        } else {
            char path[260];
            snprintf(path, sizeof(path), "/var/www/uploads/%s", file);
            FILE* f = fopen(path, "r");
            if (f) fclose(f);
        }
    }

    sqlite3_close(db);
    return 0;
}
EOF
)"

# -----------------------------------------------------------------
# 🔟  AI/ML
# -----------------------------------------------------------------
write_file "$BASE/ai_ml/vulnerable_model.py" "$(cat <<'EOF'
import pickle
import numpy as np
import tensorflow as tf
from flask import Flask, request, jsonify

app = Flask(__name__)

# ----- Hard‑coded API key for a model‑serving service (CWE-798) -----
API_KEY="***"

# Load a model from a pickle file (dangerous if the file can be tampered with)
def load_model(path):
    with open(path, "rb") as f:
        return pickle.load(f)   # CWE-502: Insecure Deserialization

model = load_model("model.pkl")   # attacker could supply a malicious pickle

@app.route("/predict", methods=["POST"])
def predict():
    # ----- No input validation – could lead to resource exhaustion or
    #       model‑stealing via crafted inputs (CWE-94: Improper Input Validation) -----
    data = request.get_json(force=True)
    vec = np.array(data["features"]).reshape(1, -1)
    pred = model.predict(vec)
    return jsonify({"prediction": pred.tolist()})

# ----- Example of a dangerous eval used to dynamically change model hyper‑params -----
@app.route("/retrain", methods=["POST"])
def retrain():
    code = request.get_json(force=True).get("code", "")
    # ----- Code Injection (CWE-94) -----
    # The attacker can inject arbitrary Python code that will be executed
    exec(code, {"model": model, "np": np})
    return jsonify({"status": "retrained"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
EOF
)"

write_file "$BASE/ai_ml/safe_model.py" "$(cat <<'EOF'
import os
import numpy as np
import tensorflow as tf
from flask import Flask, request, jsonify

app = Flask(__name__)

# ----- API key from environment – no hard‑coded secret -----
API_KEY = os.getenv("MODEL_API_KEY", "")

# Load model using TensorFlow's SavedModel format (safe)
def load_model(path):
    return tf.keras.models.load_model(path)   # no pickle

model = load_model("saved_model/")   # assume a trusted, verified model

@app.route("/predict", methods=["POST"])
def predict():
    # ----- Validate input shape and type (fixes CWE-94) -----
    data = request.get_json(force=True)
    if not isinstance(data, dict) or "features" not in data:
        return jsonify({"error": "invalid payload"}), 400
    feats = data["features"]
    if not isinstance(feats, list) or not all(isinstance(x, (int, float)) for x in feats):
        return jsonify({"error": "features must be list of numbers"}), 400
    vec = np.array(feats, dtype=np.float32).reshape(1, -1)
    pred = model.predict(vec)
    return jsonify({"prediction": pred.tolist()})

# ----- Disallow arbitrary code execution – use a controlled retraining endpoint -----
@app.route("/retrain", methods=["POST"])
def retrain():
    # Expect a JSON with new training data, not raw code
    payload = request.get_json(force=True)
    # In a real service you would validate the payload and call model.fit()
    # For this demo we just acknowledge.
    return jsonify({"status": "retraining scheduled"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
EOF
)"

# -----------------------------------------------------------------
# 1️⃣1️⃣  Ground‑truth JSON
# -----------------------------------------------------------------
write_file "$BASE/ground-truth.json" "$(cat <<'EOF'
{
  "version": "1.0",
  "results": [
    {
      "ruleId": "CWE-89",
      "message": "SQL injection via string concatenation",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "java/VulnerableServlet.java" },
            "region": { "startLine": 24 }
          }
        }
      ],
      "severity": "high"
    },
    {
      "ruleId": "CWE-78",
      "message": "Command injection via unsanitized input passed to Runtime.exec",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "java/VulnerableServlet.java" },
            "region": { "startLine": 34 }
          }
        }
      ],
      "severity": "high"
    },
    {
      "ruleId": "CWE-22",
      "message": "Path traversal – user‑controlled filename used without validation",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "java/VulnerableServlet.java" },
            "region": { "startLine": 44 }
          }
        }
      ],
      "severity": "medium"
    },
    {
      "ruleId": "CWE-798",
      "message": "Hard‑coded password in source code",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "java/VulnerableServlet.java" },
            "region": { "startLine": 12 }
          }
        }
      ],
      "severity": "medium"
    },
    {
      "ruleId": "CWE-502",
      "message": "Insecure deserialization of user‑controlled data",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "java/VulnerableServlet.java" },
            "region": { "startLine": 52 }
          }
        }
      ],
      "severity": "high"
    },

    // ----- Go -----
    {
      "ruleId": "CWE-89",
      "message": "SQL injection via string concatenation",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "go/vulnerable.go" },
            "region": { "startLine": 31 }
          }
        }
      ],
      "severity": "high"
    },
    {
      "ruleId": "CWE-78",
      "message": "Command injection via unsanitized input passed to os/exec.Command",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "go/vulnerable.go" },
            "region": { "startLine": 44 }
          }
        }
      ],
      "severity": "high"
    },
    {
      "ruleId": "CWE-22",
      "message": "Path traversal – user‑controlled filename used without validation",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "go/vulnerable.go" },
            "region": { "startLine": 55 }
          }
        }
      ],
      "severity": "medium"
    },

    // ----- Python -----
    {
      "ruleId": "CWE-798",
      "message": "Hard‑coded secret key",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "python/vulnerable_app.py" },
            "region": { "startLine": 7 }
          }
        }
      ],
      "severity": "medium"
    },
    {
      "ruleId": "CWE-89",
      "message": "SQL injection via f‑string concatenation",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "python/vulnerable_app.py" },
            "region": { "startLine": 15 }
          }
        }
      ],
      "severity": "high"
    },
    {
      "ruleId": "CWE-78",
      "message": "Command injection via shell=True + unsanitized input",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "python/vulnerable_app.py" },
            "region": { "startLine": 24 }
          }
        }
      ],
      "severity": "high"
    },
    {
      "ruleId": "CWE-502",
      "message": "Insecure deserialization via pickle.loads",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "python/vulnerable_app.py" },
            "region": { "startLine": 32 }
          }
        }
      ],
      "severity": "high"
    },
    {
      "ruleId": "CWE-94",
      "message": "Server‑side template injection (Jinja2) – render_string with unsanitized input",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "python/vulnerable_app.py" },
            "region": { "startLine": 40 }
          }
        }
      ],
      "severity": "medium"
    },

    // ----- PHP -----
    {
      "ruleId": "CWE-798",
      "message": "Hard‑coded DB password",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "php/vulnerable.php" },
            "region": { "startLine": 5 }
          }
        }
      ],
      "severity": "medium"
    },
    {
      "ruleId": "CWE-89",
      "message": "SQL injection via string concatenation in mysqli query",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "php/vulnerable.php" },
            "region": { "startLine": 14 }
          }
        }
      ],
      "severity": "high"
    },
    {
      "ruleId": "CWE-78",
      "message": "Command injection via system() with unsanitized input",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "php/vulnerable.php" },
            "region": { "startLine": 22 }
          }
        }
      ],
      "severity": "high"
    },
    {
      "ruleId": "CWE-22",
      "message": "File include with user‑controlled path (path traversal)",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "php/vulnerable.php" },
            "region": { "startLine": 28 }
          }
        }
      ],
      "severity": "medium"
    },
    {
      "ruleId": "CWE-94",
      "message": "Arbitrary code execution via eval()",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "php/vulnerable.php" },
            "region": { "startLine": 34 }
          }
        }
      ],
      "severity": "high"
    },

    // ----- Rust -----
    {
      "ruleId": "CWE-798",
      "message": "Hard‑coded database password",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "rust/vulnerable.rs" },
            "region": { "startLine": 12 }
          }
        }
      ],
      "severity": "medium"
    },
    {
      "ruleId": "CWE-89",
      "message": "SQL injection via string concatenation in rusqlite",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "rust/vulnerable.rs" },
            "region": { "startLine": 20 }
          }
        }
      ],
      "severity": "high"
    },
    {
      "ruleId": "CWE-78",
      "message": "Command injection via Command::new(\"sh\", \"-c\", user_input)",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "rust/vulnerable.rs" },
            "region": { "startLine": 33 }
          }
        }
      ],
      "severity": "high"
    },
    {
      "ruleId": "CWE-22",
      "message": "Path traversal – user‑controlled filename used without validation",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "rust/vulnerable.rs" },
            "region": { "startLine": 43 }
          }
        }
      ],
      "severity": "medium"
    },

    // ----- .NET -----
    {
      "ruleId": "CWE-798",
      "message": "Hard‑coded connection string with password",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "dotnet/VulnerableController.cs" },
            "region": { "startLine": 12 }
          }
        }
      ],
      "severity": "medium"
    },
    {
      "ruleId": "CWE-89",
      "message": "SQL injection via string concatenation in SqlCommand",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "dotnet/VulnerableController.cs" },
            "region": { "startLine": 21 }
          }
        }
      ],
      "severity": "high"
    },
    {
      "ruleId": "CWE-78",
      "message": "Command injection via Process.StartInfo with unsanitized arguments",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "dotnet/VulnerableController.cs" },
            "region": { "startLine": 33 }
          }
        }
      ],
      "severity": "high"
    },
    {
      "ruleId": "CWE-22",
      "message": "Path traversal – user‑controlled filename used without validation",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "dotnet/VulnerableController.cs" },
            "region": { "startLine": 44 }
          }
        }
      ],
      "severity": "medium"
    },

    // ----- C++ -----
    {
      "ruleId": "CWE-798",
      "message": "Hard‑coded database password",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "cpp/vulnerable.cpp" },
            "region": { "startLine": 9 }
          }
        }
      ],
      "severity": "medium"
    },
    {
      "ruleId": "CWE-89",
      "message": "SQL injection via sprintf into SQLite query",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "cpp/vulnerable.cpp" },
            "region": { "startLine": 22 }
          }
        }
      ],
      "severity": "high"
    },
    {
      "ruleId": "CWE-78",
      "message": "Command injection via system() with unsanitized input",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "cpp/vulnerable.cpp" },
            "region": { "startLine": 33 }
          }
        }
      ],
      "severity": "high"
    },
    {
      "ruleId": "CWE-22",
      "message": "Path traversal – user‑controlled filename used without validation",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "cpp/vulnerable.cpp" },
            "region": { "startLine": 42 }
          }
        }
      ],
      "severity": "medium"
    },

    // ----- AI/ML -----
    {
      "ruleId": "CWE-798",
      "message": "Hard‑coded API key for model service",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "ai_ml/vulnerable_model.py" },
            "region": { "startLine": 9 }
          }
        }
      ],
      "severity": "medium"
    },
    {
      "ruleId": "CWE-502",
      "message": "Insecure deserialization via pickle.load of model file",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "ai_ml/vulnerable_model.py" },
            "region": { "startLine": 18 }
          }
        }
      ],
      "severity": "high"
    },
    {
      "ruleId": "CWE-94",
      "message": "Improper input validation – raw JSON passed directly to model.predict",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "ai_ml/vulnerable_model.py" },
            "region": { "startLine": 28 }
          }
        }
      ],
      "severity": "medium"
    },
    {
      "ruleId": "CWE-94",
      "message": "Code injection via exec() of user‑provided string",
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": { "uri": "ai_ml/vulnerable_model.py" },
            "region": { "startLine": 38 }
          }
        }
      ],
      "severity": "high"
    }
  ]
}
EOF
)

# -----------------------------------------------------------------
# 1️⃣2️⃣  Zip the whole thing
# -----------------------------------------------------------------
ZIPNAME="vuln-test-corpus.zip"
if [ -f "$ZIPNAME" ]; then
  rm "$ZIPNAME"
fi
zip -r "$ZIPNAME" "$BASE"

echo "✅  Created $ZIPNAME"
echo "You can now scan it with R‑SecOpsX (or any other SAST/SBOM/CBOM/ABOM/AIBOM tool)."
echo "Example command (adjust to your scanner's CLI):"
echo "  R-SecOpsX scan -t $ZIPNAME -o ./report"