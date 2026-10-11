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
