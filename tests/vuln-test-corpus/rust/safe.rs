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
