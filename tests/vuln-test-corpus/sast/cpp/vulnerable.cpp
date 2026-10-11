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
