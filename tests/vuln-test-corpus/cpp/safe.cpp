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
