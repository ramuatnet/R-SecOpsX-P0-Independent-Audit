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
