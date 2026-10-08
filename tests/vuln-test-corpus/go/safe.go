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
