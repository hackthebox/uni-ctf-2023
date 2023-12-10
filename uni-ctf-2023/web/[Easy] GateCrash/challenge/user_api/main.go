package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var allowedUserAgents = []string{
	"Mozilla/7.0",
	"ChromeBot/9.5",
	"SafariX/12.2",
	"QuantumBreeze/3.0",
	"EdgeWave/5.1",
	"Dragonfly/8.0",
	"LynxProwler/2.7",
	"NavigatorX/4.3",
	"BraveCat/1.8",
	"OceanaBrowser/6.5",
}

const (
	sqlitePath = "./user.db"
	webPort    = 9090
)

type User struct {
	ID       int
	Username string
	Password string
}

func randomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func seedDatabase() {
	createTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		password TEXT NOT NULL
	);
	`

	_, err := db.Exec(createTable)
	if err != nil {
		log.Fatal(err)
	}

	for i := 0; i < 10; i++ {
		newUser, _ := randomHex(32)
		newPass, _ := randomHex(32)

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
		if err != nil {
			fmt.Println(err)
			return
		}

		_, err = db.Exec("INSERT INTO users (username, password) VALUES ('" + newUser + "', '" + string(hashedPassword) + "');")
		if err != nil {
			fmt.Println(err)
			return
		}
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	found := false
	for _, userAgent := range allowedUserAgents {
		if strings.Contains(r.Header.Get("User-Agent"), userAgent) {
			found = true
			break
		}
	}

	if !found {
		http.Error(w, "Browser not supported", http.StatusNotAcceptable)
		return
	}

	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	userPassword := user.Password

	row := db.QueryRow("SELECT * FROM users WHERE username='" + user.Username + "';")
	err = row.Scan(&user.ID, &user.Username, &user.Password)
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(userPassword))
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Login successful")
}

func main() {
	var err error
	db, err = sql.Open("sqlite3", sqlitePath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	seedDatabase()

	r := mux.NewRouter()
	r.HandleFunc("/login", loginHandler).Methods("POST")

	http.Handle("/", r)
	fmt.Println("Server is running on " + strconv.Itoa(webPort))
	http.ListenAndServe(":"+strconv.Itoa(webPort), nil)
}
