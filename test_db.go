package main

import (
    "cve-tracker/internal/db"
    "fmt"
    "os"
)

func main() {
    os.Setenv("DB_HOST", "localhost")
    os.Setenv("DB_PORT", "5432")
    os.Setenv("DB_USER", "cveuser")
    os.Setenv("DB_PASSWORD", "cvepass")
    os.Setenv("DB_NAME", "cvetracker")
    err := db.InitDB()
    fmt.Println(err)
}
