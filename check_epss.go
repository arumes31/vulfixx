package main

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		fmt.Println("DATABASE_URL environment variable is not set")
		os.Exit(1)
	}

	p, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		fmt.Println("DB connection error:", err)
		os.Exit(1)
	}
	defer p.Close()
	var c int
	err = p.QueryRow(context.Background(), "SELECT count(*) FROM cves WHERE epss_score > 0").Scan(&c)
	if err != nil {
		fmt.Println("Query error:", err)
		os.Exit(1)
	}
	fmt.Println("Count > 0:", c)
}
