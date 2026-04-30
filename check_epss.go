package main

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	p, err := pgxpool.New(context.Background(), "postgres://postgres:postgres@localhost:5432/vulfixx")
	if err != nil {
		fmt.Println("DB connection error:", err)
		return
	}
	defer p.Close()
	var c int
	err = p.QueryRow(context.Background(), "SELECT count(*) FROM cves WHERE epss_score > 0").Scan(&c)
	if err != nil {
		fmt.Println("Query error:", err)
		return
	}
	fmt.Println("Count > 0:", c)
}
