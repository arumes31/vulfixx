package web

import (
	"cve-tracker/internal/db"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/redis/go-redis/v9"
)

func BenchmarkSitemapHandler_Cached(b *testing.B) {
	mock, err := db.SetupTestDB()
	if err != nil {
		b.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	mr, err := miniredis.Run()
	if err != nil {
		b.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	redisClient := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	app := &App{
		Pool:  mock,
		Redis: redisClient,
	}

	// Setup: Run once to populate cache
	rows := pgxmock.NewRows([]string{"cve_id", "updated_at"})
	for i := 0; i < 1000; i++ {
		rows.AddRow("CVE-2023-1234", time.Now())
	}
	mock.ExpectQuery("SELECT cve_id, updated_at").WillReturnRows(rows)

	req, _ := http.NewRequest("GET", "/sitemap.xml", nil)
	rr := httptest.NewRecorder()
	app.SitemapHandler(rr, req)

	// Now benchmark the cached response
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		app.SitemapHandler(rr, req)
	}
}

func BenchmarkSitemapHandler_NoCache(b *testing.B) {
	mock, err := db.SetupTestDB()
	if err != nil {
		b.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := &App{
		Pool:  mock,
		Redis: nil, // Disable caching
	}

	rows := pgxmock.NewRows([]string{"cve_id", "updated_at"})
	for i := 0; i < 1000; i++ {
		rows.AddRow("CVE-2023-1234", time.Now())
	}

	req, _ := http.NewRequest("GET", "/sitemap.xml", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Mock DB call every time
		mock.ExpectQuery("SELECT cve_id, updated_at").WillReturnRows(rows)
		rr := httptest.NewRecorder()
		app.SitemapHandler(rr, req)
	}
}
