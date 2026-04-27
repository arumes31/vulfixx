package web

import (
	"cve-tracker/internal/db"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func RobotsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = fmt.Fprintf(w, "User-agent: *\nAllow: /\nSitemap: %s/sitemap.xml\n", GetBaseURL())
}

func SitemapHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/xml")
	_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>`+"\n")
	_, _ = fmt.Fprintf(w, `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">`+"\n")

	// Static pages
	baseURL := GetBaseURL()
	pages := []string{"", "/login", "/register"}
	for _, p := range pages {
		_, _ = fmt.Fprintf(w, "  <url>\n    <loc>%s%s</loc>\n    <changefreq>daily</changefreq>\n    <priority>0.8</priority>\n  </url>\n", baseURL, p)
	}

	// Recent/Critical CVEs (Top 1000)
	rows, err := db.Pool.Query(r.Context(), `
		SELECT cve_id, updated_at 
		FROM cves 
		ORDER BY published_date DESC LIMIT 1000
	`)
	if err != nil {
		log.Printf("Sitemap error: %v", err)
	} else {
		defer rows.Close()
		for rows.Next() {
			var id string
			var updated time.Time
			if err := rows.Scan(&id, &updated); err == nil {
				_, _ = fmt.Fprintf(w, "  <url>\n    <loc>%s/cve/%s</loc>\n    <lastmod>%s</lastmod>\n    <changefreq>weekly</changefreq>\n    <priority>0.6</priority>\n  </url>\n", baseURL, id, updated.Format("2006-01-02"))
			}
		}
	}

	_, _ = fmt.Fprintf(w, "</urlset>\n")
}

func GetBaseURL() string {
	url := os.Getenv("BASE_URL")
	if url == "" {
		return "http://localhost:8080"
	}
	return strings.TrimSuffix(url, "/")
}
