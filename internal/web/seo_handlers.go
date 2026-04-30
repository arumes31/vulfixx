package web

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func (a *App) RobotsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = fmt.Fprintf(w, "User-agent: *\nAllow: /\nSitemap: %s/sitemap.xml\n", GetBaseURL())
}

func (a *App) SitemapHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cacheKey := "cvetracker:sitemap_cache"

	// Try to serve from Redis cache
	if a.Redis != nil {
		cached, err := a.Redis.Get(ctx, cacheKey).Bytes()
		if err == nil {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write(cached)
			return
		}
	}

	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	buf.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n")

	// Static pages
	baseURL := GetBaseURL()
	var baseBuf bytes.Buffer
	_ = xml.EscapeText(&baseBuf, []byte(baseURL))
	escapedBaseURL := baseBuf.String()

	pages := []string{"", "/login", "/register"}
	for _, p := range pages {
		fmt.Fprintf(&buf, "  <url>\n    <loc>%s%s</loc>\n    <changefreq>daily</changefreq>\n    <priority>0.8</priority>\n  </url>\n", escapedBaseURL, p)
	}

	// Recent/Critical CVEs (Top 1000)
	rows, err := a.Pool.Query(ctx, `
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
			if err := rows.Scan(&id, &updated); err != nil {
				log.Printf("Error scanning sitemap row: %v", err)
			} else {
				var locBuf bytes.Buffer
				_ = xml.EscapeText(&locBuf, []byte(id))
				escapedID := locBuf.String()
				fmt.Fprintf(&buf, "  <url>\n    <loc>%s/cve/%s</loc>\n    <lastmod>%s</lastmod>\n    <changefreq>weekly</changefreq>\n    <priority>0.6</priority>\n  </url>\n", escapedBaseURL, escapedID, updated.Format("2006-01-02"))
			}
		}
		if err := rows.Err(); err != nil {
			log.Printf("Sitemap rows error: %v", err)
		}
	}

	buf.WriteString("</urlset>\n")
	res := buf.Bytes()

	// Store in Redis cache for 1 hour
	if a.Redis != nil {
		if err := a.Redis.Set(ctx, cacheKey, res, 1*time.Hour).Err(); err != nil {
			log.Printf("Sitemap cache set error: %v", err)
		}
	}

	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write(res)
}

func GetBaseURL() string {
	url := os.Getenv("BASE_URL")
	if url == "" {
		return "http://localhost:8080"
	}
	return strings.TrimSuffix(url, "/")
}
