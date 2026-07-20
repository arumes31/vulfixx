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
	cacheKey := "vulfixx:sitemap_xml"

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
	buf.Grow(150 * 1000)
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	buf.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n")

	// Static pages
	baseURL := GetBaseURL()
	var baseBuf bytes.Buffer
	_ = xml.EscapeText(&baseBuf, []byte(baseURL))
	escapedBaseURL := baseBuf.String()

	pages := []string{"", "/login", "/register"}
	for _, p := range pages {
		buf.WriteString("  <url>\n    <loc>")
		buf.WriteString(escapedBaseURL)
		buf.WriteString(p)
		buf.WriteString("</loc>\n    <changefreq>daily</changefreq>\n    <priority>0.8</priority>\n  </url>\n")
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
		timeBuf := make([]byte, 0, 10)
		defer rows.Close()
		for rows.Next() {
			var id string
			var updated time.Time
			if err := rows.Scan(&id, &updated); err != nil {
				log.Printf("Error scanning sitemap row: %v", err)
			} else {
				buf.WriteString("  <url>\n    <loc>")
				buf.WriteString(escapedBaseURL)
				buf.WriteString("/cve/")
				_ = xml.EscapeText(&buf, []byte(id))
				buf.WriteString("</loc>\n    <lastmod>")
				timeBuf = timeBuf[:0]
				timeBuf = updated.AppendFormat(timeBuf, "2006-01-02")
				buf.Write(timeBuf)
				buf.WriteString("</lastmod>\n    <changefreq>weekly</changefreq>\n    <priority>0.6</priority>\n  </url>\n")
			}
		}
		if err := rows.Err(); err != nil {
			log.Printf("Sitemap rows error: %v", err)
		}
	}

	buf.WriteString("</urlset>\n")
	res := buf.Bytes()

	// Store in Redis cache for 24 hours
	if a.Redis != nil {
		if err := a.Redis.Set(ctx, cacheKey, res, 24*time.Hour).Err(); err != nil {
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
