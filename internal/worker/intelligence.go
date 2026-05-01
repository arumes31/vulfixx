package worker

import (
	"context"
	"cve-tracker/internal/models"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

func (w *Worker) syncIntelligencePeriodically(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			log.Println("Worker: Starting Intelligence Sync (Social Sentiment & Duplicate Detection)...")
			if err := w.processIntelligence(ctx); err != nil {
				log.Printf("Worker: Intelligence sync error: %v", err)
			}
		}
	}
}

func (w *Worker) processIntelligence(ctx context.Context) error {
	// Fetch top 100 recent/critical CVEs to update intelligence for
	rows, err := w.Pool.Query(ctx, `
		SELECT id, cve_id, description, COALESCE(cvss_score, 0), osint_data 
		FROM cves 
		ORDER BY published_date DESC, id DESC LIMIT 100
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var cves []models.CVE
	for rows.Next() {
		var c models.CVE
		var osintJSON []byte
		if err := rows.Scan(&c.ID, &c.CVEID, &c.Description, &c.CVSSScore, &osintJSON); err != nil {
			continue
		}
		_ = json.Unmarshal(osintJSON, &c.OSINTData)
		if c.OSINTData == nil {
			c.OSINTData = make(map[string]interface{})
		}
		cves = append(cves, c)
	}

	for _, c := range cves {
		// 1. Social Sentiment (Reddit & HN)
		w.updateSocialSentiment(ctx, &c)

		// 2. Duplicate Detection (Simplified)
		w.detectDuplicates(ctx, &c)

		// Update DB
		osintData, _ := json.Marshal(c.OSINTData)
		_, err = w.Pool.Exec(ctx, "UPDATE cves SET osint_data = $1 WHERE id = $2", osintData, c.ID)
		if err != nil {
			log.Printf("Worker: Failed to update OSINT data for %s: %v", c.CVEID, err)
		}
		
		// Throttle to avoid rate limits
		time.Sleep(500 * time.Millisecond)
	}

	return nil
}

func (w *Worker) updateSocialSentiment(ctx context.Context, c *models.CVE) {
	// Hacker News Mentions
	hnURL := fmt.Sprintf("https://hn.algolia.com/api/v1/search?query=%s&tags=story", c.CVEID)
	var hnData struct {
		NbHits int `json:"nbHits"`
	}
	if err := w.getJSON(hnURL, &hnData); err == nil {
		c.OSINTData["hn_mentions"] = hnData.NbHits
	}

	// Reddit Mentions (Search)
	redditURL := fmt.Sprintf("https://www.reddit.com/search.json?q=%s&sort=new&limit=10", c.CVEID)
	req, _ := http.NewRequestWithContext(ctx, "GET", redditURL, nil)
	req.Header.Set("User-Agent", "Vulfixx/2.0 (Threat Intelligence Bot)")
	
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		defer resp.Body.Close()
		var redditData struct {
			Data struct {
				Children []interface{} `json:"children"`
			} `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&redditData); err == nil {
			c.OSINTData["reddit_mentions"] = len(redditData.Data.Children)
		}
	}

	// Sentiment Score Calculation (Simplified Heat Score)
	hnCount, _ := c.OSINTData["hn_mentions"].(int)
	redditCount, _ := c.OSINTData["reddit_mentions"].(int)
	githubCount := c.GitHubPoCCount
	
	heatScore := (float64(hnCount) * 2.0) + (float64(redditCount) * 1.5) + (float64(githubCount) * 5.0)
	c.OSINTData["heat_score"] = heatScore
}

func (w *Worker) detectDuplicates(ctx context.Context, c *models.CVE) {
	// Simple duplicate detection: Look for CVEs with similar descriptions published around the same time
	// or mentions of the same base vulnerability ID in description.
	
	// This is a placeholder for more complex logic. 
	// For now, we'll look for other CVEs with the same CWE and similar CVSS.
	if c.CWEID == "" || c.CWEID == "NVD-CWE-noinfo" {
		return
	}

	var duplicateIDs []string
	rows, err := w.Pool.Query(ctx, `
		SELECT cve_id FROM cves 
		WHERE cwe_id = $1 AND id != $2 AND cvss_score = $3 AND published_date > $4
		LIMIT 5
	`, c.CWEID, c.ID, c.CVSSScore, c.PublishedDate.AddDate(0, 0, -7))
	
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var dupID string
			if err := rows.Scan(&dupID); err == nil {
				duplicateIDs = append(duplicateIDs, dupID)
			}
		}
	}
	
	if len(duplicateIDs) > 0 {
		c.OSINTData["similar_threats"] = duplicateIDs
	}
}

func (w *Worker) getJSON(url string, target interface{}) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(target)
}
