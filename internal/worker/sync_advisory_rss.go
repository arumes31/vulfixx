package worker

import (
	"context"
	"encoding/xml"
	"io"
	"log"
	"net/http"
	"regexp"
	"time"

	"cve-tracker/internal/models"
)

var (
	cveRegex = regexp.MustCompile(`CVE-\d{4}-\d+`)
)

type AdvisoryFeed struct {
	Name          string
	URL           string
	DefaultVendor string
}

var advisoryFeeds = []AdvisoryFeed{
	{Name: "CISA Advisories", URL: "https://www.cisa.gov/cybersecurity-advisories/all.xml"},
	{Name: "FortiGuard PSIRT", URL: "https://filestore.fortinet.com/fortiguard/rss/ir.xml", DefaultVendor: "Fortinet"},
	{Name: "Cisco PSIRT", URL: "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml", DefaultVendor: "Cisco"},
	{Name: "Red Hat Security", URL: "https://access.redhat.com/security/data/metrics/rhsa.rss", DefaultVendor: "Red Hat"},
	{Name: "Ubuntu Security", URL: "https://ubuntu.com/security/notices/rss.xml", DefaultVendor: "Ubuntu"},
	{Name: "ZDI Advisories", URL: "https://www.zerodayinitiative.com/rss/advisories/"},
}

// Support for multiple feed formats (RSS 2.0, RSS 1.0/RDF, Atom)

type GenericFeedItem struct {
	Title       string
	Link        string
	Description string
}

type RSS2Feed struct {
	Items []struct {
		Title       string `xml:"title"`
		Link        string `xml:"link"`
		Description string `xml:"description"`
	} `xml:"channel>item"`
}

type RSS1Feed struct {
	Items []struct {
		Title       string `xml:"title"`
		Link        string `xml:"link"`
		Description string `xml:"description"`
	} `xml:"item"`
}

type AtomFeed struct {
	Entries []struct {
		Title   string `xml:"title"`
		Link    struct {
			Href string `xml:"href,attr"`
		} `xml:"link"`
		Summary string `xml:"summary"`
		Content string `xml:"content"`
	} `xml:"entry"`
}

func (w *Worker) syncAdvisoryRSSPeriodically(ctx context.Context) {
	// 12 hour interval, with a small initial delay
	w.waitUntilNextRun(ctx, "advisory_rss_sync", 12*time.Hour, 2*time.Minute)
	w.syncAdvisoryRSS(ctx)

	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.syncAdvisoryRSS(ctx)
		}
	}
}

func (w *Worker) syncAdvisoryRSS(ctx context.Context) {
	log.Printf("Worker: [SYNC] Starting Generalized Advisory feeds synchronization for %d feeds...", len(advisoryFeeds))
	for _, feed := range advisoryFeeds {
		w.processAdvisoryFeed(ctx, feed)
	}
	w.updateTaskStats(ctx, "advisory_rss_sync")
	log.Println("Worker: [SYNC] Generalized Advisory feeds synchronization complete.")
}

func (w *Worker) processAdvisoryFeed(ctx context.Context, feed AdvisoryFeed) {
	log.Printf("Worker: [DEBUG] Syncing feed: %s", feed.Name)
	req, err := http.NewRequestWithContext(ctx, "GET", feed.URL, nil)
	if err != nil {
		log.Printf("Worker: [ERROR] Failed to create request for %s: %v", feed.Name, err)
		return
	}

	resp, err := w.HTTP.Do(req)
	if err != nil {
		log.Printf("Worker: [ERROR] Failed to fetch feed for %s: %v", feed.Name, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Worker: [ERROR] Feed for %s returned status %d", feed.Name, resp.StatusCode)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Worker: [ERROR] Failed to read feed body for %s: %v", feed.Name, err)
		return
	}

	var items []GenericFeedItem

	// Try RSS 2.0
	var rss2 RSS2Feed
	if err := xml.Unmarshal(body, &rss2); err == nil && len(rss2.Items) > 0 {
		for _, item := range rss2.Items {
			items = append(items, GenericFeedItem{Title: item.Title, Link: item.Link, Description: item.Description})
		}
	} else {
		// Try Atom
		var atom AtomFeed
		if err := xml.Unmarshal(body, &atom); err == nil && len(atom.Entries) > 0 {
			for _, entry := range atom.Entries {
				desc := entry.Summary
				if desc == "" {
					desc = entry.Content
				}
				items = append(items, GenericFeedItem{Title: entry.Title, Link: entry.Link.Href, Description: desc})
			}
		} else {
			// Try RSS 1.0 (RDF)
			var rss1 RSS1Feed
			if err := xml.Unmarshal(body, &rss1); err == nil && len(rss1.Items) > 0 {
				for _, item := range rss1.Items {
					items = append(items, GenericFeedItem{Title: item.Title, Link: item.Link, Description: item.Description})
				}
			} else {
				log.Printf("Worker: [WARN] Failed to unmarshal feed for %s (unknown format or empty)", feed.Name)
				return
			}
		}
	}

	for _, item := range items {
		// Extract CVEs from Title and Description
		text := item.Title + " " + item.Description
		foundCVEs := cveRegex.FindAllString(text, -1)
		
		if len(foundCVEs) == 0 {
			continue // Strictly follow user request: only sync matched data
		}

		uniqueCVEs := make(map[string]bool)
		for _, cve := range foundCVEs {
			uniqueCVEs[cve] = true
		}

		for cveID := range uniqueCVEs {
			w.integrateAdvisoryCVE(ctx, cveID, item, feed)
		}
	}
}

func (w *Worker) integrateAdvisoryCVE(ctx context.Context, cveID string, item GenericFeedItem, feed AdvisoryFeed) {
	var model models.CVE

	// Only sync if the CVE already exists in our database to prevent "bloat" from skeleton entries
	err := w.Pool.QueryRow(ctx, "SELECT id, cve_id, description, vendor, product, \"references\" FROM cves WHERE cve_id = $1", cveID).
		Scan(&model.ID, &model.CVEID, &model.Description, &model.Vendor, &model.Product, &model.References)

	if err == nil {
		// CVE exists - check if this reference is already known
		refExists := false
		for _, ref := range model.References {
			if ref == item.Link {
				refExists = true
				break
			}
		}

		if !refExists {
			model.References = append(model.References, item.Link)
			_, err := w.Pool.Exec(ctx, "UPDATE cves SET \"references\" = $1, updated_at = NOW() WHERE id = $2", model.References, model.ID)
			if err != nil {
				log.Printf("Worker: [ERROR] Failed to update %s reference for %s: %v", feed.Name, cveID, err)
			} else {
				log.Printf("Worker: [SYNC] Added %s reference to existing CVE %s", feed.Name, cveID)
				// Enqueue alert for enrichment/update
				_ = w.enqueueAlertsForCVE(ctx, model)
			}
		}
	} else {
		// CVE doesn't exist - Skip as per "no bloat" instruction
		// log.Printf("Worker: [DEBUG] Skipping unknown CVE %s found in %s RSS", cveID, feed.Name)
	}
}
