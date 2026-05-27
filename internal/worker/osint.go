package worker

import (
	"context"
	"log"
)

// fetchOSINTLinks collects links from external platforms (HN, Reddit) for a given CVE.
func (w *Worker) fetchOSINTLinks(ctx context.Context, cveID string) map[string]interface{} {
	data := make(map[string]interface{})

	// Hacker News
	if _, links, err := w.fetchHNMentions(ctx, cveID); err == nil {
		data["hn"] = links
	} else {
		log.Printf("Worker: Failed to fetch HN results for %s: %v", cveID, err)
	}

	// Reddit
	if _, links, err := w.fetchRedditMentions(ctx, cveID); err == nil {
		data["reddit"] = links
	} else {
		log.Printf("Worker: Failed to fetch Reddit results for %s: %v", cveID, err)
	}

	return data
}
