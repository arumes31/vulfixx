package worker

import (
	"context"
	"cve-tracker/internal/models"
	"log/slog"
	"sync"

	"golang.org/x/sync/errgroup"
)

// fetchOSINTLinks collects links from external platforms (HN, Reddit) for a given CVE.
func (w *Worker) fetchOSINTLinks(ctx context.Context, cveID string) models.JSONBMap {
	data := make(models.JSONBMap)
	var mu sync.Mutex
	var g errgroup.Group

	// Hacker News
	g.Go(func() error {
		if _, links, err := w.fetchHNMentions(ctx, cveID); err == nil {
			mu.Lock()
			data["hn"] = links
			mu.Unlock()
		} else {
			slog.Error("Worker: Failed to fetch HN results", "cve_id", cveID, "error", err)
		}
		return nil
	})

	// Reddit
	g.Go(func() error {
		if _, links, err := w.fetchRedditMentions(ctx, cveID); err == nil {
			mu.Lock()
			data["reddit"] = links
			mu.Unlock()
		} else {
			slog.Error("Worker: Failed to fetch Reddit results", "cve_id", cveID, "error", err)
		}
		return nil
	})

	_ = g.Wait()
	return data
}
