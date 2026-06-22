package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"time"

	"cve-tracker/internal/models"

	"github.com/jackc/pgx/v5"
)

var githubSyncDelay = 7 * time.Second

func (w *Worker) syncGitHubBuzzPeriodically(ctx context.Context) {
	w.waitUntilNextRun(ctx, "github_buzz_sync", 4*time.Hour, 1*time.Minute)
	w.runWithLock(ctx, "github_buzz_sync", 2*time.Hour, w.syncGitHubBuzz)

	ticker := w.TickerFactory(4 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.Chan():
			w.runWithLock(ctx, "github_buzz_sync", 2*time.Hour, w.syncGitHubBuzz)
		}
	}
}

type githubUpdateItem struct {
	cveID      string
	totalCount int
	pocRepos   models.GitHubPoCRepos
}

// githubSearchResponse represents the full GitHub Search API response.
type githubSearchResponse struct {
	TotalCount int `json:"total_count"`
	Items      []struct {
		HTMLURL  string `json:"html_url"`
		FullName string `json:"full_name"`
		Stars    int    `json:"stargazers_count"`
		//nolint:tagliatelle // GitHub API uses snake_case
		Description string `json:"description"`
		UpdatedAt   string `json:"updated_at"`
	} `json:"items"`
}

func (w *Worker) syncGitHubBuzz(ctx context.Context) {
	slog.Info("Worker: [SYNC] Starting GitHub Social Buzz synchronization...")

	rows, err := w.Pool.Query(ctx, "SELECT cve_id FROM cves WHERE published_date > NOW() - INTERVAL '14 days' ORDER BY published_date DESC")
	if err != nil {
		slog.Error("Worker: [ERROR] Failed to fetch CVEs for GitHub sync", "error", err)
		return
	}
	defer rows.Close()

	var cveIDs []string
	for rows.Next() {
		var cveID string
		if err := rows.Scan(&cveID); err != nil {
			slog.Error("Worker: Error scanning CVE row for GitHub sync", "error", err)
			continue
		}
		cveIDs = append(cveIDs, cveID)
	}
	if err := rows.Err(); err != nil {
		slog.Error("Worker: [ERROR] Row iteration error in syncGitHubBuzz", "error", err)
	}

	start := time.Now()
	var pendingUpdates []githubUpdateItem

CVELoop:
	for _, cveID := range cveIDs {
		select {
		case <-ctx.Done():
			goto executeRemaining
		default:
		}

		var ghResp githubSearchResponse

		githubURL := fmt.Sprintf("https://api.github.com/search/repositories?q=%s&sort=stars&order=desc&per_page=5", cveID)
		resp, err := DoWithRetry(ctx, w.HTTP, RetryConfig{
			MaxRetries:  3,
			MaxWait:     5 * time.Minute,
			ShouldRetry: githubShouldRetry,
			Label:       "GitHub Buzz Sync",
		}, func() (*http.Request, error) {
			req, err := http.NewRequestWithContext(ctx, "GET", githubURL, nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Accept", "application/vnd.github.v3+json")
			req.Header.Set("User-Agent", "Vulfixx-Threat-Intel")
			if token := os.Getenv("GITHUB_TOKEN"); token != "" {
				req.Header.Set("Authorization", "token "+token)
			}
			return req, nil
		})
		if err != nil {
			slog.Error("Worker: [ERROR] GitHub request failed after retries", "cve_id", cveID, "error", err)
			continue CVELoop
		}
		if resp == nil {
			continue CVELoop
		}

		if resp.StatusCode != http.StatusOK {
			slog.Warn("Worker: [WARN] GitHub API returned non-OK status", "status", resp.StatusCode, "cve_id", cveID)
			_ = resp.Body.Close()
			continue CVELoop
		}

		err = json.NewDecoder(resp.Body).Decode(&ghResp)
		_ = resp.Body.Close()
		if err != nil {
			slog.Error("Worker: [ERROR] Failed to decode GitHub response", "cve_id", cveID, "error", err)
			continue CVELoop
		}

		// Extract top 5 PoC repos sorted by stars (API already sorted by stars desc)
		var topRepos models.GitHubPoCRepos
		maxRepos := 5
		if len(ghResp.Items) < maxRepos {
			maxRepos = len(ghResp.Items)
		}
		for j := 0; j < maxRepos; j++ {
			item := ghResp.Items[j]
			desc := item.Description
			runes := []rune(desc)
			if len(runes) > 100 {
				desc = string(runes[:100])
			}
			topRepos = append(topRepos, models.GitHubPoCRepo{
				URL:         item.HTMLURL,
				Name:        item.FullName,
				Stars:       item.Stars,
				Description: desc,
				UpdatedAt:   item.UpdatedAt,
			})
		}
		// Sort by stars descending (should already be, but ensure)
		sort.Slice(topRepos, func(i, j int) bool {
			return topRepos[i].Stars > topRepos[j].Stars
		})

		pendingUpdates = append(pendingUpdates, githubUpdateItem{cveID: cveID, totalCount: ghResp.TotalCount, pocRepos: topRepos})
		if len(pendingUpdates) >= 50 {
			w.updateGitHubBatch(ctx, pendingUpdates)
			pendingUpdates = nil
		}

		select {
		case <-ctx.Done():
			goto executeRemaining
		case <-time.After(githubSyncDelay):
		}
	}

executeRemaining:
	if len(pendingUpdates) > 0 {
		w.updateGitHubBatch(ctx, pendingUpdates)
	}

	w.updateTaskStats(ctx, "github_buzz_sync")
	slog.Info("Worker: [SYNC] GitHub Social Buzz synchronization complete.", "duration", time.Since(start))
}

func (w *Worker) updateGitHubBatch(ctx context.Context, updates []githubUpdateItem) {
	if len(updates) == 0 {
		return
	}

	tx, err := w.Pool.Begin(ctx)
	if err != nil {
		slog.Error("Worker: [ERROR] Failed to begin transaction for GitHub updates", "error", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	query := "UPDATE cves SET github_poc_count = $1, github_poc_repos = $2 WHERE cve_id = $3"
	batch := &pgx.Batch{}
	for _, up := range updates {
		batch.Queue(query, up.totalCount, up.pocRepos, up.cveID)
	}

	br := tx.SendBatch(ctx, batch)
	if br != nil {
		defer br.Close()
		for _, up := range updates {
			if _, err := br.Exec(); err != nil {
				slog.Error("Worker: [ERROR] Failed to update GitHub buzz in DB via batch", "cve_id", up.cveID, "error", err)
			}
		}
	} else {
		// Fallback for pgxmock test compatibility
		for _, up := range updates {
			if _, err := tx.Exec(ctx, query, up.totalCount, up.pocRepos, up.cveID); err != nil {
				slog.Error("Worker: [ERROR] Failed to update GitHub buzz in DB", "cve_id", up.cveID, "error", err)
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		slog.Error("Worker: [ERROR] Failed to commit GitHub updates", "error", err)
	}
}

func githubShouldRetry(resp *http.Response, err error, attempt int) (bool, time.Duration) {
	if err != nil {
		return true, time.Duration(math.Pow(2, float64(attempt+1))) * time.Second
	}
	if resp == nil {
		return false, 0
	}

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		var waitDur time.Duration
		if reset := resp.Header.Get("X-RateLimit-Reset"); reset != "" {
			if ts, err := strconv.ParseInt(reset, 10, 64); err == nil {
				waitDur = time.Until(time.Unix(ts, 0))
				if waitDur < 0 {
					waitDur = 0
				}
			}
		}
		if waitDur == 0 {
			waitDur = time.Duration(math.Pow(2, float64(attempt+1))) * time.Second
		}
		return true, waitDur
	}

	if resp.StatusCode >= 500 {
		return true, time.Duration(math.Pow(2, float64(attempt+1))) * time.Second
	}

	return false, 0
}
