package worker

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"cve-tracker/internal/models"

	"github.com/PuerkitoBio/goquery"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

// Ensure Worker type is properly referenced from worker.go
// The Worker struct is defined in internal/worker/worker.go

// Constants for FortiGuard sync worker configuration
const (
	fortiguardRSSURL        = "https://filestore.fortinet.com/fortiguard/rss/ir.xml"
	fortiguardBaseURL       = "https://www.fortiguard.com/psirt/"
	fortiguardSyncInterval  = 12 * time.Hour
	fortiguardRateLimit     = 1 // 1 request per 4 seconds
	fortiguardRateBurst     = 1
	fortiguardHTTPTimeout   = 30 * time.Second
	fortiguardRedisTTL      = 7 * 24 * time.Hour // 7 days
	fortiguardMaxAdvisories = 50                 // max advisories to process per sync cycle
)

// FortiGuardAdvisory represents parsed data from a FortiGuard PSIRT advisory page.
type FortiGuardAdvisory struct {
	AdvisoryID       string              `json:"advisory_id"`
	Title            string              `json:"title"`
	Severity         string              `json:"severity"`
	CVSSScore        float64             `json:"cvss_score"`
	CVSSVector       string              `json:"cvss_vector"`
	Impact           string              `json:"impact"`
	AffectedProducts []FortiGuardProduct `json:"affected_products"`
	FixInfo          string              `json:"fix_info"`
	Workaround       string              `json:"workaround"`
	Description      string              `json:"description"`
	CVEIDs           []string            `json:"cve_ids"`
	URL              string              `json:"url"`
	PublishedDate    string              `json:"published_date"`
	LastUpdated      string              `json:"last_updated"`
}

// FortiGuardProduct represents a single affected product entry from FortiGuard.
type FortiGuardProduct struct {
	Name         string `json:"name"`
	VersionRange string `json:"version_range"`
}

// rssItem represents an item in the FortiGuard RSS feed.
type rssItem struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	Description string `xml:"description"`
	PubDate     string `xml:"pubDate"`
}

// rssFeed represents the FortiGuard RSS feed structure.
type rssFeed struct {
	XMLName xml.Name `xml:"rss"`
	Channel struct {
		Title       string    `xml:"title"`
		Link        string    `xml:"link"`
		Description string    `xml:"description"`
		Items       []rssItem `xml:"item"`
	} `xml:"channel"`
}

// These regex patterns are also defined in sync_advisory_rss.go, but we redefine them here
// to avoid circular dependency issues and make this worker self-contained.
var (
	fortiGuardIDRegex = regexp.MustCompile(`FG-IR-\d{2}-\d{3}`)
	cveIDRegex        = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
)

// cvssVectorRegex matches CVSS v3.x vector strings like CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
var cvssVectorRegex = regexp.MustCompile(`CVSS:3\.[01]/[A-Za-z]+:[A-Za-z](?:/[A-Za-z]+:[A-Za-z])+`)

// fortiGuardShouldRetry handles retry logic for FortiGuard HTTP requests.
func fortiGuardShouldRetry(resp *http.Response, err error, attempt int) (bool, time.Duration) {
	if err != nil {
		return true, time.Duration(float64(attempt+1) * 1.5 * float64(time.Second))
	}
	if resp == nil {
		return false, 0
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		waitTime := 30 * time.Second // Conservative default for CDN rate limits
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if seconds, errSec := strconv.Atoi(ra); errSec == nil {
				waitTime = time.Duration(seconds) * time.Second
			}
		}
		maxWait := 5 * time.Minute
		if waitTime > maxWait {
			waitTime = maxWait
		}
		return true, waitTime
	}
	if resp.StatusCode >= 500 {
		return true, time.Duration(float64(attempt+1) * 1.5 * float64(time.Second))
	}
	return false, 0
}

// syncFortiGuardPeriodically runs the FortiGuard sync worker periodically.
func (w *Worker) syncFortiguardPeriodically(ctx context.Context) {
	w.waitUntilNextRun(ctx, "fortiguard_sync", fortiguardSyncInterval, 2*time.Minute)
	w.runWithLock(ctx, "fortiguard_sync", 30*time.Minute, w.syncFortiguard)

	ticker := w.TickerFactory(fortiguardSyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.Chan():
			w.runWithLock(ctx, "fortiguard_sync", 30*time.Minute, w.syncFortiguard)
		}
	}
}

// syncFortiGuard is the main function that synchronizes FortiGuard advisories.
func (w *Worker) syncFortiguard(ctx context.Context) {
	slog.Info("Worker: [SYNC] Starting FortiGuard PSIRT synchronization...")

	// 1. Fetch RSS feed to discover advisories
	advisoryMap, err := w.fetchFortiGuardRSS(ctx)
	if err != nil {
		slog.Error("Worker: [ERROR] Failed to fetch FortiGuard RSS feed", "error", err)
		w.updateTaskStats(ctx, "fortiguard_sync")
		return
	}

	if len(advisoryMap) == 0 {
		slog.Info("Worker: [SYNC] No FortiGuard advisories found in RSS feed")
		w.updateTaskStats(ctx, "fortiguard_sync")
		return
	}

	// 2. Filter to relevant advisories (those with CVEs that exist in our database)
	advisoriesToProcess, err := w.filterRelevantAdvisories(ctx, advisoryMap)
	if err != nil {
		slog.Error("Worker: [ERROR] Failed to filter relevant FortiGuard advisories", "error", err)
		w.updateTaskStats(ctx, "fortiguard_sync")
		return
	}

	if len(advisoriesToProcess) == 0 {
		slog.Info("Worker: [SYNC] No relevant FortiGuard advisories to process")
		w.updateTaskStats(ctx, "fortiguard_sync")
		return
	}

	// Limit the number of advisories to process per cycle
	if len(advisoriesToProcess) > fortiguardMaxAdvisories {
		advisoriesToProcess = advisoriesToProcess[:fortiguardMaxAdvisories]
		slog.Info("Worker: [SYNC] Limiting FortiGuard advisories to process", "count", fortiguardMaxAdvisories)
	}

	// 3. Process each advisory: check cache, scrape if needed, update CVEs
	processedCount, err := w.processAdvisories(ctx, advisoriesToProcess)
	if err != nil {
		slog.Error("Worker: [ERROR] Failed to process FortiGuard advisories", "error", err)
	}

	w.updateTaskStats(ctx, "fortiguard_sync")
	slog.Info("Worker: [SYNC] FortiGuard synchronization complete", "processed_count", processedCount)
}

// fetchFortiGuardRSS fetches and parses the FortiGuard RSS feed.
func (w *Worker) fetchFortiGuardRSS(ctx context.Context) (map[string]struct {
	cveIDs []string
	url    string
}, error) {
	advisoryMap := make(map[string]struct {
		cveIDs []string
		url    string
	})

	resp, err := DoWithRetry(ctx, w.HTTP, RetryConfig{
		MaxRetries:  3,
		MaxWait:     30 * time.Second,
		ShouldRetry: fortiGuardShouldRetry,
		Label:       "FortiGuard RSS Fetch",
	}, func() (*http.Request, error) {
		return http.NewRequestWithContext(ctx, "GET", fortiguardRSSURL, nil)
	})

	if err != nil {
		return nil, fmt.Errorf("failed to fetch FortiGuard RSS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("FortiGuard RSS returned status %d", resp.StatusCode)
	}

	var feed rssFeed
	if err := xml.NewDecoder(resp.Body).Decode(&feed); err != nil {
		return nil, fmt.Errorf("failed to decode FortiGuard RSS: %w", err)
	}

	// Extract advisory IDs and CVE IDs from each item
	for _, item := range feed.Channel.Items {
		advisoryID := fortiGuardIDRegex.FindString(item.Title)
		if advisoryID == "" {
			continue
		}

		// Extract CVE IDs from title and description
		allText := item.Title + " " + item.Description
		cveMatches := cveIDRegex.FindAllString(allText, -1)
		var cveIDs []string
		seenCVE := make(map[string]bool)

		for _, cveID := range cveMatches {
			cveID = strings.ToUpper(cveID)
			if !seenCVE[cveID] {
				seenCVE[cveID] = true
				cveIDs = append(cveIDs, cveID)
			}
		}

		advisoryMap[advisoryID] = struct {
			cveIDs []string
			url    string
		}{
			cveIDs: cveIDs,
			url:    item.Link,
		}
	}

	return advisoryMap, nil
}

// filterRelevantAdvisories filters advisories to only those with CVEs that exist in our database.
func (w *Worker) filterRelevantAdvisories(ctx context.Context, advisoryMap map[string]struct {
	cveIDs []string
	url    string
}) ([]string, error) {
	// Build a list of all unique CVE IDs from all advisories
	allCVEIDs := make(map[string]bool)
	advisoryToCVEMap := make(map[string][]string)

	for advisoryID, data := range advisoryMap {
		if len(data.cveIDs) == 0 {
			continue
		}
		for _, cveID := range data.cveIDs {
			allCVEIDs[cveID] = true
			advisoryToCVEMap[advisoryID] = append(advisoryToCVEMap[advisoryID], cveID)
		}
	}

	if len(allCVEIDs) == 0 {
		return nil, nil
	}

	// Convert to slice for SQL query
	cveIDList := make([]string, 0, len(allCVEIDs))
	for cveID := range allCVEIDs {
		cveIDList = append(cveIDList, cveID)
	}

	// Query database to find which CVE IDs exist
	rows, err := w.Pool.Query(ctx, `
		SELECT cve_id FROM cves WHERE cve_id = ANY($1)
	`, cveIDList)
	if err != nil {
		return nil, fmt.Errorf("failed to query CVEs: %w", err)
	}
	defer rows.Close()

	existingCVEIDs := make(map[string]bool)
	rowIndex := 0
	for rows.Next() {
		var cveID string
		if err := rows.Scan(&cveID); err != nil {
			slog.Error("Worker: [ERROR] Failed to scan CVE ID from database row", "row_index", rowIndex, "error", err)
			rowIndex++
			continue
		}
		existingCVEIDs[cveID] = true
		rowIndex++
	}

	// Find advisories that have at least one CVE in our database
	relevantAdvisories := make(map[string]bool)
	for advisoryID, cveIDs := range advisoryToCVEMap {
		for _, cveID := range cveIDs {
			if existingCVEIDs[cveID] {
				relevantAdvisories[advisoryID] = true
				break
			}
		}
	}

	// Convert to slice
	advisoryList := make([]string, 0, len(relevantAdvisories))
	for advisoryID := range relevantAdvisories {
		advisoryList = append(advisoryList, advisoryID)
	}

	return advisoryList, nil
}

// processAdvisories processes a list of advisories, checking cache and scraping if needed.
func (w *Worker) processAdvisories(ctx context.Context, advisoryIDs []string) (int, error) {
	var processedCount int
	var mu sync.Mutex

	// Rate limiter: 1 request per 4 seconds
	limiter := rate.NewLimiter(rate.Every(4*time.Second), fortiguardRateBurst)
	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(fortiguardRateLimit) // Only 1 concurrent request

	for _, advisoryID := range advisoryIDs {

		g.Go(func() error {
			if err := limiter.Wait(gCtx); err != nil {
				return err
			}

			// Check Redis cache first
			advisory, err := w.getCachedAdvisory(gCtx, advisoryID)
			if err != nil {
				slog.Warn("Worker: [WARN] Failed to check FortiGuard cache", "advisory_id", advisoryID, "error", err)
				return nil // Don't fail the whole batch for cache errors
			}

			// If not in cache or cache is stale, scrape the advisory page
			if advisory == nil {
				advisoryURL := fortiguardBaseURL + advisoryID
				advisory, err = w.scrapeFortiGuardAdvisory(gCtx, advisoryURL)
				if err != nil {
					slog.Warn("Worker: [WARN] Failed to scrape FortiGuard advisory", "advisory_id", advisoryID, "error", err)
					return nil // Don't fail the whole batch for scraping errors
				}

				// Cache the scraped advisory
				if advisory != nil {
					if err := w.cacheAdvisory(gCtx, advisory); err != nil {
						slog.Warn("Worker: [WARN] Failed to cache FortiGuard advisory", "advisory_id", advisory.AdvisoryID, "error", err)
					}
				}
			}

			if advisory == nil {
				return nil // No data to process
			}

			// Update CVEs with this advisory data
			if err := w.updateCVEsWithAdvisory(gCtx, advisory); err != nil {
				slog.Warn("Worker: [WARN] Failed to update CVEs with FortiGuard advisory", "advisory_id", advisory.AdvisoryID, "error", err)
				return nil // Don't fail the whole batch for DB update errors
			}

			mu.Lock()
			processedCount++
			mu.Unlock()

			return nil
		})
	}

	// Wait for all goroutines to complete
	if err := g.Wait(); err != nil {
		return processedCount, fmt.Errorf("FortiGuard sync failed: %w", err)
	}

	return processedCount, nil
}

// scrapeFortiGuardAdvisory scrapes a FortiGuard advisory page and extracts structured data.
func (w *Worker) scrapeFortiGuardAdvisory(ctx context.Context, url string) (*FortiGuardAdvisory, error) {
	resp, err := DoWithRetry(ctx, w.HTTP, RetryConfig{
		MaxRetries:  3,
		MaxWait:     30 * time.Second,
		ShouldRetry: fortiGuardShouldRetry,
		Label:       "FortiGuard Advisory Fetch",
	}, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Vulfixx-Threat-Intel/2.0")
		return req, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to fetch FortiGuard advisory: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("FortiGuard advisory returned status %d", resp.StatusCode)
	}

	// Parse HTML with goquery
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse FortiGuard advisory HTML: %w", err)
	}

	advisory, err := parseFortiGuardAdvisory(doc, url)
	if err != nil {
		return nil, fmt.Errorf("failed to parse FortiGuard advisory: %w", err)
	}

	return advisory, nil
}

// parseFortiGuardAdvisory parses a FortiGuard advisory page using goquery.
func parseFortiGuardAdvisory(doc *goquery.Document, url string) (*FortiGuardAdvisory, error) {
	advisory := &FortiGuardAdvisory{URL: url}

	// Check if the document has any content at all
	bodyText := strings.TrimSpace(doc.Text())
	if bodyText == "" {
		return nil, fmt.Errorf("empty or invalid HTML document")
	}

	// Extract advisory ID from URL
	if parts := strings.Split(url, "/"); len(parts) > 0 {
		advisoryID := fortiGuardIDRegex.FindString(parts[len(parts)-1])
		if advisoryID != "" {
			advisory.AdvisoryID = advisoryID
		}
	}

	// Extract title from h1
	doc.Find("h1").Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		if text != "" && advisory.Title == "" {
			if advisory.AdvisoryID != "" {
				// Remove advisory ID from title if present
				text = strings.ReplaceAll(text, advisory.AdvisoryID, "")
				text = strings.TrimSpace(text)
			}
			advisory.Title = text
		}
	})

	// Extract severity from .severity-badge
	doc.Find(".severity-badge").Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		if text == "Critical" || text == "High" || text == "Medium" || text == "Low" || text == "Informational" {
			advisory.Severity = text
		}
	})

	// Extract CVSS score and vector using regex on page text
	pageText := doc.Text()
	if scoreMatch := regexp.MustCompile(`CVSS.*?(\d+\.\d+)`).FindStringSubmatch(pageText); len(scoreMatch) > 1 {
		if score, err := strconv.ParseFloat(scoreMatch[1], 64); err == nil {
			advisory.CVSSScore = score
		}
	}
	// Match CVSS vector pattern like CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
	if vectorMatch := cvssVectorRegex.FindString(pageText); vectorMatch != "" {
		advisory.CVSSVector = vectorMatch
	}

	// Extract CVE IDs from links
	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		if cveID := cveIDRegex.FindString(s.Text()); cveID != "" {
			cveID = strings.ToUpper(cveID)
			// Check if already in slice
			if !slices.Contains(advisory.CVEIDs, cveID) {
				advisory.CVEIDs = append(advisory.CVEIDs, cveID)
			}
		}
	})

	// Extract affected products from .affected-products table rows
	doc.Find(".affected-products table tr").Each(func(i int, s *goquery.Selection) {
		cells := s.Find("td")
		if cells.Length() >= 2 {
			productName := strings.TrimSpace(cells.Eq(0).Text())
			versionRange := strings.TrimSpace(cells.Eq(1).Text())
			if productName != "" && productName != "Product" && !strings.Contains(productName, "Affected") {
				advisory.AffectedProducts = append(advisory.AffectedProducts, FortiGuardProduct{
					Name:         productName,
					VersionRange: versionRange,
				})
			}
		}
	})

	// Extract impact from <strong>Impact:</strong> pattern
	doc.Find("strong, b").Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		if strings.HasPrefix(text, "Impact:") || text == "Impact" {
			// Get the text content after the strong/b element within the same parent
			parent := s.Parent()
			if parent.Length() > 0 {
				parentText := strings.TrimSpace(parent.Text())
				// Remove the label part
				impactText := strings.TrimSpace(strings.TrimPrefix(parentText, "Impact:"))
				impactText = strings.TrimSpace(strings.TrimPrefix(impactText, "Impact"))
				if impactText != "" && advisory.Impact == "" {
					advisory.Impact = impactText
				}
			}
		}
	})

	// Extract fix information from h3:contains('Solution') sibling paragraph
	doc.Find("h3, h4").Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		if text == "Solution" && advisory.FixInfo == "" {
			next := s.Next()
			if next.Length() > 0 {
				fixText := strings.TrimSpace(next.Text())
				if fixText != "" {
					advisory.FixInfo = fixText
				}
			}
		}
	})

	// Extract workaround information from h3:contains('Workaround') sibling paragraph
	doc.Find("h3, h4").Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		if text == "Workaround" && advisory.Workaround == "" {
			next := s.Next()
			if next.Length() > 0 {
				workaroundText := strings.TrimSpace(next.Text())
				if workaroundText != "" {
					advisory.Workaround = workaroundText
				}
			}
		}
	})

	// Build a set of paragraph elements that are siblings of h3/h4 headings
	// (Solution/Workaround sections) so we can skip them when looking for description
	// Key on the underlying DOM node, not the *goquery.Selection wrapper: goquery
	// creates a fresh Selection per traversal, so wrappers around the same node
	// are distinct pointers and would never compare equal.
	sectionParagraphs := make(map[interface{}]bool)
	doc.Find("h3, h4").Each(func(i int, s *goquery.Selection) {
		s.NextUntil("h1, h2, h3, h4").Each(func(j int, p *goquery.Selection) {
			if n := p.Get(0); n != nil {
				sectionParagraphs[n] = true
			}
		})
	})

	// Extract description: find the first <p> that is a direct child of <body> and is not
	// a CVSS line, not inside a Solution/Workaround section, and has substantial text.
	doc.Find("body > p").Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		if advisory.Description != "" {
			return // Already found
		}
		// Skip paragraphs that look like CVSS metadata
		if strings.HasPrefix(text, "CVSS:") || strings.HasPrefix(text, "CVSS ") {
			return
		}
		// Skip paragraphs that are part of Solution/Workaround sections
		if n := s.Get(0); n != nil && sectionParagraphs[n] {
			return
		}
		// Take the first substantial paragraph (more than 30 chars to avoid short labels)
		if len(text) > 30 {
			advisory.Description = text
		}
	})

	// Set current time as last updated if not available
	if advisory.LastUpdated == "" {
		advisory.LastUpdated = time.Now().UTC().Format(time.RFC3339)
	}

	return advisory, nil
}

// updateCVEsWithAdvisory updates all CVEs associated with a FortiGuard advisory.
func (w *Worker) updateCVEsWithAdvisory(ctx context.Context, advisory *FortiGuardAdvisory) error {
	if len(advisory.CVEIDs) == 0 {
		return nil
	}

	// Query all CVEs that match the CVE IDs in this advisory
	rows, err := w.Pool.Query(ctx, `
		SELECT id, cve_id, affected_products, vendor_advisories FROM cves WHERE cve_id = ANY($1)
	`, advisory.CVEIDs)
	if err != nil {
		return fmt.Errorf("failed to query CVEs for advisory %s: %w", advisory.AdvisoryID, err)
	}
	defer rows.Close()

	var cvesToUpdate []models.CVE
	for rows.Next() {
		var cve models.CVE
		var vendorAdvisories models.JSONBMap
		if err := rows.Scan(&cve.ID, &cve.CVEID, &cve.AffectedProducts, &vendorAdvisories); err != nil {
			slog.Warn("Worker: [WARN] Failed to scan CVE for FortiGuard update", "error", err)
			continue
		}

		// Initialize VendorAdvisories if nil from database
		if vendorAdvisories != nil {
			cve.VendorAdvisories = vendorAdvisories
		}

		// Initialize VendorAdvisories if nil
		if cve.VendorAdvisories == nil {
			cve.VendorAdvisories = make(models.JSONBMap)
		}

		// Create the FortiGuard advisory structure for vendor_advisories
		fortiAdvisory := make(map[string]interface{})
		fortiAdvisory["advisory_id"] = advisory.AdvisoryID
		fortiAdvisory["advisory_url"] = advisory.URL
		fortiAdvisory["severity"] = advisory.Severity
		fortiAdvisory["cvss_score"] = advisory.CVSSScore
		fortiAdvisory["cvss_vector"] = advisory.CVSSVector
		fortiAdvisory["impact"] = advisory.Impact
		fortiAdvisory["fix"] = advisory.FixInfo
		fortiAdvisory["workaround"] = advisory.Workaround
		fortiAdvisory["affected_products"] = advisory.AffectedProducts
		fortiAdvisory["last_scraped"] = time.Now().UTC().Format(time.RFC3339)

		// Set the FortiGuard advisory in vendor_advisories
		cve.VendorAdvisories[models.VendorFortiGuard] = fortiAdvisory

		// Enrich AffectedProducts with Fortinet products, skipping entries that
		// already exist so repeated syncs stay idempotent.
		existingProducts := make(map[string]bool, len(cve.AffectedProducts))
		for _, p := range cve.AffectedProducts {
			existingProducts[fmt.Sprintf("%s|%s|%s|%t", p.Vendor, p.Product, p.Version, p.Unconfirmed)] = true
		}
		for _, fgProduct := range advisory.AffectedProducts {
			candidate := models.AffectedProduct{
				Vendor:      "Fortinet",
				Product:     fgProduct.Name,
				Version:     fgProduct.VersionRange,
				Unconfirmed: false,
			}
			key := fmt.Sprintf("%s|%s|%s|%t", candidate.Vendor, candidate.Product, candidate.Version, candidate.Unconfirmed)
			if existingProducts[key] {
				continue
			}
			existingProducts[key] = true
			cve.AffectedProducts = append(cve.AffectedProducts, candidate)
		}

		cvesToUpdate = append(cvesToUpdate, cve)
	}

	// Skip update if no CVEs were found
	if len(cvesToUpdate) == 0 {
		return nil
	}

	// Perform batch update with vendor_advisories and affected_products
	tx, err := w.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	query := `
		UPDATE cves
		SET
			vendor_advisories = $1,
			affected_products = $2,
			updated_at = NOW()
		WHERE id = $3
	`

	for _, cve := range cvesToUpdate {
		if _, err := tx.Exec(ctx, query, cve.VendorAdvisories, cve.AffectedProducts, cve.ID); err != nil {
			slog.Error("Worker: [ERROR] Failed to update CVE with FortiGuard data", "error", err, "cve_id", cve.CVEID)
			_ = tx.Rollback(ctx)
			return fmt.Errorf("failed to update CVE %s with FortiGuard data: %w", cve.CVEID, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// getCachedAdvisory retrieves a cached FortiGuard advisory from Redis.
func (w *Worker) getCachedAdvisory(ctx context.Context, advisoryID string) (*FortiGuardAdvisory, error) {
	cacheKey := fmt.Sprintf("fortiguard:advisory:%s", advisoryID)
	cachedData, err := w.Redis.Get(ctx, cacheKey).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil // Cache miss
		}
		return nil, fmt.Errorf("failed to get FortiGuard advisory from cache: %w", err)
	}

	var advisory FortiGuardAdvisory
	if err := json.Unmarshal(cachedData, &advisory); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cached FortiGuard advisory: %w", err)
	}

	return &advisory, nil
}

// cacheAdvisory caches a FortiGuard advisory in Redis.
func (w *Worker) cacheAdvisory(ctx context.Context, advisory *FortiGuardAdvisory) error {
	cacheKey := fmt.Sprintf("fortiguard:advisory:%s", advisory.AdvisoryID)
	advisoryData, err := json.Marshal(advisory)
	if err != nil {
		return fmt.Errorf("failed to marshal FortiGuard advisory for caching: %w", err)
	}

	return w.Redis.Set(ctx, cacheKey, advisoryData, fortiguardRedisTTL).Err()
}
