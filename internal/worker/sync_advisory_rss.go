package worker

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"html"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"cve-tracker/internal/models"

	"github.com/jackc/pgx/v5"
)

var (
	cveRegex          = regexp.MustCompile(`CVE-\d{4}-\d+`)
	fortiguardIDRegex = regexp.MustCompile(`FG-IR-\d{2}-\d{3}`)
)

const maxFeedBodySize = 10 << 20 // 10MB

// advisoryFeedKind selects how a feed body is decoded. The zero value is XML, so every
// existing entry keeps working unchanged.
type advisoryFeedKind int

const (
	// feedKindXML covers RSS 2.0, RSS 1.0/RDF and Atom.
	feedKindXML advisoryFeedKind = iota
	// feedKindGitHubJSON is the GitHub Advisory Database REST API, which serves JSON
	// and needs its own Accept header and an optional bearer token.
	feedKindGitHubJSON
)

type AdvisoryFeed struct {
	Name string
	URL  string
	Kind advisoryFeedKind
}

var advisoryFeeds = []AdvisoryFeed{
	{Name: "CISA Advisories", URL: "https://www.cisa.gov/cybersecurity-advisories/all.xml"},
	{Name: "CISA ICS Advisories", URL: "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"},
	{Name: "Microsoft Security Advisories", URL: "https://api.msrc.microsoft.com/update-guide/rss"},
	// /security-bulletins/rss/ answers 200 with an HTML page rather than a feed, so it
	// parsed to zero items and contributed nothing. /feed/ is the real endpoint.
	{Name: "AWS Security Bulletins", URL: "https://aws.amazon.com/security/security-bulletins/feed/"},
	{Name: "Oracle Security Alerts", URL: "https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/rss-otn-sec.xml"},
	// github.com/advisories.atom now answers 406 Not Acceptable for every Accept header
	// and with none at all, so this source is read through the REST API instead.
	{
		Name: "GitHub Advisory Database",
		URL:  "https://api.github.com/advisories?per_page=100&sort=published&direction=desc",
		Kind: feedKindGitHubJSON,
	},
	{Name: "CERT-EU Advisories", URL: "https://cert.europa.eu/publications/security-advisories-rss"},
	{Name: "Cisco PSIRT", URL: "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"},
	// /rss/psirt.xml is a 404; the PSIRT feed lives at /rss/ir.xml.
	{Name: "FortiGuard PSIRT", URL: "https://www.fortiguard.com/rss/ir.xml"},
	{Name: "Red Hat Security", URL: "https://access.redhat.com/security/data/metrics/rhsa.rss"},
	{Name: "Ubuntu Security", URL: "https://ubuntu.com/security/notices/rss.xml"},
	{Name: "ZDI Advisories", URL: "https://www.zerodayinitiative.com/rss/published/"},
}

// Support for multiple feed formats (RSS 2.0, RSS 1.0/RDF, Atom)

type GenericFeedItem struct {
	Title       string
	Link        string
	Description string
	Published   time.Time // zero if the feed omitted a usable date
}

type RSS2Feed struct {
	Items []struct {
		Title       string `xml:"title"`
		Link        string `xml:"link"`
		Description string `xml:"description"`
		PubDate     string `xml:"pubDate"`
		Date        string `xml:"date"` // dc:date, used by some RSS 2.0 publishers
	} `xml:"channel>item"`
}

type RSS1Feed struct {
	Items []struct {
		Title       string `xml:"title"`
		Link        string `xml:"link"`
		Description string `xml:"description"`
		Date        string `xml:"date"` // dc:date
	} `xml:"item"`
}

type AtomFeed struct {
	Entries []struct {
		Title string `xml:"title"`
		Link  struct {
			Href string `xml:"href,attr"`
		} `xml:"link"`
		Summary   string `xml:"summary"`
		Content   string `xml:"content"`
		Updated   string `xml:"updated"`
		Published string `xml:"published"`
	} `xml:"entry"`
}

// feedDateLayouts covers what the 12 configured feeds actually emit: RFC 1123 with and
// without a numeric zone (RSS 2.0 pubDate), RFC 3339 (Atom, dc:date), and a couple of
// non-conforming variants seen in the wild.
// githubAdvisory is the subset of api.github.com/advisories this worker consumes.
type githubAdvisory struct {
	GHSAID      string `json:"ghsa_id"`
	CVEID       string `json:"cve_id"`
	Summary     string `json:"summary"`
	Description string `json:"description"`
	HTMLURL     string `json:"html_url"`
	PublishedAt string `json:"published_at"`
	Severity    string `json:"severity"`
}

// parseGitHubAdvisories converts the REST payload into the same GenericFeedItem shape
// the XML parsers produce, so storage and CVE enrichment downstream are unchanged.
func parseGitHubAdvisories(body []byte) ([]GenericFeedItem, error) {
	var advisories []githubAdvisory
	if err := json.Unmarshal(body, &advisories); err != nil {
		return nil, err
	}

	items := make([]GenericFeedItem, 0, len(advisories))
	for _, a := range advisories {
		link := strings.TrimSpace(a.HTMLURL)
		if link == "" {
			continue
		}

		title := strings.TrimSpace(a.Summary)
		if title == "" {
			title = a.GHSAID // summary is occasionally empty on withdrawn advisories
		}
		if title == "" {
			continue
		}

		// The REST payload carries the CVE in its own field, but integrateAdvisoryCVE
		// discovers CVEs by running cveRegex over title+description. Without surfacing
		// it into the text the advisory would be stored as news yet never enrich the
		// CVE it is actually about — which is how the old Atom feed behaved, since it
		// spelled the ID out in the entry body.
		var desc strings.Builder
		if a.CVEID != "" {
			desc.WriteString(a.CVEID)
			desc.WriteByte(' ')
		}
		if a.Severity != "" {
			desc.WriteString("[" + a.Severity + "] ")
		}
		desc.WriteString(a.Description)

		items = append(items, GenericFeedItem{
			Title:       title,
			Link:        link,
			Description: desc.String(),
			Published:   parseFeedDate(a.PublishedAt),
		})
	}
	return items, nil
}

// feedDateLayouts is applied AFTER the leading weekday is stripped, which removes the
// need for variants covering "Mon, " vs "Mon " vs absent. Day is "2" rather than "02"
// because Go's "2" accepts both one- and two-digit days; the padded form does not.
// Between them these cover every shape the 12 configured feeds emit: full and
// abbreviated month names, two- and four-digit years, numeric and named zones, and
// bare ISO dates.
var feedDateLayouts = []string{
	"2 Jan 2006 15:04:05 -0700",
	"2 Jan 2006 15:04:05 MST",
	"2 Jan 2006 15:04:05",
	"2 Jan 2006 15:04 -0700",
	"2 Jan 2006 15:04 MST",
	"2 Jan 06 15:04:05 -0700",
	"2 Jan 06 15:04:05 MST",
	"2 Jan 06 15:04 -0700",
	"2 January 2006 15:04:05 -0700",
	"2 January 2006 15:04:05 MST",
	"2 January 2006 15:04:05",
	"2 January 2006",
	"2 Jan 2006",
	time.RFC3339,
	"2006-01-02T15:04:05Z0700",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
	"2006-01-02",
}

// weekdayPrefixes are stripped before parsing. Feeds vary on whether a comma follows
// and whether the weekday is present at all; normalising here keeps the layout list
// from combinatorially exploding.
var weekdayPrefixes = map[string]struct{}{
	"mon": {}, "tue": {}, "wed": {}, "thu": {}, "fri": {}, "sat": {}, "sun": {},
	"monday": {}, "tuesday": {}, "wednesday": {}, "thursday": {},
	"friday": {}, "saturday": {}, "sunday": {},
}

// trimWeekday removes a leading weekday token, with or without a trailing comma.
func trimWeekday(s string) string {
	first, rest, found := strings.Cut(s, " ")
	if !found {
		return s
	}
	if _, ok := weekdayPrefixes[strings.ToLower(strings.TrimSuffix(first, ","))]; ok {
		return rest
	}
	return s
}

// htmlTagRegex matches a single HTML element. Feed descriptions frequently arrive as
// escaped markup; this is for legibility in the rail, not for safety — html/template
// escapes the value on render regardless.
var htmlTagRegex = regexp.MustCompile(`<[^>]*>`)

// stripHTMLTags flattens feed markup to plain text and collapses the resulting
// whitespace so a summary renders as a single readable line.
func stripHTMLTags(s string) string {
	s = htmlTagRegex.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	return strings.Join(strings.Fields(s), " ")
}

// parseFeedDate returns the zero time when no layout matches; callers fall back to the
// fetch time rather than dropping the item.
func parseFeedDate(candidates ...string) time.Time {
	for _, raw := range candidates {
		// Collapse internal runs of whitespace as well as trimming: Oracle emits
		// "Tue, 21 July 2026  12:30:54" with a double space, which no layout matches.
		raw = trimWeekday(strings.Join(strings.Fields(raw), " "))
		if raw == "" {
			continue
		}
		for _, layout := range feedDateLayouts {
			if t, err := time.Parse(layout, raw); err == nil {
				return t.UTC()
			}
		}
	}
	return time.Time{}
}

func (w *Worker) syncAdvisoryRSSPeriodically(ctx context.Context) {
	// 12 hour interval, with a small initial delay
	w.waitUntilNextRun(ctx, "advisory_rss_sync", 12*time.Hour, 2*time.Minute)

	select {
	case <-ctx.Done():
		return
	default:
		w.runWithLock(ctx, "advisory_rss_sync", 30*time.Minute, w.syncAdvisoryRSS)
	}
	if w.OnAdvisoryRSSSyncDone != nil {
		w.OnAdvisoryRSSSyncDone()
	}

	ticker := w.TickerFactory(12 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.Chan():
			w.runWithLock(ctx, "advisory_rss_sync", 30*time.Minute, w.syncAdvisoryRSS)
			if w.OnAdvisoryRSSSyncDone != nil {
				w.OnAdvisoryRSSSyncDone()
			}
		}
	}
}

func (w *Worker) syncAdvisoryRSS(ctx context.Context) {
	slog.Info("Worker: [SYNC] Starting Generalized Advisory feeds synchronization", "feed_count", len(advisoryFeeds))
	for _, feed := range advisoryFeeds {
		select {
		case <-ctx.Done():
			return
		default:
			w.processAdvisoryFeed(ctx, feed)
		}
	}
	w.pruneAdvisoryNews(ctx)
	w.updateTaskStats(ctx, "advisory_rss_sync")
	slog.Info("Worker: [SYNC] Generalized Advisory feeds synchronization complete.")
}

func (w *Worker) processAdvisoryFeed(ctx context.Context, feed AdvisoryFeed) {
	slog.Debug("Worker: [DEBUG] Syncing feed", "name", feed.Name, "url", feed.URL)
	req, err := http.NewRequestWithContext(ctx, "GET", feed.URL, nil)
	if err != nil {
		slog.Error("Worker: [ERROR] Failed to create request for feed", "name", feed.Name, "error", err)
		return
	}
	if feed.Kind == feedKindGitHubJSON {
		// The REST API rejects the browser-style Accept used for the XML feeds.
		req.Header.Set("User-Agent", "vulfixx-advisory-sync")
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		// Unauthenticated callers get 60 requests/hour, which is ample at one request
		// per 12h sync, but reuse the token when one is configured for sync_github.
		if token := os.Getenv("GITHUB_TOKEN"); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "application/atom+xml, application/rss+xml, application/xml;q=0.9, */*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	}

	resp, err := w.HTTP.Do(req)
	if err != nil {
		slog.Error("Worker: [ERROR] HTTP request failed for feed", "name", feed.Name, "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Error("Worker: [ERROR] Feed returned error status", "name", feed.Name, "status", resp.StatusCode)
		return
	}

	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			slog.Error("Worker: [ERROR] Failed to create gzip reader for feed", "name", feed.Name, "error", err)
			return
		}
		defer gz.Close()
		reader = gz
	}

	body, err := io.ReadAll(io.LimitReader(reader, maxFeedBodySize))
	if err != nil {
		slog.Error("Worker: [ERROR] Failed to read feed body", "name", feed.Name, "error", err)
		return
	}

	if int64(len(body)) >= maxFeedBodySize {
		slog.Error("Worker: [ERROR] Feed body was truncated", "name", feed.Name, "max_size", maxFeedBodySize)
		return
	}

	var items []GenericFeedItem

	if feed.Kind == feedKindGitHubJSON {
		parsed, err := parseGitHubAdvisories(body)
		if err != nil {
			slog.Error("Worker: [ERROR] Failed to decode GitHub advisories", "name", feed.Name, "error", err)
			return
		}
		if len(parsed) == 0 {
			slog.Warn("Worker: [WARN] GitHub advisories returned no usable entries", "name", feed.Name)
			return
		}
		items = parsed
		w.storeAdvisoryNews(ctx, feed, items)
		w.integrateAdvisoryItems(ctx, feed, items)
		return
	}

	// Try RSS 2.0
	var rss2 RSS2Feed
	if err := xml.Unmarshal(body, &rss2); err == nil && len(rss2.Items) > 0 {
		for _, item := range rss2.Items {
			items = append(items, GenericFeedItem{
				Title:       item.Title,
				Link:        item.Link,
				Description: item.Description,
				Published:   parseFeedDate(item.PubDate, item.Date),
			})
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
				items = append(items, GenericFeedItem{
					Title:       entry.Title,
					Link:        entry.Link.Href,
					Description: desc,
					Published:   parseFeedDate(entry.Published, entry.Updated),
				})
			}
		} else {
			// Try RSS 1.0 (RDF)
			var rss1 RSS1Feed
			if err := xml.Unmarshal(body, &rss1); err == nil && len(rss1.Items) > 0 {
				for _, item := range rss1.Items {
					items = append(items, GenericFeedItem{
						Title:       item.Title,
						Link:        item.Link,
						Description: item.Description,
						Published:   parseFeedDate(item.Date),
					})
				}
			} else {
				slog.Warn("Worker: [WARN] Failed to unmarshal feed", "name", feed.Name)
				return
			}
		}
	}

	// Persist every item for the news rail before the CVE filter below. Plenty of
	// advisories are newsworthy without naming a CVE in the title or summary, and
	// the loop after this one drops those.
	w.storeAdvisoryNews(ctx, feed, items)
	w.integrateAdvisoryItems(ctx, feed, items)
}

// integrateAdvisoryItems enriches CVEs named by feed items. Items mentioning no CVE are
// skipped here; storeAdvisoryNews has already kept them for the news rail.
func (w *Worker) integrateAdvisoryItems(ctx context.Context, feed AdvisoryFeed, items []GenericFeedItem) {
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
	if item.Link == "" {
		return
	}

	tx, err := w.Pool.Begin(ctx)
	if err != nil {
		slog.Error("Worker: [ERROR] Failed to start transaction for advisory sync", "cve_id", cveID, "error", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var model models.CVE

	// Lock the row and fetch required fields for alert processing
	err = tx.QueryRow(ctx, "SELECT id, cve_id, COALESCE(description, ''), COALESCE(cvss_score, 0), COALESCE(vendor, ''), COALESCE(product, ''), \"references\", COALESCE(epss_score, 0) FROM cves WHERE cve_id = $1 FOR UPDATE", cveID).
		Scan(&model.ID, &model.CVEID, &model.Description, &model.CVSSScore, &model.Vendor, &model.Product, &model.References, &model.EPSSScore)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// CVE doesn't exist in our database; we skip it to prevent "bloat"
			return
		}
		slog.Error("Worker: [ERROR] Failed to query CVE for advisory sync", "cve_id", cveID, "error", err)
		return
	}

	// Check if this reference is already known
	refExists := slices.Contains(model.References, item.Link)

	// Extract FortiGuard advisory ID from title when processing the FortiGuard PSIRT feed
	var fortiguardUpdated bool
	var fortiguardID string
	if feed.Name == "FortiGuard PSIRT" {
		fortiguardID = fortiguardIDRegex.FindString(item.Title)
		if fortiguardID != "" {
			// Create vendor_advisories structure with fortiguard key
			fgData := map[string]interface{}{
				"advisory_id":  fortiguardID,
				"advisory_url": "https://www.fortiguard.com/psirt/" + fortiguardID,
			}
			vendorAdvisory := map[string]interface{}{
				"fortiguard": fgData,
			}
			vendorAdvisoryJSON, marshalErr := json.Marshal(vendorAdvisory)
			if marshalErr != nil {
				slog.Error("Worker: [ERROR] Failed to marshal FortiGuard vendor advisory, skipping update", "cve_id", cveID, "fg_id", fortiguardID, "error", marshalErr)
			} else {
				_, err = tx.Exec(ctx,
					"UPDATE cves SET vendor_advisories = COALESCE(vendor_advisories, '{}'::jsonb) || $1::jsonb, updated_at = NOW() WHERE cve_id = $2",
					vendorAdvisoryJSON, cveID)
				if err != nil {
					slog.Error("Worker: [ERROR] Failed to update vendor_advisories for FortiGuard advisory", "cve_id", cveID, "fg_id", fortiguardID, "error", err)
				} else {
					fortiguardUpdated = true
					slog.Info("Worker: [SYNC] Stored FortiGuard advisory in vendor_advisories", "cve_id", cveID, "fg_id", fortiguardID)
				}
			}
		}
	}

	if !refExists {
		model.References = append(model.References, item.Link)
		_, err := tx.Exec(ctx, "UPDATE cves SET \"references\" = $1, updated_at = NOW() WHERE id = $2", model.References, model.ID)
		if err != nil {
			slog.Error("Worker: [ERROR] Failed to update reference for CVE", "cve_id", cveID, "feed", feed.Name, "error", err)
			return
		}

		if err := tx.Commit(ctx); err != nil {
			slog.Error("Worker: [ERROR] Failed to commit transaction for CVE update", "cve_id", cveID, "error", err)
			return
		}

		slog.Info("Worker: [SYNC] Added new reference to existing CVE", "cve_id", cveID, "feed", feed.Name, "link", item.Link)
		// Enqueue alert for enrichment/update using the updated model
		if err := w.enqueueAlertsForCVE(ctx, model); err != nil {
			slog.Error("Worker: [ERROR] Failed to enqueue alerts for CVE", "cve_id", cveID, "error", err)
		}
	} else if fortiguardUpdated {
		// Reference already exists but FortiGuard advisory data was updated — commit that change
		if err := tx.Commit(ctx); err != nil {
			slog.Error("Worker: [ERROR] Failed to commit transaction for FortiGuard vendor_advisories update", "cve_id", cveID, "error", err)
		}
	}
}

// advisoryNewsRetention bounds how much feed history the news rail keeps. At roughly a
// dozen feeds publishing a handful of items a day this settles at a few hundred rows.
const advisoryNewsRetention = 30 * 24 * time.Hour

// advisoryNewsSummaryLimit truncates summaries at storage time. Feed descriptions are
// occasionally whole articles, and the rail only ever shows a couple of lines.
const advisoryNewsSummaryLimit = 400

// storeAdvisoryNews persists feed items for the dashboard news rail. Unlike
// integrateAdvisoryCVE this keeps items that mention no CVE, because they are still
// news. Conflicts on link are ignored, so re-reading a feed is a no-op.
func (w *Worker) storeAdvisoryNews(ctx context.Context, feed AdvisoryFeed, items []GenericFeedItem) {
	now := time.Now().UTC()

	// Column-oriented so the whole feed goes in one round trip via unnest, rather
	// than one statement per item.
	titles := make([]string, 0, len(items))
	links := make([]string, 0, len(items))
	summaries := make([]string, 0, len(items))
	published := make([]time.Time, 0, len(items))
	cveCSVs := make([]string, 0, len(items))

	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		title := strings.TrimSpace(item.Title)
		link := strings.TrimSpace(item.Link)
		if title == "" || link == "" {
			continue
		}
		// A feed repeating a link within one document would make the insert fail
		// on "affect row a second time"; ON CONFLICT does not cover that.
		if _, dup := seen[link]; dup {
			continue
		}
		seen[link] = struct{}{}

		at := item.Published
		if at.IsZero() {
			// Feed omitted a parseable date. Use fetch time so the item still shows,
			// rather than dropping it or sorting it to the epoch.
			at = now
		}
		// Feeds occasionally post-date items, which would pin them to the top of the
		// rail indefinitely.
		if at.After(now) {
			at = now
		}
		// Deliberately no lower bound here. Retention is pruneAdvisoryNews's job, and
		// filtering on age at write time would make ingestion depend on wall-clock
		// time and silently drop a legitimately older advisory.

		summary := stripHTMLTags(item.Description)
		if len(summary) > advisoryNewsSummaryLimit {
			summary = summary[:advisoryNewsSummaryLimit]
		}

		cves := slices.Compact(slices.Sorted(slices.Values(
			cveRegex.FindAllString(title+" "+item.Description, -1))))

		titles = append(titles, title)
		links = append(links, link)
		summaries = append(summaries, summary)
		published = append(published, at)
		cveCSVs = append(cveCSVs, strings.Join(cves, ","))
	}

	if len(links) == 0 {
		return
	}

	if _, err := w.Pool.Exec(ctx, `
		INSERT INTO advisory_news (feed_name, title, link, summary, published_at, cve_ids)
		SELECT $1, t.title, t.link, t.summary, t.published_at,
		       CASE WHEN t.cve_csv = '' THEN '{}'::text[] ELSE string_to_array(t.cve_csv, ',') END
		FROM unnest($2::text[], $3::text[], $4::text[], $5::timestamptz[], $6::text[])
		     AS t(title, link, summary, published_at, cve_csv)
		ON CONFLICT (link) DO NOTHING
	`, feed.Name, titles, links, summaries, published, cveCSVs); err != nil {
		slog.Error("Worker: [ERROR] Failed to store advisory news", "feed", feed.Name, "count", len(links), "error", err)
		return
	}

	slog.Debug("Worker: [SYNC] Stored advisory news items", "feed", feed.Name, "count", len(links))
}

// pruneAdvisoryNews drops items past the retention window. Called once per sync rather
// than per feed.
func (w *Worker) pruneAdvisoryNews(ctx context.Context) {
	cutoff := time.Now().UTC().Add(-advisoryNewsRetention)
	if _, err := w.Pool.Exec(ctx,
		`DELETE FROM advisory_news WHERE published_at < $1`, cutoff); err != nil {
		slog.Error("Worker: [ERROR] Failed to prune advisory news", "error", err)
	}
}
