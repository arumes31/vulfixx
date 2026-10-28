package web

import (
	"context"
	"encoding/json"
	"log/slog"
	"strconv"
	"time"
)

// Side rails occupy the gutter beside the max-w-7xl content column on wide screens.
// The public dashboard shows news on the left and CVE intelligence on the right;
// authenticated pages show news only, because the fixed sidebar takes the left gutter.

const (
	railNewsLimit = 8
	railCVELimit  = 4

	// Most items per feed in the news rail. Keeps one high-volume publisher from
	// taking every slot; with a dozen feeds this still leaves plenty of candidates.
	railNewsPerFeed = 2

	// Advisory feeds sync roughly every 10h and the CVE syncs are hourly at most, so
	// a short cache still serves almost every request from Redis without going stale
	// in a way anyone would notice.
	railCacheTTL = 15 * time.Minute

	railNewsCacheKey  = "vulfixx:rail:news"
	railIntelCacheKey = "vulfixx:rail:intel"
)

// NewsItem is one advisory feed entry rendered in the news rail.
type NewsItem struct {
	FeedName    string    `json:"feed_name"`
	Title       string    `json:"title"`
	Link        string    `json:"link"`
	Summary     string    `json:"summary"`
	PublishedAt time.Time `json:"published_at"`
	CVEIDs      []string  `json:"cve_ids"`
}

// RailCVE is a single CVE row in the intelligence rail.
type RailCVE struct {
	CVEID     string  `json:"cve_id"`
	CVSSScore float64 `json:"cvss_score"`
	EPSSScore float64 `json:"epss_score"`
	PoCCount  int     `json:"poc_count"`
}

// RailIntel is the CVE intelligence rail shown to logged-out visitors.
//
// TopEPSS is the highest current EPSS, not the biggest recent movers: the schema keeps
// no EPSS history, so a delta cannot be computed without a new table.
type RailIntel struct {
	LatestKEV []RailCVE `json:"latest_kev"`
	TopEPSS   []RailCVE `json:"top_epss"`
	TopPoC    []RailCVE `json:"top_poc"`
}

// IsEmpty reports whether every section is empty, so callers can omit the rail
// entirely. Templates cannot do this themselves: a struct value is always truthy.
func (r RailIntel) IsEmpty() bool {
	return len(r.LatestKEV) == 0 && len(r.TopEPSS) == 0 && len(r.TopPoC) == 0
}

// cachedRail returns a cached value, or computes and stores one. A cache or query
// failure degrades to an empty rail rather than failing the page, because a decorative
// gutter must never take the dashboard down.
func cachedRail[T any](ctx context.Context, a *App, key string, load func(context.Context) (T, error), isEmpty func(T) bool) T {
	var zero T

	if a.Redis != nil {
		if raw, err := a.Redis.Get(ctx, key).Bytes(); err == nil {
			var cached T
			if json.Unmarshal(raw, &cached) == nil {
				return cached
			}
		}
	}

	value, err := load(ctx)
	if err != nil {
		slog.Warn("Side rail query failed; rendering without it", "key", key, "error", err)
		return zero
	}

	// Never cache an empty result. On a fresh install, or before the first advisory
	// sync completes, that would pin an empty rail in place for the whole TTL even
	// once the data lands.
	if a.Redis != nil && !isEmpty(value) {
		if encoded, err := json.Marshal(value); err == nil {
			_ = a.Redis.Set(ctx, key, encoded, railCacheTTL).Err()
		}
	}
	return value
}

func (a *App) loadNewsRail(ctx context.Context) ([]NewsItem, error) {
	// Cap each feed's share before taking the newest overall. Microsoft alone accounts
	// for roughly 95% of stored items and has the freshest timestamps, so a plain
	// ORDER BY published_at DESC fills every slot with one source.
	// cve_ids is narrowed to CVEs that actually exist locally. The IDs are scraped out
	// of advisory titles, and advisories routinely name CVEs before the NVD sync has
	// imported them — linking those produced chips that 404. The subquery runs over at
	// most railNewsLimit rows and the whole result is cached, so the cost is trivial.
	rows, err := a.Pool.Query(ctx, `
		SELECT ranked.feed_name, ranked.title, ranked.link, ranked.summary, ranked.published_at,
		       COALESCE(ARRAY(
		           SELECT DISTINCT c.cve_id FROM cves c WHERE c.cve_id = ANY(ranked.cve_ids)
		       ), '{}') AS cve_ids
		FROM (
			SELECT feed_name, title, link, summary, published_at, cve_ids,
			       row_number() OVER (PARTITION BY feed_name ORDER BY published_at DESC) AS rn
			FROM advisory_news
		) ranked
		WHERE ranked.rn <= $1
		ORDER BY ranked.published_at DESC
		LIMIT $2
	`, railNewsPerFeed, railNewsLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]NewsItem, 0, railNewsLimit)
	for rows.Next() {
		var n NewsItem
		if err := rows.Scan(&n.FeedName, &n.Title, &n.Link, &n.Summary, &n.PublishedAt, &n.CVEIDs); err != nil {
			return nil, err
		}
		items = append(items, n)
	}
	return items, rows.Err()
}

func (a *App) loadIntelRail(ctx context.Context) (RailIntel, error) {
	var intel RailIntel

	sections := []struct {
		target *[]RailCVE
		query  string
	}{
		{&intel.LatestKEV, `
			SELECT cve_id, COALESCE(cvss_score, 0), COALESCE(epss_score, 0), COALESCE(github_poc_count, 0)
			FROM cves WHERE cisa_kev = true
			ORDER BY published_date DESC LIMIT $1`},
		{&intel.TopEPSS, `
			SELECT cve_id, COALESCE(cvss_score, 0), COALESCE(epss_score, 0), COALESCE(github_poc_count, 0)
			FROM cves WHERE epss_score IS NOT NULL AND epss_score > 0
			ORDER BY epss_score DESC LIMIT $1`},
		{&intel.TopPoC, `
			SELECT cve_id, COALESCE(cvss_score, 0), COALESCE(epss_score, 0), COALESCE(github_poc_count, 0)
			FROM cves WHERE github_poc_count > 0
			ORDER BY github_poc_count DESC, published_date DESC LIMIT $1`},
	}

	for _, section := range sections {
		rows, err := a.Pool.Query(ctx, section.query, railCVELimit)
		if err != nil {
			return RailIntel{}, err
		}
		list := make([]RailCVE, 0, railCVELimit)
		for rows.Next() {
			var c RailCVE
			if err := rows.Scan(&c.CVEID, &c.CVSSScore, &c.EPSSScore, &c.PoCCount); err != nil {
				rows.Close()
				return RailIntel{}, err
			}
			list = append(list, c)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return RailIntel{}, err
		}
		*section.target = list
	}

	return intel, nil
}

// RailListItem is one pre-formatted row for the rail_cve_list template. Formatting the
// metric in Go keeps the branching out of the template, which cannot do it cleanly.
type RailListItem struct {
	CVEID       string
	MetricText  string
	MetricClass string
}

// RailListData wraps the rows so rail_cve_list receives a single dot value.
type RailListData struct {
	Items []RailListItem
}

// cvssToneClass mirrors the severity banding used elsewhere in the UI.
func cvssToneClass(score float64) string {
	switch {
	case score >= 9.0:
		return "text-error"
	case score >= 7.0:
		return "text-tertiary"
	case score >= 4.0:
		return "text-yellow-500"
	default:
		return "text-gray-500"
	}
}

// buildRailList renders one CVE list section. metric selects which figure is shown:
// "cvss", "epss" or "poc".
func buildRailList(cves []RailCVE, metric string) RailListData {
	items := make([]RailListItem, 0, len(cves))
	for _, c := range cves {
		item := RailListItem{CVEID: c.CVEID}
		switch metric {
		case "epss":
			item.MetricText = strconv.FormatFloat(c.EPSSScore*100, 'f', 0, 64) + "%"
			item.MetricClass = "text-tertiary"
		case "poc":
			item.MetricText = strconv.Itoa(c.PoCCount) + " PoC"
			item.MetricClass = "text-primary"
		default:
			item.MetricText = strconv.FormatFloat(c.CVSSScore, 'f', 1, 64)
			item.MetricClass = cvssToneClass(c.CVSSScore)
		}
		items = append(items, item)
	}
	return RailListData{Items: items}
}

// attachRailData populates the side rails for one render. Only dashboard handlers call
// it, so the rails never appear on Settings, Assets or the CVE detail page. base.html
// keys off the presence of these values, so omitting the call omits the rails.
func (a *App) attachRailData(ctx context.Context, renderData map[string]interface{}, loggedIn bool) {
	news := cachedRail(ctx, a, railNewsCacheKey, a.loadNewsRail,
		func(n []NewsItem) bool { return len(n) == 0 })
	if len(news) > 0 {
		renderData["RailNews"] = news
	}

	if loggedIn {
		return
	}

	intel := cachedRail(ctx, a, railIntelCacheKey, a.loadIntelRail, RailIntel.IsEmpty)
	// Only set the key when there is something to show. A struct value is always
	// truthy to text/template, so assigning an empty RailIntel would render three
	// "No data" panels instead of hiding the rail.
	if !intel.IsEmpty() {
		renderData["RailIntel"] = intel
	}
}
