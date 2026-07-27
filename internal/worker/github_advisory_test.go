package worker

import (
	"strings"
	"testing"
)

// Trimmed from a live api.github.com/advisories response. The atom feed this replaced
// answers 406 for every Accept header, so the REST API is the only working source.
const githubAdvisoriesFixture = `[
  {
    "ghsa_id": "GHSA-6vch-q96h-7gc3",
    "cve_id": "CVE-2026-12345",
    "summary": "etcd: tlsListener.acceptLoop spawns unbounded handshake goroutines",
    "description": "A remote attacker can exhaust memory by opening many TLS connections.",
    "html_url": "https://github.com/advisories/GHSA-6vch-q96h-7gc3",
    "published_at": "2026-07-24T22:40:16Z",
    "severity": "high"
  },
  {
    "ghsa_id": "GHSA-nocve-0000-0000",
    "cve_id": null,
    "summary": "Advisory with no CVE assigned",
    "description": "Still newsworthy.",
    "html_url": "https://github.com/advisories/GHSA-nocve-0000-0000",
    "published_at": "2026-07-23T10:00:00Z",
    "severity": "moderate"
  },
  {
    "ghsa_id": "GHSA-emptysummary",
    "cve_id": null,
    "summary": "",
    "description": "Withdrawn advisories sometimes carry no summary.",
    "html_url": "https://github.com/advisories/GHSA-emptysummary",
    "published_at": "2026-07-22T09:00:00Z",
    "severity": "low"
  },
  {
    "ghsa_id": "GHSA-nolink",
    "cve_id": "CVE-2026-99999",
    "summary": "Unusable without a link",
    "description": "No html_url means nothing to link to and no dedup key.",
    "html_url": "",
    "published_at": "2026-07-21T09:00:00Z",
    "severity": "low"
  }
]`

func TestParseGitHubAdvisories(t *testing.T) {
	items, err := parseGitHubAdvisories([]byte(githubAdvisoriesFixture))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// The link-less entry must be dropped: link is the ON CONFLICT dedup key.
	if len(items) != 3 {
		t.Fatalf("expected 3 usable items, got %d", len(items))
	}

	first := items[0]
	if first.Title != "etcd: tlsListener.acceptLoop spawns unbounded handshake goroutines" {
		t.Errorf("title = %q", first.Title)
	}
	if first.Link != "https://github.com/advisories/GHSA-6vch-q96h-7gc3" {
		t.Errorf("link = %q", first.Link)
	}
	if first.Published.IsZero() || first.Published.Year() != 2026 {
		t.Errorf("published_at not parsed: %v", first.Published)
	}

	// The CVE lives in its own JSON field, but integrateAdvisoryItems finds CVEs by
	// running cveRegex over title+description. If it is not surfaced into the text the
	// advisory is stored as news yet never enriches the CVE it is about.
	if got := cveRegex.FindAllString(first.Title+" "+first.Description, -1); len(got) != 1 || got[0] != "CVE-2026-12345" {
		t.Errorf("cveRegex over the item found %v; the CVE must be discoverable in the text", got)
	}
	if !strings.Contains(first.Description, "[high]") {
		t.Errorf("severity missing from description: %q", first.Description)
	}

	// A null cve_id must not produce a literal "null" or a bogus match.
	second := items[1]
	if strings.Contains(second.Description, "null") {
		t.Errorf("null cve_id leaked into description: %q", second.Description)
	}
	if got := cveRegex.FindAllString(second.Title+" "+second.Description, -1); len(got) != 0 {
		t.Errorf("expected no CVE for an unassigned advisory, got %v", got)
	}

	// Empty summary falls back to the GHSA id rather than storing a blank title,
	// which storeAdvisoryNews would drop.
	if items[2].Title != "GHSA-emptysummary" {
		t.Errorf("expected GHSA id fallback for empty summary, got %q", items[2].Title)
	}
}

func TestParseGitHubAdvisoriesRejectsNonJSON(t *testing.T) {
	// An HTML error page must be an error, not silently zero items — that is exactly
	// how the AWS feed failed unnoticed for so long.
	if _, err := parseGitHubAdvisories([]byte("<html><body>429</body></html>")); err == nil {
		t.Error("expected an error decoding a non-JSON body")
	}
	if _, err := parseGitHubAdvisories([]byte(`{"message":"API rate limit exceeded"}`)); err == nil {
		t.Error("expected an error decoding an object where an array was required")
	}
}

// The feed must be configured to use the JSON path; wiring it as XML would silently
// yield nothing.
func TestGitHubAdvisoryFeedIsConfiguredAsJSON(t *testing.T) {
	var found bool
	for _, f := range advisoryFeeds {
		if f.Name != "GitHub Advisory Database" {
			continue
		}
		found = true
		if f.Kind != feedKindGitHubJSON {
			t.Errorf("feed Kind = %v, want feedKindGitHubJSON", f.Kind)
		}
		if !strings.HasPrefix(f.URL, "https://api.github.com/advisories") {
			t.Errorf("URL = %q; github.com/advisories.atom answers 406 and must not be used", f.URL)
		}
	}
	if !found {
		t.Error("GitHub Advisory Database feed is missing from advisoryFeeds")
	}
}
