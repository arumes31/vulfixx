package web

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"cve-tracker/internal/db"
)

func railTestNews() []NewsItem {
	return []NewsItem{{
		FeedName:    "CISA ICS Advisories",
		Title:       "ICS Advisory: Siemens SIMATIC authentication bypass",
		Link:        "https://www.cisa.gov/advisory/icsa-26-001",
		Summary:     "An authentication bypass affects several SIMATIC models.",
		PublishedAt: time.Date(2026, 7, 20, 9, 0, 0, 0, time.UTC),
		CVEIDs:      []string{"CVE-2026-1111", "CVE-2026-2222"},
	}}
}

func railTestIntel() RailIntel {
	return RailIntel{
		LatestKEV: []RailCVE{{CVEID: "CVE-2026-9001", CVSSScore: 9.8}},
		TopEPSS:   []RailCVE{{CVEID: "CVE-2026-9002", EPSSScore: 0.94}},
		TopPoC:    []RailCVE{{CVEID: "CVE-2026-9003", PoCCount: 17}},
	}
}

// The rail partials are only reachable at render time, so a bad template function
// signature or field name would otherwise not surface until a real page load.
func TestRailPartialsRender(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("setup mock db: %v", err)
	}
	defer mock.Close()
	app := setupTestApp(t, mock)

	tmpl, ok := app.TemplateMap["public_dashboard.html"]
	if !ok {
		t.Fatal("public_dashboard.html not registered")
	}

	t.Run("news", func(t *testing.T) {
		var buf bytes.Buffer
		data := map[string]interface{}{"RailNews": railTestNews()}
		if err := tmpl.ExecuteTemplate(&buf, "rail_news", data); err != nil {
			t.Fatalf("rail_news failed to render: %v", err)
		}
		out := buf.String()
		for _, want := range []string{
			"CISA ICS Advisories",
			"Siemens SIMATIC authentication bypass",
			"https://www.cisa.gov/advisory/icsa-26-001",
			`href="/cve/CVE-2026-1111"`,
			`href="/cve/CVE-2026-2222"`,
			"Jul 20",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("rail_news output missing %q", want)
			}
		}
	})

	t.Run("news empty state", func(t *testing.T) {
		var buf bytes.Buffer
		if err := tmpl.ExecuteTemplate(&buf, "rail_news", map[string]interface{}{"RailNews": []NewsItem{}}); err != nil {
			t.Fatalf("rail_news failed on empty: %v", err)
		}
		if !strings.Contains(buf.String(), "No advisories yet") {
			t.Error("expected empty state copy")
		}
	})

	t.Run("intel", func(t *testing.T) {
		var buf bytes.Buffer
		data := map[string]interface{}{"RailIntel": railTestIntel()}
		if err := tmpl.ExecuteTemplate(&buf, "rail_intel", data); err != nil {
			t.Fatalf("rail_intel failed to render: %v", err)
		}
		out := buf.String()
		for _, want := range []string{
			"Latest in KEV", "Highest EPSS", "Exploit Activity",
			"CVE-2026-9001", "9.8",
			"CVE-2026-9002", "94%",
			"CVE-2026-9003", "17 PoC",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("rail_intel output missing %q", want)
			}
		}
	})

	// The escaping fix on main removed the marshal helper; make sure a hostile feed
	// title cannot break out through the rail.
	t.Run("news escapes hostile content", func(t *testing.T) {
		hostile := railTestNews()
		hostile[0].Title = `</a><script>alert(1)</script>`
		hostile[0].Link = "javascript:alert(1)"

		var buf bytes.Buffer
		if err := tmpl.ExecuteTemplate(&buf, "rail_news", map[string]interface{}{"RailNews": hostile}); err != nil {
			t.Fatalf("render failed: %v", err)
		}
		out := buf.String()
		if strings.Contains(out, "<script>alert(1)</script>") {
			t.Error("feed title was not escaped")
		}
		if strings.Contains(out, `href="javascript:alert(1)"`) {
			t.Error("javascript: URL was not neutralised by safeURL")
		}
	})
}

func TestBuildRailList(t *testing.T) {
	tests := []struct {
		metric    string
		in        RailCVE
		wantText  string
		wantClass string
	}{
		{"cvss", RailCVE{CVEID: "A", CVSSScore: 9.8}, "9.8", "text-error"},
		{"cvss", RailCVE{CVEID: "B", CVSSScore: 7.4}, "7.4", "text-tertiary"},
		{"cvss", RailCVE{CVEID: "C", CVSSScore: 5.0}, "5.0", "text-yellow-500"},
		{"cvss", RailCVE{CVEID: "D", CVSSScore: 2.1}, "2.1", "text-gray-500"},
		{"epss", RailCVE{CVEID: "E", EPSSScore: 0.9412}, "94%", "text-tertiary"},
		{"epss", RailCVE{CVEID: "F", EPSSScore: 0.004}, "0%", "text-tertiary"},
		{"poc", RailCVE{CVEID: "G", PoCCount: 17}, "17 PoC", "text-primary"},
	}
	for _, tt := range tests {
		got := buildRailList([]RailCVE{tt.in}, tt.metric)
		if len(got.Items) != 1 {
			t.Fatalf("expected 1 item, got %d", len(got.Items))
		}
		if got.Items[0].MetricText != tt.wantText {
			t.Errorf("%s %s: text = %q, want %q", tt.metric, tt.in.CVEID, got.Items[0].MetricText, tt.wantText)
		}
		if got.Items[0].MetricClass != tt.wantClass {
			t.Errorf("%s %s: class = %q, want %q", tt.metric, tt.in.CVEID, got.Items[0].MetricClass, tt.wantClass)
		}
	}

	if got := buildRailList(nil, "cvss"); len(got.Items) != 0 {
		t.Errorf("nil input should yield no items, got %d", len(got.Items))
	}
}
