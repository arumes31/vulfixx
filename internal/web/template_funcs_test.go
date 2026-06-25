package web

import (
	"fmt"
	"html/template"
	"os"

	"testing"
	"time"

	"cve-tracker/internal/models"
)

func TestTemplateFuncs_Logic(t *testing.T) {
	app := &App{}
	funcs := app.GetTemplateFuncs()

	t.Run("formatDate", func(t *testing.T) {
		f := funcs["formatDate"].(func(time.Time) string)
		dt := time.Date(2024, time.May, 15, 0, 0, 0, 0, time.UTC)
		if got := f(dt); got != "May 15, 2024" {
			t.Errorf("expected May 15, 2024, got %s", got)
		}
	})

	t.Run("map", func(t *testing.T) {
		f := funcs["map"].(func(...interface{}) map[string]interface{})
		m := f("a", 1, "b", 2)
		if m["a"] != 1 || m["b"] != 2 {
			t.Errorf("expected map with a:1, b:2, got %v", m)
		}
		if f("a") != nil {
			t.Error("expected nil for odd number of arguments")
		}
		m2 := f(1, "a") // non-string key
		if len(m2) != 0 {
			t.Errorf("expected empty map for non-string key, got %v", m2)
		}
	})

	t.Run("contains", func(t *testing.T) {
		f := funcs["contains"].(func(string, string) bool)
		if !f("hello world", "world") {
			t.Error("expected true for contains")
		}
		if f("hello world", "foo") {
			t.Error("expected false for contains")
		}
	})

	t.Run("percent", func(t *testing.T) {
		f := funcs["percent"].(func(int, int) int)
		if f(50, 100) != 50 {
			t.Errorf("expected 50, got %d", f(50, 100))
		}
		if f(1, 0) != 0 {
			t.Errorf("expected 0, got %d", f(1, 0))
		}
	})

	t.Run("safeURL", func(t *testing.T) {
		f := funcs["safeURL"].(func(string) template.URL)
		if f("https://google.com") != "https://google.com" {
			t.Errorf("expected valid URL, got %v", f("https://google.com"))
		}
		if f("javascript:alert(1)") != "#invalid-url" {
			t.Errorf("expected #invalid-url, got %v", f("javascript:alert(1)"))
		}
		if f("/relative") != "/relative" {
			t.Errorf("expected valid relative URL, got %v", f("/relative"))
		}
		if f("//evil.com") != "#invalid-url" {
			t.Errorf("expected #invalid-url for protocol-relative, got %v", f("//evil.com"))
		}
	})

	t.Run("severity", func(t *testing.T) {
		fc := funcs["severityColor"].(func(float64) string)
		fb := funcs["severityBg"].(func(float64) string)

		cases := []struct {
			score float64
			color string
			bg    string
		}{
			{9.5, "text-red-500", "bg-red-500"},
			{7.5, "text-orange-500", "bg-orange-500"},
			{4.5, "text-yellow-500", "bg-yellow-500"},
			{2.0, "text-blue-500", "bg-blue-500"},
			{-1, "text-gray-400", "bg-gray-400"},
			{11, "text-gray-400", "bg-gray-400"},
		}

		for _, tc := range cases {
			if got := fc(tc.score); got != tc.color {
				t.Errorf("color for %f: expected %s, got %s", tc.score, tc.color, got)
			}
			if got := fb(tc.score); got != tc.bg {
				t.Errorf("bg for %f: expected %s, got %s", tc.score, tc.bg, got)
			}
		}
	})

	t.Run("vendorLinks", func(t *testing.T) {
		f := funcs["vendorLinks"].(func(string, string) []map[string]string)

		links := f("CVE-2024-1234", "This is a Microsoft Windows vulnerability")
		if len(links) == 0 || links[0]["name"] != "Microsoft Security" {
			t.Errorf("expected Microsoft link, got %v", links)
		}

		links = f("CVE-2024-5678", "RedHat Linux issue")
		if len(links) == 0 || links[0]["name"] != "RedHat Advisory" {
			t.Errorf("expected RedHat link, got %v", links)
		}

		links = f("CVE-2024-0000", "Cisco router bug")
		if len(links) == 0 || links[0]["name"] != "Cisco Advisory" {
			t.Errorf("expected Cisco link, got %v", links)
		}

		links = f("CVE-2024-1111", "Ubuntu canonical issue")
		if len(links) == 0 || links[0]["name"] != "Ubuntu Security" {
			t.Errorf("expected Ubuntu link, got %v", links)
		}

		links = f("CVE-2024-2222", "VMware ESXi vulnerability")
		if len(links) == 0 || links[0]["name"] != "VMware Advisory" {
			t.Errorf("expected VMware link, got %v", links)
		}

		// Fortinet / FortiGuard PSIRT link
		links = f("CVE-2024-388", "Fortinet FortiOS remote code execution")
		if len(links) == 0 || links[0]["name"] != "FortiGuard PSIRT" {
			t.Errorf("expected FortiGuard PSIRT link, got %v", links)
		}
		if len(links) > 0 && links[0]["url"] != "https://www.fortiguard.com/psirt?cve=CVE-2024-388" {
			t.Errorf("expected FortiGuard URL, got %s", links[0]["url"])
		}
		if len(links) > 0 && links[0]["icon"] != "shield" {
			t.Errorf("expected shield icon, got %s", links[0]["icon"])
		}

		// FortiGate keyword should also trigger Fortinet link
		links = f("CVE-2024-9999", "Vulnerability in FortiGate firewall appliance")
		if len(links) == 0 || links[0]["name"] != "FortiGuard PSIRT" {
			t.Errorf("expected FortiGuard PSIRT link for FortiGate, got %v", links)
		}

		// FortiManager keyword
		links = f("CVE-2024-5555", "FortiManager authentication bypass")
		if len(links) == 0 || links[0]["name"] != "FortiGuard PSIRT" {
			t.Errorf("expected FortiGuard PSIRT link for FortiManager, got %v", links)
		}

		// No vendor link for unrelated description
		links = f("CVE-2024-0000", "A generic software vulnerability")
		if len(links) != 0 {
			t.Errorf("expected no vendor links for generic description, got %v", links)
		}
	})

	t.Run("detectProduct", func(t *testing.T) {
		f := funcs["detectProduct"].(func(models.CVE) map[string]string)
		cve := models.CVE{
			Description: "Microsoft Windows vulnerability",
		}
		res := f(cve)
		if res == nil || res["vendor"] != "Microsoft" {
			t.Errorf("expected Microsoft, got %v", res)
		}

		cveNil := models.CVE{Description: "Unknown thing"}
		if f(cveNil) != nil {
			t.Error("expected nil for unknown product")
		}
	})

	t.Run("getLineage", func(t *testing.T) {
		f := funcs["getLineage"].(func(models.CVE) []string)
		cve := models.CVE{
			CVEID:       "CVE-2024-0001",
			Description: "Related to CVE-2024-0002",
		}
		res := f(cve)
		if len(res) != 1 || res[0] != "CVE-2024-0002" {
			t.Errorf("expected [CVE-2024-0002], got %v", res)
		}
	})

	t.Run("lower", func(t *testing.T) {
		f := funcs["lower"].(func(string) string)
		if f("HELLO") != "hello" {
			t.Errorf("expected hello, got %s", f("HELLO"))
		}
	})

	t.Run("parseCPE", func(t *testing.T) {
		f := funcs["parseCPE"].(func(string) map[string]string)
		res := f("cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*")
		if res["vendor"] != "Microsoft" {
			t.Errorf("expected Microsoft, got %s", res["vendor"])
		}
		if f("invalid") != nil {
			t.Error("expected nil for invalid CPE")
		}
	})

	t.Run("math", func(t *testing.T) {
		if funcs["add"].(func(int, int) int)(1, 2) != 3 {
			t.Error("add failed")
		}
		if funcs["subtract"].(func(int, int) int)(5, 2) != 3 {
			t.Error("subtract failed")
		}
		if funcs["multiply"].(func(float64, float64) float64)(2.0, 3.0) != 6.0 {
			t.Error("multiply failed")
		}
		if funcs["round"].(func(float64) int)(3.6) != 4 {
			t.Error("round failed")
		}
		if funcs["min"].(func(float64, float64) float64)(10, 20) != 10 {
			t.Error("min failed")
		}
		if funcs["max"].(func(float64, float64) float64)(10, 20) != 20 {
			t.Error("max failed")
		}
	})

	t.Run("GetBaseURL", func(t *testing.T) {
		f := funcs["GetBaseURL"].(func() string)

		os.Setenv("BASE_URL", "https://example.com/")
		if f() != "https://example.com" {
			t.Errorf("expected https://example.com, got %s", f())
		}

		os.Setenv("BASE_URL", "")
		if f() != "http://localhost:8080" {
			t.Errorf("expected http://localhost:8080, got %s", f())
		}
	})
}

func TestDaysSince(t *testing.T) {
	tests := []struct {
		name string
		time time.Time
		want string
	}{
		{"just now", time.Now().Add(-30 * time.Minute), "just now"},
		{"1 hour ago", time.Now().Add(-70 * time.Minute), "1 hour ago"},
		{"5 hours ago", time.Now().Add(-5 * time.Hour), "5 hours ago"},
		{"1 day ago", time.Now().Add(-25 * time.Hour), "1 day ago"},
		{"3 days ago", time.Now().Add(-3 * 24 * time.Hour), "3 days ago"},
		{"1 month ago", time.Now().Add(-35 * 24 * time.Hour), "1 month ago"},
		{"6 months ago", time.Now().Add(-180 * 24 * time.Hour), "6 months ago"},
		{"1 year ago", time.Now().Add(-370 * 24 * time.Hour), "1 year ago"},
		{"2 years ago", time.Now().Add(-800 * 24 * time.Hour), "2 years ago"},
		{"future time", time.Now().Add(1 * time.Hour), "just now"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := daysSince(tt.time)
			if got != tt.want {
				t.Errorf("daysSince(%v) = %q, want %q", tt.time, got, tt.want)
			}
		})
	}
}

func TestCVSSSeverityLabel(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{0, "N/A"},
		{3.9, "Low"},
		{4.0, "Medium"},
		{6.9, "Medium"},
		{7.0, "High"},
		{8.9, "High"},
		{9.0, "Critical"},
		{10.0, "Critical"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%.1f", tt.score), func(t *testing.T) {
			got := cvssSeverityLabel(tt.score)
			if got != tt.want {
				t.Errorf("cvssSeverityLabel(%.1f) = %q, want %q", tt.score, got, tt.want)
			}
		})
	}
}

func TestEPSSPercentileLabel(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{0, "N/A"},
		{-1, "N/A"},
		{0.0001, "0.0100% probability — Low exploit likelihood"},
		{0.001, "0.1000% probability — Moderate exploit likelihood"},
		{0.01, "1.00% probability — High exploit likelihood"},
		{0.1, "10.0% probability — Very high exploit likelihood"},
		{0.5, "50.0% probability — Extremely likely to be exploited"},
		{0.9, "90.0% probability — Extremely likely to be exploited"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%.4f", tt.score), func(t *testing.T) {
			got := epssPercentileLabel(tt.score)
			if got != tt.want {
				t.Errorf("epssPercentileLabel(%.4f) = %q, want %q", tt.score, got, tt.want)
			}
		})
	}
}

func TestExploitationSummary(t *testing.T) {
	tests := []struct {
		name           string
		cisaKEV        bool
		cisaRansomware bool
		exploitAvail   bool
		greynoiseHits  int
		githubPocCount int
		want           string
	}{
		{"no evidence", false, false, false, 0, 0, "No known exploitation evidence"},
		{"cisa kev only", true, false, false, 0, 0, "⚠️ CISA Known Exploited"},
		{"ransomware only", false, true, false, 0, 0, "⚠️ Ransomware Campaign"},
		{"greynoise only", false, false, false, 5, 0, "⚠️ Active Internet Scanning"},
		{"poc only", false, false, false, 0, 3, "⚠️ Public PoC Available"},
		{"exploit only", false, false, true, 0, 0, "⚠️ Exploit Code Available"},
		{"multiple indicators", true, true, true, 10, 2, "⚠️ CISA Known Exploited · Ransomware Campaign · Active Internet Scanning · Public PoC Available · Exploit Code Available"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := exploitationSummary(tt.cisaKEV, tt.cisaRansomware, tt.exploitAvail, tt.greynoiseHits, tt.githubPocCount)
			if got != tt.want {
				t.Errorf("exploitationSummary() = %q, want %q", got, tt.want)
			}
		})
	}
}
