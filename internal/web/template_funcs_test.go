package web

import (
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
