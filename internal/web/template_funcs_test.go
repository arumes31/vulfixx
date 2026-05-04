package web

import (
	"html/template"
	"testing"
)

func TestTemplateFuncs_Logic(t *testing.T) {
	app := &App{}
	funcs := app.GetTemplateFuncs()

	t.Run("map", func(t *testing.T) {
		f := funcs["map"].(func(...interface{}) map[string]interface{})
		m := f("a", 1, "b", 2)
		if m["a"] != 1 || m["b"] != 2 {
			t.Errorf("expected map with a:1, b:2, got %v", m)
		}
		if f("a") != nil {
			t.Error("expected nil for odd number of arguments")
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
		
		if fc(9.5) != "text-red-500" { t.Errorf("expected red for 9.5, got %s", fc(9.5)) }
		if fb(9.5) != "bg-red-500" { t.Errorf("expected red for 9.5, got %s", fb(9.5)) }
		
		if fc(7.5) != "text-orange-500" { t.Errorf("expected orange for 7.5, got %s", fc(7.5)) }
		if fc(4.5) != "text-yellow-500" { t.Errorf("expected yellow for 4.5, got %s", fc(4.5)) }
		if fc(2.0) != "text-blue-500" { t.Errorf("expected blue for 2.0, got %s", fc(2.0)) }
		if fc(-1) != "text-gray-400" { t.Errorf("expected gray for -1, got %s", fc(-1)) }
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
		if funcs["add"].(func(int, int) int)(1, 2) != 3 { t.Error("add failed") }
		if funcs["subtract"].(func(int, int) int)(5, 2) != 3 { t.Error("subtract failed") }
		if funcs["multiply"].(func(float64, float64) float64)(2.0, 3.0) != 6.0 { t.Error("multiply failed") }
		if funcs["round"].(func(float64) int)(3.6) != 4 { t.Error("round failed") }
		if funcs["min"].(func(float64, float64) float64)(10, 20) != 10 { t.Error("min failed") }
		if funcs["max"].(func(float64, float64) float64)(10, 20) != 20 { t.Error("max failed") }
	})
}
