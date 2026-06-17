package web

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cve-tracker/internal/models"
)

func daysSince(t interface{}) string {
	var tv time.Time
	switch v := t.(type) {
	case time.Time:
		tv = v
	case *time.Time:
		if v == nil {
			return ""
		}
		tv = *v
	default:
		return ""
	}
	days := int(time.Since(tv).Hours() / 24)
	if days < 0 {
		days = 0
	}
	if days == 0 {
		hours := int(time.Since(tv).Hours())
		if hours < 1 {
			return "just now"
		}
		return fmt.Sprintf("%d hour%s ago", hours, pluralS(hours))
	}
	if days < 30 {
		return fmt.Sprintf("%d day%s ago", days, pluralS(days))
	}
	if days < 365 {
		months := days / 30
		return fmt.Sprintf("%d month%s ago", months, pluralS(months))
	}
	years := days / 365
	return fmt.Sprintf("%d year%s ago", years, pluralS(years))
}

func pluralS(n int) string {
	if n != 1 {
		return "s"
	}
	return ""
}

func cvssSeverityLabel(score float64) string {
	if score >= 9.0 {
		return "Critical"
	}
	if score >= 7.0 {
		return "High"
	}
	if score >= 4.0 {
		return "Medium"
	}
	if score > 0 {
		return "Low"
	}
	return "N/A"
}

func epssPercentileLabel(score float64) string {
	if score <= 0 {
		return "N/A"
	}
	// EPSS score is a probability (0-1); express it as an exploitation probability
	pct := score * 100
	if pct >= 50 {
		return fmt.Sprintf("%.1f%% probability — Extremely likely to be exploited", pct)
	}
	if pct >= 10 {
		return fmt.Sprintf("%.1f%% probability — Very high exploit likelihood", pct)
	}
	if pct >= 1 {
		return fmt.Sprintf("%.2f%% probability — High exploit likelihood", pct)
	}
	if pct >= 0.1 {
		return fmt.Sprintf("%.4f%% probability — Moderate exploit likelihood", pct)
	}
	return fmt.Sprintf("%.4f%% probability — Low exploit likelihood", pct)
}

func exploitationSummary(cisaKEV, cisaRansomware, exploitAvailable bool, greynoiseHits int, githubPocCount int) string {
	indicators := []string{}
	if cisaKEV {
		indicators = append(indicators, "CISA Known Exploited")
	}
	if cisaRansomware {
		indicators = append(indicators, "Ransomware Campaign")
	}
	if greynoiseHits > 0 {
		indicators = append(indicators, "Active Internet Scanning")
	}
	if githubPocCount > 0 {
		indicators = append(indicators, "Public PoC Available")
	}
	if exploitAvailable {
		indicators = append(indicators, "Exploit Code Available")
	}
	if len(indicators) == 0 {
		return "No known exploitation evidence"
	}
	return "⚠️ " + strings.Join(indicators, " · ")
}

func (a *App) GetTemplateFuncs() template.FuncMap {
	return template.FuncMap{
		"formatDate": func(t time.Time) string {
			return t.Format("Jan 02, 2006")
		},
		"map": func(values ...interface{}) map[string]interface{} {
			if len(values)%2 != 0 {
				return nil
			}
			m := make(map[string]interface{}, len(values)/2)
			for i := 0; i < len(values); i += 2 {
				key, ok := values[i].(string)
				if !ok {
					continue
				}
				m[key] = values[i+1]
			}
			return m
		},
		"contains": strings.Contains,
		"percent": func(count, total int) int {
			if total == 0 {
				return 0
			}
			return int(float64(count) / float64(total) * 100)
		},
		"add":      func(a, b int) int { return a + b },
		"subtract": func(a, b int) int { return a - b },
		"multiply": func(a, b float64) float64 { return a * b },
		"round":    func(f float64) int { return int(f + 0.5) },
		"min": func(a, b float64) float64 {
			if a < b {
				return a
			}
			return b
		},
		"max": func(a, b float64) float64 {
			if a > b {
				return a
			}
			return b
		},
		"GetBaseURL": GetBaseURL,
		"safeURL": func(s string) template.URL {
			parsed, err := url.Parse(s)
			if err != nil {
				return template.URL("#invalid-url")
			}
			if parsed.Scheme == "" {
				if parsed.Host != "" {
					return template.URL("#invalid-url")
				}
			} else if parsed.Scheme != "http" && parsed.Scheme != "https" {
				return template.URL("#invalid-url")
			}
			/* #nosec G203 */
			return template.URL(s)
		},
		"severityColor": func(score float64) string {
			if score <= 0 || score > 10 {
				return "text-gray-400"
			}
			if score >= 9.0 {
				return "text-red-500"
			}
			if score >= 7.0 {
				return "text-orange-500"
			}
			if score >= 4.0 {
				return "text-yellow-500"
			}
			return "text-blue-500"
		},
		"severityBg": func(score float64) string {
			if score <= 0 || score > 10 {
				return "bg-gray-400"
			}
			if score >= 9.0 {
				return "bg-red-500"
			}
			if score >= 7.0 {
				return "bg-orange-500"
			}
			if score >= 4.0 {
				return "bg-yellow-500"
			}
			return "bg-blue-500"
		},
		"marshal": func(v interface{}) string {
			a, _ := json.Marshal(v)
			return string(a)
		},
		"vendorLinks": func(cveID string, description string) []map[string]string {
			links := []map[string]string{}
			desc := strings.ToLower(description)
			if strings.Contains(desc, "microsoft") || strings.Contains(desc, "windows") || strings.Contains(desc, "office") {
				links = append(links, map[string]string{"name": "Microsoft Security", "url": fmt.Sprintf("https://msrc.microsoft.com/update-guide/vulnerability/%s", cveID), "icon": "lan"})
			}
			if strings.Contains(desc, "red hat") || strings.Contains(desc, "redhat") || strings.Contains(desc, "fedora") || strings.Contains(desc, "rhel") {
				links = append(links, map[string]string{"name": "RedHat Advisory", "url": fmt.Sprintf("https://access.redhat.com/security/cve/%s", cveID), "icon": "security"})
			}
			if strings.Contains(desc, "cisco") {
				links = append(links, map[string]string{"name": "Cisco Advisory", "url": fmt.Sprintf("https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/%s", cveID), "icon": "router"})
			}
			if strings.Contains(desc, "ubuntu") || strings.Contains(desc, "canonical") {
				links = append(links, map[string]string{"name": "Ubuntu Security", "url": fmt.Sprintf("https://ubuntu.com/security/%s", cveID), "icon": "terminal"})
			}
			if strings.Contains(desc, "vmware") || strings.Contains(desc, "vcenter") || strings.Contains(desc, "esxi") {
				links = append(links, map[string]string{"name": "VMware Advisory", "url": fmt.Sprintf("https://www.vmware.com/security/advisories/%s.html", cveID), "icon": "layers"})
			}
			if strings.Contains(desc, "fortinet") || strings.Contains(desc, "fortigate") ||
				strings.Contains(desc, "fortios") || strings.Contains(desc, "fortimanager") ||
				strings.Contains(desc, "fortianalyzer") || strings.Contains(desc, "forticlient") {
				links = append(links, map[string]string{"name": "FortiGuard PSIRT", "url": fmt.Sprintf("https://www.fortiguard.com/psirt?cve=%s", cveID), "icon": "shield"})
			}
			return links
		},
		"detectProduct": func(c models.CVE) map[string]string {
			v, p := c.GetDetectedProduct()
			if v == "" {
				return nil
			}
			return map[string]string{"vendor": v, "product": p}
		},
		"getLineage": func(c models.CVE) []string {
			return c.GetLineage()
		},
		"lower": func(s string) string {
			return strings.ToLower(s)
		},
		"parseCPE": func(cpe string) map[string]string {
			v, p, ver, t := models.ParseCPE(cpe)
			if v == "" {
				return nil
			}
			return map[string]string{"vendor": v, "product": p, "version": ver, "type": t}
		},
		"daysSince":           daysSince,
		"cvssSeverityLabel":   cvssSeverityLabel,
		"epssPercentileLabel": epssPercentileLabel,
		"exploitationSummary": exploitationSummary,
		"split": func(s, sep string) []string {
			if s == "" {
				return nil
			}
			return strings.Split(s, sep)
		},
		"indexSafe": func(slice []string, i int) string {
			if i < 0 || i >= len(slice) {
				return ""
			}
			return slice[i]
		},
		"isset": func(m interface{}, key interface{}) bool {
			if mp, ok := m.(map[string]interface{}); ok {
				if k, ok := key.(string); ok {
					_, exists := mp[k]
					return exists
				}
			}
			return false
		},
		"isTimeZero": func(t interface{}) bool {
			if t == nil {
				return true
			}
			if tp, ok := t.(*time.Time); ok {
				return tp == nil || tp.IsZero()
			}
			if tv, ok := t.(time.Time); ok {
				return tv.IsZero()
			}
			return true
		},
		"toFloat": func(v interface{}) float64 {
			switch n := v.(type) {
			case float64:
				return n
			case float32:
				return float64(n)
			case int:
				return float64(n)
			case int64:
				return float64(n)
			default:
				return 0
			}
		},
	}
}

func (a *App) InitTemplatesWithFuncs() error {
	funcs := a.GetTemplateFuncs()

	a.TemplateMu.Lock()
	a.TemplateMap = make(map[string]*template.Template)
	a.TemplateMu.Unlock()

	templateDir := findTemplatesDir()
	if templateDir == "" {
		return fmt.Errorf("no templates directory found")
	}

	baseFile := filepath.Join(templateDir, "base.html")
	files, err := filepath.Glob(filepath.Join(templateDir, "*.html"))
	if err != nil {
		return fmt.Errorf("failed to glob templates: %v", err)
	}

	for _, file := range files {
		name := filepath.Base(file)
		if name == "base.html" {
			continue
		}
		tmpl, err := template.New(name).Funcs(funcs).ParseFiles(baseFile, file)
		if err != nil {
			continue
		}
		a.TemplateMu.Lock()
		a.TemplateMap[name] = tmpl
		a.TemplateMu.Unlock()
	}

	return nil
}

func findTemplatesDir() string {
	start, err := os.Getwd()
	if err != nil {
		return ""
	}
	candidate := start
	for i := 0; i < 5; i++ {
		dir := filepath.Join(candidate, "templates")
		if matches, err := filepath.Glob(filepath.Join(dir, "*.html")); err == nil && len(matches) > 0 {
			abs, _ := filepath.Abs(dir)
			return abs
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			break
		}
		candidate = parent
	}
	return ""
}
