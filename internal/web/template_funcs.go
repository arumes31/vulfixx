package web

import (
	"fmt"
	"html/template"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func (a *App) InitTemplatesWithFuncs() error {
	funcs := template.FuncMap{
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
		"add":        func(a, b int) int { return a + b },
		"subtract":   func(a, b int) int { return a - b },
		"multiply":   func(a, b float64) float64 { return a * b },
		"round":      func(f float64) int { return int(f + 0.5) },
		"min":        func(a, b float64) float64 { if a < b { return a }; return b },
		"max":        func(a, b float64) float64 { if a > b { return a }; return b },
		"GetBaseURL": GetBaseURL,
		"safeURL": func(s string) template.URL {
			parsed, err := url.Parse(s)
			if err != nil {
				return template.URL("#invalid-url")
			}
			// Allow empty scheme (relative URLs) but avoid protocol-relative //host
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
	}

	a.TemplateMu.Lock()
	a.TemplateMap = make(map[string]*template.Template)
	a.TemplateMu.Unlock()

	// Locate the templates directory by walking up from the current working directory.
	// This avoids os.Chdir which is not goroutine-safe.
	templateDir := findTemplatesDir()
	if templateDir == "" {
		wd, _ := os.Getwd()
		log.Printf("No templates found starting from %s", wd)
		return fmt.Errorf("no templates directory found")
	}

	baseFile := filepath.Join(templateDir, "base.html")
	pattern := filepath.Join(templateDir, "*.html")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("error globbing templates: %w", err)
	}

	for _, file := range files {
		name := filepath.Base(file)
		if name == "base.html" {
			continue
		}
		tmpl, err := template.New(name).Funcs(funcs).ParseFiles(baseFile, file)
		if err != nil {
			log.Printf("Error parsing template %s: %v", name, err)
			continue
		}
		a.TemplateMu.Lock()
		a.TemplateMap[name] = tmpl
		a.TemplateMu.Unlock()
	}

	a.TemplateMu.RLock()
	mapLen := len(a.TemplateMap)
	a.TemplateMu.RUnlock()
	if mapLen == 0 {
		log.Printf("No renderable templates loaded from %s", templateDir)
	}
	return nil
}

// findTemplatesDir walks up from the current working directory looking for a
// "templates" directory that contains at least one .html file. It checks up to
// five levels to accommodate different working directories used by tests vs the
// binary. No os.Chdir is performed.
func findTemplatesDir() string {
	start, err := os.Getwd()
	if err != nil {
		return ""
	}
	candidate := start
	for i := 0; i < 5; i++ {
		dir := filepath.Join(candidate, "templates")
		if matches, err := filepath.Glob(filepath.Join(dir, "*.html")); err != nil {
			log.Printf("Error finding templates dir: %v", err)
		} else if len(matches) > 0 {
			abs, err := filepath.Abs(dir)
			if err == nil {
				return abs
			}
			return dir
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			break // filesystem root reached
		}
		candidate = parent
	}
	return ""
}
