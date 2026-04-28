package web

import (
	"html/template"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func (a *App) InitTemplatesWithFuncs() {
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
		"GetBaseURL": GetBaseURL,
	}

	a.TemplateMap = make(map[string]*template.Template)

	// Locate the templates directory by walking up from the current working directory.
	// This avoids os.Chdir which is not goroutine-safe.
	templateDir := findTemplatesDir()
	if templateDir == "" {
		wd, _ := os.Getwd()
		log.Printf("No templates found starting from %s", wd)
		return
	}

	baseFile := filepath.Join(templateDir, "base.html")
	pattern := filepath.Join(templateDir, "*.html")
	files, _ := filepath.Glob(pattern)

	for _, file := range files {
		name := filepath.Base(file)
		if name == "base.html" {
			continue
		}
		a.TemplateMap[name] = template.Must(template.New(name).Funcs(funcs).ParseFiles(baseFile, file))
	}

	if len(a.TemplateMap) == 0 {
		log.Printf("No renderable templates loaded from %s", templateDir)
	}
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
		if matches, _ := filepath.Glob(filepath.Join(dir, "*.html")); len(matches) > 0 {
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
