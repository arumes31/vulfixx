package web

import (
	"html/template"
	"log"
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

	files, err := filepath.Glob("templates/*.html")
	if err != nil {
		log.Fatalf("Error globbing templates: %v", err)
	}
	if len(files) == 0 {
		log.Fatalf("No templates found")
	}
	for _, file := range files {
		name := filepath.Base(file)
		if name == "base.html" {
			continue
		}
		a.TemplateMap[name] = template.Must(template.New(name).Funcs(funcs).ParseFiles("templates/base.html", file))
	}
	if len(a.TemplateMap) == 0 {
		log.Fatalf("No renderable templates loaded")
	}
}
