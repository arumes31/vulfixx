package web

import "html/template"

func InitTemplatesWithFuncs() {
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
	}
	templates = template.Must(template.New("").Funcs(funcs).ParseGlob("templates/*.html"))
}
