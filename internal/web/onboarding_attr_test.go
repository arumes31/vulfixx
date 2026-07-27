package web

import (
	"html/template"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// dataOnAttrRegex finds any data-on… attribute in a template.
//
// html/template strips the data- prefix when classifying an attribute, so anything
// left starting with "on" is treated as a JavaScript event-handler context. The value
// then goes through the JS escaper, which pads it with spaces. That silently broke the
// onboarding tour: data-onboarding-completed rendered as " true ", the === 'true'
// check never matched, and the tour's z-index:200 backdrop swallowed every click on
// every page load.
var dataOnAttrRegex = regexp.MustCompile(`data-on[a-zA-Z-]*\s*=`)

// No template may introduce a data-on… attribute. Renaming one back would reintroduce
// a bug whose cause is extremely non-obvious from the symptom.
func TestNoDataOnAttributesInTemplates(t *testing.T) {
	dir := findTemplatesDir()
	if dir == "" {
		t.Skip("templates directory not found")
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.html"))
	if err != nil {
		t.Fatalf("glob templates: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no templates found")
	}

	for _, file := range files {
		body, err := os.ReadFile(file) // #nosec G304 -- test-only, path from our own glob
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		for _, match := range dataOnAttrRegex.FindAllString(string(body), -1) {
			t.Errorf("%s declares %q; html/template treats data-on* as a JS context and "+
				"pads the value with spaces. Rename it so it does not begin with \"on\".",
				filepath.Base(file), strings.TrimSuffix(match, "="))
		}
	}
}

// Pins the html/template behaviour the rule above exists for, so the reason survives
// even if the Go version changes it.
func TestDataAttributeJSContextPadding(t *testing.T) {
	render := func(attr string) string {
		tmpl := template.Must(template.New("t").Parse(`<body ` + attr + `="{{.V}}">`))
		var sb strings.Builder
		if err := tmpl.Execute(&sb, map[string]any{"V": true}); err != nil {
			t.Fatalf("execute: %v", err)
		}
		return sb.String()
	}

	if got := render("data-tour-completed"); !strings.Contains(got, `="true"`) {
		t.Errorf("data-tour-completed should render unpadded, got %s", got)
	}
	// If this ever stops padding, the naming rule can be relaxed — but not before.
	if got := render("data-onboarding-completed"); !strings.Contains(got, `=" true "`) {
		t.Logf("note: html/template no longer pads data-on* attributes (%s)", got)
	}
}

// The body tag must carry the renamed attribute and the script must read the matching
// dataset key. These two live ~660 lines apart in base.html, so a partial rename is an
// easy mistake to make.
func TestOnboardingAttributeAndReaderAgree(t *testing.T) {
	dir := findTemplatesDir()
	if dir == "" {
		t.Skip("templates directory not found")
	}
	body, err := os.ReadFile(filepath.Join(dir, "base.html")) // #nosec G304 -- test-only
	if err != nil {
		t.Fatalf("read base.html: %v", err)
	}
	src := string(body)

	if !strings.Contains(src, `data-tour-completed="{{.OnboardingCompleted}}"`) {
		t.Error("base.html no longer sets data-tour-completed from .OnboardingCompleted")
	}
	if !strings.Contains(src, "dataset.tourCompleted") {
		t.Error("base.html no longer reads dataset.tourCompleted; the attribute and its " +
			"reader must be renamed together or the tour runs on every page load")
	}
}
