package main

import (
	"cve-tracker/internal/llm"
	"os"
	"os/exec"
	"reflect"
	"testing"
)

func TestEnvOr(t *testing.T) {
	os.Setenv("TEST_ENV_OR", "foo")
	if got := envOr("TEST_ENV_OR", "bar"); got != "foo" {
		t.Errorf("envOr() = %v, want foo", got)
	}
	if got := envOr("TEST_ENV_OR_MISSING", "bar"); got != "bar" {
		t.Errorf("envOr() = %v, want bar", got)
	}
}

func TestEnvIntOr(t *testing.T) {
	os.Setenv("TEST_ENV_INT_OR", "42")
	if got := envIntOr("TEST_ENV_INT_OR", 10); got != 42 {
		t.Errorf("envIntOr() = %v, want 42", got)
	}
	if got := envIntOr("TEST_ENV_INT_OR_MISSING", 10); got != 10 {
		t.Errorf("envIntOr() = %v, want 10", got)
	}
	os.Setenv("TEST_ENV_INT_OR_INVALID", "foo")
	if got := envIntOr("TEST_ENV_INT_OR_INVALID", 10); got != 10 {
		t.Errorf("envIntOr() = %v, want 10", got)
	}
}

func TestYearSpread(t *testing.T) {
	cves := []testCVE{
		{Year: 2021},
		{Year: 2021},
		{Year: 2022},
	}
	want := "2021:2 2022:1"
	if got := yearSpread(cves); got != want {
		t.Errorf("yearSpread() = %v, want %v", got, want)
	}
}

func TestFmtTruth(t *testing.T) {
	truth := []truthProduct{
		{Vendor: "v1", Product: "p1"},
		{Vendor: "v2", Product: "p2"},
	}
	want := "v1/p1, v2/p2"
	if got := fmtTruth(truth); got != want {
		t.Errorf("fmtTruth() = %v, want %v", got, want)
	}
}

func TestFmtPred(t *testing.T) {
	preds := []llm.ProductResult{
		{Vendor: "v1", Product: "p1", Version: "1.0"},
		{Vendor: "v2", Product: "p2", Version: "2.0"},
	}
	matched := map[int]bool{0: true}
	want := "✓v1/p1 [1.0],  v2/p2 [2.0]"
	if got := fmtPred(preds, matched); got != want {
		t.Errorf("fmtPred() = %v, want %v", got, want)
	}
	if got := fmtPred([]llm.ProductResult{}, matched); got != "(none)" {
		t.Errorf("fmtPred() = %v, want (none)", got)
	}
}

func TestTokens(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"Hello World", []string{"hello", "world"}},
		{"The plugin for WordPress", []string{"wordpress"}},
		{"Foo-Bar 1.0", []string{"foo", "bar", "1", "0"}},
	}
	for _, tt := range tests {
		if got := tokens(tt.input); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("tokens(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestDescTokenSet(t *testing.T) {
	got := descTokenSet("Hello World-1.0")
	want := map[string]bool{"hello": true, "world": true, "1": true, "0": true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("descTokenSet() = %v, want %v", got, want)
	}
}

func TestMentioned(t *testing.T) {
	dtoks := map[string]bool{"wordpress": true, "plugin": true}
	if !mentioned("wordpress", dtoks) {
		t.Errorf("mentioned() = false, want true")
	}
	if mentioned("joomla", dtoks) {
		t.Errorf("mentioned() = true, want false")
	}
	// empty string / no distinct tokens
	if !mentioned("", dtoks) {
		t.Errorf("mentioned() = false, want true (default keep)")
	}
}

func TestFilterTruth(t *testing.T) {
	truth := []truthProduct{
		{Vendor: "ubuntu", Product: "linux"}, // should be filtered out
		{Vendor: "wordpress", Product: "plugin"},
		{Vendor: "unknown", Product: "missing"}, // should be filtered out because missing is not in description
	}
	desc := "This is a vulnerability in wordpress plugin."
	got := filterTruth(truth, desc)
	if len(got) != 1 || got[0].Vendor != "wordpress" {
		t.Errorf("filterTruth() = %v, want [wordpress/plugin]", got)
	}

	// test fallback if everything is filtered
	truth2 := []truthProduct{{Vendor: "ubuntu", Product: "linux"}}
	got2 := filterTruth(truth2, desc)
	if len(got2) != 1 || got2[0].Vendor != "ubuntu" {
		t.Errorf("filterTruth() = %v, want original on empty", got2)
	}
}

func TestProductMatch(t *testing.T) {
	tests := []struct {
		truth string
		pred  string
		want  bool
	}{
		{"windows_10", "Windows 10", true},
		{"popup_builder", "Popup Builder", true},
		{"joomla", "joomla plugin", true}, // Subset match
		{"foo", "bar", false},
	}
	for _, tt := range tests {
		if got := productMatch(tt.truth, tt.pred); got != tt.want {
			t.Errorf("productMatch(%q, %q) = %v, want %v", tt.truth, tt.pred, got, tt.want)
		}
	}
}

func TestScoreOne(t *testing.T) {
	truth := []truthProduct{{Vendor: "v1", Product: "p1"}}
	preds := []llm.ProductResult{{Vendor: "v1", Product: "p1"}}
	recall, precision, matched := scoreOne(truth, preds)
	if recall != 1.0 || precision != 1.0 || !matched[0] {
		t.Errorf("scoreOne() = %v, %v, %v, want 1.0, 1.0, map[0:true]", recall, precision, matched)
	}

	// zero cases
	r, p, _ := scoreOne([]truthProduct{}, preds)
	if r != 0 || p != 0 {
		t.Errorf("scoreOne(empty truth) = %v, %v, want 0, 0", r, p)
	}

	r, p, _ = scoreOne(truth, []llm.ProductResult{{Product: "wrong"}})
	if r != 0 || p != 0 {
		t.Errorf("scoreOne(wrong pred) = %v, %v, want 0, 0", r, p)
	}
}

func TestMainProcess(t *testing.T) {
	if os.Getenv("BE_CRASHER") == "1" {
		// Just verify that the code can handle file not found nicely via an exit (we simulate the os.Exit here if needed)
		// Or we can mock the file.
		os.WriteFile("testset.json", []byte(`[{"id":"CVE-1","year":2021,"desc":"test","refs":[],"truth":[]}]`), 0644)
		// Make it fast
		os.Setenv("TEST_PROVIDER", "mock")
		os.Setenv("TEST_LIMIT", "0")

		main()
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestMainProcess")
	cmd.Env = append(os.Environ(), "BE_CRASHER=1")
	err := cmd.Run()
	if err != nil {
		t.Fatalf("process ran with err %v", err)
	}
	os.Remove("testset.json")
}
