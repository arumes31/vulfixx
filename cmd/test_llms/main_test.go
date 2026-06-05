package main

import (
	"cve-tracker/internal/llm"
	"os"
	"testing"
)

func TestEnvOr(t *testing.T) {
	t.Setenv("TEST_KEY", "value")
	if got := envOr("TEST_KEY", "default"); got != "value" {
		t.Errorf("envOr() = %v, want %v", got, "value")
	}
	if got := envOr("NON_EXISTENT", "default"); got != "default" {
		t.Errorf("envOr() = %v, want %v", got, "default")
	}
}

func TestEnvIntOr(t *testing.T) {
	t.Setenv("TEST_INT_KEY", "42")
	t.Setenv("TEST_BAD_INT_KEY", "abc")

	if got := envIntOr("TEST_INT_KEY", 10); got != 42 {
		t.Errorf("envIntOr() = %v, want %v", got, 42)
	}
	if got := envIntOr("TEST_BAD_INT_KEY", 10); got != 10 {
		t.Errorf("envIntOr() = %v, want %v", got, 10)
	}
	if got := envIntOr("NON_EXISTENT", 10); got != 10 {
		t.Errorf("envIntOr() = %v, want %v", got, 10)
	}
}

func TestTokens(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"Hello World", []string{"hello", "world"}},
		{"The software project", []string{}}, // stop words removed
		{"Cisco IOS XE", []string{"cisco", "ios", "xe"}},
		{"vendor1_product-name!", []string{"vendor1", "product", "name"}},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := tokens(tc.input)
			if len(got) != len(tc.want) {
				t.Fatalf("tokens() = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("tokens()[%d] = %v, want %v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestProductMatch(t *testing.T) {
	tests := []struct {
		truth string
		pred  string
		want  bool
	}{
		{"cisco_ios", "Cisco IOS", true},
		{"windows_10", "Windows", true},
		{"windows", "Windows 10", true},
		{"vendor_product", "Different Product", false},
		{"", "pred", false},
		{"truth", "", false},
		{"apple_mac_os_x", "Mac OS X", true},
		{"some_software", "the software", false}, // empty tokens
	}

	for _, tc := range tests {
		t.Run(tc.truth+" vs "+tc.pred, func(t *testing.T) {
			got := productMatch(tc.truth, tc.pred)
			if got != tc.want {
				t.Errorf("productMatch(%q, %q) = %v, want %v", tc.truth, tc.pred, got, tc.want)
			}
		})
	}
}

func TestDescTokenSet(t *testing.T) {
	desc := "This is a Test, 123!"
	got := descTokenSet(desc)
	want := map[string]bool{"this": true, "is": true, "a": true, "test": true, "123": true}
	if len(got) != len(want) {
		t.Fatalf("descTokenSet() = %v, want %v", got, want)
	}
	for k := range want {
		if !got[k] {
			t.Errorf("descTokenSet() missing %v", k)
		}
	}
}

func TestMentioned(t *testing.T) {
	dtoks := map[string]bool{"cisco": true, "ios": true, "xe": true, "server": true}
	tests := []struct {
		name string
		want bool
	}{
		{"cisco", true},
		{"cisco ios", true},
		{"unknown", false},
		{"the server", true}, // server removed, empty => true
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mentioned(tc.name, dtoks)
			if got != tc.want {
				t.Errorf("mentioned(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestFilterTruth(t *testing.T) {
	desc := "A vulnerability in Cisco IOS XE allows an attacker to bypass."
	truth := []truthProduct{
		{Vendor: "cisco", Product: "ios_xe"},
		{Vendor: "fedoraproject", Product: "fedora"},
		{Vendor: "unknown", Product: "unrelated"},
	}

	got := filterTruth(truth, desc)
	if len(got) != 1 {
		t.Fatalf("filterTruth() returned %d items, want 1", len(got))
	}
	if got[0].Vendor != "cisco" {
		t.Errorf("filterTruth() kept wrong item: %v", got[0])
	}

	// test empty fallback
	got2 := filterTruth([]truthProduct{{Vendor: "fedoraproject", Product: "fedora"}}, "random")
	if len(got2) != 1 {
		t.Errorf("filterTruth() should return original if filtered is empty")
	}
}

func TestScoreOne(t *testing.T) {
	truth := []truthProduct{
		{Vendor: "cisco", Product: "ios_xe"},
		{Vendor: "microsoft", Product: "windows_10"},
	}
	preds := []llm.ProductResult{
		{Vendor: "Cisco", Product: "IOS XE", Version: "1.0"},
		{Vendor: "Apple", Product: "macOS", Version: "10"},
	}

	recall, precision, matched := scoreOne(truth, preds)
	if recall != 0.5 {
		t.Errorf("recall = %v, want 0.5", recall)
	}
	if precision != 0.5 {
		t.Errorf("precision = %v, want 0.5", precision)
	}
	if !matched[0] {
		t.Errorf("matched[0] = false, want true")
	}
	if matched[1] {
		t.Errorf("matched[1] = true, want false")
	}

	r2, p2, _ := scoreOne(nil, preds)
	if r2 != 0 || p2 != 0 {
		t.Errorf("empty truth: r=%v, p=%v, want 0, 0", r2, p2)
	}
}

func TestFmtTruth(t *testing.T) {
	truth := []truthProduct{
		{Vendor: "cisco", Product: "ios"},
		{Vendor: "apple", Product: "macos"},
	}
	got := fmtTruth(truth)
	want := "cisco/ios, apple/macos"
	if got != want {
		t.Errorf("fmtTruth() = %v, want %v", got, want)
	}
}

func TestFmtPred(t *testing.T) {
	preds := []llm.ProductResult{
		{Vendor: "Cisco", Product: "IOS", Version: "1.0"},
	}
	matched := map[int]bool{0: true}
	got := fmtPred(preds, matched)
	want := "✓Cisco/IOS [1.0]"
	if got != want {
		t.Errorf("fmtPred() = %q, want %q", got, want)
	}

	gotEmpty := fmtPred(nil, nil)
	if gotEmpty != "(none)" {
		t.Errorf("fmtPred() = %q, want \"(none)\"", gotEmpty)
	}
}

func TestYearSpread(t *testing.T) {
	cves := []testCVE{
		{Year: 2020},
		{Year: 2020},
		{Year: 2021},
	}
	got := yearSpread(cves)
	want := "2020:2 2021:1"
	if got != want {
		t.Errorf("yearSpread() = %q, want %q", got, want)
	}
}

func TestMainFunction(t *testing.T) {
	// Call main directly with a testset.json created
	tmpdir := t.TempDir()
	origDir, _ := os.Getwd()
	_ = os.Chdir(tmpdir)
	defer func() { _ = os.Chdir(origDir) }()

	testset := `[
		{
			"id": "CVE-2020-1234",
			"year": 2020,
			"desc": "A vulnerability in Cisco IOS.",
			"refs": [],
			"truth": [{"vendor": "cisco", "product": "ios"}]
		}
	]`
	_ = os.WriteFile("testset.json", []byte(testset), 0644)

	// Since we don't actually want to call LLM, we can limit providers
	t.Setenv("TEST_PROVIDER", "none")
	t.Setenv("TEST_LIMIT", "0")

	// Call main
	main()
}
