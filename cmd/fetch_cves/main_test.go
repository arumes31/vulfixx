package main

import (
	"cve-tracker/internal/models"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
)

func TestDistinctProducts(t *testing.T) {
	tests := []struct {
		name  string
		truth []truthProduct
		want  int
	}{
		{"empty", []truthProduct{}, 0},
		{"unique", []truthProduct{{"v1", "p1"}, {"v2", "p2"}}, 2},
		{"duplicates", []truthProduct{{"v1", "p1"}, {"v1", "p1"}, {"v2", "p1"}}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := distinctProducts(tt.truth); got != tt.want {
				t.Errorf("distinctProducts() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestToTestCVE(t *testing.T) {
	tests := []struct {
		name     string
		cve      nvdCVE
		year     int
		wantOK   bool
		wantDesc string
	}{
		{
			name: "rejected",
			cve: nvdCVE{
				ID:         "CVE-2023-1234",
				VulnStatus: "REJECT",
			},
			year:   2023,
			wantOK: false,
		},
		{
			name: "rejected description",
			cve: nvdCVE{
				ID: "CVE-2023-1234",
				Descriptions: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{{Lang: "en", Value: "** REJECT ** this is rejected"}},
			},
			year:   2023,
			wantOK: false,
		},
		{
			name: "no english desc",
			cve: nvdCVE{
				ID: "CVE-2023-1234",
				Descriptions: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{{Lang: "fr", Value: "bonjour"}},
			},
			year:   2023,
			wantOK: false,
		},
		{
			name: "no configurations",
			cve: nvdCVE{
				ID: "CVE-2023-1234",
				Descriptions: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{{Lang: "en", Value: "Valid description"}},
			},
			year:   2023,
			wantOK: false,
		},
		{
			name: "valid entry",
			cve: nvdCVE{
				ID: "CVE-2023-1234",
				Descriptions: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{{Lang: "en", Value: "Valid description"}},
				Configurations: []models.CVEConfiguration{
					{
						Nodes: []models.ConfigNode{
							{
								Operator: "OR",
								CPEMatch: []models.CPEMatch{
									{
										Vulnerable: true,
										Criteria:   "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
									},
								},
							},
						},
					},
				},
				References: []struct {
					URL string `json:"url"`
				}{
					{URL: "http://example.com/1"},
				},
			},
			year:     2023,
			wantOK:   true,
			wantDesc: "Valid description",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := toTestCVE(tt.cve, tt.year)
			if ok != tt.wantOK {
				t.Errorf("toTestCVE() ok = %v, want %v", ok, tt.wantOK)
				return
			}
			if ok && got.Desc != tt.wantDesc {
				t.Errorf("toTestCVE() desc = %v, want %v", got.Desc, tt.wantDesc)
			}
		})
	}
}

func TestFetchAndCollectYear(t *testing.T) {
	// Create mock server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := nvdResp{
			TotalResults: 1,
			Vulnerabilities: []struct {
				CVE nvdCVE `json:"cve"`
			}{
				{
					CVE: nvdCVE{
						ID: "CVE-2023-1234",
						Descriptions: []struct {
							Lang  string `json:"lang"`
							Value string `json:"value"`
						}{{Lang: "en", Value: "Valid description"}},
						Configurations: []models.CVEConfiguration{
							{
								Nodes: []models.ConfigNode{
									{
										Operator: "OR",
										CPEMatch: []models.CPEMatch{
											{
												Vulnerable: true,
												Criteria:   "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
											},
											{
												Vulnerable: true,
												Criteria:   "cpe:2.3:a:vendor:product2:1.0:*:*:*:*:*:*:*",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	// Override base
	originalNvdBase := nvdBase
	nvdBase = ts.URL
	defer func() { nvdBase = originalNvdBase }()

	client := ts.Client()

	// test fetch
	resp := fetch(client, "", ts.URL)
	if resp == nil {
		t.Fatal("fetch() returned nil")
	}
	if len(resp.Vulnerabilities) != 1 {
		t.Fatalf("fetch() got %d vulns, want 1", len(resp.Vulnerabilities))
	}

	// test collectYear
	cves := collectYear(client, "", 2023, 1)
	if len(cves) != 1 {
		t.Fatalf("collectYear() got %d cves, want 1", len(cves))
	}
	if cves[0].ID != "CVE-2023-1234" {
		t.Errorf("collectYear() cve ID = %v, want CVE-2023-1234", cves[0].ID)
	}
}

// TestFetchError ensures fetch handles errors gracefully
func TestFetchError(t *testing.T) {
	// Create mock server that returns 500
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	client := ts.Client()

	// Test short timeout for faster retries
	client.Timeout = 0

	resp := fetch(client, "", ts.URL)
	if resp != nil {
		t.Fatal("fetch() expected nil for 500 errors")
	}
}

// TestMainProcess is a helper for TestMain to run the main() function in a subprocess
func TestMainProcess(t *testing.T) {
	if os.Getenv("BE_CRASHER") == "1" {
		// Mock NVD response
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := nvdResp{}
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer ts.Close()

		nvdBase = ts.URL

		// set to small numbers to be quick
		os.Setenv("PER_YEAR", "1")
		os.Setenv("YEARS", "2024")

		main()
		os.Exit(0)
	}

	// This is the actual test that runs the subprocess
	cmd := exec.Command(os.Args[0], "-test.run=TestMainProcess")
	cmd.Env = append(os.Environ(), "BE_CRASHER=1")
	err := cmd.Run()
	if err != nil {
		t.Fatalf("process ran with err %v", err)
	}

	// Clean up created file
	defer os.Remove("testset.json")

	// Verify output
	if _, err := os.Stat("testset.json"); os.IsNotExist(err) {
		t.Fatal("testset.json was not created")
	}
}
