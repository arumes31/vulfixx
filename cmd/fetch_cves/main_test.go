package main

import (
	"cve-tracker/internal/models"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestToTestCVE(t *testing.T) {
	tests := []struct {
		name     string
		input    nvdCVE
		year     int
		wantID   string
		wantDesc string
		wantTrue bool
	}{
		{
			name: "rejected status",
			input: nvdCVE{
				VulnStatus: "REJECT",
			},
			year:     2020,
			wantTrue: false,
		},
		{
			name: "rejected desc",
			input: nvdCVE{
				VulnStatus: "ANALYZED",
				Descriptions: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{{Lang: "en", Value: "** REJECT ** DO NOT USE THIS"}},
			},
			year:     2020,
			wantTrue: false,
		},
		{
			name: "no en desc",
			input: nvdCVE{
				VulnStatus: "ANALYZED",
				Descriptions: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{{Lang: "fr", Value: "something"}},
			},
			year:     2020,
			wantTrue: false,
		},
		{
			name: "no configurations",
			input: nvdCVE{
				ID:         "CVE-2020-1234",
				VulnStatus: "ANALYZED",
				Descriptions: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{{Lang: "en", Value: "This is a test desc"}},
			},
			year:     2020,
			wantTrue: false,
		},
		{
			name: "valid configuration",
			input: nvdCVE{
				ID:         "CVE-2020-1234",
				VulnStatus: "ANALYZED",
				Descriptions: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{{Lang: "en", Value: "This is a test desc"}},
				Configurations: []models.CVEConfiguration{
					{
						Nodes: []models.ConfigNode{
							{
								CPEMatch: []models.CPEMatch{
									{
										Criteria: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
									},
								},
							},
						},
					},
				},
			},
			year:     2020,
			wantID:   "CVE-2020-1234",
			wantDesc: "This is a test desc",
			wantTrue: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := toTestCVE(tc.input, tc.year)
			if ok != tc.wantTrue {
				t.Errorf("toTestCVE() ok = %v, want %v", ok, tc.wantTrue)
			}
			if tc.wantTrue {
				if got.ID != tc.wantID {
					t.Errorf("got ID = %v, want %v", got.ID, tc.wantID)
				}
				if got.Desc != tc.wantDesc {
					t.Errorf("got Desc = %v, want %v", got.Desc, tc.wantDesc)
				}
			}
		})
	}
}

func TestDistinctProducts(t *testing.T) {
	tests := []struct {
		name  string
		input []truthProduct
		want  int
	}{
		{
			name:  "empty",
			input: []truthProduct{},
			want:  0,
		},
		{
			name: "unique products",
			input: []truthProduct{
				{Vendor: "a", Product: "prod_a"},
				{Vendor: "b", Product: "prod_b"},
			},
			want: 2,
		},
		{
			name: "duplicate products",
			input: []truthProduct{
				{Vendor: "a", Product: "prod_a"},
				{Vendor: "b", Product: "prod_a"},
			},
			want: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := distinctProducts(tc.input)
			if got != tc.want {
				t.Errorf("distinctProducts() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFetch(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		apiKey     string
		wantNil    bool
	}{
		{
			name:       "success",
			statusCode: 200,
			body:       `{"totalResults": 1, "vulnerabilities": []}`,
			wantNil:    false,
		},
		{
			name:       "non-200",
			statusCode: 500,
			body:       `{"error": "internal error"}`,
			wantNil:    true,
		},
		{
			name:       "bad json",
			statusCode: 200,
			body:       `{invalid json`,
			wantNil:    true,
		},
		{
			name:       "success with api key",
			statusCode: 200,
			body:       `{"totalResults": 1, "vulnerabilities": []}`,
			apiKey:     "test-key",
			wantNil:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.apiKey != "" && r.Header.Get("apiKey") != tc.apiKey {
					t.Errorf("missing or incorrect apiKey header")
				}
				w.WriteHeader(tc.statusCode)
				w.Write([]byte(tc.body))
			}))
			defer server.Close()

			client := server.Client()
			got := fetch(client, tc.apiKey, server.URL)
			if tc.wantNil && got != nil {
				t.Errorf("fetch() got %v, want nil", got)
			}
			if !tc.wantNil && got == nil {
				t.Errorf("fetch() got nil, want non-nil")
			}
		})
	}
}

func TestCollectYear(t *testing.T) {
	// Temporarily redirect NVD base URL to test server
	origBase := nvdBase
	defer func() { nvdBase = origBase }()

	// Start an httptest.Server to mock the NVD API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := nvdResp{
			TotalResults: 1,
			Vulnerabilities: []struct {
				CVE nvdCVE `json:"cve"`
			}{
				{
					CVE: nvdCVE{
						ID:         "CVE-2020-1234",
						VulnStatus: "ANALYZED",
						Descriptions: []struct {
							Lang  string `json:"lang"`
							Value string `json:"value"`
						}{{Lang: "en", Value: "A test description"}},
						Configurations: []models.CVEConfiguration{
							{
								Nodes: []models.ConfigNode{
									{
										CPEMatch: []models.CPEMatch{
											{
												Criteria: "cpe:2.3:a:testvendor:testproduct:1.0:*:*:*:*:*:*:*",
											},
											{
												Criteria: "cpe:2.3:a:testvendor:testproduct2:1.0:*:*:*:*:*:*:*",
											},
										},
									},
								},
							},
						},
					},
				},
				{
					CVE: nvdCVE{
						ID:         "CVE-2020-5678",
						VulnStatus: "ANALYZED",
						Descriptions: []struct {
							Lang  string `json:"lang"`
							Value string `json:"value"`
						}{{Lang: "en", Value: "Another test description"}},
						Configurations: []models.CVEConfiguration{
							{
								Nodes: []models.ConfigNode{
									{
										CPEMatch: []models.CPEMatch{
											{
												Criteria: "cpe:2.3:a:testvendor:testproduct3:1.0:*:*:*:*:*:*:*",
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
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	nvdBase = server.URL

	client := server.Client()
	got := collectYear(client, "test-key", 2020, 2)
	if len(got) == 0 {
		t.Errorf("collectYear() got 0, want >0")
	}
}

func TestMainFunction(t *testing.T) {
	// Temporarily redirect NVD base URL to test server
	origBase := nvdBase
	defer func() { nvdBase = origBase }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := nvdResp{
			TotalResults: 0,
			Vulnerabilities: nil,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	nvdBase = server.URL

	t.Setenv("YEARS", "2020")
	t.Setenv("PER_YEAR", "1")

	// Change to a temporary directory so we can write testset.json safely
	tmpdir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(tmpdir)
	defer os.Chdir(origDir)

	// Call main directly. It shouldn't os.Exit if os.WriteFile succeeds.
	main()

	// Verify testset.json was written
	if _, err := os.Stat("testset.json"); os.IsNotExist(err) {
		t.Errorf("main() did not write testset.json")
	}
}
