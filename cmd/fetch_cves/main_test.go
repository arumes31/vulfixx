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
		name string
		c    nvdCVE
		want bool
	}{
		{
			name: "reject status",
			c:    nvdCVE{VulnStatus: "REJECTED"},
			want: false,
		},
		{
			name: "no en desc",
			c: nvdCVE{Descriptions: []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			}{{Lang: "es", Value: "hola"}}},
			want: false,
		},
		{
			name: "reject desc",
			c: nvdCVE{Descriptions: []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			}{{Lang: "en", Value: "** REJECT ** this is rejected"}}},
			want: false,
		},
		{
			name: "no affected products",
			c: nvdCVE{Descriptions: []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			}{{Lang: "en", Value: "valid"}},
			},
			want: false,
		},
		{
			name: "valid cve",
			c: nvdCVE{
				ID: "CVE-123",
				Descriptions: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{{Lang: "en", Value: "valid"}},
				Configurations: []models.CVEConfiguration{
					{
						Nodes: []models.ConfigNode{
							{
								CPEMatch: []models.CPEMatch{
									{
										Criteria: "cpe:2.3:a:Vendor:Product:1.0:*:*:*:*:*:*:*",
										Vulnerable: true,
									},
								},
							},
						},
					},
				},
				References: []struct {
					URL string `json:"url"`
				}{
					{URL: "http://test.com"},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc, got := toTestCVE(tt.c, 2020)
			if got != tt.want {
				t.Errorf("toTestCVE() = %v, want %v", got, tt.want)
			}
			if tt.want {
				if tc.ID != tt.c.ID {
					t.Errorf("toTestCVE() ID = %v, want %v", tc.ID, tt.c.ID)
				}
				if len(tc.Truth) == 0 {
					t.Errorf("toTestCVE() truth empty")
				} else if tc.Truth[0].Vendor != "Vendor" || tc.Truth[0].Product != "Product" {
					t.Errorf("toTestCVE() truth = %v", tc.Truth[0])
				}
			}
		})
	}
}

func TestDistinctProducts(t *testing.T) {
	tests := []struct {
		name string
		t    []truthProduct
		want int
	}{
		{
			name: "empty",
			t:    nil,
			want: 0,
		},
		{
			name: "distinct",
			t: []truthProduct{
				{Vendor: "a", Product: "p1"},
				{Vendor: "a", Product: "p2"},
			},
			want: 2,
		},
		{
			name: "duplicate",
			t: []truthProduct{
				{Vendor: "a", Product: "p1"},
				{Vendor: "a", Product: "p1"},
			},
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := distinctProducts(tt.t); got != tt.want {
				t.Errorf("distinctProducts() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFetch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fail" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		resp := nvdResp{TotalResults: 1}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	client := ts.Client()

	resp := fetch(client, "", ts.URL)
	if resp == nil || resp.TotalResults != 1 {
		t.Errorf("fetch() = %v, want non-nil with TotalResults=1", resp)
	}
}

func TestCollectYearAndMain(t *testing.T) {
	t.Setenv("YEARS", "2020")
	t.Setenv("PER_YEAR", "0")
	err := runMain()
	if err != nil {
		t.Errorf("runMain() err = %v", err)
	}

	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"fetch_cves"}
	main()
}
