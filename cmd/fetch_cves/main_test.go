package main

import (
	"cve-tracker/internal/models"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"testing"
)

type rewriteTransport struct {
	serverURL string
	transport http.RoundTripper
}

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	u, _ := url.Parse(t.serverURL)
	newReq := req.Clone(req.Context())
	newReq.URL.Scheme = u.Scheme
	newReq.URL.Host = u.Host
	return t.transport.RoundTrip(newReq)
}

func TestDistinctProducts(t *testing.T) {
	tests := []struct {
		name  string
		truth []truthProduct
		want  int
	}{
		{
			name:  "empty",
			truth: nil,
			want:  0,
		},
		{
			name: "single product",
			truth: []truthProduct{
				{Vendor: "vendor1", Product: "prod1"},
			},
			want: 1,
		},
		{
			name: "duplicate product",
			truth: []truthProduct{
				{Vendor: "vendor1", Product: "prod1"},
				{Vendor: "vendor2", Product: "prod1"},
			},
			want: 1,
		},
		{
			name: "distinct products",
			truth: []truthProduct{
				{Vendor: "vendor1", Product: "prod1"},
				{Vendor: "vendor1", Product: "prod2"},
			},
			want: 2,
		},
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
		name   string
		c      nvdCVE
		year   int
		want   testCVE
		wantOk bool
	}{
		{
			name: "rejected status",
			c: nvdCVE{
				VulnStatus: "REJECTED",
			},
			year:   2023,
			want:   testCVE{},
			wantOk: false,
		},
		{
			name: "no english description",
			c: nvdCVE{
				VulnStatus: "Analyzed",
				Descriptions: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{
					{Lang: "es", Value: "descripcion"},
				},
			},
			year:   2023,
			want:   testCVE{},
			wantOk: false,
		},
		{
			name: "rejected description",
			c: nvdCVE{
				VulnStatus: "Analyzed",
				Descriptions: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{
					{Lang: "en", Value: "** REJECT ** this is rejected"},
				},
			},
			year:   2023,
			want:   testCVE{},
			wantOk: false,
		},
		{
			name: "valid but no configurations",
			c: nvdCVE{
				ID:         "CVE-2023-1234",
				VulnStatus: "Analyzed",
				Descriptions: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{
					{Lang: "en", Value: "Valid description"},
				},
			},
			year:   2023,
			want:   testCVE{},
			wantOk: false,
		},
		{
			name: "valid with configurations and references",
			c: nvdCVE{
				ID:         "CVE-2023-1234",
				VulnStatus: "Analyzed",
				Descriptions: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{
					{Lang: "en", Value: "Valid description"},
				},
				Configurations: []models.CVEConfiguration{
					{
						Nodes: []models.ConfigNode{
							{
								CPEMatch: []models.CPEMatch{
									{Criteria: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"},
								},
							},
						},
					},
				},
				References: []struct {
					URL string `json:"url"`
				}{
					{URL: "https://example.com/ref1"},
				},
			},
			year: 2023,
			want: testCVE{
				ID:   "CVE-2023-1234",
				Year: 2023,
				Desc: "Valid description",
				Refs: []string{"https://example.com/ref1"},
				Truth: []truthProduct{
					{Vendor: "Vendor", Product: "Product"},
				},
			},
			wantOk: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := toTestCVE(tt.c, tt.year)
			if ok != tt.wantOk {
				t.Errorf("toTestCVE() ok = %v, want %v", ok, tt.wantOk)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("toTestCVE() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRunMain(t *testing.T) {
	tests := []struct {
		name       string
		mockBody   string
		mockStatus int
		envYears   string
		envPerYear string
		wantErr    bool
	}{
		{
			name:       "success empty response",
			mockBody:   `{"totalResults": 0, "vulnerabilities": []}`,
			mockStatus: http.StatusOK,
			envYears:   "2024",
			envPerYear: "1",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalTransport := http.DefaultTransport
			defer func() { http.DefaultTransport = originalTransport }()

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.mockStatus)
				_, _ = w.Write([]byte(tt.mockBody))
			}))
			defer ts.Close()

			if originalTransport == nil {
				originalTransport = http.DefaultTransport
			}
			http.DefaultTransport = &rewriteTransport{
				serverURL: ts.URL,
				transport: originalTransport,
			}

			t.Setenv("PER_YEAR", tt.envPerYear)
			t.Setenv("YEARS", tt.envYears)
			t.Setenv("NVD_API_KEY", "test-key")

			originalWd, _ := os.Getwd()
			tmpDir := t.TempDir()
			_ = os.Chdir(tmpDir)
			defer func() { _ = os.Chdir(originalWd) }()

			err := runMain()
			if (err != nil) != tt.wantErr {
				t.Errorf("runMain() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
