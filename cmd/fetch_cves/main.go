// Command fetch_cves builds a ground-truth test set for LLM vendor/product
// extraction. It pulls real CVEs from the NVD 2.0 API across multiple years,
// keeps only entries that have an English description and CPE configuration
// data (so we have authoritative vendor/product labels), and writes them to
// testset.json. The CPE-derived vendor/product pairs are the "truth" the LLMs
// are scored against.
package main

import (
	"cve-tracker/internal/models"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

const nvdBase = "https://services.nvd.nist.gov/rest/json/cves/2.0"

type nvdCVE struct {
	ID           string `json:"id"`
	VulnStatus   string `json:"vulnStatus"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	Configurations []models.CVEConfiguration `json:"configurations"`
}

type nvdResp struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type truthProduct struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
}

type testCVE struct {
	ID    string         `json:"id"`
	Year  int            `json:"year"`
	Desc  string         `json:"desc"`
	Refs  []string       `json:"refs"`
	Truth []truthProduct `json:"truth"`
}

func main() {
	perYear := 6
	if v := os.Getenv("PER_YEAR"); v != "" {
		fmt.Sscanf(v, "%d", &perYear)
	}
	years := []int{2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024, 2025}
	if v := os.Getenv("YEARS"); v != "" {
		years = years[:0]
		for _, s := range strings.Split(v, ",") {
			var y int
			fmt.Sscanf(strings.TrimSpace(s), "%d", &y)
			if y > 0 {
				years = append(years, y)
			}
		}
	}

	apiKey := os.Getenv("NVD_API_KEY")
	client := &http.Client{Timeout: 60 * time.Second}

	var all []testCVE
	for _, year := range years {
		collected := collectYear(client, apiKey, year, perYear)
		fmt.Printf("Year %d: collected %d CVEs with CPE ground truth\n", year, len(collected))
		all = append(all, collected...)
	}

	// Sort: multi-product first within each year so they're easy to spot, then by ID.
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Year != all[j].Year {
			return all[i].Year < all[j].Year
		}
		if len(all[i].Truth) != len(all[j].Truth) {
			return len(all[i].Truth) > len(all[j].Truth)
		}
		return all[i].ID < all[j].ID
	})

	out, _ := json.MarshalIndent(all, "", "  ")
	if err := os.WriteFile("testset.json", out, 0644); err != nil {
		fmt.Printf("write error: %v\n", err)
		os.Exit(1)
	}

	multi := 0
	for _, c := range all {
		if distinctProducts(c.Truth) > 1 {
			multi++
		}
	}
	fmt.Printf("\nWrote testset.json: %d CVEs total, %d with multiple distinct products\n", len(all), multi)
}

// collectYear pages through the published window for a year and returns up to
// `want` CVEs that have an English description and at least one CPE-derived
// vendor/product pair. It prefers a mix of single- and multi-product entries.
func collectYear(client *http.Client, apiKey string, year, want int) []testCVE {
	// NVD 2.0 caps the published-date range at 120 days, so query a single
	// ~119-day window per year (Jan 1 - Apr 29). That is plenty to find a
	// handful of CVEs with clean CPE data.
	start := fmt.Sprintf("%d-01-01T00:00:00.000", year)
	end := fmt.Sprintf("%d-04-29T23:59:59.999", year)

	var result []testCVE
	multiCount := 0
	// Page through; NVD caps resultsPerPage at 2000 but we keep pages small and
	// scan a few hundred entries per year to find ones with clean CPE data.
	for startIdx := 0; startIdx < 600 && len(result) < want; startIdx += 200 {
		url := fmt.Sprintf("%s?pubStartDate=%s&pubEndDate=%s&resultsPerPage=200&startIndex=%d",
			nvdBase, start, end, startIdx)
		resp := fetch(client, apiKey, url)
		if resp == nil || len(resp.Vulnerabilities) == 0 {
			break
		}
		for _, entry := range resp.Vulnerabilities {
			if len(result) >= want {
				break
			}
			tc, ok := toTestCVE(entry.CVE, year)
			if !ok {
				continue
			}
			isMulti := distinctProducts(tc.Truth) > 1
			// Aim for at least a third multi-product; otherwise cap how many
			// single-product entries we keep so multi ones aren't crowded out.
			if !isMulti && len(result)-multiCount >= (want*2/3) && multiCount < want/3 {
				continue
			}
			if isMulti {
				multiCount++
			}
			result = append(result, tc)
		}
	}
	return result
}

func toTestCVE(c nvdCVE, year int) (testCVE, bool) {
	if strings.HasPrefix(strings.ToUpper(c.VulnStatus), "REJECT") {
		return testCVE{}, false
	}
	desc := ""
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			desc = d.Value
			break
		}
	}
	if desc == "" || strings.Contains(desc, "** REJECT **") || strings.HasPrefix(desc, "Rejected reason") {
		return testCVE{}, false
	}

	cve := models.CVE{Configurations: models.CVEConfigurations(c.Configurations)}
	affected := cve.GetAffectedProducts()
	if len(affected) == 0 {
		return testCVE{}, false
	}
	seen := map[string]bool{}
	var truth []truthProduct
	for _, a := range affected {
		if a.Vendor == "" || a.Product == "" {
			continue
		}
		key := a.Vendor + ":" + a.Product
		if seen[key] {
			continue
		}
		seen[key] = true
		truth = append(truth, truthProduct{Vendor: a.Vendor, Product: a.Product})
	}
	if len(truth) == 0 {
		return testCVE{}, false
	}

	var refs []string
	for _, r := range c.References {
		if r.URL != "" {
			refs = append(refs, r.URL)
		}
		if len(refs) >= 4 {
			break
		}
	}

	return testCVE{ID: c.ID, Year: year, Desc: desc, Refs: refs, Truth: truth}, true
}

func distinctProducts(t []truthProduct) int {
	seen := map[string]bool{}
	for _, p := range t {
		seen[p.Product] = true
	}
	return len(seen)
}

func fetch(client *http.Client, apiKey, url string) *nvdResp {
	for attempt := 0; attempt < 4; attempt++ {
		// NVD rate limits: 5 req/30s without a key, 50 req/30s with one.
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 8 * time.Second)
		} else {
			delay := 7 * time.Second
			if apiKey != "" {
				delay = 1 * time.Second
			}
			time.Sleep(delay)
		}
		req, _ := http.NewRequest("GET", url, nil)
		if apiKey != "" {
			req.Header.Set("apiKey", apiKey)
		}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("  fetch error (attempt %d): %v\n", attempt, err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			fmt.Printf("  NVD status %d (attempt %d)\n", resp.StatusCode, attempt)
			continue
		}
		var r nvdResp
		if err := json.Unmarshal(body, &r); err != nil {
			fmt.Printf("  parse error: %v\n", err)
			continue
		}
		return &r
	}
	return nil
}
