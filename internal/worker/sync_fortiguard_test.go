package worker

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"cve-tracker/internal/db"

	"github.com/PuerkitoBio/goquery"
	"github.com/alicebob/miniredis/v2"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/redis/go-redis/v9"

	"net/http"
	"time"
	"net/http/httptest"
	"crypto/tls")

func TestParseFortiGuardAdvisoryHTML(t *testing.T) {
	tests := []struct {
		name           string
		html           string
		url            string
		expected       *FortiGuardAdvisory
		expectError    bool
		expectedFields []string // fields that should be populated
	}{
		{
			name: "Complete advisory with all fields",
			html: `<html>
			<head><title>FG-IR-24-388 Multiple Vulnerabilities in FortiOS</title></head>
			<body>
				<h1>FG-IR-24-388 Multiple Vulnerabilities in FortiOS</h1>
				<div class="severity-badge">Critical</div>
				<p>CVSS: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)</p>
				<div><strong>Impact:</strong> Remote Code Execution</div>
				<div class="affected-products">
					<table>
						<tr><td>FortiOS</td><td>7.4.0 through 7.4.3</td></tr>
						<tr><td>FortiProxy</td><td>7.2.0 before 7.2.8</td></tr>
					</table>
				</div>
				<div>
					<h3>Solution</h3>
					<p>Upgrade to FortiOS version 7.4.4 or above</p>
				</div>
				<div>
					<h3>Workaround</h3>
					<p>Disable SSL-VPN service</p>
				</div>
				<p>This vulnerability allows remote attackers to execute arbitrary code on affected installations of FortiOS...</p>
				<a href="https://nvd.nist.gov/vuln/detail/CVE-2024-1234">CVE-2024-1234</a>
				<a href="https://nvd.nist.gov/vuln/detail/CVE-2024-5678">CVE-2024-5678</a>
			</body>
		</html>`,
			url: "https://www.fortiguard.com/psirt/FG-IR-24-388",
			expected: &FortiGuardAdvisory{
				AdvisoryID: "FG-IR-24-388",
				Title:      "Multiple Vulnerabilities in FortiOS",
				Severity:   "Critical",
				CVSSScore:  9.8,
				CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Impact:     "Remote Code Execution",
				AffectedProducts: []FortiGuardProduct{
					{Name: "FortiOS", VersionRange: "7.4.0 through 7.4.3"},
					{Name: "FortiProxy", VersionRange: "7.2.0 before 7.2.8"},
				},
				FixInfo:     "Upgrade to FortiOS version 7.4.4 or above",
				Workaround:  "Disable SSL-VPN service",
				Description: "This vulnerability allows remote attackers to execute arbitrary code on affected installations of FortiOS...",
				CVEIDs:      []string{"CVE-2024-1234", "CVE-2024-5678"},
				URL:         "https://www.fortiguard.com/psirt/FG-IR-24-388",
			},
			expectError:    false,
			expectedFields: []string{"AdvisoryID", "Title", "Severity", "CVSSScore", "CVSSVector", "Impact", "AffectedProducts", "FixInfo", "Workaround", "Description", "CVEIDs", "URL", "LastUpdated"},
		},
		{
			name: "Minimal advisory with missing optional fields",
			html: `<html>
			<head><title>FG-IR-23-001 Security Advisory</title></head>
			<body>
				<h1>FG-IR-23-001 Security Advisory</h1>
				<p>This is a security advisory about a vulnerability in FortiWeb.</p>
				<a href="https://nvd.nist.gov/vuln/detail/CVE-2023-9999">CVE-2023-9999</a>
			</body>
		</html>`,
			url: "https://www.fortiguard.com/psirt/FG-IR-23-001",
			expected: &FortiGuardAdvisory{
				AdvisoryID:  "FG-IR-23-001",
				Title:       "Security Advisory",
				Description: "This is a security advisory about a vulnerability in FortiWeb.",
				CVEIDs:      []string{"CVE-2023-9999"},
				URL:         "https://www.fortiguard.com/psirt/FG-IR-23-001",
			},
			expectError:    false,
			expectedFields: []string{"AdvisoryID", "Title", "Description", "CVEIDs", "URL", "LastUpdated"},
		},
		{
			name:        "Empty HTML",
			html:        ``,
			url:         "https://www.fortiguard.com/psirt/FG-IR-22-123",
			expectError: true,
		},
		{
			name:        "HTML without advisory ID in URL",
			html:        `<html><body><h1>Security Advisory</h1></body></html>`,
			url:         "https://www.fortiguard.com/psirt/invalid-url",
			expectError: false,
			expected: &FortiGuardAdvisory{
				Title: "Security Advisory",
				URL:   "https://www.fortiguard.com/psirt/invalid-url",
			},
			expectedFields: []string{"Title", "URL", "LastUpdated"},
		},
		{
			name: "Advisory with partial data (severity but no CVSS)",
			html: `<html>
			<head><title>FG-IR-24-456 Medium Severity Issue</title></head>
			<body>
				<h1>FG-IR-24-456 Medium Severity Issue</h1>
				<div class="severity-badge">Medium</div>
				<p>This is a medium severity issue affecting FortiManager.</p>
				<a href="https://nvd.nist.gov/vuln/detail/CVE-2024-4567">CVE-2024-4567</a>
			</body>
		</html>`,
			url: "https://www.fortiguard.com/psirt/FG-IR-24-456",
			expected: &FortiGuardAdvisory{
				AdvisoryID:  "FG-IR-24-456",
				Title:       "Medium Severity Issue",
				Severity:    "Medium",
				Description: "This is a medium severity issue affecting FortiManager.",
				CVEIDs:      []string{"CVE-2024-4567"},
				URL:         "https://www.fortiguard.com/psirt/FG-IR-24-456",
			},
			expectError:    false,
			expectedFields: []string{"AdvisoryID", "Title", "Severity", "Description", "CVEIDs", "URL", "LastUpdated"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := goquery.NewDocumentFromReader(strings.NewReader(tt.html))
			if err != nil && !tt.expectError {
				t.Fatalf("Failed to parse HTML: %v", err)
			} else if err != nil && tt.expectError {
				return // Expected error
			}

			advisory, err := parseFortiGuardAdvisory(doc, tt.url)
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
				return
			} else if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if tt.expectError {
				return
			}

			if tt.expected != nil {
				if advisory.AdvisoryID != tt.expected.AdvisoryID {
					t.Errorf("AdvisoryID: got %q, want %q", advisory.AdvisoryID, tt.expected.AdvisoryID)
				}
				if advisory.Title != tt.expected.Title {
					t.Errorf("Title: got %q, want %q", advisory.Title, tt.expected.Title)
				}
				if advisory.Severity != tt.expected.Severity {
					t.Errorf("Severity: got %q, want %q", advisory.Severity, tt.expected.Severity)
				}
				if advisory.CVSSScore != tt.expected.CVSSScore {
					t.Errorf("CVSSScore: got %v, want %v", advisory.CVSSScore, tt.expected.CVSSScore)
				}
				if advisory.CVSSVector != tt.expected.CVSSVector {
					t.Errorf("CVSSVector: got %q, want %q", advisory.CVSSVector, tt.expected.CVSSVector)
				}
				if advisory.Impact != tt.expected.Impact {
					t.Errorf("Impact: got %q, want %q", advisory.Impact, tt.expected.Impact)
				}
				if advisory.FixInfo != tt.expected.FixInfo {
					t.Errorf("FixInfo: got %q, want %q", advisory.FixInfo, tt.expected.FixInfo)
				}
				if advisory.Workaround != tt.expected.Workaround {
					t.Errorf("Workaround: got %q, want %q", advisory.Workaround, tt.expected.Workaround)
				}
				if advisory.Description != tt.expected.Description {
					t.Errorf("Description: got %q, want %q", advisory.Description, tt.expected.Description)
				}
				if advisory.URL != tt.expected.URL {
					t.Errorf("URL: got %q, want %q", advisory.URL, tt.expected.URL)
				}

				// Check CVEIDs (order independent)
				if len(advisory.CVEIDs) != len(tt.expected.CVEIDs) {
					t.Errorf("CVEIDs length: got %d, want %d", len(advisory.CVEIDs), len(tt.expected.CVEIDs))
				} else {
					cveMap := make(map[string]bool)
					for _, cve := range advisory.CVEIDs {
						cveMap[cve] = true
					}
					for _, expectedCVE := range tt.expected.CVEIDs {
						if !cveMap[expectedCVE] {
							t.Errorf("Missing CVEID: %q", expectedCVE)
						}
					}
				}

				// Check AffectedProducts
				if len(advisory.AffectedProducts) != len(tt.expected.AffectedProducts) {
					t.Errorf("AffectedProducts length: got %d, want %d", len(advisory.AffectedProducts), len(tt.expected.AffectedProducts))
				} else {
					for i, expectedProduct := range tt.expected.AffectedProducts {
						if i >= len(advisory.AffectedProducts) {
							break
						}
						actualProduct := advisory.AffectedProducts[i]
						if actualProduct.Name != expectedProduct.Name {
							t.Errorf("AffectedProduct[%d].Name: got %q, want %q", i, actualProduct.Name, expectedProduct.Name)
						}
						if actualProduct.VersionRange != expectedProduct.VersionRange {
							t.Errorf("AffectedProduct[%d].VersionRange: got %q, want %q", i, actualProduct.VersionRange, expectedProduct.VersionRange)
						}
					}
				}
			}

			// Verify that only expected fields are populated
			val := reflect.ValueOf(*advisory)
			for i := 0; i < val.NumField(); i++ {
				fieldName := val.Type().Field(i).Name
				fieldValue := val.Field(i).Interface()

				// Check if field should be populated
				shouldBePopulated := false
				for _, expectedField := range tt.expectedFields {
					if expectedField == fieldName {
						shouldBePopulated = true
						break
					}
				}

				if shouldBePopulated {
					// Check if field has a zero value
					zeroValue := reflect.Zero(val.Type().Field(i).Type).Interface()
					if reflect.DeepEqual(fieldValue, zeroValue) {
						t.Errorf("Field %s should be populated but is zero value", fieldName)
					}
				} else {
					// Check if field should be zero value
					zeroValue := reflect.Zero(val.Type().Field(i).Type).Interface()
					if !reflect.DeepEqual(fieldValue, zeroValue) {
						t.Errorf("Field %s should be zero value but got %v", fieldName, fieldValue)
					}
				}
			}
		})
	}
}

func TestFortiGuardRSSParsing(t *testing.T) {
	tests := []struct {
		name               string
		rssContent         string
		expectedCount      int
		expectedAdvisories map[string]struct {
			cveIDs []string
			url    string
		}
	}{
		{
			name: "Valid RSS with multiple items",
			rssContent: `<?xml version="1.0" encoding="UTF-8"?>
			<rss version="2.0">
			<channel>
				<title>FortiGuard PSIRT Advisories</title>
				<item>
					<title>FG-IR-24-388 Multiple Vulnerabilities in FortiOS CVE-2024-1234 CVE-2024-5678</title>
					<link>https://www.fortiguard.com/psirt/FG-IR-24-388</link>
					<description>Multiple vulnerabilities in FortiOS that could allow remote code execution.</description>
				</item>
				<item>
					<title>FG-IR-24-389 Security Advisory</title>
					<link>https://www.fortiguard.com/psirt/FG-IR-24-389</link>
					<description>Security advisory without CVE references.</description>
				</item>
				<item>
					<title>Random News Article</title>
					<link>https://www.fortiguard.com/news/article</link>
					<description>This is not a security advisory.</description>
				</item>
				<item>
					<title>FG-IR-23-001 Critical Vulnerability CVE-2023-9999</title>
					<link>https://www.fortiguard.com/psirt/FG-IR-23-001</link>
					<description>Critical vulnerability in FortiWeb.</description>
				</item>
			</channel>
			</rss>`,
			expectedCount: 3,
			expectedAdvisories: map[string]struct {
				cveIDs []string
				url    string
			}{
				"FG-IR-24-388": {cveIDs: []string{"CVE-2024-1234", "CVE-2024-5678"}, url: "https://www.fortiguard.com/psirt/FG-IR-24-388"},
				"FG-IR-24-389": {cveIDs: []string{}, url: "https://www.fortiguard.com/psirt/FG-IR-24-389"},
				"FG-IR-23-001": {cveIDs: []string{"CVE-2023-9999"}, url: "https://www.fortiguard.com/psirt/FG-IR-23-001"},
			},
		},
		{
			name: "Empty RSS",
			rssContent: `<?xml version="1.0" encoding="UTF-8"?>
			<rss version="2.0">
			<channel>
				<title>FortiGuard PSIRT Advisories</title>
			</channel>
			</rss>`,
			expectedCount: 0,
			expectedAdvisories: map[string]struct {
				cveIDs []string
				url    string
			}{},
		},
		{
			name: "RSS with duplicate CVE IDs",
			rssContent: `<?xml version="1.0" encoding="UTF-8"?>
			<rss version="2.0">
			<channel>
				<item>
					<title>FG-IR-24-500 Multiple CVEs CVE-2024-0001 CVE-2024-0001 CVE-2024-0002</title>
					<link>https://www.fortiguard.com/psirt/FG-IR-24-500</link>
					<description>Advisory with duplicate CVE references.</description>
				</item>
			</channel>
			</rss>`,
			expectedCount: 1,
			expectedAdvisories: map[string]struct {
				cveIDs []string
				url    string
			}{
				"FG-IR-24-500": {cveIDs: []string{"CVE-2024-0001", "CVE-2024-0002"}, url: "https://www.fortiguard.com/psirt/FG-IR-24-500"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &Worker{}
			advisoryMap, err := w.parseFortiGuardRSS(strings.NewReader(tt.rssContent))
			if err != nil {
				t.Fatalf("Failed to parse RSS: %v", err)
			}

			if len(advisoryMap) != tt.expectedCount {
				t.Errorf("Expected %d advisories, got %d", tt.expectedCount, len(advisoryMap))
			}

			for expectedID, expectedData := range tt.expectedAdvisories {
				actualData, exists := advisoryMap[expectedID]
				if !exists {
					t.Errorf("Expected advisory %q not found", expectedID)
					continue
				}

				if actualData.url != expectedData.url {
					t.Errorf("Advisory %q URL: got %q, want %q", expectedID, actualData.url, expectedData.url)
				}

				if len(actualData.cveIDs) != len(expectedData.cveIDs) {
					t.Errorf("Advisory %q CVEIDs length: got %d, want %d", expectedID, len(actualData.cveIDs), len(expectedData.cveIDs))
				} else {
					cveMap := make(map[string]bool)
					for _, cve := range actualData.cveIDs {
						cveMap[cve] = true
					}
					for _, expectedCVE := range expectedData.cveIDs {
						if !cveMap[expectedCVE] {
							t.Errorf("Advisory %q missing CVEID: %q", expectedID, expectedCVE)
						}
					}
				}
			}
		})
	}
}

// parseFortiGuardRSS is a helper method to test RSS parsing in isolation
func (w *Worker) parseFortiGuardRSS(r io.Reader) (map[string]struct {
	cveIDs []string
	url    string
}, error) {
	advisoryMap := make(map[string]struct {
		cveIDs []string
		url    string
	})

	var feed rssFeed
	if err := xml.NewDecoder(r).Decode(&feed); err != nil {
		return nil, fmt.Errorf("failed to decode RSS: %w", err)
	}

	for _, item := range feed.Channel.Items {
		parts := strings.Split(item.Title, " ")
		if len(parts) == 0 {
			continue
		}

		// Identify FortiGuard advisories with the same regex as production code
		advisoryID := fortiGuardIDRegex.FindString(item.Title)
		if advisoryID == "" {
			continue // Not a FortiGuard advisory
		}

		// Extract CVE IDs from title
		var cveIDs []string
		for _, part := range parts {
			if strings.HasPrefix(part, "CVE-") {
				cveIDs = append(cveIDs, part)
			}
		}

		// Remove duplicate CVE IDs
		uniqueCVEIDs := make(map[string]bool)
		for _, cve := range cveIDs {
			uniqueCVEIDs[cve] = true
		}
		cveIDs = []string{}
		for cve := range uniqueCVEIDs {
			cveIDs = append(cveIDs, cve)
		}

		advisoryMap[advisoryID] = struct {
			cveIDs []string
			url    string
		}{
			cveIDs: cveIDs,
			url:    item.Link,
		}
	}

	return advisoryMap, nil
}

func TestFortiGuardCVEUpdate(t *testing.T) {
	tests := []struct {
		name            string
		advisory        *FortiGuardAdvisory
		mockSetup       func(pgxmock.PgxPoolIface)
		expectError     bool
		expectedUpdates int
	}{
		{
			name: "Successful update with multiple CVEs",
			advisory: &FortiGuardAdvisory{
				AdvisoryID: "FG-IR-24-388",
				Title:      "Multiple Vulnerabilities in FortiOS",
				Severity:   "Critical",
				CVEIDs:     []string{"CVE-2024-1234", "CVE-2024-5678"},
				URL:        "https://www.fortiguard.com/psirt/FG-IR-24-388",
			},
			mockSetup: func(mock pgxmock.PgxPoolIface) {
				// Mock query for existing CVEs
				rows := pgxmock.NewRows([]string{"id", "cve_id", "affected_products", "vendor_advisories"}).
					AddRow(1, "CVE-2024-1234", []byte(`[]`), []byte(`{}`)).
					AddRow(2, "CVE-2024-5678", []byte(`[]`), []byte(`{}`))
				mock.ExpectQuery(`SELECT id, cve_id, affected_products, vendor_advisories FROM cves WHERE cve_id = ANY`).
					WithArgs([]string{"CVE-2024-1234", "CVE-2024-5678"}).
					WillReturnRows(rows)

				// Mock transaction for batch update
				mock.ExpectBegin()
				mock.ExpectExec(`UPDATE cves`).
					WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), 1).
					WillReturnResult(pgxmock.NewResult("UPDATE", 1))
				mock.ExpectExec(`UPDATE cves`).
					WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), 2).
					WillReturnResult(pgxmock.NewResult("UPDATE", 1))
				mock.ExpectCommit()
			},
			expectError:     false,
			expectedUpdates: 2,
		},
		{
			name: "No existing CVEs in database",
			advisory: &FortiGuardAdvisory{
				AdvisoryID: "FG-IR-24-389",
				Title:      "Security Advisory",
				CVEIDs:     []string{"CVE-2024-9999"},
				URL:        "https://www.fortiguard.com/psirt/FG-IR-24-389",
			},
			mockSetup: func(mock pgxmock.PgxPoolIface) {
				// Mock query for existing CVEs - return empty result
				rows := pgxmock.NewRows([]string{"id", "cve_id", "affected_products", "vendor_advisories"})
				mock.ExpectQuery(`SELECT id, cve_id, affected_products, vendor_advisories FROM cves WHERE cve_id = ANY`).
					WithArgs([]string{"CVE-2024-9999"}).
					WillReturnRows(rows)
			},
			expectError:     false,
			expectedUpdates: 0,
		},
		{
			name: "Database error during query",
			advisory: &FortiGuardAdvisory{
				AdvisoryID: "FG-IR-24-390",
				Title:      "Database Error Test",
				CVEIDs:     []string{"CVE-2024-0001"},
				URL:        "https://www.fortiguard.com/psirt/FG-IR-24-390",
			},
			mockSetup: func(mock pgxmock.PgxPoolIface) {
				// Mock query to return error
				mock.ExpectQuery(`SELECT id, cve_id, affected_products, vendor_advisories FROM cves WHERE cve_id = ANY`).
					WithArgs([]string{"CVE-2024-0001"}).
					WillReturnError(errors.New("database connection failed"))
			},
			expectError:     true,
			expectedUpdates: 0,
		},
		{
			name: "Database error during update",
			advisory: &FortiGuardAdvisory{
				AdvisoryID: "FG-IR-24-391",
				Title:      "Update Error Test",
				CVEIDs:     []string{"CVE-2024-0002"},
				URL:        "https://www.fortiguard.com/psirt/FG-IR-24-391",
			},
			mockSetup: func(mock pgxmock.PgxPoolIface) {
				// Mock query for existing CVE
				rows := pgxmock.NewRows([]string{"id", "cve_id", "affected_products", "vendor_advisories"}).
					AddRow(1, "CVE-2024-0002", []byte(`[]`), []byte(`{}`))
				mock.ExpectQuery(`SELECT id, cve_id, affected_products, vendor_advisories FROM cves WHERE cve_id = ANY`).
					WithArgs([]string{"CVE-2024-0002"}).
					WillReturnRows(rows)

				// Mock transaction for batch update
				mock.ExpectBegin()
				// Mock update to return error
				mock.ExpectExec(`UPDATE cves`).
					WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), 1).
					WillReturnError(errors.New("update failed"))
				mock.ExpectRollback()
			},
			expectError:     true,
			expectedUpdates: 0,
		},
		{
			name: "Advisory with existing vendor_advisories data",
			advisory: &FortiGuardAdvisory{
				AdvisoryID: "FG-IR-24-392",
				Title:      "Existing Data Test",
				Severity:   "High",
				CVEIDs:     []string{"CVE-2024-3333"},
				URL:        "https://www.fortiguard.com/psirt/FG-IR-24-392",
			},
			mockSetup: func(mock pgxmock.PgxPoolIface) {
				// Mock query for existing CVE with existing vendor_advisories data
				rows := pgxmock.NewRows([]string{"id", "cve_id", "affected_products", "vendor_advisories"}).
					AddRow(1, "CVE-2024-3333", []byte(`[]`), []byte(`{"cisco":{"advisory_id":"CISCO-1"}}`))
				mock.ExpectQuery(`SELECT id, cve_id, affected_products, vendor_advisories FROM cves WHERE cve_id = ANY`).
					WithArgs([]string{"CVE-2024-3333"}).
					WillReturnRows(rows)

				// Mock transaction for batch update
				mock.ExpectBegin()
				mock.ExpectExec(`UPDATE cves`).
					WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), 1).
					WillReturnResult(pgxmock.NewResult("UPDATE", 1))
				mock.ExpectCommit()
			},
			expectError:     false,
			expectedUpdates: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock, err := db.SetupTestDB()
			if err != nil {
				t.Fatalf("failed to setup mock db: %v", err)
			}
			defer mock.Close()

			mr, err := miniredis.Run()
			if err != nil {
				t.Fatalf("failed to setup mock redis: %v", err)
			}
			defer mr.Close()
			rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
			defer rdb.Close()

			tt.mockSetup(mock)

			w := NewWorker(mock, rdb, &EmailSenderMock{}, &MockHTTPClient{})

			err = w.updateCVEsWithAdvisory(context.Background(), tt.advisory)
			if (err != nil) != tt.expectError {
				t.Errorf("updateCVEsWithAdvisory() error = %v, expectError %v", err, tt.expectError)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet expectations: %v", err)
			}
		})
	}
}


func TestFortiGuardShouldRetry(t *testing.T) {
	tests := []struct {
		name        string
		resp        *http.Response
		err         error
		attempt     int
		wantRetry   bool
		wantWaitMax time.Duration
	}{
		{
			name:        "error exists",
			resp:        nil,
			err:         errors.New("network error"),
			attempt:     0,
			wantRetry:   true,
			wantWaitMax: time.Second * 2,
		},
		{
			name:        "no response, no error",
			resp:        nil,
			err:         nil,
			attempt:     0,
			wantRetry:   false,
			wantWaitMax: 0,
		},
		{
			name: "too many requests with retry-after header",
			resp: &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Header: http.Header{
					"Retry-After": []string{"10"},
				},
			},
			err:         nil,
			attempt:     0,
			wantRetry:   true,
			wantWaitMax: time.Second * 10,
		},
		{
			name: "too many requests without retry-after header",
			resp: &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Header:     http.Header{},
			},
			err:         nil,
			attempt:     0,
			wantRetry:   true,
			wantWaitMax: time.Second * 30,
		},
		{
			name: "server error (500)",
			resp: &http.Response{
				StatusCode: http.StatusInternalServerError,
			},
			err:         nil,
			attempt:     1,
			wantRetry:   true,
			wantWaitMax: time.Second * 3,
		},
		{
			name: "success (200)",
			resp: &http.Response{
				StatusCode: http.StatusOK,
			},
			err:         nil,
			attempt:     0,
			wantRetry:   false,
			wantWaitMax: 0,
		},
		{
			name: "too many requests, retry-after max limit",
			resp: &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Header: http.Header{
					"Retry-After": []string{"600"}, // 10 minutes, > 5 minutes max
				},
			},
			err:         nil,
			attempt:     0,
			wantRetry:   true,
			wantWaitMax: 5 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRetry, gotWait := fortiGuardShouldRetry(tt.resp, tt.err, tt.attempt)
			if gotRetry != tt.wantRetry {
				t.Errorf("fortiGuardShouldRetry() gotRetry = %v, want %v", gotRetry, tt.wantRetry)
			}
			if gotWait > tt.wantWaitMax {
				t.Errorf("fortiGuardShouldRetry() gotWait = %v, want max %v", gotWait, tt.wantWaitMax)
			}
		})
	}
}

func TestWorker_CachedAdvisory(t *testing.T) {
	// Setup miniredis
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	w := &Worker{Redis: rdb}
	ctx := context.Background()

	// Test cache miss
	advisory, err := w.getCachedAdvisory(ctx, "FG-IR-00-000")
	if err != nil {
		t.Errorf("getCachedAdvisory() unexpected error on miss: %v", err)
	}
	if advisory != nil {
		t.Errorf("getCachedAdvisory() expected nil on miss, got %v", advisory)
	}

	// Test cache hit
	expectedAdvisory := &FortiGuardAdvisory{
		AdvisoryID:  "FG-IR-00-001",
		Title:       "Test Advisory",
		Description: "Test Description",
	}
	err = w.cacheAdvisory(ctx, expectedAdvisory)
	if err != nil {
		t.Fatalf("cacheAdvisory() unexpected error: %v", err)
	}

	advisory, err = w.getCachedAdvisory(ctx, "FG-IR-00-001")
	if err != nil {
		t.Errorf("getCachedAdvisory() unexpected error on hit: %v", err)
	}
	if advisory == nil {
		t.Fatalf("getCachedAdvisory() expected advisory, got nil")
	}
	if advisory.AdvisoryID != expectedAdvisory.AdvisoryID {
		t.Errorf("getCachedAdvisory() ID got = %v, want %v", advisory.AdvisoryID, expectedAdvisory.AdvisoryID)
	}

	// Test invalid JSON
	mr.Set("fortiguard:advisory:FG-IR-00-002", "invalid json")
	_, err = w.getCachedAdvisory(ctx, "FG-IR-00-002")
	if err == nil {
		t.Errorf("getCachedAdvisory() expected error on invalid JSON, got nil")
	}
}



func TestWorker_FetchFortiGuardRSS(t *testing.T) {
	tests := []struct {
		name        string
		serverBody  string
		serverCode  int
		wantCount   int
		wantErr     bool
		wantErrType string
	}{
		{
			name:       "valid RSS feed",
			serverCode: http.StatusOK,
			serverBody: `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
	<channel>
		<item>
			<title>Test Advisory FG-IR-00-001</title>
			<link>https://fortiguard.com/psirt/FG-IR-00-001</link>
			<description>Affects: CVE-2023-0001, CVE-2023-0002</description>
		</item>
	</channel>
</rss>`,
			wantCount: 1,
			wantErr:   false,
		},
		{
			name:       "server error",
			serverCode: http.StatusInternalServerError,
			serverBody: "internal server error",
			wantCount:  0,
			wantErr:    true,
		},
		{
			name:       "invalid xml",
			serverCode: http.StatusOK,
			serverBody: "invalid xml",
			wantCount:  0,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.serverCode)
				w.Write([]byte(tt.serverBody))
			}))
			defer server.Close()

			// Create a new client, wait, Fortiguard URL is hardcoded in the function.
			// The original fetchFortiGuardRSS has fortiguardRSSURL hardcoded.
			// I need to intercept it somehow? Wait, DoWithRetry is used.
			// Let's replace fortiguardRSSURL during the test if possible, wait, it's a constant.
			// Let's see if we can use a custom HTTP client Transport to mock it.

			w := &Worker{
				HTTP: &mockFortiGuardClient{server: server},
			}


			ctx := context.Background()
			advisoryMap, err := w.fetchFortiGuardRSS(ctx)

			if (err != nil) != tt.wantErr {
				t.Errorf("fetchFortiGuardRSS() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(advisoryMap) != tt.wantCount {
				t.Errorf("fetchFortiGuardRSS() got %v advisories, want %v", len(advisoryMap), tt.wantCount)
			}
		})
	}
}

func TestWorker_FilterRelevantAdvisories(t *testing.T) {
	// Setup DB mock
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer mock.Close()

	w := &Worker{
		Pool: mock,
	}

	tests := []struct {
		name        string
		advisoryMap map[string]struct {
			cveIDs []string
			url    string
		}
		mockSetup func()
		wantIDs   []string
		wantErr   bool
	}{
		{
			name: "no advisories",
			advisoryMap: map[string]struct {
				cveIDs []string
				url    string
			}{},
			mockSetup: func() {},
			wantIDs:   []string{},
			wantErr:   false,
		},
		{
			name: "relevant advisories found",
			advisoryMap: map[string]struct {
				cveIDs []string
				url    string
			}{
				"FG-IR-00-001": {cveIDs: []string{"CVE-2023-0001"}, url: "http://test1"},
				"FG-IR-00-002": {cveIDs: []string{"CVE-2023-0002"}, url: "http://test2"},
			},
			mockSetup: func() {
				// The query in filterRelevantAdvisories
				// "SELECT cve_id FROM cves WHERE cve_id = ANY($1)"
				mock.ExpectQuery("SELECT cve_id FROM cves WHERE cve_id = ANY").
					WithArgs(pgxmock.AnyArg()).
					WillReturnRows(pgxmock.NewRows([]string{"cve_id"}).AddRow("CVE-2023-0001"))
			},
			wantIDs: []string{"FG-IR-00-001"},
			wantErr: false,
		},
		{
			name: "db error",
			advisoryMap: map[string]struct {
				cveIDs []string
				url    string
			}{
				"FG-IR-00-001": {cveIDs: []string{"CVE-2023-0001"}, url: "http://test1"},
			},
			mockSetup: func() {
				mock.ExpectQuery("SELECT cve_id FROM cves WHERE cve_id = ANY").
					WithArgs(pgxmock.AnyArg()).
					WillReturnError(errors.New("db error"))
			},
			wantIDs: nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockSetup()

			ctx := context.Background()
			gotIDs, err := w.filterRelevantAdvisories(ctx, tt.advisoryMap)

			if (err != nil) != tt.wantErr {
				t.Errorf("filterRelevantAdvisories() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(gotIDs) != len(tt.wantIDs) {
				t.Errorf("filterRelevantAdvisories() got len %v, want %v", len(gotIDs), len(tt.wantIDs))
			} else {
				// Check content (order doesn't matter)
				gotMap := make(map[string]bool)
				for _, id := range gotIDs {
					gotMap[id] = true
				}
				for _, id := range tt.wantIDs {
					if !gotMap[id] {
						t.Errorf("filterRelevantAdvisories() missing ID %v", id)
					}
				}
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("there were unfulfilled expectations: %s", err)
			}
		})
	}
}

func TestWorker_ScrapeFortiGuardAdvisory(t *testing.T) {
	tests := []struct {
		name        string
		serverCode  int
		serverBody  string
		wantID      string
		wantErr     bool
	}{
		{
			name:       "successful scrape",
			serverCode: http.StatusOK,
			serverBody: `
<html>
	<body>
		<h1>Test Advisory</h1>
		<div class="detail-item">
			<div class="detail-label">IR Number</div>
			<div class="detail-value">FG-IR-00-001</div>
		</div>
		<div class="detail-item">
			<div class="detail-label">Description</div>
			<div class="detail-value">Test description</div>
		</div>
	</body>
</html>`,
			wantID:  "FG-IR-00-001",
			wantErr: false,
		},
		{
			name:       "server error",
			serverCode: http.StatusInternalServerError,
			serverBody: "error",
			wantID:     "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.serverCode)
				w.Write([]byte(tt.serverBody))
			}))
			defer server.Close()

			w := &Worker{
				HTTP: &mockFortiGuardClient{server: server},
			}

			ctx := context.Background()
			advisory, err := w.scrapeFortiGuardAdvisory(ctx, server.URL+"/FG-IR-00-001")

			if (err != nil) != tt.wantErr {
				t.Errorf("scrapeFortiGuardAdvisory() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && advisory != nil {
				if advisory.AdvisoryID != tt.wantID {
					t.Errorf("scrapeFortiGuardAdvisory() got ID %v, want %v", advisory.AdvisoryID, tt.wantID)
				}
			}
		})
	}
}




type mockFortiGuardClient struct {
	server *httptest.Server
}

func (m *mockFortiGuardClient) Do(req *http.Request) (*http.Response, error) {
	// Rewrite URL to test server

	// Create a new request to the local test server
	newReq, _ := http.NewRequestWithContext(req.Context(), req.Method, m.server.URL, req.Body)
	newReq.Header = req.Header


	client := m.server.Client()
	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return client.Do(newReq)
}

func TestWorker_ProcessAdvisories(t *testing.T) {
	// Setup miniredis
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	// Setup DB mock
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer mock.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
		<html>
			<body>
				<h1>Test Advisory</h1>
				<div class="detail-item">
					<div class="detail-label">IR Number</div>
					<div class="detail-value">FG-IR-00-001</div>
				</div>
			</body>
		</html>`))
	}))
	defer server.Close()

	w := &Worker{
		Redis: rdb,
		Pool:  mock,
		HTTP:  &mockFortiGuardClient{server: server},
	}

	tests := []struct {
		name        string
		advisoryIDs []string
		mockSetup   func()
		wantCount   int
		wantErr     bool
	}{
		{
			name:        "process empty list",
			advisoryIDs: []string{},
			mockSetup:   func() {},
			wantCount:   0,
			wantErr:     false,
		},
		{
			name:        "process advisory list",
			advisoryIDs: []string{"FG-IR-00-001"},
			mockSetup:   func() {
				// updateCVEsWithAdvisory is called internally
				// "UPDATE cves SET vendor_advisories = jsonb_set(..."
				mock.ExpectExec("UPDATE cves SET vendor_advisories").
					WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
					WillReturnResult(pgxmock.NewResult("UPDATE", 1))
			},
			wantCount:   1,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockSetup()
			ctx := context.Background()
			count, err := w.processAdvisories(ctx, tt.advisoryIDs)

			if (err != nil) != tt.wantErr {
				t.Errorf("processAdvisories() error = %v, wantErr %v", err, tt.wantErr)
			}
			if count != tt.wantCount {
				t.Errorf("processAdvisories() count = %v, want %v", count, tt.wantCount)
			}
		})
	}
}

func TestWorker_SyncFortiguard(t *testing.T) {
	// Setup miniredis
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	// Setup DB mock
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer mock.Close()

	// Empty RSS server to avoid complicated parsing and db interactions
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel></channel></rss>`))
	}))
	defer server.Close()

	w := &Worker{
		Redis: rdb,
		Pool:  mock,
		HTTP:  &mockFortiGuardClient{server: server},
	}

	ctx := context.Background()
	// Mock the DB interaction from updateTaskStats
	mock.ExpectExec("INSERT INTO worker_sync_stats").WithArgs(pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))

	// Should run without errors
	w.syncFortiguard(ctx)
}
