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
)

// testLogger is a simple logger for testing that writes to t.Log
type testLogger struct {
	t *testing.T
}

func (l *testLogger) Info(msg string, args ...interface{}) {
	l.t.Logf(msg, args...)
}

func (l *testLogger) Error(msg string, args ...interface{}) {
	l.t.Logf("ERROR: "+msg, args...)
}

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

		// Check if this is a FortiGuard advisory by looking for FG-IR-XXXX-XXX pattern
		advisoryID := ""
		for _, part := range parts {
			if strings.HasPrefix(part, "FG-IR-") {
				advisoryID = part
				break
			}
		}

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
