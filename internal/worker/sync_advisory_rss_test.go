package worker

import (
	"context"
	"cve-tracker/internal/db"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/redis/go-redis/v9"
)

func TestWorkerSync_AdvisoryRSS(t *testing.T) {
	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
<channel>
    <item>
        <title>Cisco IOS - Test Advisory</title>
        <link>https://cisco.com/psirt/123</link>
        <description>Vulnerability in Cisco IOS CVE-2024-9999</description>
        <pubDate>Thu, 02 May 2024 00:00:00 GMT</pubDate>
    </item>
    <item>
        <title>Random News</title>
        <link>https://example.com/news</link>
        <description>This item does not contain any CVE ID and should be skipped.</description>
        <pubDate>Thu, 02 May 2024 00:00:00 GMT</pubDate>
    </item>
</channel>
</rss>`

	t.Run("OnlySyncMatchedCVEs", func(t *testing.T) {
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

		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.String(), "CiscoSecurityAdvisory.xml") {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(xmlContent)),
					}, nil
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`<?xml version="1.0"?><rss><channel></channel></rss>`)),
				}, nil
			},
		}
		w := NewWorker(mock, rdb, &EmailSenderMock{}, httpClient)

		// 1. Check if CVE exists - case where it doesn't
		mock.ExpectBegin()
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, cve_id, description, cvss_score, vendor, product, "references", epss_score FROM cves WHERE cve_id = $1 FOR UPDATE`)).
			WithArgs("CVE-2024-9999").
			WillReturnError(pgx.ErrNoRows)
		mock.ExpectRollback()

		// Update task stats at the very end
		mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO worker_sync_stats`)).
			WithArgs("advisory_rss_sync").
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		w.syncAdvisoryRSS(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("SyncExistingCVE", func(t *testing.T) {
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

		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.String(), "CiscoSecurityAdvisory.xml") {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(xmlContent)),
					}, nil
				} else if strings.Contains(req.URL.String(), "fortiguard") {
					// FortiGuard feed should not be called anymore, but if it is, return empty
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`<?xml version="1.0"?><rss><channel></channel></rss>`)),
					}, nil
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`<?xml version="1.0"?><rss><channel></channel></rss>`)),
				}, nil
			},
		}
		w := NewWorker(mock, rdb, &EmailSenderMock{}, httpClient)

		// 1. Check if CVE exists - case where it DOES exist
		mock.ExpectBegin()
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, cve_id, description, cvss_score, vendor, product, "references", epss_score FROM cves WHERE cve_id = $1 FOR UPDATE`)).
			WithArgs("CVE-2024-9999").
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vendor", "product", "references", "epss_score"}).
				AddRow(1, "CVE-2024-9999", "Existing desc", 7.5, "Cisco", "Cisco Product", []string{}, 0.1))

		// 2. Update references
		mock.ExpectExec(regexp.QuoteMeta(`UPDATE cves SET "references" = $1, updated_at = NOW() WHERE id = $2`)).
			WithArgs([]string{"https://cisco.com/psirt/123"}, 1).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		mock.ExpectCommit()

		// Update task stats at the very end
		mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO worker_sync_stats`)).
			WithArgs("advisory_rss_sync").
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		w.syncAdvisoryRSS(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("RSS1.0Support", func(t *testing.T) {
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

		rdfContent := `<?xml version="1.0" encoding="UTF-8"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/">
  <item>
    <title>Red Hat Advisory - CVE-2024-5678</title>
    <link>https://access.redhat.com/errata/RHSA-2024-5678</link>
    <description>Vulnerability fix for CVE-2024-5678</description>
  </item>
</rdf:RDF>`

		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(rdfContent)),
				}, nil
			},
		}
		wRDF := NewWorker(mock, rdb, &EmailSenderMock{}, httpClient)

		mock.ExpectBegin()
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, cve_id, description, cvss_score, vendor, product, "references", epss_score FROM cves WHERE cve_id = $1 FOR UPDATE`)).
			WithArgs("CVE-2024-5678").
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vendor", "product", "references", "epss_score"}).
				AddRow(1, "CVE-2024-5678", "Existing desc", 8.0, "Red Hat", "RHEL", []string{}, 0.2))

		mock.ExpectExec(regexp.QuoteMeta(`UPDATE cves SET "references" = $1, updated_at = NOW() WHERE id = $2`)).
			WithArgs([]string{"https://access.redhat.com/errata/RHSA-2024-5678"}, 1).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		mock.ExpectCommit()

		mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO worker_sync_stats`)).
			WithArgs("advisory_rss_sync").
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		wRDF.syncAdvisoryRSS(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("MultipleCVEsInOneItem", func(t *testing.T) {
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

		xmlContentMulti := `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
<channel>
    <item>
        <title>Multi-CVE Advisory</title>
        <link>https://example.com/advisory/multi</link>
        <description>This fix addresses CVE-2024-0001 and CVE-2024-0002.</description>
    </item>
</channel>
</rss>`

		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.String(), "CiscoSecurityAdvisory.xml") {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(xmlContentMulti)),
					}, nil
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`<?xml version="1.0"?><rss><channel></channel></rss>`)),
				}, nil
			},
		}
		wMulti := NewWorker(mock, rdb, &EmailSenderMock{}, httpClient)

		mock.MatchExpectationsInOrder(false)

		// Expectations for CVE-2024-0001
		mock.ExpectBegin()
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, cve_id, description, cvss_score, vendor, product, "references", epss_score FROM cves WHERE cve_id = $1 FOR UPDATE`)).
			WithArgs("CVE-2024-0001").
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vendor", "product", "references", "epss_score"}).
				AddRow(1, "CVE-2024-0001", "desc1", 5.0, "V", "P", []string{}, 0.1))
		mock.ExpectExec(regexp.QuoteMeta(`UPDATE cves SET "references" = $1, updated_at = NOW() WHERE id = $2`)).
			WithArgs([]string{"https://example.com/advisory/multi"}, 1).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectCommit()

		// Expectations for CVE-2024-0002
		mock.ExpectBegin()
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, cve_id, description, cvss_score, vendor, product, "references", epss_score FROM cves WHERE cve_id = $1 FOR UPDATE`)).
			WithArgs("CVE-2024-0002").
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vendor", "product", "references", "epss_score"}).
				AddRow(2, "CVE-2024-0002", "desc2", 6.0, "V", "P", []string{}, 0.2))
		mock.ExpectExec(regexp.QuoteMeta(`UPDATE cves SET "references" = $1, updated_at = NOW() WHERE id = $2`)).
			WithArgs([]string{"https://example.com/advisory/multi"}, 2).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectCommit()

		mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO worker_sync_stats`)).
			WithArgs("advisory_rss_sync").
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		wMulti.syncAdvisoryRSS(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("PreventDuplicateReferences", func(t *testing.T) {
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

		xmlContentDup := `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
<channel>
    <item>
        <title>Duplicate Ref Test</title>
        <link>https://example.com/ref/1</link>
        <description>Fixes CVE-2024-1111</description>
    </item>
</channel>
</rss>`

		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(xmlContentDup)),
				}, nil
			},
		}
		wDup := NewWorker(mock, rdb, &EmailSenderMock{}, httpClient)

		mock.ExpectBegin()
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, cve_id, description, cvss_score, vendor, product, "references", epss_score FROM cves WHERE cve_id = $1 FOR UPDATE`)).
			WithArgs("CVE-2024-1111").
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vendor", "product", "references", "epss_score"}).
				AddRow(1, "CVE-2024-1111", "desc", 8.0, "V", "P", []string{"https://example.com/ref/1"}, 0.3))
		mock.ExpectRollback()

		// No UPDATE should happen because reference already exists

		mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO worker_sync_stats`)).
			WithArgs("advisory_rss_sync").
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		wDup.syncAdvisoryRSS(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("HandleFeedErrors", func(t *testing.T) {
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

		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       io.NopCloser(strings.NewReader("Not Found")),
				}, nil
			},
		}
		wErr := NewWorker(mock, rdb, &EmailSenderMock{}, httpClient)

		// Expect only stats update, as all feeds will "fail" but worker continues
		mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO worker_sync_stats`)).
			WithArgs("advisory_rss_sync").
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		wErr.syncAdvisoryRSS(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}

func TestFortiGuardIDRegex(t *testing.T) {
	tests := []struct {
		input  string
		want   string
		wantOK bool
	}{
		{"FG-IR-24-388 Multiple Vulnerabilities in FortiOS", "FG-IR-24-388", true},
		{"FG-IR-25-001 Critical RCE", "FG-IR-25-001", true},
		{"FG-IR-99-999 High Severity", "FG-IR-99-999", true},
		{"Some advisory without FG ID", "", false},
		{"FG-IR-24-388 and FG-IR-24-399", "FG-IR-24-388", true}, // FindString returns first match
		{"fg-ir-24-388 lowercase", "", false},                   // regex is case-sensitive
	}
	for _, tt := range tests {
		got := fortiguardIDRegex.FindString(tt.input)
		if (got != "") != tt.wantOK {
			t.Errorf("fortiguardIDRegex.FindString(%q) = %q, wantOK %v", tt.input, got, tt.wantOK)
		}
		if got != tt.want {
			t.Errorf("fortiguardIDRegex.FindString(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestWorkerSync_FortiGuardAdvisoryID(t *testing.T) {
	fortiguardXML := `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
<channel>
<item>
<title>FG-IR-24-388 Multiple Vulnerabilities in FortiOS CVE-2024-1234</title>
<link>https://www.fortiguard.com/psirt/FG-IR-24-388</link>
<description>Multiple vulnerabilities in FortiOS CVE-2024-1234</description>
<pubDate>Thu, 02 May 2024 00:00:00 GMT</pubDate>
</item>
</channel>
</rss>`

	t.Run("FortiGuardAdvisoryIDExtracted", func(t *testing.T) {
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

		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.String(), "fortiguard") {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(fortiguardXML)),
					}, nil
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`<?xml version="1.0"?><rss><channel></channel></rss>`)),
				}, nil
			},
		}
		w := NewWorker(mock, rdb, &EmailSenderMock{}, httpClient)

		// Expect the row lock SELECT
		mock.ExpectBegin()
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, cve_id, description, cvss_score, vendor, product, "references", epss_score FROM cves WHERE cve_id = $1 FOR UPDATE`)).
			WithArgs("CVE-2024-1234").
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vendor", "product", "references", "epss_score"}).
				AddRow(1, "CVE-2024-1234", "FortiOS vulnerability", 9.0, "Fortinet", "FortiOS", []string{}, 0.5))

		// Expect vendor_advisories UPDATE with FortiGuard advisory data
		fgData := map[string]interface{}{
			"advisory_id":  "FG-IR-24-388",
			"advisory_url": "https://www.fortiguard.com/psirt/FG-IR-24-388",
		}
		vendorAdvisory := map[string]interface{}{
			"fortiguard": fgData,
		}
		vaJSON, _ := json.Marshal(vendorAdvisory)
		mock.ExpectExec(regexp.QuoteMeta(`UPDATE cves SET vendor_advisories = COALESCE(vendor_advisories, '{}'::jsonb) || $1::jsonb, updated_at = NOW() WHERE cve_id = $2`)).
			WithArgs(vaJSON, "CVE-2024-1234").
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		// Expect references UPDATE
		mock.ExpectExec(regexp.QuoteMeta(`UPDATE cves SET "references" = $1, updated_at = NOW() WHERE id = $2`)).
			WithArgs([]string{"https://www.fortiguard.com/psirt/FG-IR-24-388"}, 1).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		mock.ExpectCommit()

		// Update task stats
		mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO worker_sync_stats`)).
			WithArgs("advisory_rss_sync").
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		w.syncAdvisoryRSS(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("FortiGuardAdvisoryIDWithExistingOSINTData", func(t *testing.T) {
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

		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.String(), "fortiguard") {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(fortiguardXML)),
					}, nil
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`<?xml version="1.0"?><rss><channel></channel></rss>`)),
				}, nil
			},
		}
		w := NewWorker(mock, rdb, &EmailSenderMock{}, httpClient)

		mock.ExpectBegin()
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, cve_id, description, cvss_score, vendor, product, "references", epss_score FROM cves WHERE cve_id = $1 FOR UPDATE`)).
			WithArgs("CVE-2024-1234").
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vendor", "product", "references", "epss_score"}).
				AddRow(1, "CVE-2024-1234", "FortiOS vulnerability", 9.0, "Fortinet", "FortiOS", []string{}, 0.5))

		fgData := map[string]interface{}{
			"advisory_id":  "FG-IR-24-388",
			"advisory_url": "https://www.fortiguard.com/psirt/FG-IR-24-388",
		}
		vendorAdvisory := map[string]interface{}{
			"fortiguard": fgData,
		}
		vaJSON, _ := json.Marshal(vendorAdvisory)
		mock.ExpectExec(regexp.QuoteMeta(`UPDATE cves SET vendor_advisories = COALESCE(vendor_advisories, '{}'::jsonb) || $1::jsonb, updated_at = NOW() WHERE cve_id = $2`)).
			WithArgs(vaJSON, "CVE-2024-1234").
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		mock.ExpectExec(regexp.QuoteMeta(`UPDATE cves SET "references" = $1, updated_at = NOW() WHERE id = $2`)).
			WithArgs([]string{"https://www.fortiguard.com/psirt/FG-IR-24-388"}, 1).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		mock.ExpectCommit()

		mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO worker_sync_stats`)).
			WithArgs("advisory_rss_sync").
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		w.syncAdvisoryRSS(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("FortiGuardNoAdvisoryIDInTitle", func(t *testing.T) {
		// When the FortiGuard RSS item title doesn't contain an FG-IR ID,
		// no osint_data update should happen — only the reference is added.
		fortiguardXMLNoID := `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
<channel>
<item>
<title>Security Update for FortiOS CVE-2024-5678</title>
<link>https://www.fortiguard.com/psirt/some-other-page</link>
<description>Security update CVE-2024-5678</description>
<pubDate>Thu, 02 May 2024 00:00:00 GMT</pubDate>
</item>
</channel>
</rss>`

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

		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.String(), "fortiguard") {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(fortiguardXMLNoID)),
					}, nil
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`<?xml version="1.0"?><rss><channel></channel></rss>`)),
				}, nil
			},
		}
		w := NewWorker(mock, rdb, &EmailSenderMock{}, httpClient)

		mock.ExpectBegin()
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, cve_id, description, cvss_score, vendor, product, "references", epss_score FROM cves WHERE cve_id = $1 FOR UPDATE`)).
			WithArgs("CVE-2024-5678").
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vendor", "product", "references", "epss_score"}).
				AddRow(1, "CVE-2024-5678", "FortiOS vuln", 7.5, "Fortinet", "FortiOS", []string{}, 0.2))

		// No osint_data UPDATE expected (no FG-IR ID in title)
		// Only references UPDATE
		mock.ExpectExec(regexp.QuoteMeta(`UPDATE cves SET "references" = $1, updated_at = NOW() WHERE id = $2`)).
			WithArgs([]string{"https://www.fortiguard.com/psirt/some-other-page"}, 1).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		mock.ExpectCommit()

		mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO worker_sync_stats`)).
			WithArgs("advisory_rss_sync").
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		w.syncAdvisoryRSS(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("FortiGuardExistingReferenceWithAdvisoryID", func(t *testing.T) {
		// When the reference already exists but a new FG-IR ID is found,
		// the osint_data should still be updated and the transaction committed.
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

		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.String(), "fortiguard") {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(fortiguardXML)),
					}, nil
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`<?xml version="1.0"?><rss><channel></channel></rss>`)),
				}, nil
			},
		}
		w := NewWorker(mock, rdb, &EmailSenderMock{}, httpClient)

		// CVE already has the reference URL
		mock.ExpectBegin()
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, cve_id, description, cvss_score, vendor, product, "references", epss_score FROM cves WHERE cve_id = $1 FOR UPDATE`)).
			WithArgs("CVE-2024-1234").
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vendor", "product", "references", "epss_score"}).
				AddRow(1, "CVE-2024-1234", "FortiOS vuln", 9.0, "Fortinet", "FortiOS",
					[]string{"https://www.fortiguard.com/psirt/FG-IR-24-388"}, 0.5))

		// vendor_advisories should still be updated with the advisory ID
		fgData := map[string]interface{}{
			"advisory_id":  "FG-IR-24-388",
			"advisory_url": "https://www.fortiguard.com/psirt/FG-IR-24-388",
		}
		vendorAdvisory := map[string]interface{}{
			"fortiguard": fgData,
		}
		vaJSON, _ := json.Marshal(vendorAdvisory)
		mock.ExpectExec(regexp.QuoteMeta(`UPDATE cves SET vendor_advisories = COALESCE(vendor_advisories, '{}'::jsonb) || $1::jsonb, updated_at = NOW() WHERE cve_id = $2`)).
			WithArgs(vaJSON, "CVE-2024-1234").
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		// Transaction should be committed (fortiguardUpdated path)
		mock.ExpectCommit()

		mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO worker_sync_stats`)).
			WithArgs("advisory_rss_sync").
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		w.syncAdvisoryRSS(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}
