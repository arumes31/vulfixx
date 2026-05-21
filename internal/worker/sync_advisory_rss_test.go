package worker

import (
	"context"
	"cve-tracker/internal/db"
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

		// 3. Select back for alerting (enqueueAlertsForCVE)
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM cves WHERE cve_id = $1`)).
			WithArgs("CVE-2024-9999").
			WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(1))

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
				if strings.Contains(req.URL.String(), "rhsa.rss") {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(rdfContent)),
					}, nil
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`<?xml version="1.0"?><rss><channel></channel></rss>`)),
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

		mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM cves WHERE cve_id = $1`)).
			WithArgs("CVE-2024-5678").
			WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(1))

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
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM cves WHERE cve_id = $1`)).
			WithArgs("CVE-2024-0001").
			WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(1))

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
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM cves WHERE cve_id = $1`)).
			WithArgs("CVE-2024-0002").
			WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(2))

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
				if strings.Contains(req.URL.String(), "CiscoSecurityAdvisory.xml") {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(xmlContentDup)),
					}, nil
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`<?xml version="1.0"?><rss><channel></channel></rss>`)),
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
