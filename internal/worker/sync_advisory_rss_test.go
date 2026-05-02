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

	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v3"
)

func TestWorkerSync_AdvisoryRSS(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

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

	mr, err := db.SetupTestRedis()
	if err != nil {
		t.Fatalf("failed to setup mock redis: %v", err)
	}
	defer mr.Close()

	httpClient := &MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			if strings.Contains(req.URL.String(), "CiscoSecurityAdvisory.xml") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(xmlContent)),
				}, nil
			}
			// Return empty RSS for others to keep test fast
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`<?xml version="1.0"?><rss><channel></channel></rss>`)),
			}, nil
		},
	}
	w := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, httpClient)

	t.Run("OnlySyncMatchedCVEs", func(t *testing.T) {
		// 1. Check if CVE exists - case where it doesn't
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, cve_id, description, vendor, product, "references" FROM cves WHERE cve_id = $1`)).
			WithArgs("CVE-2024-9999").
			WillReturnError(pgx.ErrNoRows)
		
		// No Insert should happen

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
		// 1. Check if CVE exists - case where it DOES exist
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, cve_id, description, vendor, product, "references" FROM cves WHERE cve_id = $1`)).
			WithArgs("CVE-2024-9999").
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "vendor", "product", "references"}).
				AddRow(1, "CVE-2024-9999", "Existing desc", "Cisco", "Cisco Product", []string{}))

		// 2. Update references
		mock.ExpectExec(regexp.QuoteMeta(`UPDATE cves SET "references" = $1, updated_at = NOW() WHERE id = $2`)).
			WithArgs([]string{"https://cisco.com/psirt/123"}, 1).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

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
		wRDF := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, httpClient)

		mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, cve_id, description, vendor, product, "references" FROM cves WHERE cve_id = $1`)).
			WithArgs("CVE-2024-5678").
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "vendor", "product", "references"}).
				AddRow(1, "CVE-2024-5678", "Existing desc", "Red Hat", "RHEL", []string{}))

		mock.ExpectExec(regexp.QuoteMeta(`UPDATE cves SET "references" = $1, updated_at = NOW() WHERE id = $2`)).
			WithArgs([]string{"https://access.redhat.com/errata/RHSA-2024-5678"}, 1).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

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
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(xmlContentMulti)),
				}, nil
			},
		}
		wMulti := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, httpClient)

		// Expectations for CVE-2024-0001
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, cve_id, description, vendor, product, "references" FROM cves WHERE cve_id = $1`)).
			WithArgs("CVE-2024-0001").
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "vendor", "product", "references"}).
				AddRow(1, "CVE-2024-0001", "desc1", "V", "P", []string{}))
		mock.ExpectExec(regexp.QuoteMeta(`UPDATE cves SET "references" = $1, updated_at = NOW() WHERE id = $2`)).
			WithArgs([]string{"https://example.com/advisory/multi"}, 1).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM cves WHERE cve_id = $1`)).
			WithArgs("CVE-2024-0001").
			WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(1))

		// Expectations for CVE-2024-0002
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, cve_id, description, vendor, product, "references" FROM cves WHERE cve_id = $1`)).
			WithArgs("CVE-2024-0002").
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "vendor", "product", "references"}).
				AddRow(2, "CVE-2024-0002", "desc2", "V", "P", []string{}))
		mock.ExpectExec(regexp.QuoteMeta(`UPDATE cves SET "references" = $1, updated_at = NOW() WHERE id = $2`)).
			WithArgs([]string{"https://example.com/advisory/multi"}, 2).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
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
		wDup := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, httpClient)

		mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, cve_id, description, vendor, product, "references" FROM cves WHERE cve_id = $1`)).
			WithArgs("CVE-2024-1111").
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "vendor", "product", "references"}).
				AddRow(1, "CVE-2024-1111", "desc", "V", "P", []string{"https://example.com/ref/1"}))

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
		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       io.NopCloser(strings.NewReader("Not Found")),
				}, nil
			},
		}
		wErr := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, httpClient)

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
