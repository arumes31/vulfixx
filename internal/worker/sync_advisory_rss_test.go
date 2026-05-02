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

	t.Run("AtomSupport", func(t *testing.T) {
		atomContent := `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>CISA Advisory - CVE-2024-1234</title>
    <link href="https://www.cisa.gov/news/1234"/>
    <summary>Vulnerability in something CVE-2024-1234</summary>
  </entry>
</feed>`

		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(atomContent)),
				}, nil
			},
		}
		wAtom := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, httpClient)

		mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, cve_id, description, vendor, product, "references" FROM cves WHERE cve_id = $1`)).
			WithArgs("CVE-2024-1234").
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "vendor", "product", "references"}).
				AddRow(1, "CVE-2024-1234", "Existing desc", "CISA", "Advisory", []string{}))

		mock.ExpectExec(regexp.QuoteMeta(`UPDATE cves SET "references" = $1, updated_at = NOW() WHERE id = $2`)).
			WithArgs([]string{"https://www.cisa.gov/news/1234"}, 1).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM cves WHERE cve_id = $1`)).
			WithArgs("CVE-2024-1234").
			WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(1))

		mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO worker_sync_stats`)).
			WithArgs("advisory_rss_sync").
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		wAtom.syncAdvisoryRSS(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}
