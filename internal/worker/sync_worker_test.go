package worker

import (
	"context"
	"cve-tracker/internal/db"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v3"
)

func TestWorkerSync_NVD(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	mr, err := db.SetupTestRedis()
	if err != nil {
		t.Fatalf("failed to setup miniredis: %v", err)
	}
	defer mr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Mock NVD API
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := NVDResponse{
			TotalResults: 1,
			Vulnerabilities: []NVDCVEEntry{
				{
					CVE: NVDCVE{
						ID:           "CVE-2023-0001",
						Published:    time.Now().Format(time.RFC3339),
						LastModified: time.Now().Format(time.RFC3339),
						Descriptions: []struct {
							Lang  string `json:"lang"`
							Value string `json:"value"`
						}{
							{Lang: "en", Value: "Test vulnerability"},
						},
						Metrics: struct {
							CvssMetricV31 []struct {
								CvssData struct {
									BaseScore    float64 `json:"baseScore"`
									VectorString string  `json:"vectorString"`
								} `json:"cvssData"`
							} `json:"cvssMetricV31"`
							CvssMetricV30 []struct {
								CvssData struct {
									BaseScore    float64 `json:"baseScore"`
									VectorString string  `json:"vectorString"`
								} `json:"cvssData"`
							} `json:"cvssMetricV30"`
							CvssMetricV2 []struct {
								CvssData struct {
									BaseScore    float64 `json:"baseScore"`
									VectorString string  `json:"vectorString"`
								} `json:"cvssData"`
							} `json:"cvssMetricV2"`
						}{
							CvssMetricV31: []struct {
								CvssData struct {
									BaseScore    float64 `json:"baseScore"`
									VectorString string  `json:"vectorString"`
								} `json:"cvssData"`
							}{
								{
									CvssData: struct {
										BaseScore    float64 `json:"baseScore"`
										VectorString string  `json:"vectorString"`
									}{
										BaseScore:    7.5,
										VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
									},
								},
							},
						},
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	w := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, http.DefaultClient)

	t.Run("FullSync_Backfill", func(t *testing.T) {
		mock.ExpectQuery("SELECT last_run FROM worker_sync_stats WHERE task_name = 'nvd_sync'").
			WillReturnError(pgx.ErrNoRows)

		mock.ExpectQuery("SELECT value FROM sync_state WHERE key = 'nvd_backfill_index'").
			WillReturnError(pgx.ErrNoRows)

		mock.ExpectExec("INSERT INTO cves").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), 7.5, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		mock.ExpectExec("INSERT INTO sync_state").
			WithArgs(pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		mock.ExpectExec("INSERT INTO worker_sync_stats").
			WithArgs(pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		mock.ExpectExec("DELETE FROM sync_state").
			WithArgs().
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		oldURL := defaultNVDBaseURL
		defaultNVDBaseURL = ts.URL
		defer func() { defaultNVDBaseURL = oldURL }()

		w.fetchFromNVD(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("Status_403_RateLimit", func(t *testing.T) {
		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusForbidden,
					Body:       io.NopCloser(strings.NewReader("Forbidden")),
				}, nil
			},
		}
		w2 := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, httpClient)
		mock.ExpectQuery("SELECT last_run FROM worker_sync_stats WHERE task_name = 'nvd_sync'").WillReturnRows(pgxmock.NewRows([]string{"last_run"}).AddRow(time.Now()))

		shortCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
<<<<<<< Updated upstream

		w2.runFullSync(shortCtx, false)
=======
		
		w2.runFullSync(shortCtx, false, 0)
>>>>>>> Stashed changes
	})
}

func TestWorkerSync_CISA(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()
	w := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, http.DefaultClient)

	t.Run("Success", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			resp := CISAKEVResponse{
				Vulnerabilities: []struct {
					CVEID string `json:"cveID"`
				}{
					{CVEID: "CVE-2023-1111"},
				},
			}
			_ = json.NewEncoder(rw).Encode(resp)
		}))
		defer ts.Close()

		oldURL := defaultCISAKEVURL
		defaultCISAKEVURL = ts.URL
		defer func() { defaultCISAKEVURL = oldURL }()

		mock.ExpectBegin()
		mock.ExpectExec("UPDATE cves SET cisa_kev = false WHERE cisa_kev = true").WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectExec("UPDATE cves SET cisa_kev = true WHERE cve_id = ANY").
			WithArgs([]string{"CVE-2023-1111"}).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectCommit()

		w.fetchFromCISAKEV(context.Background())

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("Non200", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			rw.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()
		oldURL := defaultCISAKEVURL
		defaultCISAKEVURL = ts.URL
		defer func() { defaultCISAKEVURL = oldURL }()
		w.fetchFromCISAKEV(context.Background())
	})
}

func TestWorkerSync_EPSS(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()
	w := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, http.DefaultClient)

	t.Run("Success", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			data := `{"data":[{"epss":"0.0123"}]}`
			_, _ = fmt.Fprint(rw, data)
		}))
		defer ts.Close()
		oldURL := defaultEPSSBaseURL
		defaultEPSSBaseURL = ts.URL
		defer func() { defaultEPSSBaseURL = oldURL }()

		mock.ExpectQuery("SELECT cve_id FROM cves").WillReturnRows(pgxmock.NewRows([]string{"cve_id"}).AddRow("CVE-EPSS-1"))
		mock.ExpectExec("UPDATE cves SET epss_score = \\$1 WHERE cve_id = \\$2").WithArgs(0.0123, "CVE-EPSS-1").WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		w.syncEPSS(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}

func TestWorkerSync_GitHub(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()
	w := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, http.DefaultClient)

	t.Run("Success", func(t *testing.T) {
		// Override any internal URL if possible, or use MockHTTPClient
		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"total_count":42}`)),
				}, nil
			},
		}
		w.HTTP = httpClient

		mock.ExpectQuery("SELECT cve_id FROM cves").WillReturnRows(pgxmock.NewRows([]string{"cve_id"}).AddRow("CVE-GH-1"))
		mock.ExpectExec("UPDATE cves SET github_poc_count = \\$1 WHERE cve_id = \\$2").WithArgs(42, "CVE-GH-1").WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		w.syncGitHubBuzz(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}
