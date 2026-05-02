package worker

import (
	"compress/gzip"
	"context"
	"cve-tracker/internal/db"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v3"
)

func TestWorkerSync_NVD(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mr, err := db.SetupTestRedis()
	if err != nil {
		t.Fatalf("failed to setup miniredis: %v", err)
	}
	defer mr.Close()

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

	t.Run("FullSync_Backfill", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		w := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, http.DefaultClient)

		mock.ExpectQuery(regexp.QuoteMeta("SELECT last_run FROM worker_sync_stats WHERE task_name = 'nvd_sync'")).
			WillReturnError(pgx.ErrNoRows)
		mock.ExpectQuery(regexp.QuoteMeta("SELECT value FROM sync_state WHERE key = 'nvd_backfill_index'")).
			WillReturnError(pgx.ErrNoRows)

		mock.ExpectExec(regexp.QuoteMeta("INSERT INTO cves")).
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), 7.5, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		mock.ExpectExec(regexp.QuoteMeta("INSERT INTO sync_state")).
			WithArgs(pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		mock.ExpectExec(regexp.QuoteMeta("INSERT INTO worker_sync_stats")).
			WithArgs(pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		mock.ExpectExec(regexp.QuoteMeta("DELETE FROM sync_state")).
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
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
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
		w2.runFullSync(shortCtx, false, 0)
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
		mock.ExpectExec("INSERT INTO worker_sync_stats").WithArgs("cisa_kev_sync").WillReturnResult(pgxmock.NewResult("INSERT", 1))

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
			rw.Header().Set("Content-Type", "application/gzip")
			gz := gzip.NewWriter(rw)
			data := "cve,epss,percentile\nCVE-EPSS-1,0.0123,0.1234\n"
			_, _ = gz.Write([]byte(data))
			_ = gz.Close()
		}))
		defer ts.Close()
		oldURL := defaultEPSSBaseURL
		defaultEPSSBaseURL = ts.URL
		defer func() { defaultEPSSBaseURL = oldURL }()

		mock.ExpectExec("UPDATE cves SET epss_score = u.epss_score").
			WithArgs([]string{"CVE-EPSS-1"}, []float64{0.0123}).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectExec("INSERT INTO worker_sync_stats").WithArgs("epss_sync").WillReturnResult(pgxmock.NewResult("INSERT", 1))

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
		oldDelay := githubSyncDelay
		githubSyncDelay = 1 * time.Millisecond
		defer func() { githubSyncDelay = oldDelay }()

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
		mock.ExpectExec("INSERT INTO worker_sync_stats").WithArgs("github_buzz_sync").WillReturnResult(pgxmock.NewResult("INSERT", 1))

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		w.syncGitHubBuzz(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}

func TestWorkerSync_GreyNoise(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()
	
	httpClient := &MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			if strings.Contains(req.URL.String(), "CVE-GN-1") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"total": 5}`)),
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(strings.NewReader(`{}`)),
			}, nil
		},
	}
	w := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, httpClient)

	t.Run("Success", func(t *testing.T) {
		mock.ExpectQuery(regexp.QuoteMeta("SELECT cve_id FROM cves WHERE greynoise_last_updated IS NULL OR greynoise_last_updated < NOW() - INTERVAL '30 days' ORDER BY greynoise_last_updated ASC NULLS FIRST LIMIT 200")).
			WillReturnRows(pgxmock.NewRows([]string{"cve_id"}).AddRow("CVE-GN-1"))
		
		mock.ExpectExec(regexp.QuoteMeta("UPDATE cves SET greynoise_hits = $1, greynoise_last_updated = NOW() WHERE cve_id = $2")).
			WithArgs(5, "CVE-GN-1").
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		
		mock.ExpectExec("INSERT INTO worker_sync_stats").WithArgs("greynoise_sync").WillReturnResult(pgxmock.NewResult("INSERT", 1))

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		w.syncGreyNoise(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}

func TestWorkerSync_OSV(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	httpClient := &MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			if req.Method != "GET" {
				return &http.Response{StatusCode: http.StatusMethodNotAllowed, Body: io.NopCloser(strings.NewReader(""))}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"id":"GHSA-xxxx","summary":"Test OSV"}`)),
			}, nil
		},
	}
	w := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, httpClient)

	t.Run("Success", func(t *testing.T) {
		mock.ExpectQuery(regexp.QuoteMeta("SELECT cve_id FROM cves WHERE osv_last_updated IS NULL OR osv_last_updated < NOW() - INTERVAL '30 days' ORDER BY osv_last_updated ASC NULLS FIRST LIMIT 200")).
			WillReturnRows(pgxmock.NewRows([]string{"cve_id"}).AddRow("CVE-OSV-1"))
		
		mock.ExpectExec(regexp.QuoteMeta("UPDATE cves SET osv_data = $1, osv_last_updated = NOW() WHERE cve_id = $2")).
			WithArgs(pgxmock.AnyArg(), "CVE-OSV-1").
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		
		mock.ExpectExec("INSERT INTO worker_sync_stats").WithArgs("osv_sync").WillReturnResult(pgxmock.NewResult("INSERT", 1))

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		w.syncOSV(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("NoData_StillMarksAsChecked", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()

		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       io.NopCloser(strings.NewReader(`{}`)),
				}, nil
			},
		}
		w2 := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, httpClient)

		mock.ExpectQuery(regexp.QuoteMeta("SELECT cve_id FROM cves WHERE osv_last_updated IS NULL OR osv_last_updated < NOW() - INTERVAL '30 days' ORDER BY osv_last_updated ASC NULLS FIRST LIMIT 200")).
			WillReturnRows(pgxmock.NewRows([]string{"cve_id"}).AddRow("CVE-OSV-NONE"))
		
		mock.ExpectExec(regexp.QuoteMeta("UPDATE cves SET osv_last_updated = NOW() WHERE cve_id = $1")).
			WithArgs("CVE-OSV-NONE").
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		
		mock.ExpectExec("INSERT INTO worker_sync_stats").WithArgs("osv_sync").WillReturnResult(pgxmock.NewResult("INSERT", 1))

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		w2.syncOSV(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}
