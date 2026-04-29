package worker

import (
	"context"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/redis/go-redis/v9"
)

func TestWorkerAlert_EvaluateSubscriptions(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	mr, err := db.SetupTestRedis()
	if err != nil {
		t.Fatalf("failed to setup redis: %v", err)
	}
	defer mr.Close()

	ctx := context.Background()
	w := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, http.DefaultClient)

	t.Run("AssetMatch_Regex", func(t *testing.T) {
		cve := &models.CVE{
			ID:          1,
			CVEID:       "CVE-ASSET",
			Description: "Vulnerability in WordPress Plugin",
			CVSSScore:   8.0,
		}

		mock.ExpectQuery("SELECT s.id, s.user_id").
			WithArgs(cve.CVSSScore, cve.Description).
			WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "keyword", "min_severity", "webhook_url", "enable_email", "enable_webhook", "filter_logic", "email"}))
		mock.ExpectQuery("SELECT ak.keyword, a.user_id").
			WithArgs(cve.Description).
			WillReturnRows(pgxmock.NewRows([]string{"keyword", "user_id", "email", "name"}).
				AddRow("wordpress", 1, "user@example.com", "My Site"))
		
		mock.ExpectQuery("SELECT EXISTS").WithArgs(1, 1).WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(false))
		mock.ExpectExec("INSERT INTO alert_history").WithArgs(1, 1).WillReturnResult(pgxmock.NewResult("INSERT", 1))

		w.evaluateSubscriptions(ctx, cve)
		
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

    t.Run("FilterLogic_Complex", func(t *testing.T) {
		cve := &models.CVE{
			ID:          1,
			CVEID:       "CVE-COMPLEX",
			Description: "Serious exploit in software",
			CVSSScore:   9.8,
			EPSSScore:   0.5,
			CISAKEV:     true,
			GitHubPoCCount: 10,
		}

		testCases := []struct {
			logic string
			want  bool
		}{
			{"epss > 0.1", true},
			{"epss > 0.6", false},
			{"cisa = true", true},
			{"buzz >= 5", true},
			{"regex: exploit", true},
			{"regex: unknown", false},
		}

		for _, tc := range testCases {
			if got := evaluateComplexFilter(tc.logic, cve); got != tc.want {
				t.Errorf("evaluateComplexFilter(%q) = %v, want %v", tc.logic, got, tc.want)
			}
		}
	})
}

func TestWorkerAlert_SendAlert(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("SetupTestDB: %v", err)
	}
	defer mock.Close()
	_, err = db.SetupTestRedis()
	if err != nil {
		t.Fatalf("SetupTestRedis: %v", err)
	}

	t.Run("Webhook_Detailed", func(t *testing.T) {
        tests := []struct {
            name       string
            statusCode int
            shouldPass bool
        }{
            {"Webhook_200", 200, true},
            {"Webhook_400", 400, false},
        }

        for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(tt.statusCode)
				}))
				defer ts.Close()
				t.Setenv("TEST_MODE", "1")
				
				httpClient := &MockHTTPClient{
					DoFunc: func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: tt.statusCode,
							Body:       io.NopCloser(strings.NewReader("")),
						}, nil
					},
				}

				w := &Worker{
					Pool:   mock,
					Redis:  db.RedisClient,
					Mailer: &EmailSenderMock{},
					HTTP:   httpClient,
				}

				sub := models.UserSubscription{
					EnableWebhook: true,
					WebhookURL:    ts.URL,
				}
				cve := &models.CVE{CVEID: "CVE-2023-0001", CVSSScore: 9.5}

				success := w.sendAlert(sub, cve, "user@example.com", "Asset1")
				if success != tt.shouldPass {
					t.Errorf("expected success %v, got %v", tt.shouldPass, success)
				}
			})
        }
    })

    t.Run("Email_FullCoverage", func(t *testing.T) {
		mailer := &EmailSenderMock{}
		w := &Worker{Pool: mock, Redis: db.RedisClient, Mailer: mailer, HTTP: http.DefaultClient}
		
		t.Setenv("BASE_URL", "https://vulfixx.io")
		
		cve := &models.CVE{CVEID: "CVE-CRIT", CVSSScore: 10.0, CISAKEV: true}
        sub := models.UserSubscription{EnableEmail: true}
        
        w.sendAlert(sub, cve, "user@example.com", "Asset")
		
		if mailer.Count != 1 {
			t.Errorf("expected 1 email sent, got %d", mailer.Count)
		}
		if !strings.Contains(mailer.LastSubject, "CVE-CRIT") {
			t.Errorf("subject should contain CVE ID")
		}
		if mailer.LastTo != "user@example.com" {
			t.Errorf("wrong recipient: %s", mailer.LastTo)
		}
	})
}

func TestWorkerAlert_ProcessUserBuffer(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	w := &Worker{
		Pool:   mock,
		Redis:  rdb,
		Mailer: &EmailSenderMock{},
		HTTP:   http.DefaultClient,
	}

	userID := 1
	key := fmt.Sprintf("alert_buffer:%d", userID)

	t.Run("MultipleItems_Digest", func(t *testing.T) {
		cve1 := models.CVE{CVEID: "CVE-2023-0001", CVSSScore: 8.0}
		cve2 := models.CVE{CVEID: "CVE-2023-0002", CVSSScore: 7.0}
		sub := models.UserSubscription{EnableEmail: true}
		
		data1, _ := json.Marshal(map[string]interface{}{"cve": cve1, "email": "user@example.com", "asset_name": "A1", "sub": sub})
		data2, _ := json.Marshal(map[string]interface{}{"cve": cve2, "email": "user@example.com", "asset_name": "", "sub": sub})
		
		rdb.RPush(context.Background(), key, data1, data2)

		w.processUserBuffer(context.Background(), userID)

		llen, _ := rdb.LLen(context.Background(), key).Result()
		if llen != 0 {
			t.Errorf("expected buffer to be empty, got %d", llen)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}
