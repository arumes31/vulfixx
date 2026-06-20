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
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/redis/go-redis/v9"
)

func TestWorker_matchCVE(t *testing.T) {
	cve := &models.CVE{
		CVEID:       "CVE-123",
		Description: "A test vulnerability",
		CVSSScore:   5.0,
	}

	tests := []struct {
		name string
		sub  models.UserSubscription
		want bool
	}{
		{"match_keyword", models.UserSubscription{Keyword: "test"}, true},
		{"no_match_keyword", models.UserSubscription{Keyword: "foo"}, false},
		{"match_severity", models.UserSubscription{MinSeverity: 4.0}, true},
		{"no_match_severity", models.UserSubscription{MinSeverity: 6.0}, false},
		{"complex_filter", models.UserSubscription{FilterLogic: "regex: test"}, true},
		{"complex_filter_false", models.UserSubscription{FilterLogic: "regex: foo"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchCVE(cve, tt.sub); got != tt.want {
				t.Errorf("matchCVE() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWorker_processAlerts_Coverage(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()
	mock.MatchExpectationsInOrder(false)

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	w := NewWorker(mock, rdb, &EmailSenderMock{}, http.DefaultClient)

	cve := models.CVE{CVEID: "CVE-TEST"}
	data, _ := json.Marshal(cve)

	// We expect evaluateSubscriptions to be called for the valid item, which does a query
	mock.ExpectQuery("SELECT user_id FROM alert_history WHERE cve_id =").WithArgs(pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"user_id"}))
	mock.ExpectQuery("SELECT s.id, s.user_id").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "keyword", "min_severity", "webhook_url", "enable_email", "enable_webhook", "filter_logic", "email"}))
	mock.ExpectQuery("SELECT ak.keyword, a.user_id").WithArgs(pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"keyword", "user_id", "email", "name"}))

	// Invalid JSON item first
	rdb.LPush(context.Background(), "cve_alerts_queue", "{invalid")
	// Valid item
	rdb.LPush(context.Background(), "cve_alerts_queue", data)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			llen, _ := rdb.LLen(context.Background(), "cve_alerts_queue").Result()
			if llen == 0 {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	w.processAlerts(ctx)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

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

		mock.ExpectQuery("SELECT user_id FROM alert_history WHERE cve_id =").
			WithArgs(cve.ID).
			WillReturnRows(pgxmock.NewRows([]string{"user_id"}))
		mock.ExpectQuery("SELECT s.id, s.user_id").
			WithArgs(cve.CVSSScore, cve.Description).
			WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "keyword", "min_severity", "webhook_url", "enable_email", "enable_webhook", "filter_logic", "email"}))
		mock.ExpectQuery("SELECT ak.keyword, a.user_id").
			WithArgs(cve.Description).
			WillReturnRows(pgxmock.NewRows([]string{"keyword", "user_id", "email", "name"}).
				AddRow("wordpress", 1, "user@example.com", "My Site"))

		mock.ExpectExec("INSERT INTO alert_history").WithArgs(1, 1).WillReturnResult(pgxmock.NewResult("INSERT", 1))

		w.evaluateSubscriptions(ctx, cve)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("FilterLogic_Complex", func(t *testing.T) {
		cve := &models.CVE{
			ID:             1,
			CVEID:          "CVE-COMPLEX",
			Description:    "Serious exploit in software",
			CVSSScore:      9.8,
			EPSSScore:      0.5,
			CISAKEV:        true,
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
			// Less-than / less-than-or-equal operators (previously silently ignored).
			{"epss < 0.6", true},
			{"epss < 0.4", false},
			{"epss <= 0.5", true},
			{"buzz < 10", false},
			{"buzz <= 10", true},
			// Equality / inequality operators.
			{"epss == 0.5", true},
			{"epss != 0.5", false},
			{"cisa != true", false},
			{"cisa = false", false},
			// severity / cvss variable (documented in the README but previously unhandled).
			{"severity > 9", true},
			{"severity < 9", false},
			{"cvss >= 9.8", true},
			// AND combinations.
			{"cisa = true && epss > 0.1", true},
			{"cisa = true && epss > 0.9", false},
			// OR combinations (previously treated as AND).
			{"epss > 0.9 || cisa = true", true},
			{"epss > 0.9 || buzz > 100", false},
			// AND binds tighter than OR: (severity > 100 && cisa = true) || buzz >= 5.
			{"severity > 100 && cisa = true || buzz >= 5", true},
			// Malformed / unknown terms fail closed.
			{"epss >", false},
			{"unknownvar > 1", false},
			{"epss !! 0.5", false},
		}

		for _, tc := range testCases {
			if got := evaluateComplexFilter(tc.logic, cve); got != tc.want {
				t.Errorf("evaluateComplexFilter(%q) = %v, want %v", tc.logic, got, tc.want)
			}
		}
	})
}

func TestValidateComplexFilter(t *testing.T) {
	cases := []struct {
		logic   string
		wantErr bool
	}{
		{"", false},
		{"epss > 0.1", false},
		{"epss <= 0.5", false},
		{"cisa = true && severity >= 9", false},
		{"epss > 0.1 || buzz < 5", false},
		{"regex: openssl", false},
		{"epss >", true},                // truncated term
		{"unknownvar > 1", true},        // unknown variable
		{"epss !! 0.5", true},           // bad operator
		{"epss > 0.1 &&", true},         // dangling operator
		{"&& epss > 0.1", true},         // leading operator
		{"epss > 0.1 epss > 0.2", true}, // missing connective
		{"epss > notanumber", true},     // non-numeric value
	}
	for _, c := range cases {
		err := ValidateComplexFilter(c.logic)
		if (err != nil) != c.wantErr {
			t.Errorf("ValidateComplexFilter(%q) error = %v, wantErr %v", c.logic, err, c.wantErr)
		}
	}
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
					WebhookSecret: "test_signing_key_123",
					Pool:          mock,
					Redis:         db.RedisClient,
					Mailer:        &EmailSenderMock{},
					HTTP:          httpClient,
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
		w := &Worker{
			WebhookSecret: "test_signing_key_123", Pool: mock, Redis: db.RedisClient, Mailer: mailer, HTTP: http.DefaultClient}

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
	defer func() { _ = rdb.Close() }()

	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	w := &Worker{
		WebhookSecret: "test_signing_key_123",
		Pool:          mock,
		Redis:         rdb,
		Mailer:        &EmailSenderMock{},
		HTTP:          http.DefaultClient,
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
	t.Run("JSON_Marshal_Error", func(t *testing.T) {
		// Placeholder for testing marshaling errors if data becomes complex
	})

	t.Run("Redis_RPush_Error", func(t *testing.T) {
		mr2, err := miniredis.Run()
		if err != nil {
			t.Fatalf("failed to start miniredis: %v", err)
		}
		rdb2 := redis.NewClient(&redis.Options{Addr: mr2.Addr()})
		mr2.Close() // Force connection error

		w2 := &Worker{Redis: rdb2}
		cve := &models.CVE{CVSSScore: 7.0}
		sub := models.UserSubscription{}

		success := w2.bufferAlert(context.Background(), 1, cve, sub, "user@example.com", "Asset")
		if success {
			t.Errorf("expected bufferAlert to fail for redis error")
		}
	})
}

func TestWorker_notifyIfNewWithCache(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	w := NewWorker(mock, rdb, &EmailSenderMock{}, http.DefaultClient)
	ctx := context.Background()

	userID := 1
	email := "user@example.com"
	assetName := "test-asset"
	sub := models.UserSubscription{ID: 1, UserID: userID}

	t.Run("cached_already_notified", func(t *testing.T) {
		cve := &models.CVE{ID: 1, CVEID: "CVE-TEST"}
		cache := map[int]bool{userID: true}
		got := w.notifyIfNewWithCache(ctx, userID, cve, sub, email, assetName, cache)
		if got != false {
			t.Errorf("expected false, got %v", got)
		}
	})

	t.Run("db_already_notified", func(t *testing.T) {
		cve := &models.CVE{ID: 2, CVEID: "CVE-TEST-2"}
		mock.ExpectQuery("SELECT EXISTS").WithArgs(userID, cve.ID).WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))

		got := w.notifyIfNewWithCache(ctx, userID, cve, sub, email, assetName, nil)
		if got != false {
			t.Errorf("expected false, got %v", got)
		}
	})

	t.Run("flood_protection", func(t *testing.T) {
		cve := &models.CVE{ID: 3, CVEID: "CVE-TEST-3"}
		mock.ExpectQuery("SELECT EXISTS").WithArgs(userID, cve.ID).WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(false))

		// Simulate flood count = 50, so Incr makes it 51
		rdb.Set(ctx, fmt.Sprintf("flood_protection:%d", userID), 50, 0)

		got := w.notifyIfNewWithCache(ctx, userID, cve, sub, email, assetName, nil)
		if got != false {
			t.Errorf("expected false, got %v", got)
		}
	})

	t.Run("fetch_cve_fails", func(t *testing.T) {
		// Empty CVEID triggers DB fetch
		cve := &models.CVE{ID: 4, CVEID: ""}
		mock.ExpectQuery("SELECT EXISTS").WithArgs(userID, cve.ID).WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(false))

		// Reset flood count to 0 so it increments to 1
		rdb.Set(ctx, fmt.Sprintf("flood_protection:%d", userID), 0, 0)

		mock.ExpectQuery("SELECT cve_id, description, cvss_score").WithArgs(cve.ID).WillReturnError(fmt.Errorf("db error"))

		got := w.notifyIfNewWithCache(ctx, userID, cve, sub, email, assetName, nil)
		if got != false {
			t.Errorf("expected false, got %v", got)
		}

		// Ensure flood count was decremented back to 0
		count, _ := rdb.Get(ctx, fmt.Sprintf("flood_protection:%d", userID)).Int()
		if count != 0 {
			t.Errorf("expected flood count 0, got %d", count)
		}
	})

	t.Run("success_path", func(t *testing.T) {
		cve := &models.CVE{ID: 5, CVEID: "CVE-TEST-5"}
		mock.ExpectQuery("SELECT EXISTS").WithArgs(userID, cve.ID).WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(false))

		// Setup for w.bufferAlert to succeed
		sub.AggregationMode = "instant"
		sub.EnableEmail = true // Enable email to ensure hasAnySuccess becomes true

		mock.ExpectExec("INSERT INTO notification_delivery_logs").WithArgs(userID, sub.ID, cve.ID, "email", "success", "").WillReturnResult(pgxmock.NewResult("INSERT", 1))

		mock.ExpectExec("INSERT INTO alert_history").WithArgs(userID, cve.ID).WillReturnResult(pgxmock.NewResult("INSERT", 1))

		got := w.notifyIfNewWithCache(ctx, userID, cve, sub, email, assetName, nil)
		if got != true {
			t.Errorf("expected true, got %v", got)
		}
	})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}
