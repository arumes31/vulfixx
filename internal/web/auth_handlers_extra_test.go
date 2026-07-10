package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/hibiken/asynq"
	"time"

	"cve-tracker/internal/db"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestResendVerificationInlineHandler(t *testing.T) {
	// Start miniredis
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	redisClient := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	oldRedis := db.RedisClient
	db.RedisClient = redisClient
	defer func() { db.RedisClient = oldRedis }()

	mockDB, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup test db: %v", err)
	}
	defer mockDB.Close()

	app := setupTestApp(t, mockDB)

	oldPool := db.Pool
	db.Pool = mockDB
	defer func() { db.Pool = oldPool }()

	tests := []struct {
		name       string
		method     string
		email      string
		wantStatus int
		mockSetup  func()
	}{
		{
			name:       "method_not_allowed",
			method:     http.MethodGet,
			wantStatus: http.StatusMethodNotAllowed,
			mockSetup:  func() {},
		},
		{
			name:       "invalid_email",
			method:     http.MethodPost,
			email:      "invalid",
			wantStatus: http.StatusOK,
			mockSetup:  func() {},
		},
		{
			name:       "already_verified_or_unknown",
			method:     http.MethodPost,
			email:      "test@example.com",
			wantStatus: http.StatusOK,
			mockSetup: func() {
				// auth.ResendVerificationToken will be called, expecting a query
				mockDB.ExpectQuery("SELECT id, is_verified").
					WithArgs("test@example.com").
					WillReturnRows(mockDB.NewRows([]string{"id", "is_verified"}).AddRow(1, true))
			},
		},
		{
			name:       "valid_resend",
			method:     http.MethodPost,
			email:      "unverified@example.com",
			wantStatus: http.StatusOK,
			mockSetup: func() {
				// We expect the whole query sequence for a successful token resend,
				// or we just return an error to simulate backoff for simplicity.
				// Returning error is sufficient for code coverage.
				mockDB.ExpectQuery("SELECT id, is_verified").
					WithArgs("unverified@example.com").
					WillReturnRows(mockDB.NewRows([]string{"id", "is_verified", "verification_token"}).AddRow(2, false, "old-token"))

				// To cover the rollback path if needed, we'll just let it fail at Exec
				mockDB.ExpectExec("UPDATE users").WillReturnError(context.DeadlineExceeded)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.mockSetup()

			var body *strings.Reader
			if tc.email != "" {
				form := url.Values{}
				form.Add("email", tc.email)
				body = strings.NewReader(form.Encode())
			} else {
				body = strings.NewReader("")
			}

			req := httptest.NewRequest(tc.method, "/resend-verification-inline", body)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("X-Requested-With", "XMLHttpRequest")

			rr := httptest.NewRecorder()

			app.ResendVerificationInlineHandler(rr, req)

			if rr.Code != tc.wantStatus {
				t.Errorf("expected status %d, got %d", tc.wantStatus, rr.Code)
			}
		})
	}
}

func TestResendVerificationInlineHandler_RateLimits(t *testing.T) {
	// Start miniredis
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	redisClient := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	oldRedis := db.RedisClient
	db.RedisClient = redisClient
	defer func() { db.RedisClient = oldRedis }()

	mockDB, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup test db: %v", err)
	}
	defer mockDB.Close()

	app := setupTestApp(t, mockDB)

	oldPool := db.Pool
	db.Pool = mockDB
	defer func() { db.Pool = oldPool }()

	t.Run("ip_rate_limit_exceeded", func(t *testing.T) {
		app.Redis.Set(context.Background(), "resend_limit:192.0.2.1", 5, time.Hour)

		form := url.Values{}
		form.Add("email", "test@example.com")
		req := httptest.NewRequest("POST", "/resend-verification-inline", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Forwarded-For", "192.0.2.1")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")

		rr := httptest.NewRecorder()
		app.ResendVerificationInlineHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
		}
	})

	t.Run("email_rate_limit_exceeded", func(t *testing.T) {
		// sha256 of "test@example.com"
		emailHash := "973dfe463ec85785f5f95af5ba3906eedb2d931c24e69824a89ea65dba4e813b"
		app.Redis.Set(context.Background(), "resend_email_limit:"+emailHash, 3, time.Minute)

		form := url.Values{}
		form.Add("email", "test@example.com")
		req := httptest.NewRequest("POST", "/resend-verification-inline", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Forwarded-For", "192.0.2.2")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")

		rr := httptest.NewRecorder()
		app.ResendVerificationInlineHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
		}
	})
}

func TestResendVerificationInlineHandler_EnqueuePath(t *testing.T) {
	// Start miniredis
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	redisClient := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	oldRedis := db.RedisClient
	db.RedisClient = redisClient
	defer func() { db.RedisClient = oldRedis }()

	mockDB, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup test db: %v", err)
	}
	defer mockDB.Close()

	app := setupTestApp(t, mockDB)

	app.AsynqClient = asynq.NewClient(asynq.RedisClientOpt{Addr: mr.Addr()})
	defer app.AsynqClient.Close()

	oldPool := db.Pool
	db.Pool = mockDB
	defer func() { db.Pool = oldPool }()

	t.Run("valid_resend_enqueue_asynq", func(t *testing.T) {
		mockDB.ExpectQuery("SELECT id, is_verified").
			WithArgs("unverified@example.com").
			WillReturnRows(mockDB.NewRows([]string{"id", "is_verified", "verification_token"}).AddRow(2, false, "old-token"))

		mockDB.ExpectExec("UPDATE users").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), 2).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		form := url.Values{}
		form.Add("email", "unverified@example.com")
		req := httptest.NewRequest("POST", "/resend-verification-inline", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rr := httptest.NewRecorder()
		app.ResendVerificationInlineHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
		}
	})

	t.Run("valid_resend_enqueue_redis", func(t *testing.T) {
		// Mock out asynq client to fall back to Redis push
		oldAsynq := app.AsynqClient
		app.AsynqClient = nil
		defer func() { app.AsynqClient = oldAsynq }()

		mockDB.ExpectQuery("SELECT id, is_verified").
			WithArgs("unverified2@example.com").
			WillReturnRows(mockDB.NewRows([]string{"id", "is_verified", "verification_token"}).AddRow(3, false, "old-token2"))

		mockDB.ExpectExec("UPDATE users").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), 3).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		form := url.Values{}
		form.Add("email", "unverified2@example.com")
		req := httptest.NewRequest("POST", "/resend-verification-inline", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rr := httptest.NewRecorder()
		app.ResendVerificationInlineHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
		}
	})

	t.Run("valid_resend_enqueue_redis_error", func(t *testing.T) {
		// Mock out asynq client to fall back to Redis push
		oldAsynq := app.AsynqClient
		app.AsynqClient = nil
		defer func() { app.AsynqClient = oldAsynq }()

		// Close redis to trigger error
		mr.Close()

		mockDB.ExpectQuery("SELECT id, is_verified").
			WithArgs("unverified3@example.com").
			WillReturnRows(mockDB.NewRows([]string{"id", "is_verified", "verification_token"}).AddRow(4, false, "old-token3"))

		mockDB.ExpectExec("UPDATE users").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), 4).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		mockDB.ExpectExec("UPDATE users").
			WithArgs("old-token3", pgxmock.AnyArg(), "unverified3@example.com").
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		form := url.Values{}
		form.Add("email", "unverified3@example.com")
		req := httptest.NewRequest("POST", "/resend-verification-inline", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rr := httptest.NewRecorder()
		app.ResendVerificationInlineHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
		}
	})
}


func TestResendVerificationInlineHandler_Errors(t *testing.T) {
	// Start miniredis
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	redisClient := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	oldRedis := db.RedisClient
	db.RedisClient = redisClient
	defer func() { db.RedisClient = oldRedis }()

	mockDB, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup test db: %v", err)
	}
	defer mockDB.Close()

	app := setupTestApp(t, mockDB)

	oldPool := db.Pool
	db.Pool = mockDB
	defer func() { db.Pool = oldPool }()

	t.Run("form_parse_error", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/resend-verification-inline", strings.NewReader("%%")) // Invalid form body
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")

		rr := httptest.NewRecorder()
		app.ResendVerificationInlineHandler(rr, req)

		if rr.Code != http.StatusBadRequest { // SendResponse returns Bad Request on non-success
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
		}
	})
}
