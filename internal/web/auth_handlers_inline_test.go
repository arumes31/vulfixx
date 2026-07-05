package web

import (
    "net/http"
    "net/http/httptest"
    "testing"
    "cve-tracker/internal/db"
    "strings"
    "time"
    "github.com/alicebob/miniredis/v2"
    "github.com/redis/go-redis/v9"
    "github.com/pashagolub/pgxmock/v3"
    "crypto/sha256"
    "encoding/hex"
    "net/url"
)

func TestResendVerificationInlineHandler(t *testing.T) {
    mock, err := db.SetupTestDB()
    if err != nil {
        t.Fatalf("failed to setup mock db: %v", err)
    }
    defer mock.Close()

    app := setupTestApp(t, mock)

    oldPool := db.Pool
    db.Pool = mock
    defer func() { db.Pool = oldPool }()

    mr, err := miniredis.Run()
    if err != nil {
        t.Fatalf("miniredis error: %v", err)
    }
    defer mr.Close()
    app.Redis = redis.NewClient(&redis.Options{Addr: mr.Addr()})

    t.Run("MethodNotAllowed_AJAX", func(t *testing.T) {
        req, _ := http.NewRequest(http.MethodGet, "/resend-verification-inline", nil)
        req.Header.Set("X-Requested-With", "XMLHttpRequest")
        rr := httptest.NewRecorder()

        app.ResendVerificationInlineHandler(rr, req)

        if rr.Code != http.StatusBadRequest && rr.Code != http.StatusMethodNotAllowed {
            t.Errorf("expected 400, got %d", rr.Code) // Actually 400 with success=false
        }
    })

    t.Run("InvalidEmail_PretendSuccess", func(t *testing.T) {
        formData := url.Values{}
        formData.Set("email", "invalidemail")
        req, _ := http.NewRequest(http.MethodPost, "/resend-verification-inline", strings.NewReader(formData.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        req.Header.Set("X-Requested-With", "XMLHttpRequest")

        rr := httptest.NewRecorder()
        app.ResendVerificationInlineHandler(rr, req)

        if rr.Code != http.StatusOK {
            t.Errorf("expected 200, got %d", rr.Code)
        }
    })

    t.Run("ValidEmail_Success", func(t *testing.T) {
        email := "test@example.com"
        formData := url.Values{}
        formData.Set("email", email)
        req, _ := http.NewRequest(http.MethodPost, "/resend-verification-inline", strings.NewReader(formData.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        req.Header.Set("X-Requested-With", "XMLHttpRequest")

        // Mock ResendVerificationToken query
        mock.ExpectBegin()
        mock.ExpectQuery("SELECT id, is_verified, verification_token, verification_sent_at").
            WithArgs(email).
            WillReturnRows(pgxmock.NewRows([]string{"id", "is_verified", "verification_token", "verification_sent_at"}).
                AddRow(1, false, "oldtoken", time.Now().Add(-2*time.Hour)))
        mock.ExpectExec("UPDATE users SET verification_token").
            WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), 1).
            WillReturnResult(pgxmock.NewResult("UPDATE", 1))
        mock.ExpectCommit()

        rr := httptest.NewRecorder()
        app.ResendVerificationInlineHandler(rr, req)

        if rr.Code != http.StatusOK {
            t.Errorf("expected 200, got %d", rr.Code)
        }
    })

    t.Run("PerIPRateLimit", func(t *testing.T) {
        email := "test2@example.com"
        formData := url.Values{}
        formData.Set("email", email)
        req, _ := http.NewRequest(http.MethodPost, "/resend-verification-inline", strings.NewReader(formData.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        req.Header.Set("X-Requested-With", "XMLHttpRequest")
        req.RemoteAddr = "1.2.3.4:1234"

        app.Redis.Set(req.Context(), "resend_limit:1.2.3.4", 5, time.Hour)

        rr := httptest.NewRecorder()
        app.ResendVerificationInlineHandler(rr, req)

        if rr.Code != http.StatusOK {
            t.Errorf("expected 200, got %d", rr.Code)
        }
    })

    t.Run("PerEmailRateLimit", func(t *testing.T) {
        email := "test3@example.com"
        formData := url.Values{}
        formData.Set("email", email)
        req, _ := http.NewRequest(http.MethodPost, "/resend-verification-inline", strings.NewReader(formData.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        req.Header.Set("X-Requested-With", "XMLHttpRequest")
        req.RemoteAddr = "5.6.7.8:1234"

        emailHash := sha256.Sum256([]byte(email))
        emailRlKey := "resend_email_limit:" + hex.EncodeToString(emailHash[:])
        app.Redis.Set(req.Context(), emailRlKey, 3, 30*time.Minute)

        rr := httptest.NewRecorder()
        app.ResendVerificationInlineHandler(rr, req)

        if rr.Code != http.StatusOK {
            t.Errorf("expected 200, got %d", rr.Code)
        }
    })
}
