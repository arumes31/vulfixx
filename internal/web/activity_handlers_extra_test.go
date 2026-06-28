package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cve-tracker/internal/db"

	"github.com/pashagolub/pgxmock/v3"
)

func TestActivityLogHandler_Errors(t *testing.T) {
	t.Run("UnauthorizedRedirect", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		app := setupTestApp(t, mock)

		req := httptest.NewRequest("GET", "/activity", nil)
		rr := httptest.NewRecorder()
		app.ActivityLogHandler(rr, req)

		if rr.Code != http.StatusFound {
			t.Errorf("expected 302 Found, got %d", rr.Code)
		}
	})

	t.Run("ScanError", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		app := setupTestApp(t, mock)

		req := httptest.NewRequest("GET", "/activity", nil)
		setSessionUser(t, app, req, 1, false)

		// Return incompatible type to trigger scan error
		mock.ExpectQuery("SELECT").WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"id", "activity_type", "description", "ip_address", "created_at"}).
				AddRow("not-an-int", "login", "desc", "127.0.0.1", "bad-time"))

		expectBaseQueries(mock, 1)

		rr := httptest.NewRecorder()
		app.ActivityLogHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK even with row scan errors, got %d", rr.Code)
		}
	})

	t.Run("RowsError", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		app := setupTestApp(t, mock)

		req := httptest.NewRequest("GET", "/activity", nil)
		setSessionUser(t, app, req, 1, false)

		rows := pgxmock.NewRows([]string{"id", "activity_type", "description", "ip_address", "created_at"}).
			RowError(0, errors.New("iteration error"))

		mock.ExpectQuery("SELECT").WithArgs(1).WillReturnRows(rows)

		rr := httptest.NewRecorder()
		app.ActivityLogHandler(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("expected 500 Internal Server Error, got %d", rr.Code)
		}
	})
}

func TestExportActivityLogHandler_Errors(t *testing.T) {
	t.Run("Unauthorized", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		app := setupTestApp(t, mock)

		req := httptest.NewRequest("GET", "/activity/export", nil)
		rr := httptest.NewRecorder()
		app.ExportActivityLogHandler(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized, got %d", rr.Code)
		}
	})

	t.Run("ScanError", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		app := setupTestApp(t, mock)

		req := httptest.NewRequest("GET", "/activity/export", nil)
		setSessionUser(t, app, req, 1, false)

		mock.ExpectQuery("SELECT").WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"id", "activity_type", "description", "ip_address", "created_at"}).
				AddRow("not-an-int", "login", "desc", "127.0.0.1", "bad-time"))

		rr := httptest.NewRecorder()
		app.ExportActivityLogHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
	})

	t.Run("RowsError", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		app := setupTestApp(t, mock)

		req := httptest.NewRequest("GET", "/activity/export", nil)
		setSessionUser(t, app, req, 1, false)

		rows := pgxmock.NewRows([]string{"id", "activity_type", "description", "ip_address", "created_at"}).
			RowError(0, errors.New("iteration error"))

		mock.ExpectQuery("SELECT").WithArgs(1).WillReturnRows(rows)

		rr := httptest.NewRecorder()
		app.ExportActivityLogHandler(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("expected 500 Internal Server Error, got %d", rr.Code)
		}
	})
}

// NonFlusherResponseWriter does not implement http.Flusher
type NonFlusherResponseWriter struct {
	header http.Header
	code   int
	body   []byte
}

func (n *NonFlusherResponseWriter) Header() http.Header {
	if n.header == nil {
		n.header = make(http.Header)
	}
	return n.header
}

func (n *NonFlusherResponseWriter) Write(b []byte) (int, error) {
	n.body = append(n.body, b...)
	return len(b), nil
}

func (n *NonFlusherResponseWriter) WriteHeader(statusCode int) {
	n.code = statusCode
}

func TestActivityStreamHandler_Errors(t *testing.T) {
	t.Run("Unauthorized", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		app := setupTestApp(t, mock)

		req := httptest.NewRequest("GET", "/api/activity/stream", nil)
		rr := httptest.NewRecorder()
		app.ActivityStreamHandler(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized, got %d", rr.Code)
		}
	})

	t.Run("FlusherUnsupported", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		app := setupTestApp(t, mock)

		req := httptest.NewRequest("GET", "/api/activity/stream", nil)
		setSessionUser(t, app, req, 1, false)

		w := &NonFlusherResponseWriter{}
		app.ActivityStreamHandler(w, req)

		if w.code != http.StatusInternalServerError {
			t.Errorf("expected 500 Internal Server Error, got %d", w.code)
		}
	})

	t.Run("RedisSubscriptionUnsupported", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		app := setupTestApp(t, mock)

		// Set Redis client to an interface that doesn't support Subscribe
		app.Redis = dummyRedisProvider{}

		req := httptest.NewRequest("GET", "/api/activity/stream", nil)
		setSessionUser(t, app, req, 1, false)

		rr := httptest.NewRecorder()
		app.ActivityStreamHandler(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("expected 500 Internal Server Error, got %d", rr.Code)
		}
	})

	t.Run("FiltersAndPayloadErrors", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		app := setupTestApp(t, mock)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		req, _ := http.NewRequestWithContext(ctx, "GET", "/api/activity/stream", nil)
		setSessionUser(t, app, req, 1, false)

		rr := httptest.NewRecorder()

		done := make(chan struct{})
		go func() {
			app.ActivityStreamHandler(rr, req)
			close(done)
		}()

		time.Sleep(50 * time.Millisecond)

		// 1. Publish invalid JSON payload (should be skipped)
		mock.ExpectExec("INSERT INTO user_activity_logs").WillReturnResult(pgxmock.NewResult("INSERT", 1))
		app.Redis.Publish(context.Background(), "vulfixx:activity_channel", "{invalid json")

		// 2. Publish payload for a different user (user_id = 999, our user is 1) (should be filtered out)
		differentUserPayload := `{"user_id": 999, "activity_type": "event", "description": "other user event"}`
		app.Redis.Publish(context.Background(), "vulfixx:activity_channel", differentUserPayload)

		// 3. Publish valid payload for our user (user_id = 1) (should be processed)
		validUserPayload := `{"user_id": 1, "activity_type": "event", "description": "our user event"}`
		app.Redis.Publish(context.Background(), "vulfixx:activity_channel", validUserPayload)

		time.Sleep(50 * time.Millisecond)
		cancel()
		<-done

		body := rr.Body.String()
		if !strings.Contains(body, "our user event") {
			t.Errorf("expected 'our user event' in stream, got %q", body)
		}
		if strings.Contains(body, "other user event") {
			t.Errorf("did not expect 'other user event' in stream, got %q", body)
		}
	})
}
