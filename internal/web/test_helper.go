package web

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gorilla/sessions"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/redis/go-redis/v9"
)

type MockMailer struct {
	SentEmails []struct {
		To      string
		Subject string
		Body    string
	}
}

func (m *MockMailer) SendEmail(to, subject, body string) error {
	m.SentEmails = append(m.SentEmails, struct {
		To      string
		Subject string
		Body    string
	}{to, subject, body})
	return nil
}

func setupTestApp(t *testing.T, mock pgxmock.PgxPoolIface) *App {
	t.Helper()
	// Locate the templates/ directory
	if dir := findTemplatesDir(); dir == "" {
		t.Fatalf("could not find templates directory")
	}

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	t.Cleanup(mr.Close)

	redisClient := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	app := NewApp(mock, redisClient, sessions.NewCookieStore([]byte("test-secret")), &MockMailer{})
	_ = app.InitTemplatesWithFuncs()

	return app
}

func setSessionUser(t *testing.T, app *App, r *http.Request, userID int, isAdmin bool) {
	session, err := app.SessionStore.Get(r, "vulfixx-session")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	session.Values["user_id"] = userID
	session.Values["is_admin"] = isAdmin
	rr := httptest.NewRecorder()
	err = session.Save(r, rr)
	if err != nil {
		t.Fatalf("failed to save session: %v", err)
	}
	for _, cookie := range rr.Result().Cookies() {
		r.AddCookie(cookie)
	}
}

func expectBaseQueries(mock pgxmock.PgxPoolIface, userID int) {
	if userID <= 0 {
		return
	}
	// Onboarding status query in RenderTemplate
	mock.ExpectQuery(regexp.QuoteMeta("SELECT onboarding_completed FROM users WHERE id = $1")).
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows([]string{"onboarding_completed"}).AddRow(true))

	// Team list query in RenderTemplate
	mock.ExpectQuery(regexp.QuoteMeta("SELECT t.id, t.name FROM teams t JOIN team_members tm ON t.id = tm.team_id WHERE tm.user_id = $1")).
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows([]string{"id", "name"}))
}

func setupTestServer(t *testing.T, mock pgxmock.PgxPoolIface) (*httptest.Server, *App, *http.Client) {
	app := setupTestApp(t, mock)

	r := http.NewServeMux()
	// Add routes as needed for TestWebEndpointsCoverage
	// For simplicity, we can just use the real router if available
	// but here we define what we need.
	r.HandleFunc("/", app.IndexHandler)
	r.HandleFunc("/login", app.LoginHandler)
	r.HandleFunc("/register", app.RegisterHandler)
	r.HandleFunc("/captcha", app.CaptchaHandler)
	r.Handle("/dashboard", app.AuthMiddleware(http.HandlerFunc(app.DashboardHandler)))
	r.Handle("/subscriptions", app.AuthMiddleware(http.HandlerFunc(app.SubscriptionsHandler)))
	r.Handle("/settings", app.AuthMiddleware(http.HandlerFunc(app.SettingsHandler)))
	r.Handle("/activity", app.AuthMiddleware(http.HandlerFunc(app.ActivityLogHandler)))
	r.Handle("/alerts", app.AuthMiddleware(http.HandlerFunc(app.AlertHistoryHandler)))

	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return ts, app, client
}
