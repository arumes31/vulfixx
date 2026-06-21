package web

import (
	"cve-tracker/internal/config"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	sentryhttp "github.com/getsentry/sentry-go/http"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	csrf "filippo.io/csrf/gorilla"
	"github.com/rs/cors"
)

// Routes initializes the application router and middlewares.
func (app *App) Routes(cfg *config.Config) (http.Handler, error) {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP) //nolint:staticcheck
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(app.ProxyMiddleware)
	r.Use(app.SecurityHeadersMiddleware)
	r.Use(middleware.Timeout(60 * time.Second))

	// Public routes
	r.Method("GET", "/", app.RateLimitMiddleware(http.HandlerFunc(app.IndexHandler)))
	r.Method("GET", "/feed", app.RateLimitMiddleware(http.HandlerFunc(app.RSSFeedHandler)))
	r.Method("GET", "/login", app.RateLimitMiddleware(http.HandlerFunc(app.LoginHandler)))
	r.Method("POST", "/login", app.RateLimitMiddleware(http.HandlerFunc(app.LoginHandler)))
	r.Method("GET", "/register", app.RateLimitMiddleware(http.HandlerFunc(app.RegisterHandler)))
	r.Method("POST", "/register", app.RateLimitMiddleware(http.HandlerFunc(app.RegisterHandler)))
	r.Method("GET", "/resend-verification", app.RateLimitMiddleware(http.HandlerFunc(app.ResendVerificationHandler)))
	r.Method("POST", "/resend-verification", app.RateLimitMiddleware(http.HandlerFunc(app.ResendVerificationHandler)))
	r.Method("POST", "/resend-verification-inline", app.RateLimitMiddleware(http.HandlerFunc(app.ResendVerificationInlineHandler)))
	r.Method("GET", "/captcha", app.RateLimitMiddleware(http.HandlerFunc(app.CaptchaHandler)))
	r.Method("GET", "/verify-email", app.RateLimitMiddleware(http.HandlerFunc(app.VerifyEmailHandler)))
	r.Method("GET", "/confirm-email-change", app.RateLimitMiddleware(http.HandlerFunc(app.ConfirmEmailChangeHandler)))
	r.Method("GET", "/alert-action", app.RateLimitMiddleware(http.HandlerFunc(app.HandleAlertAction)))
	r.Method("POST", "/alert-action", app.RateLimitMiddleware(http.HandlerFunc(app.HandleAlertAction)))
	r.Method("POST", "/logout", app.RateLimitMiddleware(http.HandlerFunc(app.LogoutHandler)))
	r.HandleFunc("/healthz", app.HealthzHandler)
	r.HandleFunc("/readyz", app.ReadyzHandler)
	r.Method("POST", "/api/errors", app.RateLimitMiddleware(http.HandlerFunc(app.ErrorReportHandler)))
	r.Method("POST", "/api/csp-report", app.RateLimitMiddleware(http.HandlerFunc(app.CSPReportHandler)))
	r.Method("GET", "/robots.txt", app.RateLimitMiddleware(http.HandlerFunc(app.RobotsHandler)))
	r.Method("GET", "/sitemap.xml", app.RateLimitMiddleware(http.HandlerFunc(app.SitemapHandler)))
	r.Method("GET", "/cve/{id}", app.RateLimitMiddleware(http.HandlerFunc(app.CVEDetailHandler)))

	// Protected & Admin Routes
	r.Group(func(r chi.Router) {
		r.Use(app.AuthMiddleware)
		r.HandleFunc("/dashboard", app.DashboardHandler)
		r.Method("POST", "/api/status", app.RateLimitMiddleware(http.HandlerFunc(app.UpdateCVEStatusHandler)))
		r.Method("POST", "/api/status/bulk", app.RateLimitMiddleware(http.HandlerFunc(app.BulkUpdateCVEStatusHandler)))
		r.Method("POST", "/api/notes", app.RateLimitMiddleware(http.HandlerFunc(app.UpdateCVENoteHandler)))
		r.Method("GET", "/api/cves", app.RateLimitMiddleware(http.HandlerFunc(app.APICVEsHandler)))
		r.HandleFunc("/subscriptions", app.SubscriptionsHandler)
		r.Method("POST", "/subscriptions", app.RateLimitMiddleware(http.HandlerFunc(app.SubscriptionsHandler)))
		r.Method("POST", "/subscriptions/delete", app.RateLimitMiddleware(http.HandlerFunc(app.DeleteSubscriptionHandler)))
		r.Method("POST", "/subscriptions/update", app.RateLimitMiddleware(http.HandlerFunc(app.UpdateSubscriptionHandler)))
		r.HandleFunc("/assets", app.AssetsHandler)
		r.Method("POST", "/assets", app.RateLimitMiddleware(http.HandlerFunc(app.AssetsHandler)))
		r.Method("POST", "/assets/delete", app.RateLimitMiddleware(http.HandlerFunc(app.DeleteAssetHandler)))
		r.Method("GET", "/export", app.RateLimitMiddleware(http.HandlerFunc(app.ExportCVEsHandler)))
		r.HandleFunc("/activity", app.ActivityLogHandler)
		r.Method("GET", "/activity/export", app.RateLimitMiddleware(http.HandlerFunc(app.ExportActivityLogHandler)))
		r.HandleFunc("/api/activity/stream", app.ActivityStreamHandler)
		r.HandleFunc("/alerts", app.AlertHistoryHandler)
		r.HandleFunc("/settings", app.SettingsHandler)
		r.Method("POST", "/settings/totp/generate", app.RateLimitMiddleware(http.HandlerFunc(app.GenerateTOTPHandler)))
		r.Method("POST", "/settings/totp/verify", app.RateLimitMiddleware(http.HandlerFunc(app.VerifyTOTPHandler)))
		r.Method("POST", "/settings/password", app.RateLimitMiddleware(http.HandlerFunc(app.ChangePasswordHandler)))
		r.Method("POST", "/settings/email", app.RateLimitMiddleware(http.HandlerFunc(app.ChangeEmailHandler)))
		r.Method("POST", "/settings/delete", app.RateLimitMiddleware(http.HandlerFunc(app.DeleteAccountHandler)))
		r.Method("POST", "/api/onboarding/complete", app.RateLimitMiddleware(http.HandlerFunc(app.CompleteOnboardingHandler)))

		// Team routes
		r.HandleFunc("/teams", app.TeamsHandler)
		r.HandleFunc("/teams/create", app.CreateTeamHandler)
		r.Method("POST", "/teams/create", app.RateLimitMiddleware(http.HandlerFunc(app.CreateTeamHandler)))
		r.HandleFunc("/teams/join", app.JoinTeamHandler)
		r.Method("POST", "/teams/join", app.RateLimitMiddleware(http.HandlerFunc(app.JoinTeamHandler)))
		r.Method("POST", "/teams/leave", app.RateLimitMiddleware(http.HandlerFunc(app.LeaveTeamHandler)))
		r.Method("POST", "/teams/switch", app.RateLimitMiddleware(http.HandlerFunc(app.SwitchTeamHandler)))

		// Admin routes
		r.Group(func(r chi.Router) {
			r.Use(app.AdminMiddleware)
			r.HandleFunc("/admin/users", app.AdminUserManagementHandler)
			r.Method("POST", "/admin/users/delete", app.RateLimitMiddleware(http.HandlerFunc(app.AdminDeleteUserHandler)))
		})
	})

	// Static files
	r.Handle("/static/*", http.StripPrefix("/static/", staticFileHandler(http.Dir("./static/"))))

	csrfKey := cfg.CSRFKey
	if csrfKey == "" || len(csrfKey) != 32 {
		return nil, fmt.Errorf("cfg.CSRFKey is required and must be exactly 32 bytes")
	}

	csrfMiddleware := csrf.Protect(
		[]byte(csrfKey),
		csrf.Secure(cfg.SecureCookie),
		csrf.HttpOnly(true),
		csrf.SameSite(csrf.SameSiteStrictMode),
		csrf.Path("/"),
		csrf.FieldName("gorilla.csrf.Token"),
		csrf.RequestHeader("X-CSRF-Token"),
	)

	// Bypass CSRF checks for browser CSP report endpoint
	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/api/csp-report" {
			if req.Method != http.MethodPost {
				http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
				return
			}
			contentType := req.Header.Get("Content-Type")
			if !strings.Contains(contentType, "application/csp-report") && !strings.Contains(contentType, "application/json") {
				http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
				return
			}
			r.ServeHTTP(w, req)
			return
		}
		csrfMiddleware(r).ServeHTTP(w, req)
	})

	// Configure strict CORS policies (Item 7)
	var allowedOrigins []string
	allowedOriginsStr := os.Getenv("ALLOWED_ORIGINS")
	if allowedOriginsStr != "" {
		for _, s := range strings.Split(allowedOriginsStr, ",") {
			allowedOrigins = append(allowedOrigins, strings.TrimSpace(s))
		}
	} else {
		allowedOrigins = []string{"http://localhost:8080", "http://127.0.0.1:8080"}
		baseURL := os.Getenv("BASE_URL")
		if baseURL != "" {
			allowedOrigins = append(allowedOrigins, strings.TrimSpace(baseURL))
		}
	}

	corsMiddleware := cors.New(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization", "X-CSRF-Token"},
		AllowCredentials: true,
		Debug:            os.Getenv("APP_ENV") == "development",
	})
	handler = corsMiddleware.Handler(handler)

	if cfg.SentryDSN != "" {
		sentryHandler := sentryhttp.New(sentryhttp.Options{
			Repanic: true,
		})
		handler = sentryHandler.Handle(handler)
	}

	return handler, nil
}

// staticFileHandler wraps http.FileServer to block directory listing and add cache headers.
func staticFileHandler(root http.FileSystem) http.Handler {
	fs := http.FileServer(root)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block directory listings by checking if path ends with "/"
		if strings.HasSuffix(r.URL.Path, "/") || r.URL.Path == "" {
			http.NotFound(w, r)
			return
		}
		f, err := root.Open(r.URL.Path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		stat, err := f.Stat()
		_ = f.Close()
		if err != nil || stat.IsDir() {
			http.NotFound(w, r)
			return
		}

		if r.URL.Path == "/favicon.ico" || r.URL.Path == "/favicon.png" {
			w.Header().Set("Cache-Control", "public, max-age=86400")
		} else {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		fs.ServeHTTP(w, r)
	})
}
