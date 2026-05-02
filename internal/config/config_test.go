package config

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Backup original log functions
	origFatalf := logFatalf
	origPrintf := logPrintf
	defer func() {
		logFatalf = origFatalf
		logPrintf = origPrintf
	}()

	tests := []struct {
		name         string
		envs         map[string]string
		wantSMTPPort int
		wantSecure   bool
		wantFatal    bool
		wantWarning  bool
		checkConfig  func(t *testing.T, c Config)
	}{
		{
			name: "Default values in development",
			envs: map[string]string{
				"APP_ENV": "development",
			},
			wantSMTPPort: 587,
			wantSecure:   true,
			wantFatal:    false,
			wantWarning:  true,
			checkConfig: func(t *testing.T, c Config) {
				if c.DBHost != "db" {
					t.Errorf("DBHost = %v, want db", c.DBHost)
				}
				if c.DBPort != "5432" {
					t.Errorf("DBPort = %v, want 5432", c.DBPort)
				}
				if c.DBUser != "cveuser" {
					t.Errorf("DBUser = %v, want cveuser", c.DBUser)
				}
				if c.DBName != "cvetracker" {
					t.Errorf("DBName = %v, want cvetracker", c.DBName)
				}
				if c.RedisURL != "redis:6379" {
					t.Errorf("RedisURL = %v, want redis:6379", c.RedisURL)
				}
				if c.BaseURL != "http://localhost:8080" {
					t.Errorf("BaseURL = %v, want http://localhost:8080", c.BaseURL)
				}
				if c.SMTPHost != "smtp.example.com" {
					t.Errorf("SMTPHost = %v, want smtp.example.com", c.SMTPHost)
				}
				if c.SMTPUser != "user@example.com" {
					t.Errorf("SMTPUser = %v, want user@example.com", c.SMTPUser)
				}
			},
		},
		{
			name: "Custom environment variables",
			envs: map[string]string{
				"APP_ENV":           "development",
				"DB_HOST":           "localhost",
				"DB_PORT":           "5433",
				"DB_USER":           "testuser",
				"DB_PASSWORD":       "testpass",
				"DB_NAME":           "testdb",
				"REDIS_URL":         "localhost:6379",
				"SESSION_KEY":       "session",
				"CSRF_KEY":          "csrf",
				"BASE_URL":          "https://test.local",
				"SMTP_HOST":         "smtp.test.local",
				"SMTP_PORT":         "25",
				"SMTP_USER":         "user@test.local",
				"SMTP_PASS":         "pass",
				"ADMIN_EMAIL":       "admin@test.local",
				"ADMIN_PASSWORD":    "adminpass",
				"ADMIN_TOTP_SECRET": "secret",
				"SECURE_COOKIE":     "false",
				"SMTP_MAILFROM":     "alerts@test.local",
			},
			wantSMTPPort: 25,
			wantSecure:   false,
			wantFatal:    false,
			checkConfig: func(t *testing.T, c Config) {
				if c.SMTPMailFrom != "alerts@test.local" {
					t.Errorf("SMTPMailFrom = %v, want alerts@test.local", c.SMTPMailFrom)
				}
				if c.DBHost != "localhost" {
					t.Errorf("DBHost = %v, want localhost", c.DBHost)
				}
				if c.SMTPPort != 25 {
					t.Errorf("SMTPPort = %v, want 25", c.SMTPPort)
				}
				if c.SecureCookie != false {
					t.Errorf("SecureCookie = %v, want false", c.SecureCookie)
				}
				if c.DBPassword != "testpass" {
					t.Errorf("DBPassword = %v, want testpass", c.DBPassword)
				}
			},
		},
		{
			name: "Invalid SMTP_PORT falls back to default",
			envs: map[string]string{
				"APP_ENV":   "development",
				"SMTP_PORT": "abc",
			},
			wantSMTPPort: 587,
			wantFatal:    false,
		},
		{
			name: "Invalid SECURE_COOKIE falls back to default",
			envs: map[string]string{
				"APP_ENV":       "development",
				"SECURE_COOKIE": "maybe",
			},
			wantSecure: true,
			wantFatal:  false,
		},
		{
			name: "Missing sensitive keys in production should fatal",
			envs: map[string]string{
				"APP_ENV": "production",
			},
			wantFatal: true,
		},
		{
			name: "All sensitive keys provided in production should not fatal",
			envs: map[string]string{
				"APP_ENV":           "production",
				"DB_PASSWORD":       "p",
				"SESSION_KEY":       "THIS_IS_A_MOCK_SESSION_KEY_32_BY",
				"CSRF_KEY":          "MOCK_CSRF_KEY_32_BYTES_FOR_TEST!",
				"SMTP_PASS":         "sm",
				"ADMIN_EMAIL":       "admin@example.com",
				"ADMIN_PASSWORD":    "ap",
				"ADMIN_TOTP_SECRET": "at",
			},
			wantFatal: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset AppConfig
			AppConfig = Config{}

			// Mock logging — logFatalf panics so LoadConfig truly stops
			fatalCalled := false
			logFatalf = func(format string, v ...interface{}) {
				fatalCalled = true
				t.Logf("FATAL CALLED: "+format, v...)
				panic(fmt.Sprintf(format, v...))
			}
			warningCalled := false
			logPrintf = func(format string, v ...interface{}) {
				if strings.Contains(format, "Warning") {
					warningCalled = true
				}
				t.Logf(format, v...)
			}

			// Unset all potential env vars first to ensure clean state for defaults
			keys := []string{
				"APP_ENV", "DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME",
				"REDIS_URL", "SESSION_KEY", "CSRF_KEY", "BASE_URL", "SMTP_HOST",
				"SMTP_PORT", "SMTP_USER", "SMTP_PASS", "ADMIN_EMAIL", "ADMIN_PASSWORD",
				"ADMIN_TOTP_SECRET", "SECURE_COOKIE",
			}
			for _, k := range keys {
				val, ok := os.LookupEnv(k)
				if ok {
					_ = os.Unsetenv(k)
					// Use a local variable to capture current key and value
					currKey := k
					currVal := val
					t.Cleanup(func() {
						_ = os.Setenv(currKey, currVal)
					})
				}
			}

			// Set env vars for this test
			for k, v := range tt.envs {
				t.Setenv(k, v)
			}

			// Wrap LoadConfig in a recover so panics from logFatalf are caught
			func() {
				defer func() {
					if r := recover(); r != nil {
						// panic was intentionally triggered by logFatalf mock; fatalCalled flag is already set
						_ = r
					}
				}()
				LoadConfig()
			}()

			if fatalCalled != tt.wantFatal {
				t.Errorf("fatalCalled = %v, want %v", fatalCalled, tt.wantFatal)
			}

			if tt.wantWarning && !warningCalled {
				t.Errorf("Expected warning but it was not called")
			}

			if !tt.wantFatal {
				if tt.wantSMTPPort != 0 && AppConfig.SMTPPort != tt.wantSMTPPort {
					t.Errorf("SMTPPort = %v, want %v", AppConfig.SMTPPort, tt.wantSMTPPort)
				}
				// Check SecureCookie specifically if expected
				if tt.name == "Default values in development" || tt.name == "Invalid SECURE_COOKIE falls back to default" {
					if AppConfig.SecureCookie != tt.wantSecure {
						t.Errorf("SecureCookie = %v, want %v", AppConfig.SecureCookie, tt.wantSecure)
					}
				}
			}

			if tt.checkConfig != nil {
				tt.checkConfig(t, AppConfig)
			}
		})
	}
}

func TestGetEnv(t *testing.T) {
	t.Run("Existing env", func(t *testing.T) {
		t.Setenv("TEST_KEY", "value")
		if got := getEnv("TEST_KEY", "fallback"); got != "value" {
			t.Errorf("getEnv() = %v, want value", got)
		}
	})

	t.Run("Missing env", func(t *testing.T) {
		// Ensure it's missing
		val, ok := os.LookupEnv("MISSING_KEY_XYZ")
		if ok {
			_ = os.Unsetenv("MISSING_KEY_XYZ")
			t.Cleanup(func() { _ = os.Setenv("MISSING_KEY_XYZ", val) })
		}
		if got := getEnv("MISSING_KEY_XYZ", "fallback"); got != "fallback" {
			t.Errorf("getEnv() = %v, want fallback", got)
		}
	})
}
