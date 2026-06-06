package config

import (
	"cve-tracker/internal/security"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Backup original log functions
	origPrintf := logPrintf
	defer func() {
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
				if c.DBPort != DefaultDBPort {
					t.Errorf("DBPort = %v, want %s", c.DBPort, DefaultDBPort)
				}
				if c.DBUser != "cveuser" {
					t.Errorf("DBUser = %v, want cveuser", c.DBUser)
				}
				if c.DBName != "cvetracker" {
					t.Errorf("DBName = %v, want cvetracker", c.DBName)
				}
				if c.RedisURL != DefaultRedisURL {
					t.Errorf("RedisURL = %v, want %s", c.RedisURL, DefaultRedisURL)
				}
				if c.BaseURL != DefaultBaseURL {
					t.Errorf("BaseURL = %v, want %s", c.BaseURL, DefaultBaseURL)
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
				"WEBHOOK_SECRET":    "w",
			},
			wantFatal: false,
		},
		{
			name: "SMTPMailFrom defaults to SMTPUser if empty",
			envs: map[string]string{
				"APP_ENV":       "development",
				"SMTP_USER":     "default@example.com",
				"SMTP_MAILFROM": "",
			},
			wantFatal: false,
			checkConfig: func(t *testing.T, c Config) {
				if c.SMTPMailFrom != "default@example.com" {
					t.Errorf("SMTPMailFrom = %v, want default@example.com", c.SMTPMailFrom)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset AppConfig
			AppConfig = Config{}

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
				"ADMIN_TOTP_SECRET", "SECURE_COOKIE", "WEBHOOK_SECRET",
			}
			for _, k := range keys {
				val, ok := os.LookupEnv(k)
				if ok {
					_ = os.Unsetenv(k)
					kk, vv := k, val
					t.Cleanup(func() {
						_ = os.Setenv(kk, vv)
					})
				}
			}

			// Set env vars for this test
			for k, v := range tt.envs {
				t.Setenv(k, v)
			}

			err := LoadConfig()
			fatalCalled := err != nil

			if fatalCalled != tt.wantFatal {
				t.Errorf("fatalCalled = %v (err: %v), want %v", fatalCalled, err, tt.wantFatal)
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

func TestLoadConfigDecryption(t *testing.T) {
	t.Setenv("ENCRYPTION_KEY", "vulfixx-default-dev-secret-key-32bytes")
	// Import or use encryption module directly
	// Let's encrypt a mock Sentry DSN
	importSecurityEncrypt := func(plainText string) string {
		// We'll import security below by modifying the import block, but since we are in the same package we can also call security.Encrypt
		return ""
	}
	_ = importSecurityEncrypt

	// Using the actual package "cve-tracker/internal/security"
	plainDSN := "https://user@sentry.example.com/123"
	cipherDSN, err := security.Encrypt(plainDSN)
	if err != nil {
		t.Fatalf("failed to encrypt sentry dsn: %v", err)
	}

	t.Setenv("APP_ENV", "development")
	t.Setenv("SENTRY_DSN", "cve-gcm:"+cipherDSN)
	// Run LoadConfig
	err = LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if AppConfig.SentryDSN != plainDSN {
		t.Errorf("expected decrypted SentryDSN %q, got %q", plainDSN, AppConfig.SentryDSN)
	}
}

func TestGetEnvInt(t *testing.T) {
	t.Run("ValidInt", func(t *testing.T) {
		t.Setenv("TEST_INT_VAL", "42")
		if val := getEnvInt("TEST_INT_VAL", 10); val != 42 {
			t.Errorf("expected 42, got %d", val)
		}
	})

	t.Run("InvalidInt", func(t *testing.T) {
		// Mock logPrintf
		origPrintf := logPrintf
		defer func() { logPrintf = origPrintf }()
		logPrintfCalled := false
		logPrintf = func(format string, v ...interface{}) {
			logPrintfCalled = true
		}

		t.Setenv("TEST_INT_VAL", "invalid")
		if val := getEnvInt("TEST_INT_VAL", 10); val != 10 {
			t.Errorf("expected 10 fallback, got %d", val)
		}
		if !logPrintfCalled {
			t.Error("expected logPrintf to be called for invalid int")
		}
	})
}

func TestDecryptIfEncrypted_Error(t *testing.T) {
	t.Setenv("ENCRYPTION_KEY", "vulfixx-default-dev-secret-key-32bytes")
	// Mock logPrintf
	origPrintf := logPrintf
	defer func() { logPrintf = origPrintf }()
	logPrintfCalled := false
	logPrintf = func(format string, v ...interface{}) {
		logPrintfCalled = true
	}

	val := "cve-gcm:invalid-encrypted-payload"
	decrypted := decryptIfEncrypted(val)
	if decrypted != "" {
		t.Errorf("expected empty string on decryption error, got %s", decrypted)
	}
	if !logPrintfCalled {
		t.Error("expected logPrintf to be called for decryption error")
	}
}

func TestDecodeKey_Detailed(t *testing.T) {
	origPrintf := logPrintf
	defer func() {
		logPrintf = origPrintf
	}()

	t.Run("HexDecode", func(t *testing.T) {
		hexKey := strings.Repeat("a", 64) // 64 chars = 32 bytes hex
		decoded, err := decodeKey("Key", hexKey, 32, "production")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(decoded) != 32 {
			t.Errorf("expected 32 bytes, got %d", len(decoded))
		}
	})

	t.Run("Base64Decode", func(t *testing.T) {
		base64Key := base64.StdEncoding.EncodeToString(make([]byte, 32))
		decoded, err := decodeKey("Key", base64Key, 32, "production")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(decoded) != 32 {
			t.Errorf("expected 32 bytes, got %d", len(decoded))
		}
	})

	t.Run("InvalidLen_Production", func(t *testing.T) {
		_, err := decodeKey("Key", "short", 32, "production")
		if err == nil {
			t.Error("expected error to be returned in production for short key")
		}
	})

	t.Run("InvalidLen_Development", func(t *testing.T) {
		warningCalled := false
		logPrintf = func(format string, v ...interface{}) {
			warningCalled = true
		}
		_, err := decodeKey("Key", "short", 32, "development")
		if err != nil {
			t.Errorf("unexpected error in development: %v", err)
		}
		if !warningCalled {
			t.Error("expected logPrintf warning to be called in development")
		}
	})
}
