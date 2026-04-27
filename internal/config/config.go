package config

import (
	"log"
	"os"
	"strconv"
)

type Config struct {
	DBHost          string
	DBPort          string
	DBUser          string
	DBPassword      string
	DBName          string
	RedisURL        string
	SessionKey      string
	CSRFKey         string
	BaseURL         string
	SMTPHost        string
	SMTPPort        int
	SMTPUser        string
	SMTPPass        string
	AdminEmail      string
	AdminPassword   string
	AdminTOTPSecret string
	SecureCookie    bool
}

var (
	logFatalf = log.Fatalf
	logPrintf = log.Printf
)

var AppConfig Config

func LoadConfig() {
	AppConfig = Config{
		DBHost:          getEnv("DB_HOST", "db"),
		DBPort:          getEnv("DB_PORT", "5432"),
		DBUser:          getEnv("DB_USER", "cveuser"),
		DBPassword:      getEnv("DB_PASSWORD", ""),
		DBName:          getEnv("DB_NAME", "cvetracker"),
		RedisURL:        getEnv("REDIS_URL", "redis:6379"),
		SessionKey:      getEnv("SESSION_KEY", ""),
		CSRFKey:         getEnv("CSRF_KEY", ""),
		BaseURL:         getEnv("BASE_URL", "http://localhost:8080"),
		SMTPHost:        getEnv("SMTP_HOST", "smtp.example.com"),
		SMTPUser:        getEnv("SMTP_USER", "user@example.com"),
		SMTPPass:        getEnv("SMTP_PASS", ""),
		AdminEmail:      getEnv("ADMIN_EMAIL", ""),
		AdminPassword:   getEnv("ADMIN_PASSWORD", ""),
		AdminTOTPSecret: getEnv("ADMIN_TOTP_SECRET", ""),
	}

	port, err := strconv.Atoi(getEnv("SMTP_PORT", "587"))
	if err != nil {
		logPrintf("Invalid SMTP_PORT: %v. Defaulting to 587", err)
		port = 587
	}
	AppConfig.SMTPPort = port

	secureCookie, err := strconv.ParseBool(getEnv("SECURE_COOKIE", "true"))
	if err != nil {
		logPrintf("Invalid SECURE_COOKIE: %v. Defaulting to true", err)
		secureCookie = true
	}
	AppConfig.SecureCookie = secureCookie

	appEnv := getEnv("APP_ENV", "production")
	if AppConfig.DBPassword == "" || AppConfig.SessionKey == "" || AppConfig.CSRFKey == "" || AppConfig.SMTPPass == "" || AppConfig.AdminPassword == "" || AppConfig.AdminTOTPSecret == "" {
		if appEnv != "development" {
			logFatalf("Fatal: DBPassword, SessionKey, CSRFKey, SMTPPass, AdminPassword, and AdminTOTPSecret must be explicitly set in production mode")
		} else {
			logPrintf("Warning: Using empty values for sensitive keys in development mode")
		}
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
