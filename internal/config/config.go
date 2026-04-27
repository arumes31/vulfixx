package config

import (
	"os"
	"strconv"
)

type Config struct {
	DBHost            string
	DBPort            string
	DBUser            string
	DBPassword        string
	DBName            string
	RedisURL          string
	SessionKey        string
	CSRFKey           string
	BaseURL           string
	SMTPHost          string
	SMTPPort          int
	SMTPUser          string
	SMTPPass          string
	AdminEmail        string
	AdminPassword     string
	AdminTOTPSecret   string
	SecureCookie      bool
}

var AppConfig Config

func LoadConfig() {
	AppConfig = Config{
		DBHost:          getEnv("DB_HOST", "db"),
		DBPort:          getEnv("DB_PORT", "5432"),
		DBUser:          getEnv("DB_USER", "cveuser"),
		DBPassword:      getEnv("DB_PASSWORD", "cvepass"),
		DBName:          getEnv("DB_NAME", "cvetracker"),
		RedisURL:        getEnv("REDIS_URL", "redis:6379"),
		SessionKey:      getEnv("SESSION_KEY", "supersecretkey-change-me"),
		CSRFKey:         getEnv("CSRF_KEY", "0123456789abcdef0123456789abcdef"),
		BaseURL:         getEnv("BASE_URL", "http://localhost:8080"),
		SMTPHost:        getEnv("SMTP_HOST", "smtp.example.com"),
		SMTPUser:        getEnv("SMTP_USER", "user@example.com"),
		SMTPPass:        getEnv("SMTP_PASS", "password"),
		AdminEmail:      getEnv("ADMIN_EMAIL", ""),
		AdminPassword:   getEnv("ADMIN_PASSWORD", ""),
		AdminTOTPSecret: getEnv("ADMIN_TOTP_SECRET", ""),
	}

	port, _ := strconv.Atoi(getEnv("SMTP_PORT", "587"))
	AppConfig.SMTPPort = port

	AppConfig.SecureCookie, _ = strconv.ParseBool(getEnv("SECURE_COOKIE", "false"))
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
