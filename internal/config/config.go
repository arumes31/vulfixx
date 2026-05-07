package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
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
	SMTPMailFrom    string
	AdminEmail      string
	AdminPassword   string
	AdminTOTPSecret string
	SecureCookie    bool
	AppPort         string
	SentryDSN       string
	GeminiAPIKey    string
	GeminiModel     string
	LLMProvider     string // "ollama" or "gemini"
	LLMEndpoint     string // e.g. "http://ollama:11434"
	LLMModel        string // e.g. "phi3" or "llama3"
	LLMTimeout      int    // timeout in seconds
	ArliAIAPIKey    string
	ArliAIModel     string
	ArliAIEndpoint  string
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
		AppPort:         getEnv("PORT", "8080"),
		SentryDSN:       getEnv("SENTRY_DSN", ""),
		GeminiAPIKey:    getEnv("GEMINI_API_KEY", ""),
		GeminiModel:     getEnv("GEMINI_MODEL", "gemini-1.5-flash"),
		LLMProvider:     getEnv("LLM_PROVIDER", "ollama"),
		LLMEndpoint:     getEnv("LLM_ENDPOINT", "http://ollama:11434"),
		LLMModel:        getEnv("LLM_MODEL", "phi3-vulfixx"),
		LLMTimeout:      getEnvInt("LLM_TIMEOUT", 600),
		ArliAIAPIKey:    getEnv("ARLIAI_API_KEY", ""),
		ArliAIModel:     getEnv("ARLIAI_MODEL", "Qwen2.5-72B-Instruct"),
		ArliAIEndpoint:  getEnv("ARLIAI_ENDPOINT", "https://api.arliai.com/v1"),
	}

	port, err := strconv.Atoi(getEnv("SMTP_PORT", "587"))
	if err != nil {
		logPrintf("Invalid SMTP_PORT: %v. Defaulting to 587", err)
		port = 587
	}
	AppConfig.SMTPPort = port

	AppConfig.SMTPMailFrom = getEnv("SMTP_MAILFROM", getEnv("SMTP_FROM", ""))
	if AppConfig.SMTPMailFrom == "" {
		AppConfig.SMTPMailFrom = AppConfig.SMTPUser
	}

	secureCookie, err := strconv.ParseBool(getEnv("SECURE_COOKIE", "true"))
	if err != nil {
		logPrintf("Invalid SECURE_COOKIE: %v. Defaulting to true", err)
		secureCookie = true
	}
	AppConfig.SecureCookie = secureCookie

	appEnv := getEnv("APP_ENV", "production")
	var missingFields []string
	if AppConfig.DBPassword == "" {
		missingFields = append(missingFields, "DBPassword")
	}
	if AppConfig.SessionKey == "" {
		if appEnv == "development" {
			logPrintf("Warning: SESSION_KEY is not set. Generating a random one for development.")
			AppConfig.SessionKey = generateRandomKey(32)
		} else {
			missingFields = append(missingFields, "SessionKey")
		}
	}
	if AppConfig.CSRFKey == "" {
		if appEnv == "development" {
			logPrintf("Warning: CSRF_KEY is not set. Generating a random one for development.")
			AppConfig.CSRFKey = generateRandomKey(32)
		} else {
			missingFields = append(missingFields, "CSRFKey")
		}
	}
	if AppConfig.SMTPPass == "" {
		missingFields = append(missingFields, "SMTPPass")
	}
	if AppConfig.AdminEmail == "" {
		missingFields = append(missingFields, "AdminEmail")
	}
	if AppConfig.AdminPassword == "" {
		missingFields = append(missingFields, "AdminPassword")
	}
	if AppConfig.AdminTOTPSecret == "" {
		missingFields = append(missingFields, "AdminTOTPSecret")
	}
	if len(missingFields) > 0 {
		if appEnv != "development" {
			logFatalf("Fatal: the following required fields are not set in production mode: %s", strings.Join(missingFields, ", "))
		} else {
			logPrintf("Warning: the following sensitive fields are empty in development mode: %s", strings.Join(missingFields, ", "))
		}
	}

	// Validate and decode keys
	AppConfig.CSRFKey = decodeKey("CSRFKey", AppConfig.CSRFKey, 32, appEnv)
	AppConfig.SessionKey = decodeKey("SessionKey", AppConfig.SessionKey, 32, appEnv)
}

func decodeKey(name, val string, expectedLen int, appEnv string) string {
	if val == "" {
		return ""
	}

	var decoded []byte
	var err error

	// Try hex first only if length matches
	if len(val) == expectedLen*2 {
		decoded, err = hex.DecodeString(val)
		if err == nil && len(decoded) == expectedLen {
			return string(decoded)
		}
	}

	// Try base64
	decoded, err = base64.StdEncoding.DecodeString(val)
	if err == nil && len(decoded) == expectedLen {
		return string(decoded)
	}

	// Fallback to raw bytes
	decoded = []byte(val)

	if len(decoded) != expectedLen {
		msg := fmt.Sprintf("%s must be exactly %d bytes (got %d)", name, expectedLen, len(decoded))
		if appEnv != "development" {
			logFatalf("Fatal: %s", msg)
		} else {
			logPrintf("Warning: %s", msg)
			return ""
		}
	}
	return string(decoded)
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	valStr := getEnv(key, "")
	if valStr == "" {
		return fallback
	}
	val, err := strconv.Atoi(valStr)
	if err != nil {
		logPrintf("Invalid %s: %v. Defaulting to %d", key, err, fallback)
		return fallback
	}
	return val
}

func generateRandomKey(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		logFatalf("Fatal: failed to generate random key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}
