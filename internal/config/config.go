package config

import (
	"crypto/rand"
	"cve-tracker/internal/security"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

func decryptIfEncrypted(val string) string {
	if strings.HasPrefix(val, "cve-gcm:") {
		encryptedBase64 := strings.TrimPrefix(val, "cve-gcm:")
		decrypted, err := security.Decrypt(encryptedBase64)
		if err != nil {
			logPrintf("Warning: failed to decrypt configuration field: %v", err)
			return ""
		}
		return decrypted
	}
	return val
}

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
	SMTPMailFrom      string
	AdminEmail        string
	AdminPassword     string
	AdminTOTPSecret   string
	SecureCookie      bool
	AppPort           string
	SentryDSN         string
	GeminiAPIKey      string
	Gemini31LiteModel string
	GeminiAPIVersion  string
	Gemini35Model     string // higher-quality, low-quota Gemini failover (e.g. gemini-3.5-flash)
	Gemini3Model      string // Gemini 3 Flash failover (e.g. gemini-3-flash-preview)
	LLMProvider       string // default priority chain, fallback matches .env.example ("gemini31flashlite,mistral")
	LLMEndpoint       string // e.g. "http://ollama:11434"
	LLMModel          string // e.g. "phi3" or "llama3"
	LLMTimeout        int    // timeout in seconds
	MistralAPIKey     string
	MistralModel      string
	MistralEndpoint   string
	OpenAIAPIKey      string
	OpenAIModel       string
	OpenAIEndpoint    string
	GRPCPort          string
	GRPCCertFile      string
	GRPCKeyFile       string
	WebhookSecret     string
}

var (
	logPrintf = log.Printf
)

var AppConfig Config

func LoadConfig() error {
	AppConfig = Config{
		DBHost:            getEnv("DB_HOST", "db"),
		DBPort:            getEnv("DB_PORT", "5432"),
		DBUser:            getEnv("DB_USER", "cveuser"),
		DBPassword:        decryptIfEncrypted(getEnv("DB_PASSWORD", "")),
		DBName:            getEnv("DB_NAME", "cvetracker"),
		RedisURL:          getEnv("REDIS_URL", "redis:6379"),
		SessionKey:        getEnv("SESSION_KEY", ""),
		CSRFKey:           getEnv("CSRF_KEY", ""),
		BaseURL:           getEnv("BASE_URL", "http://localhost:8080"),
		SMTPHost:          getEnv("SMTP_HOST", "smtp.example.com"),
		SMTPUser:          getEnv("SMTP_USER", "user@example.com"),
		SMTPPass:          decryptIfEncrypted(getEnv("SMTP_PASS", "")),
		AdminEmail:        getEnv("ADMIN_EMAIL", ""),
		AdminPassword:     decryptIfEncrypted(getEnv("ADMIN_PASSWORD", "")),
		AdminTOTPSecret:   decryptIfEncrypted(getEnv("ADMIN_TOTP_SECRET", "")),
		AppPort:           getEnv("PORT", "8080"),
		SentryDSN:         decryptIfEncrypted(getEnv("SENTRY_DSN", "")),
		GeminiAPIKey:      decryptIfEncrypted(getEnv("GEMINI_API_KEY", "")),
		Gemini31LiteModel: getEnv("GEMINI31FLASHLITE_MODEL", getEnv("GEMINI31LITE_MODEL", getEnv("GEMINI_MODEL", "gemini-3.1-flash-lite"))),
		// v1beta is required: the structured-output fields the extractor relies on
		// (responseMimeType / responseSchema) are rejected by the stable v1 API.
		GeminiAPIVersion: getEnv("GEMINI_API_VERSION", "v1beta"),
		Gemini35Model:    getEnv("GEMINI35FLASH_MODEL", getEnv("GEMINI35_MODEL", "gemini-3.5-flash")),
		Gemini3Model:     getEnv("GEMINI3FLASH_MODEL", getEnv("GEMINI3_MODEL", "gemini-3-flash-preview")),
		LLMProvider:      getEnv("LLM_PROVIDER", "gemini31flashlite,mistral"),
		LLMEndpoint:      getEnv("LLM_ENDPOINT", "http://ollama:11434"),
		LLMModel:         getEnv("LLM_MODEL", "phi3-vulfixx"),
		LLMTimeout:       getEnvInt("LLM_TIMEOUT", 600),
		MistralAPIKey:    decryptIfEncrypted(getEnv("MISTRAL_API_KEY", "")),
		MistralModel:     getEnv("MISTRAL_MODEL", "mistral-small-latest"),
		MistralEndpoint:  getEnv("MISTRAL_ENDPOINT", "https://api.mistral.ai/v1"),
		OpenAIAPIKey:     decryptIfEncrypted(getEnv("OPENAI_API_KEY", "")),
		OpenAIModel:      getEnv("OPENAI_MODEL", "kilo-auto/free"),
		OpenAIEndpoint:   getEnv("OPENAI_ENDPOINT", "http://100.115.58.99:18080/workspace/sys-kilo/v1"),
		GRPCPort:         getEnv("GRPC_PORT", "9091"),
		GRPCCertFile:     getEnv("GRPC_CERT_FILE", ""),
		GRPCKeyFile:      getEnv("GRPC_KEY_FILE", ""),
		WebhookSecret:    getEnv("WEBHOOK_SECRET", ""),
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
			k, err := generateRandomKey(32)
			if err != nil {
				return err
			}
			AppConfig.SessionKey = k
		} else {
			missingFields = append(missingFields, "SessionKey")
		}
	}
	if AppConfig.CSRFKey == "" {
		if appEnv == "development" {
			logPrintf("Warning: CSRF_KEY is not set. Generating a random one for development.")
			k, err := generateRandomKey(32)
			if err != nil {
				return err
			}
			AppConfig.CSRFKey = k
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
	if AppConfig.WebhookSecret == "" {
		if appEnv == "development" || appEnv == "local" || appEnv == "test" {
			logPrintf("Warning: WEBHOOK_SECRET is not set. Generating a random one for development.")
			k, err := generateRandomKey(32)
			if err != nil {
				return err
			}
			AppConfig.WebhookSecret = k
		} else {
			missingFields = append(missingFields, "WebhookSecret")
		}
	}
	if len(missingFields) > 0 {
		if appEnv != "development" {
			return fmt.Errorf("the following required fields are not set in production mode: %s", strings.Join(missingFields, ", "))
		} else {
			logPrintf("Warning: the following sensitive fields are empty in development mode: %s", strings.Join(missingFields, ", "))
		}
	}

	// Validate and decode keys
	csrfKey, err := decodeKey("CSRFKey", AppConfig.CSRFKey, appEnv)
	if err != nil {
		return err
	}
	AppConfig.CSRFKey = csrfKey

	sessionKey, err := decodeKey("SessionKey", AppConfig.SessionKey, appEnv)
	if err != nil {
		return err
	}
	AppConfig.SessionKey = sessionKey

	return nil
}

func decodeKey(name, val string, appEnv string) (string, error) {
	if val == "" {
		return "", nil
	}

	var decoded []byte
	var err error

	// Try hex first only if length matches
	if len(val) == 32*2 {
		decoded, err = hex.DecodeString(val)
		if err == nil && len(decoded) == 32 {
			return string(decoded), nil
		}
	}

	// Try base64
	decoded, err = base64.StdEncoding.DecodeString(val)
	if err == nil && len(decoded) == 32 {
		return string(decoded), nil
	}

	// Fallback to raw bytes
	decoded = []byte(val)

	if len(decoded) != 32 {
		msg := fmt.Sprintf("%s must be exactly %d bytes (got %d)", name, 32, len(decoded))
		if appEnv != "development" {
			return "", fmt.Errorf("%s", msg)
		} else {
			logPrintf("Warning: %s", msg)
			return "", nil
		}
	}
	return string(decoded), nil
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

func generateRandomKey(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
