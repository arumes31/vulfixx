package web

import (
	"cve-tracker/internal/db"
	"html/template"
	"sync"

	"github.com/gorilla/sessions"
	"github.com/hibiken/asynq"
	"github.com/ulule/limiter/v3"
	"time"
)

// EmailSender defines the interface for sending emails.
type EmailSender interface {
	SendEmail(to, subject, body string) error
}

type App struct {
	Pool          db.DBPool
	AssetRepo     db.AssetRepository
	Redis         db.RedisProvider
	SessionStore  sessions.Store
	Mailer        EmailSender
	TemplateMap   map[string]*template.Template
	TemplateMu    sync.RWMutex
	Now           func() time.Time
	rateLimiter   *limiter.Limiter
	rateLimiterMu sync.Mutex
	AsynqClient   *asynq.Client
	StatsInterval time.Duration
}

func NewApp(pool db.DBPool, redis db.RedisProvider, sessionStore sessions.Store, mailer EmailSender) *App {
	return &App{
		Pool:          pool,
		AssetRepo:     db.NewAssetRepository(pool),
		Redis:         redis,
		SessionStore:  sessionStore,
		Mailer:        mailer,
		TemplateMap:   make(map[string]*template.Template),
		Now:           time.Now,
		StatsInterval: 5 * time.Minute,
	}
}
