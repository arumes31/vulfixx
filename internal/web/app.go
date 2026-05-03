package web

import (
	"cve-tracker/internal/db"
	"html/template"
	"sync"

	"github.com/gorilla/sessions"
	"time"
)

// EmailSender defines the interface for sending emails.
type EmailSender interface {
	SendEmail(to, subject, body string) error
}

type App struct {
	Pool         db.DBPool
	Redis        db.RedisProvider
	SessionStore sessions.Store
	Mailer       EmailSender
	TemplateMap  map[string]*template.Template
	TemplateMu   sync.RWMutex
	Now          func() time.Time
}

func NewApp(pool db.DBPool, redis db.RedisProvider, sessionStore sessions.Store, mailer EmailSender) *App {
	return &App{
		Pool:         pool,
		Redis:        redis,
		SessionStore: sessionStore,
		Mailer:       mailer,
		TemplateMap:  make(map[string]*template.Template),
		Now:          time.Now,
	}
}
