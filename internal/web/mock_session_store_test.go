package web

import (
	"net/http"
	"github.com/gorilla/sessions"
)

type MockSessionStore struct {
	GetFunc func(r *http.Request, name string) (*sessions.Session, error)
	NewFunc func(r *http.Request, name string) (*sessions.Session, error)
	SaveFunc func(r *http.Request, w http.ResponseWriter, s *sessions.Session) error
}

func (m *MockSessionStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	if m.GetFunc != nil {
		return m.GetFunc(r, name)
	}
	return sessions.NewSession(m, name), nil
}

func (m *MockSessionStore) New(r *http.Request, name string) (*sessions.Session, error) {
	if m.NewFunc != nil {
		return m.NewFunc(r, name)
	}
	return sessions.NewSession(m, name), nil
}

func (m *MockSessionStore) Save(r *http.Request, w http.ResponseWriter, s *sessions.Session) error {
	if m.SaveFunc != nil {
		return m.SaveFunc(r, w, s)
	}
	return nil
}
