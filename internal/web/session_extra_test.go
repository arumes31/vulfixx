package web

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/sessions"
)

// mockSessionStore is a flexible mock for sessions.Store
type mockSessionStore struct {
	sessions.Store
	GetFunc  func(r *http.Request, name string) (*sessions.Session, error)
	SaveFunc func(r *http.Request, w http.ResponseWriter, s *sessions.Session) error
}

func (m *mockSessionStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	if m.GetFunc != nil {
		return m.GetFunc(r, name)
	}
	return sessions.NewSession(m, name), nil
}

func (m *mockSessionStore) Save(r *http.Request, w http.ResponseWriter, s *sessions.Session) error {
	if m.SaveFunc != nil {
		return m.SaveFunc(r, w, s)
	}
	return nil
}

func TestGetActiveUserID_Comprehensive(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockStore := &mockSessionStore{
			GetFunc: func(r *http.Request, name string) (*sessions.Session, error) {
				s := sessions.NewSession(nil, name)
				s.Values["user_id"] = 42
				return s, nil
			},
		}
		app := &App{SessionStore: mockStore}
		req := httptest.NewRequest("GET", "/", nil)

		id, ok := app.GetActiveUserID(req)
		if !ok || id != 42 {
			t.Errorf("expected (42, true), got (%d, %v)", id, ok)
		}
	})

	t.Run("NilStore", func(t *testing.T) {
		app := &App{SessionStore: nil}
		req := httptest.NewRequest("GET", "/", nil)

		id, ok := app.GetActiveUserID(req)
		if ok || id != 0 {
			t.Errorf("expected (0, false), got (%d, %v)", id, ok)
		}
	})

	t.Run("StoreGetError", func(t *testing.T) {
		mockStore := &mockSessionStore{
			GetFunc: func(r *http.Request, name string) (*sessions.Session, error) {
				return nil, errors.New("db error")
			},
		}
		app := &App{SessionStore: mockStore}
		req := httptest.NewRequest("GET", "/", nil)

		id, ok := app.GetActiveUserID(req)
		if ok || id != 0 {
			t.Errorf("expected (0, false), got (%d, %v)", id, ok)
		}
	})

	t.Run("MissingValue", func(t *testing.T) {
		mockStore := &mockSessionStore{
			GetFunc: func(r *http.Request, name string) (*sessions.Session, error) {
				return sessions.NewSession(nil, name), nil
			},
		}
		app := &App{SessionStore: mockStore}
		req := httptest.NewRequest("GET", "/", nil)

		id, ok := app.GetActiveUserID(req)
		if ok || id != 0 {
			t.Errorf("expected (0, false), got (%d, %v)", id, ok)
		}
	})

	t.Run("InvalidValueType", func(t *testing.T) {
		mockStore := &mockSessionStore{
			GetFunc: func(r *http.Request, name string) (*sessions.Session, error) {
				s := sessions.NewSession(nil, name)
				s.Values["user_id"] = "not-an-int"
				return s, nil
			},
		}
		app := &App{SessionStore: mockStore}
		req := httptest.NewRequest("GET", "/", nil)

		id, ok := app.GetActiveUserID(req)
		if ok || id != 0 {
			t.Errorf("expected (0, false), got (%d, %v)", id, ok)
		}
	})
}

func TestGetActiveTeamID_Extra(t *testing.T) {
	t.Run("NilStore", func(t *testing.T) {
		app := &App{SessionStore: nil}
		req := httptest.NewRequest("GET", "/", nil)
		id, ok := app.GetActiveTeamID(req)
		if ok || id != 0 {
			t.Errorf("expected (0, false), got (%d, %v)", id, ok)
		}
	})
}

func TestSetActiveTeamID_Extra(t *testing.T) {
	t.Run("NilStore", func(t *testing.T) {
		app := &App{SessionStore: nil}
		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		err := app.SetActiveTeamID(rr, req, 1)
		if err == nil {
			t.Error("expected error for nil store")
		}
	})

	t.Run("SaveError", func(t *testing.T) {
		mockStore := &mockSessionStore{
			SaveFunc: func(r *http.Request, w http.ResponseWriter, s *sessions.Session) error {
				return errors.New("save failed")
			},
		}
		app := &App{SessionStore: mockStore}
		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		err := app.SetActiveTeamID(rr, req, 1)
		if err == nil {
			t.Error("expected error when Save fails")
		}
	})
}

func TestIsAdmin_Extra(t *testing.T) {
	t.Run("NilStore", func(t *testing.T) {
		app := &App{SessionStore: nil}
		req := httptest.NewRequest("GET", "/", nil)
		if app.IsAdmin(req) {
			t.Error("expected false for nil store")
		}
	})
}
