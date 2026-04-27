package mocks

import (
	"net/http"
)

// EmailSenderMock is a mock implementation of worker.EmailSender.
type EmailSenderMock struct {
	SendEmailFunc func(to, subject, body string) error
	InjectedErr   error
}

func (m *EmailSenderMock) SendEmail(to, subject, body string) error {
	if m.InjectedErr != nil {
		return m.InjectedErr
	}
	if m.SendEmailFunc != nil {
		return m.SendEmailFunc(to, subject, body)
	}
	return nil
}

// HTTPClientMock is a mock implementation of worker.HTTPClient.
type HTTPClientMock struct {
	DoFunc      func(req *http.Request) (*http.Response, error)
	InjectedErr error
}

func (m *HTTPClientMock) Do(req *http.Request) (*http.Response, error) {
	if m.InjectedErr != nil {
		return nil, m.InjectedErr
	}
	if m.DoFunc != nil {
		return m.DoFunc(req)
	}
	return nil, nil
}
