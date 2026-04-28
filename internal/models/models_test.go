package models

import (
	"testing"
	"time"
)

func TestModels(t *testing.T) {
	u := User{
		ID:               1,
		Email:            "test@example.com",
		PasswordHash:     "hash",
		IsEmailVerified:  true,
		EmailVerifyToken: "token",
		TOTPSecret:       "secret",
		IsTOTPEnabled:    true,
		CreatedAt:        time.Now(),
	}
	if u.ID != 1 || u.Email != "test@example.com" || u.PasswordHash != "hash" || 
	   !u.IsEmailVerified || u.EmailVerifyToken != "token" || u.TOTPSecret != "secret" || 
	   !u.IsTOTPEnabled || u.CreatedAt.IsZero() {
		t.Errorf("user model validation failed")
	}

	cve := CVE{
		ID:            1,
		CVEID:         "CVE-2023-1234",
		Description:   "test",
		CVSSScore:     9.8,
		CISAKEV:       true,
		PublishedDate: time.Now(),
		UpdatedDate:   time.Now(),
		CreatedAt:     time.Now(),
	}
	if cve.ID != 1 || cve.CVEID != "CVE-2023-1234" || cve.Description != "test" || 
	   cve.CVSSScore != 9.8 || !cve.CISAKEV || cve.PublishedDate.IsZero() || 
	   cve.UpdatedDate.IsZero() || cve.CreatedAt.IsZero() {
		t.Errorf("cve model validation failed")
	}

	sub := UserSubscription{
		ID:          1,
		UserID:      1,
		Keyword:     "test",
		MinSeverity: 5.0,
		WebhookURL:  "http://example.com",
		CreatedAt:   time.Now(),
	}
	if sub.ID != 1 || sub.UserID != 1 || sub.Keyword != "test" || 
	   sub.MinSeverity != 5.0 || sub.WebhookURL != "http://example.com" || sub.CreatedAt.IsZero() {
		t.Errorf("subscription model validation failed")
	}

	status := UserCVEStatus{
		UserID:    1,
		CVEID:     1,
		Status:    "resolved",
		UpdatedAt: time.Now(),
	}
	if status.UserID != 1 || status.CVEID != 1 || status.Status != "resolved" || status.UpdatedAt.IsZero() {
		t.Errorf("status model validation failed")
	}

	alert := AlertHistory{
		ID:     1,
		UserID: 1,
		CVEID:  1,
		SentAt: time.Now(),
	}
	if alert.ID != 1 || alert.UserID != 1 || alert.CVEID != 1 || alert.SentAt.IsZero() {
		t.Errorf("alert model validation failed")
	}
}
