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
	if u.Email != "test@example.com" {
		t.Errorf("expected test@example.com, got %s", u.Email)
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
	if cve.CVEID != "CVE-2023-1234" {
		t.Errorf("expected CVE-2023-1234, got %s", cve.CVEID)
	}

	sub := UserSubscription{
		ID:          1,
		UserID:      1,
		Keyword:     "test",
		MinSeverity: 5.0,
		WebhookURL:  "http://example.com",
		CreatedAt:   time.Now(),
	}
	if sub.Keyword != "test" {
		t.Errorf("expected test, got %s", sub.Keyword)
	}

	status := UserCVEStatus{
		UserID:    1,
		CVEID:     1,
		Status:    "resolved",
		UpdatedAt: time.Now(),
	}
	if status.Status != "resolved" {
		t.Errorf("expected resolved, got %s", status.Status)
	}

	alert := AlertHistory{
		ID:     1,
		UserID: 1,
		CVEID:  1,
		SentAt: time.Now(),
	}
	if alert.ID != 1 {
		t.Errorf("expected 1, got %d", alert.ID)
	}
}
