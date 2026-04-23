package models

import "time"

type User struct {
	ID               int
	Email            string
	PasswordHash     string
	IsEmailVerified  bool
	EmailVerifyToken string
	TOTPSecret       string
	IsTOTPEnabled    bool
	IsAdmin          bool
	CreatedAt        time.Time
}

type CVE struct {
	ID            int
	CVEID         string
	Description   string
	CVSSScore     float64
	CISAKEV       bool
	Status        string
	PublishedDate time.Time
	UpdatedDate   time.Time
	CreatedAt     time.Time
}

type UserSubscription struct {
	ID          int
	UserID      int
	Keyword     string
	MinSeverity float64
	WebhookURL  string
	CreatedAt   time.Time
}

type UserCVEStatus struct {
	UserID    int
	CVEID     int
	Status    string
	UpdatedAt time.Time
}

type AlertHistory struct {
	ID     int
	UserID int
	CVEID  int
	SentAt time.Time
}
