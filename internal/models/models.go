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
	VectorString  string
	CISAKEV       bool
	EPSSScore     float64
	CWEID         string
	CWEName       string
	GitHubPoCCount int
	OSINTData     map[string]interface{}
	Status        string
	Notes         string
	References    []string
	PublishedDate time.Time
	UpdatedDate   time.Time
	CreatedAt     time.Time
}

type Team struct {
	ID         int
	Name       string
	InviteCode string
	CreatedAt  time.Time
}

type TeamMember struct {
	TeamID   int
	UserID   int
	Role     string // owner, admin, member
	JoinedAt time.Time
}

type UserSubscription struct {
	ID            int
	UserID        int
	TeamID        *int
	Keyword       string
	MinSeverity   float64
	WebhookURL    string
	EnableEmail   bool
	EnableWebhook bool
	FilterLogic   string
	CreatedAt     time.Time
}

type UserCVEStatus struct {
	UserID    int
	TeamID    *int
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

type Asset struct {
	ID        int
	UserID    int
	TeamID    *int
	Name      string
	Type      string // e.g., 'Server', 'Software', 'Network'
	CreatedAt time.Time
}

type AssetKeyword struct {
	ID      int
	AssetID int
	Keyword string
}

type CVENote struct {
	UserID    int
	TeamID    *int
	CVEID     int
	Notes     string
	UpdatedAt time.Time
}
