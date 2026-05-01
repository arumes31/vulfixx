package models

import "time"

type User struct {
	ID               int       `json:"id"`
	Email            string    `json:"email"`
	PasswordHash     string    `json:"-"`
	IsEmailVerified  bool      `json:"is_email_verified"`
	EmailVerifyToken string    `json:"-"`
	TOTPSecret       string    `json:"-"`
	IsTOTPEnabled    bool      `json:"is_totp_enabled"`
	IsAdmin          bool      `json:"is_admin"`
	CreatedAt        time.Time `json:"created_at"`
}

type CVE struct {
	ID             int                    `json:"id"`
	CVEID          string                 `json:"cve_id"`
	Description    string                 `json:"description"`
	CVSSScore      float64                `json:"cvss_score"`
	VectorString   string                 `json:"vector_string"`
	CISAKEV        bool                   `json:"cisa_kev"`
	EPSSScore      float64                `json:"epss_score"`
	CWEID          string                 `json:"cwe_id"`
	CWEName        string                 `json:"cwe_name"`
	GitHubPoCCount int                    `json:"github_poc_count"`
	OSINTData      map[string]interface{} `json:"osint_data"`
	Status         string                 `json:"status"`
	Notes          string                 `json:"notes"`
	References     []string               `json:"references"`
	Configurations []CVEConfiguration     `json:"configurations"`
	PublishedDate  time.Time              `json:"published_date"`
	UpdatedDate    time.Time              `json:"updated_date"`
	CreatedAt      time.Time              `json:"created_at"`
}

type CVEConfiguration struct {
	Nodes []ConfigNode `json:"nodes"`
}

type ConfigNode struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate"`
	CPEMatch []CPEMatch `json:"cpeMatch"`
}

type CPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	MatchCriteriaID       string `json:"matchCriteriaId"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

type Team struct {
	ID         int       `json:"id"`
	Name       string    `json:"name"`
	InviteCode string    `json:"-"`
	CreatedAt  time.Time `json:"created_at"`
}

// TeamWithInviteCode is used only from admin/owner endpoints to expose the invite code.
type TeamWithInviteCode struct {
	Team
	InviteCode string `json:"invite_code"`
}

// NewTeamWithInviteCode constructs a TeamWithInviteCode from a Team, copying the invite code
// so callers don't have to populate it manually.
func NewTeamWithInviteCode(team Team) TeamWithInviteCode {
	return TeamWithInviteCode{Team: team, InviteCode: team.InviteCode}
}

type TeamMember struct {
	TeamID   int       `json:"team_id"`
	UserID   int       `json:"user_id"`
	Role     string    `json:"role"` // owner, admin, member
	JoinedAt time.Time `json:"joined_at"`
}

type UserSubscription struct {
	ID            int       `json:"id"`
	UserID        int       `json:"user_id"`
	TeamID        *int      `json:"team_id"`
	Keyword       string    `json:"keyword"`
	MinSeverity   float64   `json:"min_severity"`
	WebhookURL    string    `json:"webhook_url"`
	EnableEmail   bool      `json:"enable_email"`
	EnableWebhook bool      `json:"enable_webhook"`
	FilterLogic   string    `json:"filter_logic"`
	CreatedAt     time.Time `json:"created_at"`
}

type UserCVEStatus struct {
	UserID    int       `json:"user_id"`
	TeamID    *int      `json:"team_id"`
	CVEID     int       `json:"cve_id"`
	Status    string    `json:"status"`
	UpdatedAt time.Time `json:"updated_at"`
}

type AlertHistory struct {
	ID     int       `json:"id"`
	UserID int       `json:"user_id"`
	CVEID  int       `json:"cve_id"`
	SentAt time.Time `json:"sent_at"`
}

type Asset struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	TeamID    *int      `json:"team_id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"` // e.g., 'Server', 'Software', 'Network'
	CreatedAt time.Time `json:"created_at"`
}

type AssetKeyword struct {
	ID      int    `json:"id"`
	AssetID int    `json:"asset_id"`
	Keyword string `json:"keyword"`
}

type CVENote struct {
	UserID    int       `json:"user_id"`
	TeamID    *int      `json:"team_id"`
	CVEID     int       `json:"cve_id"`
	Notes     string    `json:"notes"`
	UpdatedAt time.Time `json:"updated_at"`
}

type ActivityLog struct {
	ID                 int        `json:"id"`
	UserID             int        `json:"user_id"`
	ActivityType       string     `json:"activity_type"`
	Description        string     `json:"description"`
	IPAddress          string     `json:"-"`
	UserAgent          string     `json:"-"`
	CreatedAt          time.Time  `json:"created_at"`
	RetentionExpiresAt *time.Time `json:"retention_expires_at,omitempty"`
	DeletedAt          *time.Time `json:"deleted_at,omitempty"`
}
