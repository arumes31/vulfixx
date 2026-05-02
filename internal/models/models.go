package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

type User struct {
	ID                  int       `json:"id"`
	Email               string    `json:"email"`
	PasswordHash        string    `json:"-"`
	IsEmailVerified     bool      `json:"is_email_verified"`
	EmailVerifyToken    string    `json:"-"`
	TOTPSecret          string    `json:"-"`
	IsTOTPEnabled       bool      `json:"is_totp_enabled"`
	IsAdmin             bool      `json:"is_admin"`
	OnboardingCompleted bool      `json:"onboarding_completed"`
	CreatedAt           time.Time `json:"created_at"`
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
	GreyNoiseHits  int                    `json:"greynoise_hits"`
	GreyNoiseClass string                 `json:"greynoise_classification"`
	OSVData        JSONBMap               `json:"osv_data"`
	OSINTData      JSONBMap               `json:"osint_data"`
	Status         string                 `json:"status"`
	Notes          string                 `json:"notes"`
	References     []string               `json:"references"`
	Configurations CVEConfigurations      `json:"configurations"`
	Vendor         string                 `json:"vendor"`
	Product        string                 `json:"product"`
	AffectedProducts AffectedProducts     `json:"affected_products"`
	PublishedDate  time.Time              `json:"published_date"`
	UpdatedDate    time.Time              `json:"updated_date"`
	CreatedAt      time.Time              `json:"created_at"`
}

type CVEConfigurations []CVEConfiguration

type AffectedProduct struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	Type    string `json:"type"` // a, o, h
}

type AffectedProducts []AffectedProduct

// Scan implements the sql.Scanner interface for JSONB.
func (a *AffectedProducts) Scan(value interface{}) error {
	if value == nil {
		*a = nil
		return nil
	}
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("type assertion to []byte failed")
	}
	return json.Unmarshal(b, a)
}

// Value implements the driver.Valuer interface for JSONB.
func (a AffectedProducts) Value() (driver.Value, error) {
	if a == nil {
		return nil, nil
	}
	return json.Marshal(a)
}

// Scan implements the sql.Scanner interface.
func (c *CVEConfigurations) Scan(value interface{}) error {
	if value == nil {
		*c = nil
		return nil
	}
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("type assertion to []byte failed")
	}
	return json.Unmarshal(b, &c)
}

// Value implements the driver.Valuer interface.
func (c CVEConfigurations) Value() (driver.Value, error) {
	if c == nil {
		return nil, nil
	}
	return json.Marshal(c)
}

type JSONBMap map[string]interface{}

// Scan implements the sql.Scanner interface for JSONB.
func (m *JSONBMap) Scan(value interface{}) error {
	if value == nil {
		*m = nil
		return nil
	}
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("type assertion to []byte failed")
	}
	return json.Unmarshal(b, m)
}

// Value implements the driver.Valuer interface for JSONB.
func (m JSONBMap) Value() (driver.Value, error) {
	if m == nil {
		return nil, nil
	}
	return json.Marshal(m)
}

func (c *CVE) GetDetectedProduct() (vendor, product string) {
	products := c.GetAffectedProducts()
	if len(products) > 0 {
		return products[0].Vendor, products[0].Product
	}

	// Fallback to regex pattern on description
	re := regexp.MustCompile(`(?i)(?:detected in|affects|found in|vulnerability in) (?:the )?([a-zA-Z0-9_\-\.]{2,}) ([a-zA-Z0-9_\-\.]{2,})`)
	matches := re.FindStringSubmatch(c.Description)
	if len(matches) >= 3 {
		v := matches[1]
		p := matches[2]
		// Avoid noise words
		noise := map[string]bool{"the": true, "this": true, "that": true, "and": true, "with": true, "from": true}
		if !noise[strings.ToLower(v)] && !noise[strings.ToLower(p)] {
			return v, p
		}
	}
	return "", ""
}

func (c *CVE) GetCPEs() []string {
	var cpes []string
	seen := make(map[string]bool)
	for _, config := range c.Configurations {
		for _, node := range config.Nodes {
			for _, match := range node.CPEMatch {
				if match.Criteria != "" && !seen[match.Criteria] {
					seen[match.Criteria] = true
					cpes = append(cpes, match.Criteria)
				}
			}
		}
	}
	return cpes
}

func (c *CVE) GetAffectedProducts() []AffectedProduct {
	var products []AffectedProduct
	seen := make(map[string]bool)
	for _, config := range c.Configurations {
		for _, node := range config.Nodes {
			for _, match := range node.CPEMatch {
				if match.Criteria != "" {
					v, p, _, t := ParseCPE(match.Criteria)
					if v != "" && p != "" {
						key := fmt.Sprintf("%s:%s:%s", v, p, t)
						if !seen[key] {
							seen[key] = true
							products = append(products, AffectedProduct{
								Vendor:  v,
								Product: p,
								Type:    t,
							})
						}
					}
				}
			}
		}
	}
	return products
}

func ParseCPE(cpe string) (vendor, product, version, part string) {
	if !strings.HasPrefix(cpe, "cpe:2.3:") {
		return "", "", "", ""
	}
	parts := strings.Split(cpe, ":")
	if len(parts) >= 6 {
		// cpe:2.3:part:vendor:product:version:...
		t := parts[2]
		v := parts[3]
		p := parts[4]
		ver := parts[5]
		if ver == "*" || ver == "-" {
			ver = ""
		}
		return NormalizeName(v), NormalizeName(p), ver, t
	}
	if len(parts) >= 5 {
		t := parts[2]
		v := parts[3]
		p := parts[4]
		return NormalizeName(v), NormalizeName(p), "", t
	}
	return "", "", "", ""
}

var nameAliases = map[string]string{
	"microsoft":                  "Microsoft",
	"microsoft_corp":             "Microsoft",
	"oracle_corp":                "Oracle",
	"linux_kernel":               "Linux Kernel",
	"apple_inc":                  "Apple",
	"google_inc":                 "Google",
	"apache_software_foundation": "Apache",
	"redhat":                     "Red Hat",
	"debian_linux":               "Debian",
	"canonical":                  "Ubuntu",
}

func NormalizeName(name string) string {
	low := strings.ToLower(name)
	if alias, ok := nameAliases[low]; ok {
		return alias
	}
	return capitalize(strings.ReplaceAll(name, "_", " "))
}

func capitalize(s string) string {
	if s == "" {
		return ""
	}
	words := strings.Fields(s)
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[0:1]) + strings.ToLower(w[1:])
		}
	}
	return strings.Join(words, " ")
}

func (c *CVE) GetLineage() []string {
	re := regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)
	unique := make(map[string]bool)
	var lineage []string

	process := func(text string) {
		matches := re.FindAllString(text, -1)
		for _, m := range matches {
			m = strings.ToUpper(m)
			if m != strings.ToUpper(c.CVEID) && !unique[m] {
				unique[m] = true
				lineage = append(lineage, m)
			}
		}
	}

	process(c.Description)
	for _, ref := range c.References {
		process(ref)
	}

	// Check OSINT data if available
	if c.OSINTData != nil {
		if related, ok := c.OSINTData["related_cves"].([]interface{}); ok {
			for _, r := range related {
				if s, ok := r.(string); ok {
					process(s)
				}
			}
		}
	}

	return lineage
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

type TeamWithInviteCode struct {
	Team
	InviteCode string `json:"invite_code"`
}

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
