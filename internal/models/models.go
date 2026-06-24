package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	VendorFortiGuard = "fortiguard"
	VendorCisco      = "cisco"
	VendorRedHat     = "redhat"
)

// JSONBMap represents a JSONB data type in PostgreSQL
// that is mapped to a Go map[string]interface{}.
type JSONBMap map[string]interface{}

// Scan implements the sql.Scanner interface for JSONB.
func (j *JSONBMap) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("type assertion to []byte failed")
	}
	return json.Unmarshal(b, j)
}

// Value implements the driver.Valuer interface for JSONB.
func (j JSONBMap) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

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

type CPEMatch struct {
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
	VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
	VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
	Vulnerable            bool   `json:"vulnerable"`
}

type ConfigNode struct {
	Operator string     `json:"operator,omitempty"`
	CPEMatch []CPEMatch `json:"cpeMatch,omitempty"`
}

type CVEConfiguration struct {
	Vulnerable            bool         `json:"vulnerable"`
	Criteria              string       `json:"criteria"`
	VersionStartIncluding string       `json:"versionStartIncluding,omitempty"`
	VersionStartExcluding string       `json:"versionStartExcluding,omitempty"`
	VersionEndIncluding   string       `json:"versionEndIncluding,omitempty"`
	VersionEndExcluding   string       `json:"versionEndExcluding,omitempty"`
	MatchCriteriaID       string       `json:"matchCriteriaId,omitempty"`
	Nodes                 []ConfigNode `json:"nodes,omitempty"`
}

type CVE struct {
	ID                   int               `json:"id"`
	CVEID                string            `json:"cve_id"`
	Description          string            `json:"description"`
	CVSSScore            float64           `json:"cvss_score"`
	VectorString         string            `json:"vector_string"`
	CISAKEV              bool              `json:"cisa_kev"`
	CISARansomware       bool              `json:"cisa_ransomware"`
	CISAKEVData          JSONBMap          `json:"cisa_kev_data" db:"cisa_kev_data"`
	EPSSScore            float64           `json:"epss_score"`
	EPSSPercentile       float64           `json:"epss_percentile" db:"epss_percentile"`
	CWEID                string            `json:"cwe_id"`
	CWEName              string            `json:"cwe_name"`
	GitHubPoCCount       int               `json:"github_poc_count"`
	GitHubPoCRepos       GitHubPoCRepos    `json:"github_poc_repos" db:"github_poc_repos"`
	GreyNoiseHits        int               `json:"greynoise_hits"`
	GreyNoiseClass       string            `json:"greynoise_classification"`
	OSVData              JSONBMap          `json:"osv_data"`
	OSINTData            JSONBMap          `json:"osint_data" db:"osint_data"`
	OSVLastUpdated       *time.Time        `json:"osv_last_updated,omitempty"`
	GreyNoiseLastUpdated *time.Time        `json:"greynoise_last_updated,omitempty"`
	InTheWildData        JSONBMap          `json:"inthewild_data" db:"inthewild_data"`
	InTheWildLastUpdated *time.Time        `json:"inthewild_last_updated,omitempty" db:"inthewild_last_updated"`
	VendorAdvisories     JSONBMap          `json:"vendor_advisories" db:"vendor_advisories"`
	ExploitAvailable     bool              `json:"exploit_available" db:"exploit_available"`
	Status               string            `json:"status"`
	Notes                string            `json:"notes"`
	References           []string          `json:"references"`
	ReferenceTags        []string          `json:"reference_tags" db:"reference_tags"` // parallel to References
	Configurations       CVEConfigurations `json:"configurations"`
	Vendor               string            `json:"vendor"`
	Product              string            `json:"product"`
	AffectedProducts     AffectedProducts  `json:"affected_products"`

	PublishedDate time.Time `json:"published_date"`
	UpdatedDate   time.Time `json:"updated_date"`
	CreatedAt     time.Time `json:"created_at"`
	Priority      string    `json:"priority"`
}

// GetVendorAdvisory returns the advisory data for a specific vendor from VendorAdvisories.
// Returns nil if no advisory exists for the given vendor.
func (c *CVE) GetVendorAdvisory(vendor string) map[string]interface{} {
	if c.VendorAdvisories == nil {
		return nil
	}
	data, ok := c.VendorAdvisories[vendor]
	if !ok {
		return nil
	}
	result, ok := data.(map[string]interface{})
	if !ok {
		return nil
	}
	return result
}

// SetVendorAdvisory sets the advisory data for a specific vendor in VendorAdvisories.
func (c *CVE) SetVendorAdvisory(vendor string, advisory map[string]interface{}) {
	if c.VendorAdvisories == nil {
		c.VendorAdvisories = make(JSONBMap)
	}
	c.VendorAdvisories[vendor] = advisory
}

// HasVendorAdvisory checks if any vendor advisory data exists.
func (c *CVE) HasVendorAdvisory() bool {
	return len(c.VendorAdvisories) > 0
}

type CVEConfigurations []CVEConfiguration

// GitHubPoCRepo represents a GitHub proof-of-concept repository.
type GitHubPoCRepo struct {
	URL         string `json:"url"`
	Name        string `json:"name"`
	Stars       int    `json:"stars"`
	Description string `json:"description"`
	UpdatedAt   string `json:"updated_at"`
}

// GitHubPoCRepos is a slice of GitHubPoCRepo with JSONB scan/value support.
type GitHubPoCRepos []GitHubPoCRepo

// Scan implements the sql.Scanner interface for JSONB.
func (g *GitHubPoCRepos) Scan(value interface{}) error {
	if value == nil {
		*g = nil
		return nil
	}
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("type assertion to []byte failed")
	}
	return json.Unmarshal(b, g)
}

// Value implements the driver.Valuer interface for JSONB.
func (g GitHubPoCRepos) Value() (driver.Value, error) {
	if g == nil {
		return nil, nil
	}
	return json.Marshal(g)
}

type AffectedProduct struct {
	Vendor      string `json:"vendor"`
	Product     string `json:"product"`
	Version     string `json:"version"`
	Type        string `json:"type"` // a, o, h
	Unconfirmed bool   `json:"unconfirmed"`
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

// AssetWithKeywords represents an asset with its associated keywords and team info.
type AssetWithKeywords struct {
	ID        int      `json:"id"`
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	Priority  string   `json:"priority"`
	CreatedAt string   `json:"created_at"`
	Keywords  []string `json:"keywords"`
	TeamName  string   `json:"team_name"`
}

// UserSubscription represents a user's CVE alert subscription.
type UserSubscription struct {
	ID                int       `json:"id"`
	UserID            int       `json:"user_id"`
	Keyword           string    `json:"keyword"`
	MinSeverity       float64   `json:"min_severity"`
	WebhookURL        string    `json:"webhook_url"`
	SlackWebhookURL   string    `json:"slack_webhook_url,omitempty"`
	TeamsWebhookURL   string    `json:"teams_webhook_url,omitempty"`
	EnableEmail       bool      `json:"enable_email"`
	EnableWebhook     bool      `json:"enable_webhook"`
	EnableSlack       bool      `json:"enable_slack"`
	EnableTeams       bool      `json:"enable_teams"`
	EnableBrowserPush bool      `json:"enable_browser_push"`
	AggregationMode   string    `json:"aggregation_mode"`
	FilterLogic       string    `json:"filter_logic"`
	TeamID            *int      `json:"team_id,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
}

// UserCVEStatus represents a user's status tracking for a CVE.
type UserCVEStatus struct {
	UserID    int       `json:"user_id"`
	CVEID     int       `json:"cve_id"`
	Status    string    `json:"status"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AlertHistory represents a record of an alert sent to a user.
type AlertHistory struct {
	ID     int       `json:"id"`
	UserID int       `json:"user_id"`
	CVEID  int       `json:"cve_id"`
	SentAt time.Time `json:"sent_at"`
}

// GetDetectedProduct attempts to determine the vendor and product from the CVE description
// or from CPE configuration data.
func (c *CVE) GetDetectedProduct() (vendor, product string) {
	// First try CPE configurations: prefer matches flagged vulnerable, but fall
	// back to the first criteria if none are flagged.
	if len(c.Configurations) > 0 {
		firstCriteria := ""
		for _, config := range c.Configurations {
			for _, node := range config.Nodes {
				for _, match := range node.CPEMatch {
					if match.Criteria == "" {
						continue
					}
					if match.Vulnerable {
						return parseCPEVendorProduct(match.Criteria)
					}
					if firstCriteria == "" {
						firstCriteria = match.Criteria
					}
				}
			}
		}
		if firstCriteria != "" {
			return parseCPEVendorProduct(firstCriteria)
		}
	}

	// Fallback to description-based heuristic
	return detectProductFromDescription(c.Description)
}

// GetAffectedProducts returns a list of affected products derived from CPE configuration data.
// Falls back to heuristic detection from vendor/product fields if no structured data exists.
func (c *CVE) GetAffectedProducts() []AffectedProduct {
	var products []AffectedProduct

	// Try CPE configurations first
	if len(c.Configurations) > 0 {
		for _, config := range c.Configurations {
			for _, node := range config.Nodes {
				for _, match := range node.CPEMatch {
					if match.Criteria == "" {
						continue
					}
					vendor, product, exactVersion, _ := ParseCPE(match.Criteria)
					version := formatVersionRange(match)
					// Fall back to the exact version embedded in the CPE string
					// (e.g. cpe:2.3:o:next:next:1.0:*) when no range is specified,
					// otherwise the card wrongly shows "All Versions Affected".
					if version == "" {
						version = exactVersion
					}
					products = append(products, AffectedProduct{
						Vendor:  vendor,
						Product: product,
						Version: version,
					})
				}
			}
		}
	}

	// Fallback to heuristic from vendor/product fields
	if len(products) == 0 && (c.Vendor != "" || c.Product != "") {
		products = append(products, AffectedProduct{
			Vendor:      c.Vendor,
			Product:     c.Product,
			Unconfirmed: true,
		})
	}

	return products
}

// parseCPEVendorProduct extracts vendor and product from a CPE 2.3 URI string,
// normalized the same way as ParseCPE.
func parseCPEVendorProduct(cpe string) (string, string) {
	vendor, product, _, _ := ParseCPE(cpe)
	return vendor, product
}

// formatVersionRange builds a human-readable version range string from CPE match data.
func formatVersionRange(match CPEMatch) string {
	var parts []string
	if match.VersionStartIncluding != "" {
		parts = append(parts, "≥"+match.VersionStartIncluding)
	}
	if match.VersionStartExcluding != "" {
		parts = append(parts, ">"+match.VersionStartExcluding)
	}
	if match.VersionEndIncluding != "" {
		parts = append(parts, "≤"+match.VersionEndIncluding)
	}
	if match.VersionEndExcluding != "" {
		parts = append(parts, "<"+match.VersionEndExcluding)
	}
	return strings.Join(parts, " ")
}

// knownVendorProducts is an ordered list (deterministic iteration) of vendors
// and their product keywords used for description-based detection.
var knownVendorProducts = []struct {
	vendor   string
	products []string
}{
	{"Fortinet", []string{"FortiGate", "FortiManager", "FortiAnalyzer", "FortiOS", "FortiProxy", "FortiMail", "FortiWeb", "FortiEDR", "FortiSIEM", "FortiSandbox"}},
	{"Cisco", []string{"IOS", "IOS XE", "IOS XR", "ASA", "NX-OS", "ACI", "Duo", "Umbrella", "Webex", "AnyConnect"}},
	{"Microsoft", []string{"Windows", "Office", "Exchange", "SharePoint", "Azure", "IIS", "SQL Server", ".NET", "Edge"}},
	{"Apache", []string{"Tomcat", "HTTP Server", "Kafka", "Struts", "Log4j", "Spark", "Hadoop", "Flink"}},
	{"VMware", []string{"vCenter Server", "vCenter", "ESXi", "Workstation", "Fusion", "NSX", "Horizon"}},
	{"Linux", []string{"Kernel"}},
	{"Red Hat", []string{"Enterprise Linux", "OpenShift", "JBoss"}},
	{"Oracle", []string{"Java", "MySQL", "VirtualBox", "WebLogic", "Database"}},
	{"Google", []string{"Chrome", "Android"}},
	{"Apple", []string{"iOS", "macOS", "Safari", "Xcode"}},
	{"Mozilla", []string{"Firefox"}},
	{"Grafana", []string{"Grafana"}},
}

// detectProductFromDescription uses keyword matching to guess vendor/product from a description.
func detectProductFromDescription(desc string) (string, string) {
	// Pass 1: product keyword match. Prefer the longest matching keyword so
	// specific names win over their prefixes (e.g. "IOS XE" over "IOS").
	bestVendor, bestProduct := "", ""
	for _, entry := range knownVendorProducts {
		for _, product := range entry.products {
			if strings.Contains(desc, product) && len(product) > len(bestProduct) {
				bestVendor, bestProduct = entry.vendor, product
			}
		}
	}
	if bestProduct != "" {
		return bestVendor, bestProduct
	}

	// Pass 2: vendor name appears in the description.
	lowerDesc := strings.ToLower(desc)
	for _, entry := range knownVendorProducts {
		if strings.Contains(lowerDesc, strings.ToLower(entry.vendor)) {
			return entry.vendor, ""
		}
	}

	// Pass 3: "in <vendor> <Product>" pattern, e.g. "detected in alexta69 MeTube".
	words := strings.Fields(desc)
	for i := 0; i+2 < len(words); i++ {
		if !strings.EqualFold(words[i], "in") {
			continue
		}
		vendorWord := strings.Trim(words[i+1], ".,;:()")
		productWord := strings.Trim(words[i+2], ".,;:()")
		if len(vendorWord) > 2 && len(productWord) > 0 && productWord[0] >= 'A' && productWord[0] <= 'Z' {
			return capitalize(vendorWord), capitalize(productWord)
		}
	}

	// Pass 4: generic "<Vendor> <Product>" capitalized-pair heuristic.
	fields := strings.Fields(desc)
	for i, word := range fields {
		if i+1 < len(fields) && len(word) > 2 && word[0] >= 'A' && word[0] <= 'Z' {
			// Check if next word could be a product
			nextWord := fields[i+1]
			if len(nextWord) > 0 && nextWord[0] >= 'A' && nextWord[0] <= 'Z' {
				return word, nextWord
			}
		}
	}

	return "", ""
}

// ThreatAssociation represents a link between a CVE and a threat actor or ransomware group.
type ThreatAssociation struct {
	ID         int       `json:"id"`
	CVEID      string    `json:"cve_id"`
	EntityName string    `json:"entity_name"`
	EntityType string    `json:"entity_type"`
	Source     string    `json:"source"`
	CreatedAt  time.Time `json:"created_at"`
}

// AddAffectedProduct appends an AffectedProduct to the CVE's AffectedProducts slice.
// If a product with the same vendor+product already exists, it updates the version
// only if the existing version is empty and the new one is not.
func (c *CVE) AddAffectedProduct(vendor, product, version string, unconfirmed bool) {
	for i := range c.AffectedProducts {
		if c.AffectedProducts[i].Vendor == vendor && c.AffectedProducts[i].Product == product {
			// Only update version if existing is empty and new is not
			if c.AffectedProducts[i].Version == "" && version != "" {
				c.AffectedProducts[i].Version = version
			}
			return
		}
	}
	c.AffectedProducts = append(c.AffectedProducts, AffectedProduct{
		Vendor:      vendor,
		Product:     product,
		Version:     version,
		Unconfirmed: unconfirmed,
	})
}

// ActivityLog represents a user activity log entry.
type ActivityLog struct {
	ID           int       `json:"id"`
	ActivityType string    `json:"activity_type"`
	Description  string    `json:"description"`
	IPAddress    string    `json:"ip_address"`
	CreatedAt    time.Time `json:"created_at"`
}

// Team represents a team in the system.
type Team struct {
	ID         int       `json:"id"`
	Name       string    `json:"name"`
	InviteCode string    `json:"invite_code"`
	CreatedAt  time.Time `json:"created_at"`
}

var cveLineageRegex = regexp.MustCompile(`CVE-\d{4}-\d+`)

// GetLineage extracts related CVE IDs from the description, references, and OSINT data.
func (c *CVE) GetLineage() []string {
	seen := make(map[string]bool)
	var result []string

	// Don't include self
	seen[c.CVEID] = true

	// Extract CVE IDs from description
	for _, match := range cveLineageRegex.FindAllString(c.Description, -1) {
		upper := strings.ToUpper(match)
		if !seen[upper] {
			seen[upper] = true
			result = append(result, upper)
		}
	}

	// Extract CVE IDs from references
	for _, ref := range c.References {
		for _, match := range cveLineageRegex.FindAllString(ref, -1) {
			upper := strings.ToUpper(match)
			if !seen[upper] {
				seen[upper] = true
				result = append(result, upper)
			}
		}
	}

	// Extract from OSINT data related_cves
	if c.OSINTData != nil {
		if rc, ok := c.OSINTData["related_cves"]; ok {
			if arr, ok := rc.([]interface{}); ok {
				for _, item := range arr {
					if s, ok := item.(string); ok {
						upper := strings.ToUpper(s)
						if !seen[upper] {
							seen[upper] = true
							result = append(result, upper)
						}
					}
				}
			}
		}
	}

	return result
}

// cpeVendorAliases maps raw CPE vendor tokens to their common display names.
var cpeVendorAliases = map[string]string{
	"canonical": "Ubuntu",
}

// ParseCPE parses a CPE 2.3 URI string and returns vendor, product, version, and type.
// Vendor and product are capitalized and underscores replaced with spaces. The type is
// the CPE "part" component: "a" (application), "o" (OS), or "h" (hardware).
func ParseCPE(cpe string) (vendor, product, version, cpeType string) {
	parts := strings.Split(cpe, ":")
	if len(parts) < 5 {
		return "", "", "", ""
	}
	if alias, ok := cpeVendorAliases[strings.ToLower(parts[3])]; ok {
		vendor = alias
	} else {
		vendor = capitalize(strings.ReplaceAll(parts[3], "_", " "))
	}
	product = capitalize(strings.ReplaceAll(parts[4], "_", " "))
	if len(parts) > 5 {
		version = parts[5]
		if version == "-" || version == "*" {
			version = ""
		}
	}
	cpeType = parts[2]
	return vendor, product, version, cpeType
}

// capitalize capitalizes the first letter of each word in the string.
func capitalize(s string) string {
	if s == "" {
		return ""
	}
	words := strings.Fields(s)
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(word[:1]) + strings.ToLower(word[1:])
		}
	}
	return strings.Join(words, " ")
}

// GetCPEs returns a deduplicated list of CPE criteria strings from the CVE configurations.
func (c *CVE) GetCPEs() []string {
	seen := make(map[string]bool)
	var result []string
	for _, config := range c.Configurations {
		for _, node := range config.Nodes {
			for _, match := range node.CPEMatch {
				if match.Criteria != "" && !seen[match.Criteria] {
					seen[match.Criteria] = true
					result = append(result, match.Criteria)
				}
			}
		}
	}
	return result
}

// TeamWithInviteCode is a Team that includes the invite code in JSON output.
type TeamWithInviteCode struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	InviteCode string `json:"invite_code"`
	CreatedAt  string `json:"created_at,omitempty"`
}

// NewTeamWithInviteCode creates a TeamWithInviteCode from a Team.
func NewTeamWithInviteCode(t Team) TeamWithInviteCode {
	return TeamWithInviteCode{
		ID:         t.ID,
		Name:       t.Name,
		InviteCode: t.InviteCode,
		CreatedAt:  t.CreatedAt.Format(time.RFC3339),
	}
}

// NormalizeName normalizes a name string by trimming whitespace and capitalizing words.
func NormalizeName(name string) string {
	return capitalize(strings.TrimSpace(name))
}

// Scan implements the sql.Scanner interface for CVEConfigurations JSONB.
func (c *CVEConfigurations) Scan(value interface{}) error {
	if value == nil {
		*c = nil
		return nil
	}
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("type assertion to []byte failed")
	}
	return json.Unmarshal(b, c)
}

// Value implements the driver.Valuer interface for CVEConfigurations JSONB.
func (c CVEConfigurations) Value() (driver.Value, error) {
	if c == nil {
		return nil, nil
	}
	return json.Marshal(c)
}
