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
	OSVLastUpdated *time.Time             `json:"osv_last_updated,omitempty"`
	GreyNoiseLastUpdated *time.Time       `json:"greynoise_last_updated,omitempty"`
	InTheWildData        JSONBMap               `json:"inthewild_data"`
	InTheWildLastUpdated *time.Time             `json:"inthewild_last_updated,omitempty"`
	ExploitAvailable     bool                   `json:"exploit_available"`
	Status         string                 `json:"status"`
	Notes          string                 `json:"notes"`
	References     []string               `json:"references"`
	Configurations CVEConfigurations      `json:"configurations"`
	Vendor         string                 `json:"vendor"`
	Product        string                 `json:"product"`
	AffectedProducts AffectedProducts     `json:"affected_products"`
	DarknetMentions  int                    `json:"darknet_mentions"`
	DarknetLastSeen  *time.Time             `json:"darknet_last_seen,omitempty"`
	DarknetHits      DarknetHits            `json:"darknet_hits,omitempty"`
	PublishedDate  time.Time              `json:"published_date"`
	UpdatedDate    time.Time              `json:"updated_date"`
	CreatedAt      time.Time              `json:"created_at"`
	Priority       string                 `json:"priority"`
}

type DarknetHit struct {
	Title       string    `json:"title"`
	URL         string    `json:"url"`
	Engine      string    `json:"engine"`
	Snippet     string    `json:"snippet"`
	Language    string    `json:"language"`
	IsHoneyLink bool      `json:"is_honey_link"`
	CreatedAt   time.Time `json:"created_at"`
}

type DarknetHits []DarknetHit

// Scan implements the sql.Scanner interface for JSONB.
func (d *DarknetHits) Scan(value interface{}) error {
	if value == nil {
		*d = nil
		return nil
	}
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("type assertion to []byte failed")
	}
	return json.Unmarshal(b, d)
}

// Value implements the driver.Valuer interface for JSONB.
func (d DarknetHits) Value() (driver.Value, error) {
	if d == nil {
		return nil, nil
	}
	return json.Marshal(d)
}

type CVEConfigurations []CVEConfiguration

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

func (c *CVE) AddAffectedProduct(vendor, product, version string, unconfirmed bool) {
	for i, p := range c.AffectedProducts {
		if p.Vendor == vendor && p.Product == product {
			// If we already have a version, don't overwrite it with an empty one
			if p.Version == "" && version != "" {
				c.AffectedProducts[i].Version = version
			}
			return
		}
	}
	c.AffectedProducts = append(c.AffectedProducts, AffectedProduct{
		Vendor:      vendor,
		Product:     product,
		Version:     version,
		Type:        "a",
		Unconfirmed: unconfirmed,
	})
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

// descriptionPatterns is a list of compiled regex patterns used to extract vendor/product
// from CVE descriptions when CPE configuration data is not available. Compiled at init time.
var descriptionPatterns []*regexp.Regexp

// knownVendorKeywords maps lowercase keywords found in descriptions to (vendor, product) pairs.
// Used as a last-resort heuristic when neither CPE nor regex patterns match.
var knownVendorKeywords []struct {
	keyword string
	vendor  string
	product string
}

func init() {
	// Pre-compile all description regex patterns for performance
	patterns := []string{
		// "vulnerability in Vendor Product"
		`(?i)(?:vulnerability|flaw|issue|bug|weakness) in (?:the )?([A-Za-z][A-Za-z0-9_\-\.]+) ([A-Za-z][A-Za-z0-9_\-\.]+)`,
		// "detected in Vendor Product"
		`(?i)(?:detected|discovered|identified|reported) in (?:the )?([A-Za-z][A-Za-z0-9_\-\.]+) ([A-Za-z][A-Za-z0-9_\-\.]+)`,
		// "affects Vendor Product"
		`(?i)(?:affects?|impacts?) (?:the )?([A-Za-z][A-Za-z0-9_\-\.]+) ([A-Za-z][A-Za-z0-9_\-\.]+)`,
		// "found in Vendor Product"
		`(?i)found in (?:the )?([A-Za-z][A-Za-z0-9_\-\.]+) ([A-Za-z][A-Za-z0-9_\-\.]+)`,
		// "Vendor Product before/prior to version"
		`(?i)([A-Za-z][A-Za-z0-9_\-\.]+) ([A-Za-z][A-Za-z0-9_\-\.]+) (?:before|prior to|through|up to) (?:version )?[\d]`,
		// "in Vendor Product version/before"
		`(?i) in ([A-Za-z][A-Za-z0-9_\-\.]+) ([A-Za-z][A-Za-z0-9_\-\.]+) (?:version|v\.?|before|prior|through|up to) `,
		// "Vendor Product versions X through Y"
		`(?i)([A-Za-z][A-Za-z0-9_\-\.]+) ([A-Za-z][A-Za-z0-9_\-\.]+) versions? `,
		// "XSS/SQLi/RCE/etc in Vendor Product"
		`(?i)(?:XSS|SQL injection|remote code execution|buffer overflow|path traversal|SSRF|CSRF|RCE|directory traversal|code injection|command injection) (?:in|via) (?:the )?([A-Za-z][A-Za-z0-9_\-\.]+) ([A-Za-z][A-Za-z0-9_\-\.]+)`,
		// "allows ... via Vendor Product"
		`(?i)allows? .{0,80}via (?:the )?([A-Za-z][A-Za-z0-9_\-\.]+) ([A-Za-z][A-Za-z0-9_\-\.]+)`,
		// "Vendor's Product"
		`(?i)([A-Za-z][A-Za-z0-9_\-\.]+)'s ([A-Za-z][A-Za-z0-9_\-\.]+)`,
	}
	for _, p := range patterns {
		descriptionPatterns = append(descriptionPatterns, regexp.MustCompile(p))
	}

	// Known vendor keyword pairs for last-resort description scanning
	knownVendorKeywords = []struct {
		keyword string
		vendor  string
		product string
	}{
		{"microsoft windows", "Microsoft", "Windows"},
		{"microsoft office", "Microsoft", "Office"},
		{"microsoft exchange", "Microsoft", "Exchange Server"},
		{"microsoft edge", "Microsoft", "Edge"},
		{"microsoft .net", "Microsoft", ".NET Framework"},
		{"microsoft sharepoint", "Microsoft", "SharePoint"},
		{"microsoft outlook", "Microsoft", "Outlook"},
		{"microsoft teams", "Microsoft", "Teams"},
		{"microsoft azure", "Microsoft", "Azure"},
		{"active directory", "Microsoft", "Active Directory"},
		{"internet explorer", "Microsoft", "Internet Explorer"},
		{"google chrome", "Google", "Chrome"},
		{"google android", "Google", "Android"},
		{"google kubernetes", "Google", "Kubernetes Engine"},
		{"mozilla firefox", "Mozilla", "Firefox"},
		{"mozilla thunderbird", "Mozilla", "Thunderbird"},
		{"apple safari", "Apple", "Safari"},
		{"apple macos", "Apple", "macOS"},
		{"apple ios", "Apple", "iOS"},
		{"apple ipados", "Apple", "iPadOS"},
		{"apple watchos", "Apple", "watchOS"},
		{"apple tvos", "Apple", "tvOS"},
		{"apple xcode", "Apple", "Xcode"},
		{"linux kernel", "Linux", "Kernel"},
		{"apache http", "Apache", "HTTP Server"},
		{"apache tomcat", "Apache", "Tomcat"},
		{"apache struts", "Apache", "Struts"},
		{"apache log4j", "Apache", "Log4j"},
		{"apache kafka", "Apache", "Kafka"},
		{"apache solr", "Apache", "Solr"},
		{"apache activemq", "Apache", "ActiveMQ"},
		{"apache camel", "Apache", "Camel"},
		{"apache airflow", "Apache", "Airflow"},
		{"apache superset", "Apache", "Superset"},
		{"nginx", "Nginx", "Nginx"},
		{"wordpress", "WordPress", "WordPress"},
		{"drupal", "Drupal", "Drupal"},
		{"joomla", "Joomla", "Joomla"},
		{"jenkins", "Jenkins", "Jenkins"},
		{"gitlab", "GitLab", "GitLab"},
		{"grafana", "Grafana", "Grafana"},
		{"elasticsearch", "Elastic", "Elasticsearch"},
		{"kibana", "Elastic", "Kibana"},
		{"logstash", "Elastic", "Logstash"},
		{"docker", "Docker", "Docker"},
		{"kubernetes", "Kubernetes", "Kubernetes"},
		{"vmware vcenter", "VMware", "vCenter Server"},
		{"vmware esxi", "VMware", "ESXi"},
		{"vmware workstation", "VMware", "Workstation"},
		{"vmware fusion", "VMware", "Fusion"},
		{"vmware horizon", "VMware", "Horizon"},
		{"vmware nsx", "VMware", "NSX"},
		{"vmware aria", "VMware", "Aria"},
		{"fortinet fortigate", "Fortinet", "FortiGate"},
		{"fortinet fortios", "Fortinet", "FortiOS"},
		{"fortinet fortimanager", "Fortinet", "FortiManager"},
		{"fortinet fortianalyzer", "Fortinet", "FortiAnalyzer"},
		{"fortinet forticlient", "Fortinet", "FortiClient"},
		{"fortinet fortiweb", "Fortinet", "FortiWeb"},
		{"fortinet fortimail", "Fortinet", "FortiMail"},
		{"fortinet fortisiem", "Fortinet", "FortiSIEM"},
		{"fortinet fortiproxy", "Fortinet", "FortiProxy"},
		{"fortinet fortiswitch", "Fortinet", "FortiSwitch"},
		{"fortinet fortiap", "Fortinet", "FortiAP"},
		{"palo alto pan-os", "Palo Alto Networks", "PAN-OS"},
		{"palo alto panorama", "Palo Alto Networks", "Panorama"},
		{"palo alto cortex", "Palo Alto Networks", "Cortex"},
		{"palo alto globalprotect", "Palo Alto Networks", "GlobalProtect"},
		{"cisco ios xe", "Cisco", "IOS XE"},
		{"cisco ios xr", "Cisco", "IOS XR"},
		{"cisco ios", "Cisco", "IOS"},
		{"cisco nexus", "Cisco", "Nexus"},
		{"cisco asa", "Cisco", "ASA"},
		{"cisco firepower", "Cisco", "Firepower"},
		{"cisco webex", "Cisco", "WebEx"},
		{"cisco meraki", "Cisco", "Meraki"},
		{"cisco anyconnect", "Cisco", "AnyConnect"},
		{"cisco umbrella", "Cisco", "Umbrella"},
		{"cisco duo", "Cisco", "Duo"},
		{"citrix netscaler", "Citrix", "NetScaler"},
		{"citrix adc", "Citrix", "ADC"},
		{"citrix xenserver", "Citrix", "XenServer"},
		{"citrix xenapp", "Citrix", "XenApp"},
		{"citrix virtual apps", "Citrix", "Virtual Apps and Desktops"},
		{"sophos", "Sophos", "Sophos"},
		{"juniper junos", "Juniper", "Junos OS"},
		{"juniper srx", "Juniper", "SRX"},
		{"oracle java", "Oracle", "Java"},
		{"oracle weblogic", "Oracle", "WebLogic Server"},
		{"oracle mysql", "Oracle", "MySQL"},
		{"oracle database", "Oracle", "Database"},
		{"oracle peoplesoft", "Oracle", "PeopleSoft"},
		{"oracle e-business", "Oracle", "E-Business Suite"},
		{"sap netweaver", "SAP", "NetWeaver"},
		{"sap hana", "SAP", "HANA"},
		{"sap business", "SAP", "Business Suite"},
		{"ibm websphere", "IBM", "WebSphere"},
		{"ibm db2", "IBM", "Db2"},
		{"ibm cognos", "IBM", "Cognos"},
		{"ibm qradar", "IBM", "QRadar"},
		{"ibm mq", "IBM", "MQ"},
		{"dell idrac", "Dell", "iDRAC"},
		{"dell emc", "Dell", "EMC"},
		{"dell powerstore", "Dell", "PowerStore"},
		{"hp ilo", "HP", "iLO"},
		{"hpe ilo", "HPE", "iLO"},
		{"synology", "Synology", "DiskStation Manager"},
		{"qnap", "QNAP", "QTS"},
		{"sonicwall", "SonicWall", "SonicOS"},
		{"zyxel", "Zyxel", "Zyxel"},
		{"zoom", "Zoom", "Zoom"},
		{"slack", "Salesforce", "Slack"},
		{"redis", "Redis", "Redis"},
		{"postgresql", "PostgreSQL", "PostgreSQL"},
		{"mongodb", "MongoDB", "MongoDB"},
		{"openssl", "OpenSSL", "OpenSSL"},
		{"node.js", "Node.js", "Node.js"},
		{"python", "Python", "Python"},
		{"php", "PHP", "PHP"},
		{"spring framework", "VMware", "Spring Framework"},
		{"spring boot", "VMware", "Spring Boot"},
		{"next.js", "Vercel", "Next.js"},
		{"react", "Meta", "React"},
		{"tensorflow", "Google", "TensorFlow"},
		{"pytorch", "Meta", "PyTorch"},
		{"veeam", "Veeam", "Veeam"},
		{"ivanti", "Ivanti", "Ivanti"},
		{"atlassian confluence", "Atlassian", "Confluence"},
		{"atlassian jira", "Atlassian", "Jira"},
		{"atlassian bitbucket", "Atlassian", "Bitbucket"},
		{"hashicorp vault", "HashiCorp", "Vault"},
		{"hashicorp terraform", "HashiCorp", "Terraform"},
		{"hashicorp consul", "HashiCorp", "Consul"},
		{"mattermost", "Mattermost", "Mattermost"},
		{"nextcloud", "Nextcloud", "Nextcloud"},
		{"typo3", "TYPO3", "TYPO3"},
		{"roundcube", "Roundcube", "Roundcube"},
		{"keycloak", "Red Hat", "Keycloak"},
		{"traefik", "Traefik Labs", "Traefik"},
		{"aruba", "HPE Aruba", "ArubaOS"},
		{"tp-link", "TP-Link", "TP-Link"},
		{"d-link", "D-Link", "D-Link"},
		{"netgear", "NETGEAR", "NETGEAR"},
		{"hikvision", "Hikvision", "Hikvision"},
		{"dahua", "Dahua", "Dahua"},
	}
}

// noiseWords are words that should never match as vendor or product from regex.
var noiseWords = map[string]bool{
	"the": true, "this": true, "that": true, "and": true, "with": true,
	"from": true, "for": true, "not": true, "are": true, "was": true,
	"were": true, "been": true, "being": true, "have": true, "has": true,
	"had": true, "does": true, "did": true, "will": true, "would": true,
	"could": true, "should": true, "may": true, "might": true, "can": true,
	"via": true, "due": true, "which": true, "where": true, "when": true,
	"how": true, "its": true, "certain": true, "some": true, "any": true,
	"all": true, "each": true, "other": true, "such": true, "remote": true,
	"local": true, "allow": true, "allows": true, "attacker": true,
	"attackers": true, "user": true, "users": true, "malicious": true,
	"crafted": true, "specially": true, "arbitrary": true, "code": true,
	"execute": true, "execution": true, "denial": true, "service": true,
	"cross-site": true, "scripting": true, "injection": true, "overflow": true,
	"buffer": true, "stack": true, "heap": true, "null": true, "pointer": true,
	"multiple": true, "several": true, "various": true, "version": true,
	"versions": true, "before": true, "after": true, "prior": true,
	"through": true, "unauthenticated": true, "authenticated": true,
	"unauthorized": true, "improper": true, "insufficient": true,
	"incorrect": true, "unspecified": true, "unknown": true, "exist": true,
	"exists": true, "leading": true, "resulting": true, "cause": true,
	"causes": true, "caused": true, "request": true, "data": true,
}

func (c *CVE) GetDetectedProduct() (vendor, product string) {
	// 1. Primary: extract from CPE configuration data (highest confidence)
	products := c.GetAffectedProducts()
	if len(products) > 0 {
		return products[0].Vendor, products[0].Product
	}

	// 2. Secondary: Check if we already have stored values (populated by LLM or manual entry)
	if c.Vendor != "" && c.Product != "" {
		return c.Vendor, c.Product
	}

	desc := c.Description

	// 3. Tertiary: known vendor keyword matching on description (high confidence)
	descLower := strings.ToLower(desc)
	for _, kw := range knownVendorKeywords {
		if strings.Contains(descLower, kw.keyword) {
			return kw.vendor, kw.product
		}
	}

	// 4. Quaternary: regex pattern matching on description (medium confidence)
	for _, re := range descriptionPatterns {
		matches := re.FindStringSubmatch(desc)
		if len(matches) >= 3 {
			v := strings.TrimRight(matches[1], ".'\"")
			p := strings.TrimRight(matches[2], ".'\"")
			if len(v) < 2 || len(p) < 2 {
				continue
			}
			if noiseWords[strings.ToLower(v)] || noiseWords[strings.ToLower(p)] {
				continue
			}
			return NormalizeName(v), NormalizeName(p)
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
					v, p, v_ver, t := ParseCPE(match.Criteria)
					if v != "" && p != "" {
						key := fmt.Sprintf("%s:%s:%s", v, p, t)
						if !seen[key] {
							seen[key] = true
							versionStr := ""
							if match.VersionStartIncluding != "" || match.VersionEndIncluding != "" || match.VersionStartExcluding != "" || match.VersionEndExcluding != "" {
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
								versionStr = strings.Join(parts, " ")
							} else if v_ver != "" && v_ver != "*" && v_ver != "-" {
								versionStr = v_ver
							}

							products = append(products, AffectedProduct{
								Vendor:  v,
								Product: p,
								Version: versionStr,
								Type:    t,
							})
						}
					}
				}
			}
		}
	}
	if len(products) == 0 && c.Vendor != "" && c.Product != "" {
		products = append(products, AffectedProduct{
			Vendor:      c.Vendor,
			Product:     c.Product,
			Unconfirmed: true,
			Type:        "a", // Default to application for heuristic matches
		})
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
	// Microsoft
	"microsoft":                  "Microsoft",
	"microsoft_corp":             "Microsoft",
	"microsoft_corporation":      "Microsoft",
	// Apple
	"apple":                      "Apple",
	"apple_inc":                  "Apple",
	"apple_inc.":                 "Apple",
	// Google
	"google":                     "Google",
	"google_inc":                 "Google",
	"google_inc.":                "Google",
	"google_llc":                 "Google",
	"alphabet":                   "Google",
	// Linux
	"linux":                      "Linux",
	"linux_kernel":               "Linux Kernel",
	"torvalds":                   "Linux",
	// Apache
	"apache":                     "Apache",
	"apache_software_foundation": "Apache",
	// Red Hat / Fedora
	"redhat":                     "Red Hat",
	"red_hat":                    "Red Hat",
	"fedoraproject":              "Fedora",
	// Debian / Ubuntu
	"debian":                     "Debian",
	"debian_linux":               "Debian",
	"canonical":                  "Ubuntu",
	"canonical_ltd":              "Ubuntu",
	// Oracle
	"oracle":                     "Oracle",
	"oracle_corp":                "Oracle",
	"oracle_corporation":         "Oracle",
	// IBM
	"ibm":                        "IBM",
	"ibm_corporation":            "IBM",
	// Cisco
	"cisco":                      "Cisco",
	"cisco_systems":              "Cisco",
	"cisco_systems_inc":          "Cisco",
	// VMware / Broadcom
	"vmware":                     "VMware",
	"vmware_inc":                 "VMware",
	"broadcom":                   "Broadcom",
	// Fortinet
	"fortinet":                   "Fortinet",
	"fortinet_inc":               "Fortinet",
	// Palo Alto Networks
	"paloaltonetworks":           "Palo Alto Networks",
	"palo_alto_networks":         "Palo Alto Networks",
	// Juniper
	"juniper":                    "Juniper",
	"juniper_networks":           "Juniper",
	// Citrix
	"citrix":                     "Citrix",
	"citrix_systems":             "Citrix",
	// Dell / HP / HPE
	"dell":                       "Dell",
	"dell_inc":                   "Dell",
	"hp":                         "HP",
	"hp_inc":                     "HP",
	"hewlett_packard_enterprise": "HPE",
	"hpe":                        "HPE",
	// SAP
	"sap":                        "SAP",
	"sap_se":                     "SAP",
	// Mozilla
	"mozilla":                    "Mozilla",
	"mozilla_foundation":         "Mozilla",
	// Samsung / Huawei
	"samsung":                    "Samsung",
	"huawei":                     "Huawei",
	// Atlassian
	"atlassian":                  "Atlassian",
	"atlassian_pty":              "Atlassian",
	// F5
	"f5":                         "F5",
	"f5_networks":                "F5",
	// SonicWall
	"sonicwall":                  "SonicWall",
	"sonicwall_inc":              "SonicWall",
	// Sophos
	"sophos":                     "Sophos",
	"sophos_ltd":                 "Sophos",
	// Zyxel
	"zyxel":                      "Zyxel",
	"zyxel_communications":       "Zyxel",
	// Network gear
	"netgear":                    "NETGEAR",
	"tp-link":                    "TP-Link",
	"d-link":                     "D-Link",
	"dlink":                      "D-Link",
	// NAS / IoT
	"synology":                   "Synology",
	"qnap":                       "QNAP",
	"qnap_systems":               "QNAP",
	"hikvision":                  "Hikvision",
	"dahua":                      "Dahua",
	// Cloud / DevOps
	"hashicorp":                  "HashiCorp",
	"docker":                     "Docker",
	"docker_inc":                 "Docker",
	"gitlab":                     "GitLab",
	"github":                     "GitHub",
	"elastic":                    "Elastic",
	"elasticsearch":              "Elastic",
	"grafana":                    "Grafana",
	"jenkins":                    "Jenkins",
	// Security vendors
	"ivanti":                     "Ivanti",
	"ivanti_inc":                 "Ivanti",
	"veeam":                      "Veeam",
	"trendmicro":                 "Trend Micro",
	"trend_micro":                "Trend Micro",
	"mcafee":                     "McAfee",
	"kaspersky":                  "Kaspersky",
	"crowdstrike":                "CrowdStrike",
	"symantec":                   "Symantec",
	// CMS
	"wordpress":                  "WordPress",
	"automattic":                 "WordPress",
	"drupal":                     "Drupal",
	"joomla":                     "Joomla",
	"typo3":                      "TYPO3",
	// Databases
	"postgresql":                 "PostgreSQL",
	"mongodb":                    "MongoDB",
	"mongodb_inc":                "MongoDB",
	"redis":                      "Redis",
	"redis_ltd":                  "Redis",
	// Other
	"openssl":                    "OpenSSL",
	"openssl_project":            "OpenSSL",
	"nodejs":                     "Node.js",
	"node.js":                    "Node.js",
	"python":                     "Python",
	"python_software_foundation": "Python",
	"php":                        "PHP",
	"php_group":                  "PHP",
	"zoom":                       "Zoom",
	"zoom_video_communications":  "Zoom",
	"mattermost":                 "Mattermost",
	"nextcloud":                  "Nextcloud",
	"roundcube":                  "Roundcube",
	"nginx":                      "Nginx",
}

// acronyms contains words that should be preserved as-is (all uppercase or special casing).
var acronyms = map[string]string{
	"ibm": "IBM", "sap": "SAP", "hp": "HP", "hpe": "HPE",
	"aws": "AWS", "gcp": "GCP", "api": "API", "ssl": "SSL", "tls": "TLS",
	"ssh": "SSH", "dns": "DNS", "tcp": "TCP", "udp": "UDP", "ftp": "FTP",
	"rce": "RCE", "xss": "XSS", "csrf": "CSRF", "ssrf": "SSRF", "sql": "SQL",
	"nsx": "NSX", "asa": "ASA", "ios": "IOS", "adc": "ADC",
	"pan-os": "PAN-OS", "esxi": "ESXi", "idrac": "iDRAC", "ilo": "iLO",
	"vmware": "VMware", "macos": "macOS", "ipados": "iPadOS",
	"webex": "WebEx", "gitlab": "GitLab", "github": "GitHub",
	"wordpress": "WordPress", "javascript": "JavaScript", "typescript": "TypeScript",
	"postgresql": "PostgreSQL", "mongodb": "MongoDB", "openssl": "OpenSSL",
	"activemq": "ActiveMQ", "netweaver": "NetWeaver", "qradar": "QRadar",
	"fortios": "FortiOS", "fortigate": "FortiGate", "fortimanager": "FortiManager",
	"fortianalyzer": "FortiAnalyzer", "forticlient": "FortiClient",
	"fortiweb": "FortiWeb", "fortimail": "FortiMail", "fortisiem": "FortiSIEM",
	"fortiproxy": "FortiProxy", "fortiswitch": "FortiSwitch", "fortiap": "FortiAP",
	"sonicwall": "SonicWall", "netscaler": "NetScaler",
	"log4j": "Log4j", "vcenter": "vCenter",
	"qnap": "QNAP", "netgear": "NETGEAR",
}

func NormalizeName(name string) string {
	low := strings.ToLower(name)
	if alias, ok := nameAliases[low]; ok {
		return alias
	}
	// Also check with underscores replaced
	lowFlat := strings.ToLower(strings.ReplaceAll(name, "_", " "))
	lowFlat = strings.TrimSpace(lowFlat)
	if alias, ok := nameAliases[strings.ReplaceAll(lowFlat, " ", "_")]; ok {
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
		low := strings.ToLower(w)
		// Check if the word is a known acronym or special-cased word
		if acr, ok := acronyms[low]; ok {
			words[i] = acr
		} else if len(w) > 0 {
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
	ID                int       `json:"id"`
	UserID            int       `json:"user_id"`
	TeamID            *int      `json:"team_id"`
	Keyword           string    `json:"keyword"`
	MinSeverity       float64   `json:"min_severity"`
	WebhookURL        string    `json:"-"`
	SlackWebhookURL   string    `json:"-"`
	TeamsWebhookURL   string    `json:"-"`
	EnableEmail       bool      `json:"enable_email"`
	EnableWebhook     bool      `json:"enable_webhook"`
	EnableSlack       bool      `json:"enable_slack"`
	EnableTeams       bool      `json:"enable_teams"`
	EnableBrowserPush bool      `json:"enable_browser_push"`
	FilterLogic       string    `json:"filter_logic"`
	AggregationMode   string    `json:"aggregation_mode"` // instant, hourly, daily
	CreatedAt         time.Time `json:"created_at"`
}

type BrowserPushSubscription struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	Endpoint  string    `json:"endpoint"`
	P256dh    string    `json:"p256dh"`
	Auth      string    `json:"auth"`
	CreatedAt time.Time `json:"created_at"`
}

type NotificationDeliveryLog struct {
	ID             int       `json:"id"`
	UserID         int       `json:"user_id"`
	SubscriptionID int       `json:"subscription_id"`
	CVEID          int       `json:"cve_id"`
	Channel        string    `json:"channel"` // email, webhook, slack, teams, browser
	Status         string    `json:"status"`  // success, failure
	ErrorMessage   string    `json:"-"`
	DeliveryTime   time.Time `json:"delivery_time"`
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
	Priority  string    `json:"priority"`
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
