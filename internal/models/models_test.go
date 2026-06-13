package models

import (
	"encoding/base64"
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

func TestGetDetectedProduct(t *testing.T) {
	tests := []struct {
		description string
		wantVendor  string
		wantProduct string
	}{
		{
			description: "A security vulnerability has been detected in alexta69 MeTube up to 2026.04.09.",
			wantVendor:  "Alexta69",
			wantProduct: "Metube",
		},
		{
			description: "This affects the Linux Kernel before version 5.10.",
			wantVendor:  "Linux",
			wantProduct: "Kernel",
		},
		{
			description: "A flaw was found in Microsoft Windows 10.",
			wantVendor:  "Microsoft",
			wantProduct: "Windows",
		},
		{
			description: "No product mentioned here.",
			wantVendor:  "",
			wantProduct: "",
		},
		{
			description: "CPE test",
			wantVendor:  "Microsoft",
			wantProduct: "Office",
		},
		// New test: keyword-based detection
		{
			description: "A remote code execution vulnerability exists in Apache Tomcat.",
			wantVendor:  "Apache",
			wantProduct: "Tomcat",
		},
		// New test: Fortinet product
		{
			description: "An OS command injection vulnerability in Fortinet FortiManager versions 7.0.0 through 7.4.2.",
			wantVendor:  "Fortinet",
			wantProduct: "FortiManager",
		},
		// New test: Cisco product
		{
			description: "A vulnerability in Cisco IOS XE Software could allow an unauthenticated attacker to execute arbitrary code.",
			wantVendor:  "Cisco",
			wantProduct: "IOS XE",
		},
		// New test: VMware product
		{
			description: "VMware vCenter Server contains a heap-overflow vulnerability.",
			wantVendor:  "VMware",
			wantProduct: "vCenter Server",
		},
		// New test: generic description-based
		{
			description: "SQL injection in Grafana allows remote attackers.",
			wantVendor:  "Grafana",
			wantProduct: "Grafana",
		},
	}

	for i, tt := range tests {
		cve := CVE{Description: tt.description}
		if tt.description == "CPE test" {
			cve.Configurations = []CVEConfiguration{
				{
					Nodes: []ConfigNode{
						{
							CPEMatch: []CPEMatch{
								{Criteria: "cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*"},
							},
						},
					},
				},
			}
		}

		gotV, gotP := cve.GetDetectedProduct()
		if gotV != tt.wantVendor || gotP != tt.wantProduct {
			t.Errorf("Test %d: GetDetectedProduct() = (%q, %q), want (%q, %q) for description: %q", i, gotV, gotP, tt.wantVendor, tt.wantProduct, tt.description)
		}
	}
}

func TestGetCWEName(t *testing.T) {
	tests := []struct {
		id       string
		existing string
		want     string
	}{
		{"CWE-119", "", "Improper Restriction of Operations within the Bounds of a Memory Buffer"},
		{"CWE-119", "Existing Name", "Existing Name"},
		{"CWE-119", "Unknown", "Improper Restriction of Operations within the Bounds of a Memory Buffer"},
		{"NVD-CWE-noinfo", "", "Insufficient Information"},
		{"NVD-CWE-Other", "", "Other Vulnerability Type"},
		{"CWE-9999", "", "Vulnerability Type Unspecified"},
	}

	for _, tt := range tests {
		got := GetCWEName(tt.id, tt.existing)
		if got != tt.want {
			t.Errorf("GetCWEName(%q, %q) = %q, want %q", tt.id, tt.existing, got, tt.want)
		}
	}
}

func TestAffectedProducts_ScanValue(t *testing.T) {
	ap := AffectedProducts{{Vendor: "V", Product: "P"}}
	val, err := ap.Value()
	if err != nil {
		t.Fatalf("Value() error: %v", err)
	}

	var ap2 AffectedProducts
	err = ap2.Scan(val)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if len(ap2) != 1 || ap2[0].Vendor != "V" {
		t.Errorf("Scan/Value roundtrip failed")
	}

	// Test nil
	var apNil AffectedProducts
	val, _ = apNil.Value()
	if val != nil {
		t.Errorf("expected nil value for nil slice")
	}
	err = apNil.Scan(nil)
	if err != nil || apNil != nil {
		t.Errorf("Scan(nil) failed")
	}

	// Test error
	err = apNil.Scan("not bytes")
	if err == nil {
		t.Errorf("expected error for non-byte scan")
	}
}

func TestCVEConfigurations_ScanValue(t *testing.T) {
	conf := CVEConfigurations{{Nodes: []ConfigNode{{Operator: "AND"}}}}
	val, err := conf.Value()
	if err != nil {
		t.Fatalf("Value() error: %v", err)
	}

	var conf2 CVEConfigurations
	err = conf2.Scan(val)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if len(conf2) != 1 || conf2[0].Nodes[0].Operator != "AND" {
		t.Errorf("Scan/Value roundtrip failed")
	}

	// Test nil
	var confNil CVEConfigurations
	val, _ = confNil.Value()
	if val != nil {
		t.Errorf("expected nil value for nil slice")
	}
	err = confNil.Scan(nil)
	if err != nil || confNil != nil {
		t.Errorf("Scan(nil) failed")
	}
}

func TestJSONBMap_ScanValue(t *testing.T) {
	m := JSONBMap{"key": "value"}
	val, err := m.Value()
	if err != nil {
		t.Fatalf("Value() error: %v", err)
	}

	var m2 JSONBMap
	err = m2.Scan(val)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if m2["key"] != "value" {
		t.Errorf("Scan/Value roundtrip failed")
	}

	// Test nil
	var mNil JSONBMap
	val, _ = mNil.Value()
	if val != nil {
		t.Errorf("expected nil value for nil map")
	}
	err = mNil.Scan(nil)
	if err != nil || mNil != nil {
		t.Errorf("Scan(nil) failed")
	}
}

func TestCVE_GetCPEs(t *testing.T) {
	cve := CVE{
		Configurations: CVEConfigurations{
			{
				Nodes: []ConfigNode{
					{
						CPEMatch: []CPEMatch{
							{Criteria: "cpe:2.3:a:v:p1:1:*:*:*:*:*:*:*"},
							{Criteria: "cpe:2.3:a:v:p2:2:*:*:*:*:*:*:*"},
							{Criteria: "cpe:2.3:a:v:p1:1:*:*:*:*:*:*:*"}, // Duplicate
						},
					},
				},
			},
		},
	}

	cpes := cve.GetCPEs()
	if len(cpes) != 2 {
		t.Errorf("expected 2 unique CPEs, got %d", len(cpes))
	}
}

func TestParseCPE(t *testing.T) {
	tests := []struct {
		cpe     string
		vendor  string
		product string
		version string
		part    string
	}{
		{"cpe:2.3:a:microsoft:windows_10:1809:*:*:*:*:*:*:*", "Microsoft", "Windows 10", "1809", "a"},
		{"cpe:2.3:o:linux:linux_kernel:5.4:*:*:*:*:*:*:*", "Linux", "Linux Kernel", "5.4", "o"},
		{"cpe:2.3:a:canonical:ubuntu_linux:-:*:*:*:*:*:*:*", "Ubuntu", "Ubuntu Linux", "", "a"},
		{"invalid", "", "", "", ""},
		{"cpe:2.3:a:v:p", "V", "P", "", "a"},
		{"cpe:2.3:a:v:p:v1:extra", "V", "P", "v1", "a"},
	}

	for _, tt := range tests {
		v, p, ver, t_part := ParseCPE(tt.cpe)
		if v != tt.vendor || p != tt.product || ver != tt.version || t_part != tt.part {
			t.Errorf("ParseCPE(%q) = (%q, %q, %q, %q), want (%q, %q, %q, %q)", tt.cpe, v, p, ver, t_part, tt.vendor, tt.product, tt.version, tt.part)
		}
	}
}

func TestCapitalizeEmpty(t *testing.T) {
	if capitalize("") != "" {
		t.Errorf("capitalize empty string failed")
	}
}

func TestNewTeamWithInviteCode(t *testing.T) {
	team := Team{ID: 1, Name: "Team1", InviteCode: "secret"}
	twic := NewTeamWithInviteCode(team)
	if twic.ID != 1 || twic.InviteCode != "secret" {
		t.Errorf("NewTeamWithInviteCode failed")
	}
}

func TestGetAffectedProducts(t *testing.T) {
	tests := []struct {
		name            string
		vendor          string
		product         string
		configurations  CVEConfigurations
		wantLen         int
		wantUnconfirmed bool
		wantVendor      string
		wantProduct     string
		wantVersion     string
	}{
		{
			name:    "Structured Data Present",
			vendor:  "kleneway",
			product: "awesome-cursor-mpc-server",
			configurations: CVEConfigurations{
				{
					Nodes: []ConfigNode{
						{
							CPEMatch: []CPEMatch{
								{Criteria: "cpe:2.3:a:kleneway:awesome-cursor-mpc-server:2.0.1:*:*:*:*:*:*:*"},
							},
						},
					},
				},
			},
			wantLen:         1,
			wantUnconfirmed: false,
			wantVendor:      "Kleneway",                  // Normalized
			wantProduct:     "Awesome-cursor-mpc-server", // Normalized
		},
		{
			name:           "Exact Version In CPE",
			configurations: CVEConfigurations{{Nodes: []ConfigNode{{CPEMatch: []CPEMatch{{Criteria: "cpe:2.3:o:next:next:1.0:*:*:*:*:*:*:*"}}}}}},
			wantLen:        1,
			wantVersion:    "1.0",
		},
		{
			name:           "Version Range Including",
			configurations: CVEConfigurations{{Nodes: []ConfigNode{{CPEMatch: []CPEMatch{{Criteria: "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", VersionStartIncluding: "1.0", VersionEndExcluding: "2.0"}}}}}},
			wantLen:        1,
			wantVersion:    "≥1.0 <2.0",
		},
		{
			name:           "Version Range Excluding",
			configurations: CVEConfigurations{{Nodes: []ConfigNode{{CPEMatch: []CPEMatch{{Criteria: "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", VersionStartExcluding: "1.0", VersionEndIncluding: "2.0"}}}}}},
			wantLen:        1,
			wantVersion:    ">1.0 ≤2.0",
		},
		{
			name:            "Fallback to Heuristic",
			vendor:          "kleneway",
			product:         "awesome-cursor-mpc-server",
			configurations:  nil,
			wantLen:         1,
			wantUnconfirmed: true,
			wantVendor:      "kleneway",
			wantProduct:     "awesome-cursor-mpc-server",
		},
		{
			name:            "Empty All",
			vendor:          "",
			product:         "",
			configurations:  nil,
			wantLen:         0,
			wantUnconfirmed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CVE{
				Vendor:         tt.vendor,
				Product:        tt.product,
				Configurations: tt.configurations,
			}
			got := c.GetAffectedProducts()
			if len(got) != tt.wantLen {
				t.Errorf("GetAffectedProducts() len = %d, want %d", len(got), tt.wantLen)
				return
			}
			if tt.wantLen > 0 {
				if tt.wantVendor != "" && got[0].Vendor != tt.wantVendor {
					t.Errorf("GetAffectedProducts() Vendor = %q, want %q", got[0].Vendor, tt.wantVendor)
				}
				if tt.wantProduct != "" && got[0].Product != tt.wantProduct {
					t.Errorf("GetAffectedProducts() Product = %q, want %q", got[0].Product, tt.wantProduct)
				}
				if tt.wantVersion != "" && got[0].Version != tt.wantVersion {
					t.Errorf("GetAffectedProducts() Version = %q, want %q", got[0].Version, tt.wantVersion)
				}
				if got[0].Unconfirmed != tt.wantUnconfirmed {
					t.Errorf("GetAffectedProducts() Unconfirmed = %v, want %v", got[0].Unconfirmed, tt.wantUnconfirmed)
				}
			}
		})
	}
}

func TestGetLineage(t *testing.T) {
	tests := []struct {
		cveID       string
		description string
		references  []string
		osintData   JSONBMap
		want        []string
	}{
		{
			cveID:       "CVE-2026-1001",
			description: "Fix for CVE-2025-9999 and related to CVE-2024-8888",
			references:  []string{"https://example.com/CVE-2023-7777"},
			want:        []string{"CVE-2025-9999", "CVE-2024-8888", "CVE-2023-7777"},
		},
		{
			cveID:       "CVE-2026-1002",
			description: "No mentions here",
			references:  []string{},
			want:        []string(nil),
		},
		{
			cveID:       "CVE-2026-1003",
			description: "Duplicate mention of CVE-2025-9999 CVE-2025-9999",
			references:  []string{"https://example.com/cve-2025-9999"},
			want:        []string{"CVE-2025-9999"},
		},
		{
			cveID: "CVE-2024-INTEL",
			osintData: JSONBMap{
				"related_cves": []interface{}{"CVE-2024-9999", 123}, // OSINT match
			},
			want: []string{"CVE-2024-9999"},
		},
	}

	for _, tt := range tests {
		cve := &CVE{CVEID: tt.cveID, Description: tt.description, References: tt.references, OSINTData: tt.osintData}
		got := cve.GetLineage()
		if len(got) != len(tt.want) {
			t.Errorf("GetLineage(%q) len = %d; want %d", tt.description, len(got), len(tt.want))
			continue
		}
		for i, v := range got {
			if v != tt.want[i] {
				t.Errorf("GetLineage(%q)[%d] = %q; want %q", tt.description, i, v, tt.want[i])
			}
		}
	}
}

func TestCVE_AddAffectedProduct(t *testing.T) {
	cve := &CVE{}

	// 1. Initial add
	cve.AddAffectedProduct("VendorA", "ProductA", "1.0", false)
	if len(cve.AffectedProducts) != 1 {
		t.Fatalf("expected 1 product, got %d", len(cve.AffectedProducts))
	}
	if cve.AffectedProducts[0].Version != "1.0" {
		t.Errorf("expected version 1.0, got %s", cve.AffectedProducts[0].Version)
	}

	// 2. Add with empty version shouldn't overwrite existing
	cve.AddAffectedProduct("VendorA", "ProductA", "", false)
	if cve.AffectedProducts[0].Version != "1.0" {
		t.Errorf("expected version to remain 1.0, got %s", cve.AffectedProducts[0].Version)
	}

	// 3. Add with same vendor/product but existing is empty version
	cve2 := &CVE{}
	cve2.AddAffectedProduct("VendorA", "ProductA", "", false)
	cve2.AddAffectedProduct("VendorA", "ProductA", "2.0", false)
	if cve2.AffectedProducts[0].Version != "2.0" {
		t.Errorf("expected version to be updated to 2.0, got %s", cve2.AffectedProducts[0].Version)
	}

	// 4. Add new product
	cve.AddAffectedProduct("VendorB", "ProductB", "3.0", true)
	if len(cve.AffectedProducts) != 2 {
		t.Fatalf("expected 2 products, got %d", len(cve.AffectedProducts))
	}
}

func TestWebhookEncryption(t *testing.T) {
	// 1. Test empty plaintext
	res, err := EncryptWebhook("")
	if err != nil || res != "" {
		t.Errorf("expected empty string and nil error, got (%q, %v)", res, err)
	}

	resDec, err := DecryptWebhook("")
	if err != nil || resDec != "" {
		t.Errorf("expected empty string and nil error, got (%q, %v)", resDec, err)
	}

	// 2. Test missing SESSION_KEY
	t.Setenv("SESSION_KEY", "")
	_, err = EncryptWebhook("secret")
	if err == nil || err.Error() != "missing SESSION_KEY" {
		t.Errorf("expected 'missing SESSION_KEY' error, got %v", err)
	}

	_, err = DecryptWebhook("secret")
	if err == nil || err.Error() != "missing SESSION_KEY" {
		t.Errorf("expected 'missing SESSION_KEY' error, got %v", err)
	}

	// 3. Test success path
	t.Setenv("SESSION_KEY", "THIS_IS_A_MOCK_SESSION_KEY_32_BY")
	plaintext := "http://mywebhook.com/payload"
	cipher, err := EncryptWebhook(plaintext)
	if err != nil {
		t.Fatalf("unexpected encrypt error: %v", err)
	}

	decrypted, err := DecryptWebhook(cipher)
	if err != nil {
		t.Fatalf("unexpected decrypt error: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("expected %q, got %q", plaintext, decrypted)
	}

	// 4. Test decrypt failures
	_, err = DecryptWebhook("invalid-base-64!")
	if err == nil {
		t.Error("expected base64 decode error, got nil")
	}

	// Short ciphertext error
	shortCipher := base64.URLEncoding.EncodeToString([]byte("short"))
	_, err = DecryptWebhook(shortCipher)
	if err == nil || err.Error() != "ciphertext too short" {
		t.Errorf("expected 'ciphertext too short' error, got %v", err)
	}

	// Decrypt auth tag failure / tampered ciphertext
	tampered := cipher[:len(cipher)-4] + "AAAA"
	_, err = DecryptWebhook(tampered)
	if err == nil {
		t.Error("expected GCM authentication check failure error, got nil")
	}
}

func TestGetVendorAdvisory(t *testing.T) {
	t.Run("Returns nil when VendorAdvisories is nil", func(t *testing.T) {
		cve := &CVE{}
		result := cve.GetVendorAdvisory(VendorFortiGuard)
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("Returns nil for missing vendor", func(t *testing.T) {
		cve := &CVE{VendorAdvisories: JSONBMap{"cisco": map[string]interface{}{"advisory_id": "CISCO-1"}}}
		result := cve.GetVendorAdvisory(VendorFortiGuard)
		if result != nil {
			t.Errorf("expected nil for missing vendor, got %v", result)
		}
	})

	t.Run("Returns advisory data for existing vendor", func(t *testing.T) {
		fgData := map[string]interface{}{
			"advisory_id":  "FG-IR-24-388",
			"advisory_url": "https://www.fortiguard.com/psirt/FG-IR-24-388",
			"severity":     "Critical",
		}
		cve := &CVE{VendorAdvisories: JSONBMap{VendorFortiGuard: fgData}}
		result := cve.GetVendorAdvisory(VendorFortiGuard)
		if result == nil {
			t.Fatal("expected advisory data, got nil")
		}
		if result["advisory_id"] != "FG-IR-24-388" {
			t.Errorf("expected advisory_id FG-IR-24-388, got %v", result["advisory_id"])
		}
		if result["severity"] != "Critical" {
			t.Errorf("expected severity Critical, got %v", result["severity"])
		}
	})

	t.Run("Returns nil for non-map value", func(t *testing.T) {
		cve := &CVE{VendorAdvisories: JSONBMap{VendorFortiGuard: "not-a-map"}}
		result := cve.GetVendorAdvisory(VendorFortiGuard)
		if result != nil {
			t.Errorf("expected nil for non-map value, got %v", result)
		}
	})
}

func TestSetVendorAdvisory(t *testing.T) {
	t.Run("Initializes VendorAdvisories if nil", func(t *testing.T) {
		cve := &CVE{}
		fgData := map[string]interface{}{"advisory_id": "FG-IR-24-388"}
		cve.SetVendorAdvisory(VendorFortiGuard, fgData)
		if cve.VendorAdvisories == nil {
			t.Fatal("expected VendorAdvisories to be initialized")
		}
		if cve.VendorAdvisories[VendorFortiGuard] == nil {
			t.Fatal("expected fortiguard advisory to be set")
		}
	})

	t.Run("Overwrites existing vendor advisory", func(t *testing.T) {
		cve := &CVE{VendorAdvisories: JSONBMap{VendorFortiGuard: map[string]interface{}{"advisory_id": "OLD"}}}
		newData := map[string]interface{}{"advisory_id": "FG-IR-24-999"}
		cve.SetVendorAdvisory(VendorFortiGuard, newData)
		result := cve.GetVendorAdvisory(VendorFortiGuard)
		if result["advisory_id"] != "FG-IR-24-999" {
			t.Errorf("expected advisory_id FG-IR-24-999, got %v", result["advisory_id"])
		}
	})

	t.Run("Adds new vendor without removing others", func(t *testing.T) {
		fgData := map[string]interface{}{"advisory_id": "FG-IR-24-388"}
		cve := &CVE{VendorAdvisories: JSONBMap{VendorFortiGuard: fgData}}
		ciscoData := map[string]interface{}{"advisory_id": "CISCO-2024-001"}
		cve.SetVendorAdvisory(VendorCisco, ciscoData)
		if len(cve.VendorAdvisories) != 2 {
			t.Errorf("expected 2 vendors, got %d", len(cve.VendorAdvisories))
		}
		if cve.GetVendorAdvisory(VendorFortiGuard) == nil {
			t.Error("expected FortiGuard advisory to still exist")
		}
		if cve.GetVendorAdvisory(VendorCisco) == nil {
			t.Error("expected Cisco advisory to exist")
		}
	})
}

func TestHasVendorAdvisory(t *testing.T) {
	t.Run("Returns false when VendorAdvisories is nil", func(t *testing.T) {
		cve := &CVE{}
		if cve.HasVendorAdvisory() {
			t.Error("expected false for nil VendorAdvisories")
		}
	})

	t.Run("Returns false when VendorAdvisories is empty", func(t *testing.T) {
		cve := &CVE{VendorAdvisories: JSONBMap{}}
		if cve.HasVendorAdvisory() {
			t.Error("expected false for empty VendorAdvisories")
		}
	})

	t.Run("Returns true when VendorAdvisories has data", func(t *testing.T) {
		cve := &CVE{VendorAdvisories: JSONBMap{VendorFortiGuard: map[string]interface{}{"advisory_id": "FG-IR-24-388"}}}
		if !cve.HasVendorAdvisory() {
			t.Error("expected true for non-empty VendorAdvisories")
		}
	})
}
