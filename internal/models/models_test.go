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

func TestGetDetectedProduct(t *testing.T) {
	tests := []struct {
		description string
		wantVendor  string
		wantProduct string
	}{
		{
			description: "A security vulnerability has been detected in alexta69 MeTube up to 2026.04.09.",
			wantVendor:  "alexta69",
			wantProduct: "MeTube",
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
			wantVendor:      "Kleneway", // Normalized
			wantProduct:     "Awesome-cursor-mpc-server", // Normalized
		},
		{
			name:            "Version Range Including",
			configurations: CVEConfigurations{{Nodes: []ConfigNode{{CPEMatch: []CPEMatch{{Criteria: "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", VersionStartIncluding: "1.0", VersionEndExcluding: "2.0"}}}}}},
			wantLen:         1,
			wantVersion:     "≥1.0 <2.0",
		},
		{
			name:            "Version Range Excluding",
			configurations: CVEConfigurations{{Nodes: []ConfigNode{{CPEMatch: []CPEMatch{{Criteria: "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", VersionStartExcluding: "1.0", VersionEndIncluding: "2.0"}}}}}},
			wantLen:         1,
			wantVersion:     ">1.0 ≤2.0",
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
