package models

import (
	"testing"
)

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

func TestCVE_GetAffectedProducts_Excluding(t *testing.T) {
	cve := CVE{
		Configurations: CVEConfigurations{
			{
				Nodes: []ConfigNode{
					{
						CPEMatch: []CPEMatch{
							{
								Criteria:              "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*",
								VersionStartExcluding: "1.0",
								VersionEndIncluding:   "2.0",
							},
						},
					},
				},
			},
		},
	}

	products := cve.GetAffectedProducts()
	if len(products) != 1 || products[0].Version != ">1.0 ≤2.0" {
		t.Errorf("Version string formatting failed, got %q", products[0].Version)
	}
}

func TestNewTeamWithInviteCode(t *testing.T) {
	team := Team{ID: 1, Name: "Team1", InviteCode: "secret"}
	twic := NewTeamWithInviteCode(team)
	if twic.ID != 1 || twic.InviteCode != "secret" {
		t.Errorf("NewTeamWithInviteCode failed")
	}
}

func TestCVE_GetAffectedProducts_Versions(t *testing.T) {
	cve := CVE{
		Configurations: CVEConfigurations{
			{
				Nodes: []ConfigNode{
					{
						CPEMatch: []CPEMatch{
							{
								Criteria:              "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*",
								VersionStartIncluding: "1.0",
								VersionEndExcluding:   "2.0",
							},
						},
					},
				},
			},
		},
	}

	products := cve.GetAffectedProducts()
	if len(products) != 1 || products[0].Version != "≥1.0 <2.0" {
		t.Errorf("Version string formatting failed, got %q", products[0].Version)
	}
}

func TestCVE_GetLineage_OSINT(t *testing.T) {
	cve := CVE{
		CVEID: "CVE-2024-0001",
		OSINTData: JSONBMap{
			"related_cves": []interface{}{"CVE-2024-9999", 123}, // Mixed valid/invalid
		},
	}
	lineage := cve.GetLineage()
	found := false
	for _, l := range lineage {
		if l == "CVE-2024-9999" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Failed to find related CVE from OSINT data")
	}
}
