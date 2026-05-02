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

func TestGetLineage(t *testing.T) {
	tests := []struct {
		cveID       string
		description string
		references  []string
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
	}

	for _, tt := range tests {
		cve := &CVE{CVEID: tt.cveID, Description: tt.description, References: tt.references}
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
