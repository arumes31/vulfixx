package models

import "testing"

func TestGetCWEName(t *testing.T) {
	tests := []struct {
		id       string
		existing string
		want     string
	}{
		{"CWE-119", "", "Improper Restriction of Operations within the Bounds of a Memory Buffer"},
		{"CWE-119", "Existing Name", "Existing Name"},
		{"CWE-119", "Unknown", "Improper Restriction of Operations within the Bounds of a Memory Buffer"},
		{"CWE-119", "NVD-CWE-noinfo", "Improper Restriction of Operations within the Bounds of a Memory Buffer"},
		{"CWE-119", "NVD-CWE-Other", "Improper Restriction of Operations within the Bounds of a Memory Buffer"},
		{"NVD-CWE-noinfo", "", "Insufficient Information"},
		{"NVD-CWE-noinfo", "Unknown", "Insufficient Information"},
		{"NVD-CWE-Other", "", "Other Vulnerability Type"},
		{"NVD-CWE-Other", "NVD-CWE-Other", "Other Vulnerability Type"},
		{"CWE-9999", "", "Vulnerability Type Unspecified"},
		{"CWE-9999", "Unknown", "Vulnerability Type Unspecified"},
	}

	for _, tt := range tests {
		got := GetCWEName(tt.id, tt.existing)
		if got != tt.want {
			t.Errorf("GetCWEName(%q, %q) = %q, want %q", tt.id, tt.existing, got, tt.want)
		}
	}
}
