package models

import "testing"

func TestGetCWEName(t *testing.T) {
	tests := []struct {
		name         string
		cweID        string
		existingName string
		want         string
	}{
		{
			name:         "Existing valid name",
			cweID:        "CWE-79",
			existingName: "Cross-site Scripting",
			want:         "Cross-site Scripting",
		},
		{
			name:         "Existing 'Unknown' name, map lookup",
			cweID:        "CWE-79",
			existingName: "Unknown",
			want:         "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
		},
		{
			name:         "Existing 'NVD-CWE-noinfo' name, map lookup",
			cweID:        "CWE-89",
			existingName: "NVD-CWE-noinfo",
			want:         "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
		},
		{
			name:         "Existing 'NVD-CWE-Other' name, map lookup",
			cweID:        "CWE-20",
			existingName: "NVD-CWE-Other",
			want:         "Improper Input Validation",
		},
		{
			name:         "Empty existing name, NVD-CWE-noinfo ID",
			cweID:        "NVD-CWE-noinfo",
			existingName: "",
			want:         "Insufficient Information",
		},
		{
			name:         "Empty existing name, NVD-CWE-Other ID",
			cweID:        "NVD-CWE-Other",
			existingName: "",
			want:         "Other Vulnerability Type",
		},
		{
			name:         "Empty existing name, unknown ID",
			cweID:        "CWE-9999",
			existingName: "",
			want:         "Vulnerability Type Unspecified",
		},
		{
			name:         "Empty existing name, map lookup",
			cweID:        "CWE-119",
			existingName: "",
			want:         "Improper Restriction of Operations within the Bounds of a Memory Buffer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetCWEName(tt.cweID, tt.existingName); got != tt.want {
				t.Errorf("GetCWEName(%q, %q) = %q, want %q", tt.cweID, tt.existingName, got, tt.want)
			}
		})
	}
}
