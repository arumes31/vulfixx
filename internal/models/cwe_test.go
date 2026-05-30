package models

import "testing"

func TestGetCWEName(t *testing.T) {
	tests := []struct {
		cweID        string
		existingName string
		want         string
	}{
		{
			cweID:        "CWE-119",
			existingName: "Custom Name",
			want:         "Custom Name",
		},
		{
			cweID:        "CWE-119",
			existingName: "",
			want:         "Improper Restriction of Operations within the Bounds of a Memory Buffer",
		},
		{
			cweID:        "CWE-125",
			existingName: "Unknown",
			want:         "Out-of-bounds Read",
		},
		{
			cweID:        "CWE-20",
			existingName: "NVD-CWE-noinfo",
			want:         "Improper Input Validation",
		},
		{
			cweID:        "CWE-200",
			existingName: "NVD-CWE-Other",
			want:         "Exposure of Sensitive Information to an Unauthorized Actor",
		},
		{
			cweID:        "NVD-CWE-noinfo",
			existingName: "",
			want:         "Insufficient Information",
		},
		{
			cweID:        "NVD-CWE-Other",
			existingName: "",
			want:         "Other Vulnerability Type",
		},
		{
			cweID:        "CWE-999",
			existingName: "",
			want:         "Vulnerability Type Unspecified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.cweID+"/"+tt.existingName, func(t *testing.T) {
			got := GetCWEName(tt.cweID, tt.existingName)
			if got != tt.want {
				t.Errorf("GetCWEName(%q, %q) = %q; want %q", tt.cweID, tt.existingName, got, tt.want)
			}
		})
	}
}
