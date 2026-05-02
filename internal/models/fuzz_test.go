package models

import (
	"testing"
)

func FuzzParseCPE(f *testing.F) {
	seeds := []string{
		"cpe:2.3:a:microsoft:excel:2016:*:*:*:*:*:*:*",
		"cpe:2.3:o:linux:linux_kernel:4.19.1:*:*:*:*:*:*:*",
		"cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*",
		"cpe:2.3:a:oracle:mysql:5.7.28:*:*:*:*:*:*:*",
		"cpe:2.3:h:cisco:firepower_9300:*:*:*:*:*:*:*:*",
		"cpe:2.3:a:vendor:product:version",
		"invalid",
		"cpe:2.3:a:a:a",
		"cpe:2.3:a:a:a:a",
		"cpe:2.3:a:multiple:words_in_name:1.0",
		"cpe:2.3:a:::version",
		"::::::",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, cpe string) {
		vendor, product, version, part := ParseCPE(cpe)
		
		// Basic sanity check: if it started with the prefix, we might expect some results
		// but since it splits by colon, even "cpe:2.3:" might return something.
		
		// The main goal is to ensure no panics.
		_ = vendor
		_ = product
		_ = version
		_ = part
	})
}

func FuzzGetCWEName(f *testing.F) {
	f.Add("CWE-119", "")
	f.Add("CWE-79", "Cross-site Scripting")
	f.Add("CWE-999", "")
	f.Add("", "")
	f.Add("NVD-CWE-noinfo", "Unknown")
	f.Add("CWE-125", "NVD-CWE-Other")
	f.Add("ANYTHING", "ANYTHING")

	f.Fuzz(func(t *testing.T, cweID string, existingName string) {
		name := GetCWEName(cweID, existingName)
		if name == "" {
			t.Errorf("GetCWEName returned empty string for ID: %s, Existing: %s", cweID, existingName)
		}
	})
}
