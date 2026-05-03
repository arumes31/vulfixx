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
		// Ensure no panics for arbitrary inputs
		_ = GetCWEName(cweID, existingName)
	})
}

func FuzzNormalizeName(f *testing.F) {
	f.Add("microsoft")
	f.Add("linux_kernel")
	f.Add("Normal Name")
	f.Add("multiple_underscores_here")
	f.Add("")
	f.Add(" ")

	f.Fuzz(func(t *testing.T, name string) {
		NormalizeName(name)
	})
}

func FuzzCapitalize(f *testing.F) {
	f.Add("hello world")
	f.Add("multiple   spaces")
	f.Add("ALREADY CAPS")
	f.Add("")
	f.Add("a b c")

	f.Fuzz(func(t *testing.T, s string) {
		capitalize(s)
	})
}

func FuzzGetDetectedProduct(f *testing.F) {
	f.Add("vulnerability in vendor product version 1.0")
	f.Add("detected in Microsoft Office 2019")
	f.Add("affects some_vendor some_product")
	f.Add("found in the Cisco IOS")
	f.Add("nothing here")
	f.Add("")

	f.Fuzz(func(t *testing.T, description string) {
		cve := &CVE{Description: description}
		cve.GetDetectedProduct()
	})
}

func FuzzGetLineage(f *testing.F) {
	f.Add("Related to CVE-2023-1234 and CVE-2022-5678")
	f.Add("Fixed in CVE-2024-0001")
	f.Add("http://example.com/CVE-2021-9999")
	f.Add("No CVEs here")
	f.Add("")

	f.Fuzz(func(t *testing.T, data string) {
		cve := &CVE{
			CVEID:       "CVE-2024-TEST",
			Description: data,
			References:  []string{data},
		}
		cve.GetLineage()
	})
}
