package models

// CommonCWEMap maps common CWE IDs to their names in case NVD leaves it blank.
var CommonCWEMap = map[string]string{
	"CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
	"CWE-125": "Out-of-bounds Read",
	"CWE-20":  "Improper Input Validation",
	"CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
	"CWE-22":  "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
	"CWE-269": "Improper Privilege Management",
	"CWE-287": "Improper Authentication",
	"CWE-352": "Cross-Site Request Forgery (CSRF)",
	"CWE-416": "Use After Free",
	"CWE-476": "NULL Pointer Dereference",
	"CWE-502": "Deserialization of Untrusted Data",
	"CWE-78":  "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
	"CWE-787": "Out-of-bounds Write",
	"CWE-79":  "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
	"CWE-862": "Missing Authorization",
	"CWE-863": "Incorrect Authorization",
	"CWE-89":  "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
	"CWE-94":  "Improper Control of Generation of Code ('Code Injection')",
	"CWE-178": "Improper Handling of Case Sensitivity",
	"CWE-732": "Incorrect Permission Assignment for Critical Resource",
	"CWE-611": "Improper Restriction of XML External Entity Reference",
	"CWE-190": "Integer Overflow or Wraparound",
	"CWE-400": "Uncontrolled Resource Consumption",
	"CWE-601": "URL Redirection to Untrusted Site ('Open Redirect')",
	"CWE-295": "Improper Certificate Validation",
	"CWE-312": "Cleartext Storage of Sensitive Information",
	"CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
	"CWE-426": "Untrusted Search Path",
	"CWE-434": "Unrestricted Upload of File with Dangerous Type",
	"CWE-532": "Insertion of Sensitive Information into Log File",
	"CWE-668": "Exposure of Resource to Wrong Sphere",
	"CWE-770": "Allocation of Resources Without Limits or Throttling",
	"CWE-918": "Server-Side Request Forgery (SSRF)",
	"CWE-120": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
	"CWE-131": "Incorrect Calculation of Buffer Size",
	"CWE-209": "Generation of Error Message Containing Sensitive Information",
	"CWE-326": "Inadequate Encryption Strength",
	"CWE-330": "Use of Insufficiently Random Values",
	"CWE-362": "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
	"CWE-415": "Double Free",
	"CWE-617": "Reachable Assertion",
	"CWE-917": "Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')",
}

// GetCWEName returns the CWE name, falling back to the map if empty.
func GetCWEName(cweID, existingName string) string {
	if existingName != "" && existingName != "Unknown" && existingName != "NVD-CWE-noinfo" && existingName != "NVD-CWE-Other" {
		return existingName
	}
	if name, ok := CommonCWEMap[cweID]; ok {
		return name
	}
	if cweID == "NVD-CWE-noinfo" {
		return "Insufficient Information"
	}
	if cweID == "NVD-CWE-Other" {
		return "Other Vulnerability Type"
	}
	return "Vulnerability Type Unspecified"
}
