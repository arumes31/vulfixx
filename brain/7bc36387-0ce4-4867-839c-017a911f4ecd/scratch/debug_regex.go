package main

import (
	"fmt"
	"regexp"
)

func main() {
	cveRegex := regexp.MustCompile(`CVE-\d{4}-\d+`)
	text := "Cisco IOS - Test Advisory Vulnerability in Cisco IOS CVE-2024-9999"
	found := cveRegex.FindAllString(text, -1)
	fmt.Printf("Found: %v (len: %d)\n", found, len(found))
}
