package main

import (
	"context"
	"testing"
	"vulfixx-scalper/proto"
)

func TestParseAhmiaHTML(t *testing.T) {
	sampleHTML := `
		<html>
			<body>
				<li class="result">
					<h4>Exploit for CVE-2024-1234</h4>
					<cite>http://onion-link-1.onion</cite>
				</li>
				<li class="result">
					<h4>Discussion: CVE-2024-1234 RCE</h4>
					<cite>http://onion-link-2.onion/post/1</cite>
				</li>
			</body>
		</html>
	`

	hits := parseAhmiaHTML(sampleHTML, "CVE-2024-1234")

	if len(hits) != 2 {
		t.Errorf("expected 2 hits, got %d", len(hits))
	}

	if hits[0].Title != "Exploit for CVE-2024-1234" {
		t.Errorf("wrong title for first hit: %s", hits[0].Title)
	}

	if hits[1].Url != "http://onion-link-2.onion/post/1" {
		t.Errorf("wrong URL for second hit: %s", hits[1].Url)
	}
}

func TestScalperService_Health(t *testing.T) {
	server := &scalperServer{}
	resp, err := server.Health(context.Background(), &proto.HealthRequest{})
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}
	if resp.Status != "OK" {
		t.Errorf("expected status OK, got %s", resp.Status)
	}
}
