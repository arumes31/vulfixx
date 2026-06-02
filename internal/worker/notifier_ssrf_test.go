package worker

import (
	"cve-tracker/internal/models"
	"cve-tracker/internal/security"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestWebhookSSRF_Vulnerabilities(t *testing.T) {
	os.Setenv("TEST_MODE", "0")
	os.Setenv("WEBHOOK_SECRET", "test_secret")
	defer func() {
		os.Unsetenv("TEST_MODE")
		os.Unsetenv("WEBHOOK_SECRET")
	}()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	w := &Worker{HTTP: http.DefaultClient, WebhookSecret: "test_secret"}
	cve := &models.CVE{CVEID: "CVE-2024-TEST", Description: "Test", CVSSScore: 5.0}

	t.Run("BlocksNonStandardPort", func(t *testing.T) {
		success, err := w.sendGenericWebhook(ts.URL, cve, "Asset", "test@example.com")
		if success {
			t.Errorf("Expected non-standard port to be blocked, but it succeeded")
		} else {
			t.Logf("Correctly blocked non-standard port: %s", err)
		}
	})

	t.Run("BlocksPrivateIPOnStandardPort", func(t *testing.T) {
		// We use a hostname that resolves to 127.0.0.1 but use port 80
		success, err := w.sendGenericWebhook("http://127.0.0.1:80", cve, "Asset", "test@example.com")
		if success {
			t.Errorf("Expected private IP to be blocked on port 80, but it succeeded")
		} else {
			t.Logf("Correctly blocked private IP: %s", err)
		}
	})
}

func TestWebhookSSRF_AllowedPorts(t *testing.T) {
	os.Setenv("TEST_MODE", "1")
	os.Setenv("WEBHOOK_SECRET", "test_secret")
	defer func() {
		os.Unsetenv("TEST_MODE")
		os.Unsetenv("WEBHOOK_SECRET")
	}()

	w := &Worker{HTTP: http.DefaultClient, WebhookSecret: "test_secret"}
	cve := &models.CVE{CVEID: "CVE-2024-TEST", Description: "Test", CVSSScore: 5.0}

	allowedPorts := []string{"80", "443", "8080", "8443"}
	for _, port := range allowedPorts {
		// We dont care if it actually connects, just that it doesnt return "blocked non-standard port"
		success, err := w.sendGenericWebhook("http://1.1.1.1:"+port, cve, "Asset", "test@example.com")
		_ = success
		if err != "" && (err == "blocked non-standard port: "+port || (len(err) > 26 && err[:26] == "blocked non-standard port:")) {
			t.Errorf("Port %s should be allowed, but got error: %s", port, err)
		}
	}
}

func TestWebhookSSRF_Redirects(t *testing.T) {
	os.Setenv("TEST_MODE", "1") // Allow loopback and non-standard ports
	os.Setenv("WEBHOOK_SECRET", "test_secret")
	defer func() {
		os.Unsetenv("TEST_MODE")
		os.Unsetenv("WEBHOOK_SECRET")
	}()

	var targetCalled bool
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer targetServer.Close()

	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetServer.URL, http.StatusFound)
	}))
	defer redirectServer.Close()

	w := &Worker{HTTP: http.DefaultClient, WebhookSecret: "test_secret"}
	cve := &models.CVE{CVEID: "CVE-2024-TEST", Description: "Test", CVSSScore: 5.0}

	success, err := w.sendGenericWebhook(redirectServer.URL, cve, "Asset", "test@example.com")

	if !success {
		t.Errorf("Redirect failed: %s", err)
	}
	if !targetCalled {
		t.Errorf("Redirect succeeded but target was never reached")
	}

	t.Run("HopLimit", func(t *testing.T) {
		var hopCount int
		var hopServer *httptest.Server
		hopServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hopCount++
			http.Redirect(w, r, hopServer.URL, http.StatusFound)
		}))
		defer hopServer.Close()

		success, err := w.sendGenericWebhook(hopServer.URL, cve, "Asset", "test@example.com")
		if success {
			t.Errorf("Expected infinite redirect to fail")
		}
		if !strings.Contains(err, "too many redirects") {
			t.Errorf("Expected too many redirects error, got: %s", err)
		}
	})

	t.Run("CrossHostHeaderStripping", func(t *testing.T) {
		var signatureHeader, timestampHeader string
		targetServer2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			signatureHeader = r.Header.Get("X-Vulfixx-Signature")
			timestampHeader = r.Header.Get("X-Vulfixx-Timestamp")
			w.WriteHeader(http.StatusOK)
		}))
		defer targetServer2.Close()

		redirectServer2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, targetServer2.URL, http.StatusFound)
		}))
		defer redirectServer2.Close()

		success, err := w.sendGenericWebhook(redirectServer2.URL, cve, "Asset", "test@example.com")
		if !success {
			t.Errorf("Redirect failed: %s", err)
		}
		if signatureHeader != "" || timestampHeader != "" {
			t.Errorf("Expected sensitive headers to be stripped on cross-host redirect, but got Signature: %s, Timestamp: %s", signatureHeader, timestampHeader)
		}
	})

	t.Run("InvalidSchemeRedirect", func(t *testing.T) {
		redirectServer3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "ftp://example.com", http.StatusFound)
		}))
		defer redirectServer3.Close()

		success, err := w.sendGenericWebhook(redirectServer3.URL, cve, "Asset", "test@example.com")
		if success {
			t.Errorf("Expected redirect to invalid scheme to fail")
		}
		if !strings.Contains(err, "invalid redirect scheme") {
			t.Errorf("Expected invalid redirect scheme error, got: %s", err)
		}
	})
}

func TestIsSafeIP_Internal(t *testing.T) {
	tests := []struct {
		ip   string
		safe bool
	}{
		{"1.1.1.1", true},
		{"8.8.8.8", true},
		{"127.0.0.1", false},
		{"10.0.0.1", false},
		{"192.168.1.1", false},
		{"172.16.0.1", false},
		{"169.254.169.254", false},
		{"::1", false},
	}

	for _, tc := range tests {
		ip := net.ParseIP(tc.ip)
		if security.IsIPSafe(ip) != tc.safe {
			t.Errorf("security.IsIPSafe(%s) = %v, want %v", tc.ip, !tc.safe, tc.safe)
		}
	}
}
