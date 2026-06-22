package worker

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"cve-tracker/internal/models"
)

func TestNotifier_Security(t *testing.T) {
	os.Setenv("TEST_MODE", "1") // Allow localhost for initial request
	os.Setenv("WEBHOOK_SECRET", "test_secret")
	defer func() {
		os.Unsetenv("TEST_MODE")
		os.Unsetenv("WEBHOOK_SECRET")
	}()

	var leakedSignature string
	var leakedHost string
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leakedSignature = r.Header.Get("X-Vulfixx-Signature")
		leakedHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer targetServer.Close()

	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetServer.URL, http.StatusFound)
	}))
	defer redirectServer.Close()

	w := &Worker{WebhookSecret: "test_secret"}
	cve := &models.CVE{CVEID: "CVE-2024-TEST", Description: "Test", CVSSScore: 5.0}

	t.Run("DoesNotLeakSignatureOnRedirect", func(t *testing.T) {
		success, _ := w.sendGenericWebhook(redirectServer.URL, cve, "Asset", "test@example.com")
		if !success {
			t.Fatalf("Request failed")
		}
		if leakedSignature != "" {
			t.Errorf("X-Vulfixx-Signature leaked to different host: %s", leakedSignature)
		}
	})

	t.Run("DoesNotLeakHostHeaderOnRedirect", func(t *testing.T) {
		success, _ := w.sendGenericWebhook(redirectServer.URL, cve, "Asset", "test@example.com")
		if !success {
			t.Fatalf("Request failed")
		}
		if leakedHost != targetServer.Listener.Addr().String() {
			t.Errorf("Host header leaked or incorrect: got %s, want %s", leakedHost, targetServer.Listener.Addr().String())
		}
	})

	t.Run("BlocksRedirectToPrivateIP", func(t *testing.T) {
		var targetReached bool
		tsInner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			targetReached = true
			w.WriteHeader(http.StatusOK)
		}))
		defer tsInner.Close()

		rsInner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			os.Setenv("TEST_MODE", "0") // Block next hop
			http.Redirect(w, r, tsInner.URL, http.StatusFound)
		}))
		defer rsInner.Close()

		success, err := w.sendGenericWebhook(rsInner.URL, cve, "Asset", "test@example.com")
		if success {
			t.Errorf("Expected failure on second hop redirect to private IP, but succeeded")
		} else {
			t.Logf("Correctly blocked during redirect: %s", err)
		}
		if targetReached {
			t.Errorf("Target server should not have been reached")
		}
	})

	t.Run("BlocksInvalidRedirectSchemes", func(t *testing.T) {
		rsInner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "ftp://example.com", http.StatusFound)
		}))
		defer rsInner.Close()

		success, err := w.sendGenericWebhook(rsInner.URL, cve, "Asset", "test@example.com")
		if success {
			t.Errorf("Expected failure on invalid scheme redirect, but succeeded")
		} else {
			t.Logf("Correctly blocked invalid scheme: %s", err)
		}
	})
}
