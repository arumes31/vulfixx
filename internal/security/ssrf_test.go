package security

import (
	"context"
	"net"
	"os"
	"testing"
)

func TestIsIPSafe(t *testing.T) {
	tests := []struct {
		ip       string
		testMode bool
		want     bool
	}{
		// Public IPs
		{"8.8.8.8", false, true},
		{"1.1.1.1", false, true},
		{"2606:4700:4700::1111", false, true},

		// Private/Internal IPs
		{"127.0.0.1", false, false},
		{"10.0.0.1", false, false},
		{"192.168.1.1", false, false},
		{"172.16.0.1", false, false},
		{"169.254.0.1", false, false},
		{"::1", false, false},
		{"0.0.0.0", false, false},

		// Private IPs in Test Mode
		{"127.0.0.1", true, true},
		{"10.0.0.1", true, true},
		{"192.168.1.1", true, true},
		{"::1", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			if tt.testMode {
				os.Setenv("TEST_MODE", "1")
			} else {
				os.Unsetenv("TEST_MODE")
			}
			defer os.Unsetenv("TEST_MODE")

			ip := net.ParseIP(tt.ip)
			if got := IsIPSafe(ip); got != tt.want {
				t.Errorf("IsIPSafe(%s) in TEST_MODE=%v = %v, want %v", tt.ip, tt.testMode, got, tt.want)
			}
		})
	}
}

func TestIsIPSafe_NilAndMalformed(t *testing.T) {
	t.Run("NilIP", func(t *testing.T) {
		if IsIPSafe(nil) {
			t.Error("expected IsIPSafe(nil) to be false")
		}
	})

	t.Run("MalformedIPLength", func(t *testing.T) {
		// A 3-byte IP slice is neither 4 nor 16 bytes, making netip.AddrFromSlice return ok=false
		malformed := net.IP([]byte{1, 2, 3})
		if IsIPSafe(malformed) {
			t.Error("expected IsIPSafe(malformed) to be false")
		}
	})
}

func TestResolveSafeIP(t *testing.T) {
	ctx := context.Background()

	t.Run("ValidPublicHost", func(t *testing.T) {
		// localhost typically resolves to 127.0.0.1, which is not safe unless TEST_MODE=1
		os.Unsetenv("TEST_MODE")
		_, err := ResolveSafeIP(ctx, "localhost")
		if err == nil {
			t.Error("expected error for localhost when TEST_MODE=0")
		}

		os.Setenv("TEST_MODE", "1")
		defer os.Unsetenv("TEST_MODE")

		ip, err := ResolveSafeIP(ctx, "localhost")
		if err != nil {
			t.Fatalf("expected no error for localhost in TEST_MODE=1, got %v", err)
		}
		if ip == nil {
			t.Fatal("expected an IP for localhost")
		}
	})

	t.Run("UnsafeHost", func(t *testing.T) {
		os.Unsetenv("TEST_MODE")
		_, err := ResolveSafeIP(ctx, "localhost")
		if err == nil {
			t.Fatal("expected error for unsafe host (localhost) when TEST_MODE=0")
		}
	})
}

func TestIsHostSafe(t *testing.T) {
	ctx := context.Background()

	t.Run("UnsafeHost", func(t *testing.T) {
		os.Unsetenv("TEST_MODE")
		safe, err := IsHostSafe(ctx, "localhost")
		if err != nil {
			t.Fatalf("IsHostSafe returned error: %v", err)
		}
		if safe {
			t.Fatal("expected IsHostSafe(localhost) to be false")
		}
	})

	t.Run("SafeHostInTestMode", func(t *testing.T) {
		os.Setenv("TEST_MODE", "1")
		defer os.Unsetenv("TEST_MODE")
		safe, err := IsHostSafe(ctx, "localhost")
		if err != nil {
			t.Fatalf("IsHostSafe returned error: %v", err)
		}
		if !safe {
			t.Fatal("expected IsHostSafe(localhost) to be true in TEST_MODE=1")
		}
	})
}
