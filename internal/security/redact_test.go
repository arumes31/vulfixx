package security

import "testing"

func TestMaskEmail(t *testing.T) {
	tests := []struct {
		email    string
		expected string
	}{
		{"test@example.com", "te****@example.com"},
		{"a@b.com", "*@b.com"},
		{"ab@c.com", "*@c.com"},
		{"abc@d.com", "ab****@d.com"},
		{"invalid", "[invalid-email]"},
		{"too@many@parts", "[invalid-email]"},
		{"", "[invalid-email]"},
	}

	for _, tt := range tests {
		got := MaskEmail(tt.email)
		if got != tt.expected {
			t.Errorf("MaskEmail(%q) = %q, want %q", tt.email, got, tt.expected)
		}
	}
}
