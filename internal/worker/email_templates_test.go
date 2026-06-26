package worker

import (
	"strings"
	"testing"
)

func TestRenderEmailTemplate(t *testing.T) {
	tests := []struct {
		name        string
		title       string
		bodyTmpl    string
		data        interface{}
		expectErr   bool
		errContains string
		checkOutput func(t *testing.T, out string)
	}{
		{
			name:     "HappyPath",
			title:    "Welcome to Vulfixx",
			bodyTmpl: "<p>Hello {{.Name}}, welcome to the platform.</p>",
			data: map[string]string{
				"Name": "Alice",
			},
			expectErr: false,
			checkOutput: func(t *testing.T, out string) {
				if !strings.Contains(out, "Welcome to Vulfixx") {
					t.Errorf("expected output to contain title, got: %s", out)
				}
				if !strings.Contains(out, "Hello Alice, welcome to the platform.") {
					t.Errorf("expected output to contain rendered body, got: %s", out)
				}
				if !strings.Contains(out, "<div class=\"wrapper\">") {
					t.Errorf("expected output to contain layout, got: %s", out)
				}
			},
		},
		{
			name:        "TemplateParseError",
			title:       "Error Test",
			bodyTmpl:    "<p>Hello {{.Name}", // Missing closing brace
			data:        nil,
			expectErr:   true,
			errContains: "failed to parse inner email template",
		},
		{
			name:        "TemplateExecuteError",
			title:       "Execute Error",
			bodyTmpl:    "<p>Hello {{.User.Name}}</p>",
			data:        "not a struct or map", // Cannot evaluate field
			expectErr:   true,
			errContains: "failed to execute inner email template",
		},
		{
			name:     "SanitizationCheck",
			title:    "XSS Test",
			bodyTmpl: "<p>Hello {{.Name}} <script>alert('xss');</script></p>",
			data: map[string]string{
				"Name": "Bob",
			},
			expectErr: false,
			checkOutput: func(t *testing.T, out string) {
				if strings.Contains(out, "<script>") {
					t.Errorf("expected script tag to be sanitized out, got: %s", out)
				}
				if !strings.Contains(out, "Hello Bob") {
					t.Errorf("expected harmless content to remain, got: %s", out)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := RenderEmailTemplate(tt.title, tt.bodyTmpl, tt.data)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %q", tt.errContains, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.checkOutput != nil {
				tt.checkOutput(t, out)
			}
		})
	}
}
