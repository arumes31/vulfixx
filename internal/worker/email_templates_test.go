package worker

import (
	"strings"
	"testing"
)

func TestRenderEmailTemplate(t *testing.T) {
	title := "Security Alert"
	bodyTmpl := "<p>Message for {{.Name}}: {{.Alert}}</p>"
	data := struct {
		Name  string
		Alert string
	}{
		Name:  "Admin",
		Alert: "<script>alert('xss')</script>",
	}

	res, err := RenderEmailTemplate(title, bodyTmpl, data)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if !strings.Contains(res, "Security Alert") {
		t.Errorf("Expected result to contain title, got: %s", res)
	}
	if strings.Contains(res, "<script>") {
		t.Errorf("Expected script tag to be escaped, but found in output: %s", res)
	}
	if !strings.Contains(res, "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;") {
		t.Errorf("Expected escaped alert in output, got: %s", res)
	}
}
