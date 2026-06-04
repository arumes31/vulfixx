package web

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindTemplatesDir(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a templates directory deep inside
	targetDir := filepath.Join(tmpDir, "a", "b", "c", "d")
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		t.Fatalf("failed to create target dir: %v", err)
	}

	templatesDir := filepath.Join(tmpDir, "templates")
	if err := os.MkdirAll(templatesDir, 0755); err != nil {
		t.Fatalf("failed to create templates dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(templatesDir, "test.html"), []byte("<html></html>"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// Change to targetDir
	t.Chdir(targetDir)

	found := findTemplatesDir()
	if found == "" {
		t.Fatal("expected to find templates directory")
	}

	absTemplatesDir, _ := filepath.Abs(templatesDir)
	if found != absTemplatesDir {
		t.Errorf("expected %s, got %s", absTemplatesDir, found)
	}
}

func TestInitTemplatesWithFuncs(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		tmpDir := t.TempDir()
		templatesDir := filepath.Join(tmpDir, "templates")
		os.MkdirAll(templatesDir, 0755)

		os.WriteFile(filepath.Join(templatesDir, "base.html"), []byte("{{define \"base\"}}BASE{{template \"content\" .}}END{{end}}"), 0644)
		os.WriteFile(filepath.Join(templatesDir, "page.html"), []byte("{{define \"content\"}}PAGE{{end}}"), 0644)

		t.Chdir(tmpDir)

		app := &App{}
		err := app.InitTemplatesWithFuncs()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if len(app.TemplateMap) != 1 {
			t.Errorf("expected 1 template, got %d", len(app.TemplateMap))
		}
		if _, ok := app.TemplateMap["page.html"]; !ok {
			t.Error("expected page.html in TemplateMap")
		}
	})

	t.Run("NoTemplatesDir", func(t *testing.T) {
		tmpDir := t.TempDir()
		t.Chdir(tmpDir)

		app := &App{}
		err := app.InitTemplatesWithFuncs()
		if err == nil {
			t.Fatal("expected error when no templates dir found")
		}
	})

	t.Run("InvalidTemplate", func(t *testing.T) {
		tmpDir := t.TempDir()
		templatesDir := filepath.Join(tmpDir, "templates")
		os.MkdirAll(templatesDir, 0755)

		os.WriteFile(filepath.Join(templatesDir, "base.html"), []byte("{{define \"base\"}}BASE{{template \"content\" .}}END{{end}}"), 0644)
		os.WriteFile(filepath.Join(templatesDir, "invalid.html"), []byte("{{define \"content\"}}{{end"), 0644)
		os.WriteFile(filepath.Join(templatesDir, "valid.html"), []byte("{{define \"content\"}}VALID{{end}}"), 0644)

		t.Chdir(tmpDir)

		app := &App{}
		err := app.InitTemplatesWithFuncs()
		if err != nil {
			t.Fatalf("expected no error overall even if one template fails, got %v", err)
		}

		if len(app.TemplateMap) != 1 {
			t.Errorf("expected 1 valid template, got %d", len(app.TemplateMap))
		}
	})
}
