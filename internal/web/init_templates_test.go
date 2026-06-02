package web

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitTemplatesWithFuncs(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		tmpDir := t.TempDir()
		t.Chdir(tmpDir)

		templatesDir := filepath.Join(tmpDir, "templates")
		if err := os.Mkdir(templatesDir, 0755); err != nil {
			t.Fatalf("failed to create templates dir: %v", err)
		}

		baseContent := "<html><body>{{block \"content\" .}}{{end}}</body></html>"
		indexContent := "{{define \"content\"}}<h1>Index</h1>{{end}}"

		if err := os.WriteFile(filepath.Join(templatesDir, "base.html"), []byte(baseContent), 0644); err != nil {
			t.Fatalf("failed to write base.html: %v", err)
		}
		if err := os.WriteFile(filepath.Join(templatesDir, "index.html"), []byte(indexContent), 0644); err != nil {
			t.Fatalf("failed to write index.html: %v", err)
		}

		app := &App{}
		err := app.InitTemplatesWithFuncs()
		if err != nil {
			t.Fatalf("InitTemplatesWithFuncs failed: %v", err)
		}

		app.TemplateMu.RLock()
		defer app.TemplateMu.RUnlock()

		if _, ok := app.TemplateMap["index.html"]; !ok {
			t.Error("expected index.html to be in TemplateMap")
		}
		if _, ok := app.TemplateMap["base.html"]; ok {
			t.Error("expected base.html to NOT be in TemplateMap as a key")
		}
	})

	t.Run("no templates dir", func(t *testing.T) {
		tmpDir := t.TempDir()
		t.Chdir(tmpDir)

		app := &App{}
		err := app.InitTemplatesWithFuncs()
		if err == nil {
			t.Fatal("expected error when no templates dir exists, got nil")
		}
	})
}

func TestFindTemplatesDir(t *testing.T) {
	t.Run("current directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		t.Chdir(tmpDir)

		templatesDir := filepath.Join(tmpDir, "templates")
		os.Mkdir(templatesDir, 0755)
		os.WriteFile(filepath.Join(templatesDir, "test.html"), []byte("test"), 0644)

		found := findTemplatesDir()
		absTemplatesDir, _ := filepath.Abs(templatesDir)
		if found != absTemplatesDir {
			t.Errorf("expected %s, got %s", absTemplatesDir, found)
		}
	})

	t.Run("parent directory", func(t *testing.T) {
		tmpDir := t.TempDir()

		templatesDir := filepath.Join(tmpDir, "templates")
		os.Mkdir(templatesDir, 0755)
		os.WriteFile(filepath.Join(templatesDir, "test.html"), []byte("test"), 0644)

		nestedDir := filepath.Join(tmpDir, "a", "b", "c")
		os.MkdirAll(nestedDir, 0755)
		t.Chdir(nestedDir)

		found := findTemplatesDir()
		absTemplatesDir, _ := filepath.Abs(templatesDir)
		if found != absTemplatesDir {
			t.Errorf("expected %s, got %s", absTemplatesDir, found)
		}
	})

	t.Run("too deep", func(t *testing.T) {
		tmpDir := t.TempDir()

		templatesDir := filepath.Join(tmpDir, "templates")
		os.Mkdir(templatesDir, 0755)
		os.WriteFile(filepath.Join(templatesDir, "test.html"), []byte("test"), 0644)

		nestedDir := filepath.Join(tmpDir, "1", "2", "3", "4", "5", "6")
		os.MkdirAll(nestedDir, 0755)
		t.Chdir(nestedDir)

		found := findTemplatesDir()
		if found != "" {
			t.Errorf("expected empty string for too deep nesting, got %s", found)
		}
	})

	t.Run("not found", func(t *testing.T) {
		tmpDir := t.TempDir()
		t.Chdir(tmpDir)

		found := findTemplatesDir()
		if found != "" {
			t.Errorf("expected empty string, got %s", found)
		}
	})
}
