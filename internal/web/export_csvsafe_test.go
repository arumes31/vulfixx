package web

import (
	"encoding/csv"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v5"
)

func TestCSVSafe(t *testing.T) {
	cases := map[string]string{
		"":                        "",
		"plain text":              "plain text",
		"CVE-2024-1234":           "CVE-2024-1234",
		"=1+1":                    "'=1+1",
		"+cmd":                    "'+cmd",
		"-2+3":                    "'-2+3",
		"@SUM(A1)":                "'@SUM(A1)",
		"\t=1":                    "'\t=1",
		"\r=1":                    "'\r=1",
		"a =HYPERLINK(\"x\")":     "a =HYPERLINK(\"x\")",
		"=HYPERLINK(\"x\",\"y\")": "'=HYPERLINK(\"x\",\"y\")",
	}
	for in, want := range cases {
		if got := csvSafe(in); got != want {
			t.Errorf("csvSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExportCVEsHandler_NeutralizesFormulaCells(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()
	app := setupTestApp(t, mock)

	req, _ := http.NewRequest("GET", "/export", nil)
	setSessionUser(t, app, req, 1, false)

	mock.ExpectQuery(`(?is)SELECT DISTINCT c.cve_id,.*priority`).
		WithArgs(1).
		WillReturnRows(pgxmock.NewRows([]string{"cve_id", "description", "cvss_score", "cisa_kev", "published_date", "priority"}).
			AddRow("CVE-2023-0001", "=1+1", 9.8, true, time.Now(), "P0"))

	rr := httptest.NewRecorder()
	app.ExportCVEsHandler(rr, req)

	records, err := csv.NewReader(strings.NewReader(rr.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("failed to parse CSV: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected header + 1 row, got %d records", len(records))
	}
	if got := records[1][1]; got != "'=1+1" {
		t.Errorf("description cell = %q, want neutralized \"'=1+1\"", got)
	}
}
