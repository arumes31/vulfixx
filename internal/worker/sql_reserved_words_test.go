package worker

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// sqlLineRegex picks out lines that look like they carry SQL.
var sqlLineRegex = regexp.MustCompile(`(?i)\b(SELECT|INSERT INTO|UPDATE|DELETE FROM)\b`)

// unquotedReferences matches the column `references` used bare in SQL. It is a reserved
// word in Postgres and must be written \"references\" inside a Go string literal.
//
// This is not hypothetical: two queries in cron_worker.go shipped with it unquoted and
// were parse errors, so the intelligence-enrichment worker's per-CVE lookup never once
// succeeded. Postgres logged 5,250 copies of
//
//	ERROR: syntax error at or near "references"
//
// in a single session. The unit tests did not catch it because pgxmock matches query
// strings by regexp and never parses them, so a syntactically invalid statement passes
// every mock-based test.
var unquotedReferences = regexp.MustCompile(`(^|[ ,(])references($|[ ,)])`)

// Reserved words used as column names must be quoted in every SQL string in this
// package. Only `references` is checked today because it is the only reserved word the
// schema uses as a column name.
func TestNoUnquotedReservedWordsInSQL(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}

	for _, file := range files {
		body, err := os.ReadFile(file) // #nosec G304 -- test-only, path from our own glob
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		for i, line := range strings.Split(string(body), "\n") {
			if !sqlLineRegex.MatchString(line) {
				continue
			}
			// Ignore the escaped form, which is what correct code looks like.
			stripped := strings.ReplaceAll(line, `\"references\"`, "")
			if !unquotedReferences.MatchString(stripped) {
				continue
			}
			// Comments describing column lists are not SQL.
			if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "//") {
				continue
			}
			t.Errorf(`%s:%d uses bare "references" in SQL; it is a reserved word in `+
				`Postgres and must be written \"references\". pgxmock will not catch `+
				`this — it never parses the statement.`, file, i+1)
		}
	}
}
