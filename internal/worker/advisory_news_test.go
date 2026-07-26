package worker

import (
	"context"
	"regexp"
	"testing"
	"time"

	"cve-tracker/internal/db"

	"github.com/pashagolub/pgxmock/v3"
)

func TestParseFeedDate(t *testing.T) {
	tests := []struct {
		name       string
		candidates []string
		wantZero   bool
		wantYear   int
	}{
		{"RSS 2.0 pubDate with zone", []string{"Thu, 02 May 2024 00:00:00 GMT"}, false, 2024},
		{"RSS 2.0 pubDate numeric zone", []string{"Mon, 15 Jan 2026 09:30:00 +0100"}, false, 2026},
		{"Atom RFC3339", []string{"2026-03-04T11:22:33Z"}, false, 2026},
		{"dc:date bare", []string{"2025-12-01"}, false, 2025},
		{"falls through to second candidate", []string{"", "2026-03-04T11:22:33Z"}, false, 2026},
		{"skips unparseable and uses next", []string{"not a date", "2025-12-01"}, false, 2025},
		{"all empty", []string{"", "  "}, true, 0},
		{"all unparseable", []string{"yesterday"}, true, 0},
		{"no candidates", nil, true, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseFeedDate(tt.candidates...)
			if tt.wantZero {
				if !got.IsZero() {
					t.Errorf("expected zero time, got %v", got)
				}
				return
			}
			if got.IsZero() {
				t.Fatal("expected a parsed time, got zero")
			}
			if got.Year() != tt.wantYear {
				t.Errorf("year: got %d want %d", got.Year(), tt.wantYear)
			}
		})
	}
}

func TestStripHTMLTags(t *testing.T) {
	tests := []struct{ in, want string }{
		{"<p>Hello <b>world</b></p>", "Hello world"},
		{"plain text", "plain text"},
		{"&lt;script&gt;alert(1)&lt;/script&gt;", "<script>alert(1)</script>"},
		{"a\n\n  b\tc", "a b c"},
		{"", ""},
		{"<a href=\"x\">link</a> &amp; more", "link & more"},
	}
	for _, tt := range tests {
		if got := stripHTMLTags(tt.in); got != tt.want {
			t.Errorf("stripHTMLTags(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// storeAdvisoryNews must issue no statement at all when nothing is worth storing,
// otherwise every empty feed would cost a round trip.
func TestStoreAdvisoryNews_NoStorableItems(t *testing.T) {
	cases := map[string][]GenericFeedItem{
		"no items":       {},
		"missing link":   {{Title: "Has title", Link: ""}},
		"missing title":  {{Title: "", Link: "https://example.com/a"}},
		"blank via trim": {{Title: "   ", Link: "  "}},
	}
	for name, items := range cases {
		t.Run(name, func(t *testing.T) {
			mock, err := db.SetupTestDB()
			if err != nil {
				t.Fatalf("setup mock db: %v", err)
			}
			defer mock.Close()
			w := NewWorker(mock, nil, nil, nil)

			// No ExpectExec registered: any statement fails the test.
			w.storeAdvisoryNews(context.Background(), AdvisoryFeed{Name: "Test Feed"}, items)

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet expectations: %v", err)
			}
		})
	}
}

func TestStoreAdvisoryNews_BatchesOneStatementPerFeed(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("setup mock db: %v", err)
	}
	defer mock.Close()
	w := NewWorker(mock, nil, nil, nil)

	// Three storable items must collapse into a single insert, not three.
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO advisory_news")).
		WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
			pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 3))

	items := []GenericFeedItem{
		{Title: "One", Link: "https://example.com/1", Description: "affects CVE-2026-1111"},
		{Title: "Two", Link: "https://example.com/2", Description: "<p>markup</p>"},
		{Title: "Three", Link: "https://example.com/3"},
		// Duplicate link inside a single feed document: ON CONFLICT does not cover
		// "cannot affect row a second time", so this must be filtered in Go.
		{Title: "One again", Link: "https://example.com/1"},
	}
	w.storeAdvisoryNews(context.Background(), AdvisoryFeed{Name: "Test Feed"}, items)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// capturePublished records the published_at slice passed to the insert so the test can
// assert on values pgxmock would otherwise only compare for equality.
type capturePublished struct{ got *[]time.Time }

func (c capturePublished) Match(v any) bool {
	ts, ok := v.([]time.Time)
	if !ok {
		return false
	}
	*c.got = ts
	return true
}

// A feed that post-dates an item must not be able to pin it to the top of the rail,
// and an item with no parseable date must fall back to now rather than the epoch.
func TestStoreAdvisoryNews_NormalisesPublishedAt(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("setup mock db: %v", err)
	}
	defer mock.Close()
	w := NewWorker(mock, nil, nil, nil)

	var got []time.Time
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO advisory_news")).
		WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
			capturePublished{got: &got}, pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 3))

	past := time.Now().UTC().Add(-48 * time.Hour)
	before := time.Now().UTC()
	w.storeAdvisoryNews(context.Background(), AdvisoryFeed{Name: "Test Feed"}, []GenericFeedItem{
		{Title: "Future", Link: "https://example.com/f", Published: time.Now().UTC().Add(72 * time.Hour)},
		{Title: "Undated", Link: "https://example.com/u"},
		{Title: "Past", Link: "https://example.com/p", Published: past},
	})
	after := time.Now().UTC()

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 published_at values, got %d", len(got))
	}
	if got[0].After(after) {
		t.Errorf("future date was not clamped: %v is after %v", got[0], after)
	}
	if got[1].Before(before) || got[1].After(after) {
		t.Errorf("undated item should fall back to now, got %v", got[1])
	}
	if !got[2].Equal(past) {
		t.Errorf("past date should be preserved verbatim: got %v want %v", got[2], past)
	}
}

func TestPruneAdvisoryNews(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("setup mock db: %v", err)
	}
	defer mock.Close()
	w := NewWorker(mock, nil, nil, nil)

	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM advisory_news")).
		WithArgs(pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("DELETE", 5))

	w.pruneAdvisoryNews(context.Background())

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}
