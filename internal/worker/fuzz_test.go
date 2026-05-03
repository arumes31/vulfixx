package worker

import (
	"testing"
)

func FuzzParseNVDDate(f *testing.F) {
	f.Add("2023-04-29T10:00:00.123Z")
	f.Add("2023-04-29T10:00:00Z")
	f.Add("2003-12-31T05:00:00.000")
	f.Add("2003-12-31T05:00:00")
	f.Add("not-a-date")
	f.Add("")

	f.Fuzz(func(t *testing.T, dateStr string) {
		_, _ = parseNVDDate(dateStr)
	})
}
