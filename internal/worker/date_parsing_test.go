package worker

import (
	"testing"
	"time"
)

func TestParseNVDDate(t *testing.T) {
	tests := []struct {
		name    string
		dateStr string
		want    time.Time
		wantErr bool
	}{
		{
			name:    "RFC3339Nano",
			dateStr: "2023-04-29T10:00:00.123Z",
			want:    time.Date(2023, 4, 29, 10, 0, 0, 123000000, time.UTC),
			wantErr: false,
		},
		{
			name:    "RFC3339",
			dateStr: "2023-04-29T10:00:00Z",
			want:    time.Date(2023, 4, 29, 10, 0, 0, 0, time.UTC),
			wantErr: false,
		},
		{
			name:    "MissingTimezoneWithMillis",
			dateStr: "2003-12-31T05:00:00.000",
			want:    time.Date(2003, 12, 31, 5, 0, 0, 0, time.UTC),
			wantErr: false,
		},
		{
			name:    "MissingTimezoneNoMillis",
			dateStr: "2003-12-31T05:00:00",
			want:    time.Date(2003, 12, 31, 5, 0, 0, 0, time.UTC),
			wantErr: false,
		},
		{
			name:    "InvalidDate",
			dateStr: "not-a-date",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseNVDDate(tt.dateStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseNVDDate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !got.Equal(tt.want) {
				t.Errorf("parseNVDDate() got = %v, want %v", got, tt.want)
			}
		})
	}
}
