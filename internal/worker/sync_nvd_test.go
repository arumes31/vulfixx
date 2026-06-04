package worker

import (
	"context"
	"errors"
	"testing"

	"github.com/pashagolub/pgxmock/v3"
	"github.com/jackc/pgx/v5"
)

func TestGetCWEID(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	ctx := context.Background()

	tests := []struct {
		name     string
		cweName  string
		mockFunc func()
		expected *int
	}{
		{
			name:    "Happy path - returns ID",
			cweName: "CWE-79",
			mockFunc: func() {
				mock.ExpectQuery("SELECT id FROM cwes WHERE name = \\$1").
					WithArgs("CWE-79").
					WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(42))
			},
			expected: ptr(42),
		},
		{
			name:    "Error path - row not found",
			cweName: "CWE-999",
			mockFunc: func() {
				mock.ExpectQuery("SELECT id FROM cwes WHERE name = \\$1").
					WithArgs("CWE-999").
					WillReturnError(pgx.ErrNoRows)
			},
			expected: nil,
		},
		{
			name:    "Error path - database connection error",
			cweName: "CWE-123",
			mockFunc: func() {
				mock.ExpectQuery("SELECT id FROM cwes WHERE name = \\$1").
					WithArgs("CWE-123").
					WillReturnError(errors.New("db connection failed"))
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockFunc()

			result := getCWEID(ctx, mock, tt.cweName)

			if tt.expected == nil {
				if result != nil {
					t.Errorf("getCWEID() = %v, want nil", result)
				}
			} else {
				if result == nil {
					t.Errorf("getCWEID() = nil, want %v", *tt.expected)
				} else if *result != *tt.expected {
					t.Errorf("getCWEID() = %v, want %v", *result, *tt.expected)
				}
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("there were unfulfilled expectations: %s", err)
			}
		})
	}
}

func ptr(i int) *int {
	return &i
}

func TestExtractCWEID(t *testing.T) {
	// Recreate the anonymous struct type used by extractCWEID
	type description struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	}
	type weakness struct {
		Description []description `json:"description"`
	}

	tests := []struct {
		name       string
		weaknesses []weakness
		expected   string
	}{
		{
			name: "Happy path - first weakness has CWE",
			weaknesses: []weakness{
				{
					Description: []description{
						{Lang: "en", Value: "CWE-79"},
					},
				},
			},
			expected: "CWE-79",
		},
		{
			name:       "Empty weaknesses list",
			weaknesses: []weakness{},
			expected:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var arg []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			}

			for _, w := range tt.weaknesses {
				var descArg []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}
				for _, d := range w.Description {
					descArg = append(descArg, struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					}{
						Lang:  d.Lang,
						Value: d.Value,
					})
				}
				arg = append(arg, struct {
					Description []struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					} `json:"description"`
				}{
					Description: descArg,
				})
			}

			result := extractCWEID(arg)
			if result != tt.expected {
				t.Errorf("extractCWEID() = %v, want %v", result, tt.expected)
			}
		})
	}
}
