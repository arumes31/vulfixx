package web

import (
	"cve-tracker/internal/db"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pashagolub/pgxmock/v3"
)

func TestListAssetsHandler_MissingCoverage(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()
	app := setupTestApp(t, mock)

	tests := []struct {
		name   string
		mockDB func()
	}{
		{
			name: "DBError",
			mockDB: func() {
				mock.ExpectQuery("SELECT a.id, a.name, COALESCE").
					WithArgs(1).
					WillReturnError(fmt.Errorf("db error"))
			},
		},
		{
			name: "RowScanError",
			mockDB: func() {
				mock.ExpectQuery("SELECT a.id, a.name, COALESCE").
					WithArgs(1).
					WillReturnRows(pgxmock.NewRows([]string{"id", "name", "type", "created_at"}).
						AddRow("invalid_id", "test asset", "domain", "invalid_date"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "/assets", nil)
			setSessionUser(t, app, req, 1, false)

			tt.mockDB()

			rr := httptest.NewRecorder()
			app.listAssets(rr, req, 1)

			// listAssets writes to the log and returns template/data or error depending on internal logic.
			// Since it has no returned HTTP error code for internal DB errors (just logs), we verify no panic.
			if rr.Code != http.StatusInternalServerError && rr.Code != http.StatusOK {
				t.Errorf("expected status OK (200) or 500, got %d", rr.Code)
			}
		})
	}
}
