package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v3"
)

func TestNewAssetRepository(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create pgxmock: %v", err)
	}
	defer mock.Close()

	repo := NewAssetRepository(mock)
	if repo == nil {
		t.Error("expected NewAssetRepository to return non-nil instance")
	}
}

func TestListAssets(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create pgxmock: %v", err)
		}
		defer mock.Close()

		repo := NewAssetRepository(mock)
		ctx := context.Background()
		userID := 42

		columns := []string{"id", "name", "type", "priority", "created_at", "keywords", "team_name"}
		createdAt := time.Now()
		rows := pgxmock.NewRows(columns).
			AddRow(1, "Server A", "Server", "High", createdAt, []string{"prod", "web"}, "Team 1").
			AddRow(2, "DB B", "", "Critical", createdAt.Add(-time.Hour), []string{"db"}, "")

		mock.ExpectQuery(`SELECT a.id, a.name, COALESCE\(a.type, ''\), a.priority, a.created_at`).
			WithArgs(userID).
			WillReturnRows(rows)

		assets, err := repo.ListAssets(ctx, userID)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if len(assets) != 2 {
			t.Errorf("expected 2 assets, got %d", len(assets))
		}

		if assets[0].ID != 1 || assets[0].Name != "Server A" || assets[0].Type != "Server" || assets[0].Priority != "High" || assets[0].TeamName != "Team 1" {
			t.Errorf("unexpected asset [0]: %+v", assets[0])
		}
		if assets[1].ID != 2 || assets[1].Name != "DB B" || assets[1].Type != "" || assets[1].Priority != "Critical" || assets[1].TeamName != "" {
			t.Errorf("unexpected asset [1]: %+v", assets[1])
		}
	})

	t.Run("QueryError", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create pgxmock: %v", err)
		}
		defer mock.Close()

		repo := NewAssetRepository(mock)
		ctx := context.Background()
		userID := 42

		mock.ExpectQuery(`SELECT a.id, a.name, COALESCE\(a.type, ''\), a.priority, a.created_at`).
			WithArgs(userID).
			WillReturnError(fmt.Errorf("forced query error"))

		_, err = repo.ListAssets(ctx, userID)
		if err == nil || err.Error() != "forced query error" {
			t.Errorf("expected 'forced query error', got: %v", err)
		}
	})

	t.Run("ScanError", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create pgxmock: %v", err)
		}
		defer mock.Close()

		repo := NewAssetRepository(mock)
		ctx := context.Background()
		userID := 42

		columns := []string{"id", "name", "type", "priority", "created_at", "keywords", "team_name"}
		// Pass an incompatible string type to the ID field to force Scan to fail
		rows := pgxmock.NewRows(columns).AddRow("not-an-int", "Server A", "Server", "High", time.Now(), []string{"prod"}, "Team 1")

		mock.ExpectQuery(`SELECT a.id, a.name, COALESCE\(a.type, ''\), a.priority, a.created_at`).
			WithArgs(userID).
			WillReturnRows(rows)

		_, err = repo.ListAssets(ctx, userID)
		if err == nil {
			t.Error("expected error during row scan, got nil")
		}
	})
}

func TestCreateAsset(t *testing.T) {
	t.Run("BeginTransactionFailure", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create pgxmock: %v", err)
		}
		defer mock.Close()

		repo := NewAssetRepository(mock)
		ctx := context.Background()

		mock.ExpectBegin().WillReturnError(fmt.Errorf("begin error"))

		_, err = repo.CreateAsset(ctx, 42, nil, "Server A", "Server", "High", nil)
		if err == nil || err.Error() != "begin error" {
			t.Errorf("expected 'begin error', got %v", err)
		}
	})

	t.Run("TeamMode_PermissionDenied", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create pgxmock: %v", err)
		}
		defer mock.Close()

		repo := NewAssetRepository(mock)
		ctx := context.Background()
		userID := 42
		teamID := 10

		mock.ExpectBegin()
		mock.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM team_members WHERE team_id = \$1 AND user_id = \$2\)`).
			WithArgs(teamID, userID).
			WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(false))
		mock.ExpectRollback()

		_, err = repo.CreateAsset(ctx, userID, &teamID, "Server A", "Server", "High", nil)
		if err == nil || err.Error() != "permission denied" {
			t.Errorf("expected 'permission denied', got %v", err)
		}
	})

	t.Run("TeamMode_MembershipQueryError", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create pgxmock: %v", err)
		}
		defer mock.Close()

		repo := NewAssetRepository(mock)
		ctx := context.Background()
		userID := 42
		teamID := 10

		mock.ExpectBegin()
		mock.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM team_members WHERE team_id = \$1 AND user_id = \$2\)`).
			WithArgs(teamID, userID).
			WillReturnError(fmt.Errorf("db error"))
		mock.ExpectRollback()

		_, err = repo.CreateAsset(ctx, userID, &teamID, "Server A", "Server", "High", nil)
		if err == nil || err.Error() != "db error" {
			t.Errorf("expected 'db error', got %v", err)
		}
	})

	t.Run("TeamMode_QuotaExceeded", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create pgxmock: %v", err)
		}
		defer mock.Close()

		repo := NewAssetRepository(mock)
		ctx := context.Background()
		userID := 42
		teamID := 10

		mock.ExpectBegin()
		mock.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM team_members WHERE team_id = \$1 AND user_id = \$2\)`).
			WithArgs(teamID, userID).
			WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))

		mock.ExpectQuery(`SELECT max_assets FROM teams WHERE id = \$1 FOR UPDATE`).
			WithArgs(teamID).
			WillReturnRows(pgxmock.NewRows([]string{"max_assets"}).AddRow(5))

		mock.ExpectQuery(`SELECT COUNT\(\*\) FROM assets WHERE team_id = \$1`).
			WithArgs(teamID).
			WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(5))

		mock.ExpectRollback()

		_, err = repo.CreateAsset(ctx, userID, &teamID, "Server A", "Server", "High", nil)
		if err == nil || err.Error() != "maximum of 5 assets allowed for this team" {
			t.Errorf("expected quota exceeded error, got %v", err)
		}
	})

	t.Run("UserMode_QuotaExceeded", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create pgxmock: %v", err)
		}
		defer mock.Close()

		repo := NewAssetRepository(mock)
		ctx := context.Background()
		userID := 42

		mock.ExpectBegin()
		mock.ExpectQuery(`SELECT max_assets FROM users WHERE id = \$1 FOR UPDATE`).
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"max_assets"}).AddRow(3))

		mock.ExpectQuery(`SELECT COUNT\(\*\) FROM assets WHERE user_id = \$1 AND team_id IS NULL`).
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(3))

		mock.ExpectRollback()

		_, err = repo.CreateAsset(ctx, userID, nil, "Server A", "Server", "High", nil)
		if err == nil || err.Error() != "maximum of 3 assets allowed for this account" {
			t.Errorf("expected quota exceeded error, got %v", err)
		}
	})

	t.Run("InsertAssetError", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create pgxmock: %v", err)
		}
		defer mock.Close()

		repo := NewAssetRepository(mock)
		ctx := context.Background()
		userID := 42

		mock.ExpectBegin()
		mock.ExpectQuery(`SELECT max_assets FROM users WHERE id = \$1 FOR UPDATE`).
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"max_assets"}).AddRow(3))

		mock.ExpectQuery(`SELECT COUNT\(\*\) FROM assets WHERE user_id = \$1 AND team_id IS NULL`).
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(1))

		mock.ExpectQuery(`INSERT INTO assets`).
			WithArgs(userID, pgxmock.AnyArg(), "Server A", "Server", "High").
			WillReturnError(fmt.Errorf("insert failed"))

		mock.ExpectRollback()

		_, err = repo.CreateAsset(ctx, userID, nil, "Server A", "Server", "High", nil)
		if err == nil || err.Error() != "insert failed" {
			t.Errorf("expected 'insert failed', got %v", err)
		}
	})

	t.Run("InsertKeywordsError", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create pgxmock: %v", err)
		}
		defer mock.Close()

		repo := NewAssetRepository(mock)
		ctx := context.Background()
		userID := 42

		mock.ExpectBegin()
		mock.ExpectQuery(`SELECT max_assets FROM users WHERE id = \$1 FOR UPDATE`).
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"max_assets"}).AddRow(3))

		mock.ExpectQuery(`SELECT COUNT\(\*\) FROM assets WHERE user_id = \$1 AND team_id IS NULL`).
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(1))

		mock.ExpectQuery(`INSERT INTO assets`).
			WithArgs(userID, pgxmock.AnyArg(), "Server A", "Server", "High").
			WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(100))

		mock.ExpectExec(`INSERT INTO asset_keywords`).
			WithArgs(100, "prod").
			WillReturnError(fmt.Errorf("keyword insert failed"))

		mock.ExpectRollback()

		_, err = repo.CreateAsset(ctx, userID, nil, "Server A", "Server", "High", []string{"prod"})
		if err == nil || err.Error() != "keyword insert failed" {
			t.Errorf("expected 'keyword insert failed', got %v", err)
		}
	})

	t.Run("Success_UserMode", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create pgxmock: %v", err)
		}
		defer mock.Close()

		repo := NewAssetRepository(mock)
		ctx := context.Background()
		userID := 42

		mock.ExpectBegin()
		mock.ExpectQuery(`SELECT max_assets FROM users WHERE id = \$1 FOR UPDATE`).
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"max_assets"}).AddRow(3))

		mock.ExpectQuery(`SELECT COUNT\(\*\) FROM assets WHERE user_id = \$1 AND team_id IS NULL`).
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(1))

		mock.ExpectQuery(`INSERT INTO assets`).
			WithArgs(userID, pgxmock.AnyArg(), "Server A", "Server", "High").
			WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(100))

		// keywords has "prod", "web", and an empty "" keyword which should be skipped
		mock.ExpectExec(`INSERT INTO asset_keywords`).
			WithArgs(100, "prod").
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		mock.ExpectExec(`INSERT INTO asset_keywords`).
			WithArgs(100, "web").
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		mock.ExpectCommit()

		assetID, err := repo.CreateAsset(ctx, userID, nil, "Server A", "Server", "High", []string{"prod", "", "web"})
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if assetID != 100 {
			t.Errorf("expected assetID 100, got %d", assetID)
		}
	})
}

func TestDeleteAsset(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create pgxmock: %v", err)
		}
		defer mock.Close()

		repo := NewAssetRepository(mock)
		ctx := context.Background()
		assetID := 100
		userID := 42

		mock.ExpectExec(`DELETE FROM assets WHERE id = \$1 AND`).
			WithArgs(assetID, userID).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		rowsAffected, err := repo.DeleteAsset(ctx, assetID, userID)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if rowsAffected != 1 {
			t.Errorf("expected 1 row affected, got %d", rowsAffected)
		}
	})

	t.Run("Error", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create pgxmock: %v", err)
		}
		defer mock.Close()

		repo := NewAssetRepository(mock)
		ctx := context.Background()
		assetID := 100
		userID := 42

		mock.ExpectExec(`DELETE FROM assets WHERE id = \$1 AND`).
			WithArgs(assetID, userID).
			WillReturnError(fmt.Errorf("delete failed"))

		_, err = repo.DeleteAsset(ctx, assetID, userID)
		if err == nil || err.Error() != "delete failed" {
			t.Errorf("expected 'delete failed', got %v", err)
		}
	})
}
