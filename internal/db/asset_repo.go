package db

import (
	"context"
	"cve-tracker/internal/models"
	"fmt"
	"time"
)

type AssetRepository interface {
	ListAssets(ctx context.Context, userID int) ([]models.AssetWithKeywords, error)
	CreateAsset(ctx context.Context, params models.CreateAssetParams) (int, error)
	DeleteAsset(ctx context.Context, assetID int, userID int) (int64, error)
}

type assetRepo struct {
	pool DBPool
}

func NewAssetRepository(pool DBPool) AssetRepository {
	return &assetRepo{pool: pool}
}

func (r *assetRepo) ListAssets(ctx context.Context, userID int) ([]models.AssetWithKeywords, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT a.id, a.name, COALESCE(a.type, ''), a.priority, a.created_at,
		       COALESCE(array_agg(ak.keyword) FILTER (WHERE ak.keyword IS NOT NULL), '{}'),
		       COALESCE(t.name, '') as team_name
		FROM assets a
		LEFT JOIN asset_keywords ak ON a.id = ak.asset_id
		LEFT JOIN teams t ON a.team_id = t.id
		WHERE a.user_id = $1 OR a.team_id IN (SELECT team_id FROM team_members WHERE user_id = $1)
		GROUP BY a.id, t.id, t.name
		ORDER BY a.created_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var assets []models.AssetWithKeywords
	for rows.Next() {
		var as models.AssetWithKeywords
		var createdAt time.Time
		if err := rows.Scan(&as.ID, &as.Name, &as.Type, &as.Priority, &createdAt, &as.Keywords, &as.TeamName); err != nil {
			return nil, err
		}
		as.CreatedAt = createdAt.Format(time.RFC3339)
		assets = append(assets, as)
	}
	return assets, rows.Err()
}

func (r *assetRepo) CreateAsset(ctx context.Context, params models.CreateAssetParams) (int, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Enforce Quota
	var currentCount int
	var maxAssets int
	if params.TeamID != nil {
		// Verify membership inside transaction
		var exists bool
		err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2)", *params.TeamID, params.UserID).Scan(&exists)
		if err != nil {
			return 0, err
		}
		if !exists {
			return 0, fmt.Errorf("permission denied")
		}

		err = tx.QueryRow(ctx, "SELECT max_assets FROM teams WHERE id = $1 FOR UPDATE", *params.TeamID).Scan(&maxAssets)
		if err != nil {
			return 0, err
		}
		err = tx.QueryRow(ctx, "SELECT COUNT(*) FROM assets WHERE team_id = $1", *params.TeamID).Scan(&currentCount)
	} else {
		err = tx.QueryRow(ctx, "SELECT max_assets FROM users WHERE id = $1 FOR UPDATE", params.UserID).Scan(&maxAssets)
		if err != nil {
			return 0, err
		}
		err = tx.QueryRow(ctx, "SELECT COUNT(*) FROM assets WHERE user_id = $1 AND team_id IS NULL", params.UserID).Scan(&currentCount)
	}
	if err != nil {
		return 0, err
	}

	if currentCount >= maxAssets {
		entity := "account"
		if params.TeamID != nil {
			entity = "team"
		}
		return 0, fmt.Errorf("maximum of %d assets allowed for this %s", maxAssets, entity)
	}

	var assetID int
	err = tx.QueryRow(ctx, `
		INSERT INTO assets (user_id, team_id, name, type, priority) VALUES ($1, $2, $3, $4, $5) RETURNING id
	`, params.UserID, params.TeamID, params.Name, params.AssetType, params.Priority).Scan(&assetID)
	if err != nil {
		return 0, err
	}

	for _, kw := range params.Keywords {
		if kw == "" {
			continue
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO asset_keywords (asset_id, keyword) VALUES ($1, $2)
			ON CONFLICT DO NOTHING
		`, assetID, kw)
		if err != nil {
			return 0, err
		}
	}

	if err = tx.Commit(ctx); err != nil {
		return 0, err
	}

	return assetID, nil
}

func (r *assetRepo) DeleteAsset(ctx context.Context, assetID int, userID int) (int64, error) {
	commandTag, err := r.pool.Exec(ctx, "DELETE FROM assets WHERE id = $1 AND (user_id = $2 OR team_id IN (SELECT team_id FROM team_members WHERE user_id = $2 AND role IN ('owner', 'admin')))", assetID, userID)
	if err != nil {
		return 0, err
	}
	return commandTag.RowsAffected(), nil
}
