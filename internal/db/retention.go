package db

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PurgeExpiredActivityLogs anonymizes or deletes logs that have passed their retention period.
func PurgeExpiredActivityLogs(ctx context.Context, pool *pgxpool.Pool) error {
	now := time.Now()
	
	// Anonymize IP address and User Agent for expired logs instead of full deletion
	// to keep audit trails while protecting PII.
	res, err := pool.Exec(ctx, `
		UPDATE user_activity_logs 
		SET ip_address = '[REDACTED]', user_agent = '[REDACTED]', deleted_at = $1
		WHERE retention_expires_at < $1 AND deleted_at IS NULL
	`, now)
	if err != nil {
		return err
	}
	
	if rows := res.RowsAffected(); rows > 0 {
		log.Printf("Retention: Purged/Anonymized %d expired activity logs", rows)
	}
	
	return nil
}

// EraseUserActivityLogs removes or anonymizes all activity logs for a specific user.
func EraseUserActivityLogs(ctx context.Context, pool *pgxpool.Pool, userID int) error {
	now := time.Now()
	_, err := pool.Exec(ctx, `
		UPDATE user_activity_logs 
		SET ip_address = '[REDACTED]', user_agent = '[REDACTED]', description = '[USER_ERASED]', deleted_at = $2
		WHERE user_id = $1 AND deleted_at IS NULL
	`, userID, now)
	return err
}
