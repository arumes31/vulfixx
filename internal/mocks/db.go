package mocks

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// DBPoolMock is a mock implementation of db.DBPool.
type DBPoolMock struct {
	ExecFunc     func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	QueryFunc    func(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRowFunc func(ctx context.Context, sql string, args ...any) pgx.Row
	BeginFunc    func(ctx context.Context) (pgx.Tx, error)
	CloseFunc    func()
	PingFunc     func(ctx context.Context) error

	// Helper for simple error injection
	InjectedErr error
}

func (m *DBPoolMock) Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
	if m.InjectedErr != nil {
		return pgconn.CommandTag{}, m.InjectedErr
	}
	if m.ExecFunc != nil {
		return m.ExecFunc(ctx, sql, arguments...)
	}
	return pgconn.CommandTag{}, nil
}

func (m *DBPoolMock) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if m.InjectedErr != nil {
		return nil, m.InjectedErr
	}
	if m.QueryFunc != nil {
		return m.QueryFunc(ctx, sql, args...)
	}
	return nil, nil
}

// errorRow implements pgx.Row and always returns the stored error from Scan.
type errorRow struct{ err error }

func (e errorRow) Scan(dest ...any) error { return e.err }

func (m *DBPoolMock) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if m.InjectedErr != nil {
		return errorRow{err: m.InjectedErr}
	}
	if m.QueryRowFunc != nil {
		return m.QueryRowFunc(ctx, sql, args...)
	}
	return errorRow{err: nil}
}

func (m *DBPoolMock) Begin(ctx context.Context) (pgx.Tx, error) {
	if m.InjectedErr != nil {
		return nil, m.InjectedErr
	}
	if m.BeginFunc != nil {
		return m.BeginFunc(ctx)
	}
	return nil, nil
}

func (m *DBPoolMock) Close() {
	if m.CloseFunc != nil {
		m.CloseFunc()
	}
}

func (m *DBPoolMock) Ping(ctx context.Context) error {
	if m.InjectedErr != nil {
		return m.InjectedErr
	}
	if m.PingFunc != nil {
		return m.PingFunc(ctx)
	}
	return nil
}
