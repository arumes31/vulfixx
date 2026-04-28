package mocks

import (
	"context"
	"errors"
	"fmt"
	"io"

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

// emptyRows is a no-op pgx.Rows implementation returned when no QueryFunc or InjectedErr is set.
type emptyRows struct{}

func (e emptyRows) Close()                                       {}
func (e emptyRows) Err() error                                   { return nil }
func (e emptyRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (e emptyRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (e emptyRows) Next() bool                                   { return false }
func (e emptyRows) Scan(dest ...any) error                       { return nil }
func (e emptyRows) Values() ([]any, error)                       { return nil, nil }
func (e emptyRows) RawValues() [][]byte                          { return nil }
func (e emptyRows) Conn() *pgx.Conn                              { return nil }

func (m *DBPoolMock) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if m.InjectedErr != nil {
		return nil, m.InjectedErr
	}
	if m.QueryFunc != nil {
		return m.QueryFunc(ctx, sql, args...)
	}
	return emptyRows{}, nil
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

// noopTx is a minimal pgx.Tx that satisfies the interface without panicking.
type noopTx struct{}

func (t noopTx) Begin(ctx context.Context) (pgx.Tx, error)                                     { return noopTx{}, nil }
func (t noopTx) Commit(ctx context.Context) error                                               { return nil }
func (t noopTx) Rollback(ctx context.Context) error                                             { return nil }
func (t noopTx) CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error) {
	return 0, errors.New("noopTx: CopyFrom not implemented")
}
func (t noopTx) SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults {
	return noopBatchResults{}
}

type noopBatchResults struct{}

func (n noopBatchResults) Exec() (pgconn.CommandTag, error) { return pgconn.CommandTag{}, nil }
func (n noopBatchResults) Query() (pgx.Rows, error)          { return emptyRows{}, nil }
func (n noopBatchResults) QueryRow() pgx.Row                { return errorRow{err: nil} }
func (n noopBatchResults) QueryRowContext(ctx context.Context) pgx.Row {
	return errorRow{err: nil}
}
func (n noopBatchResults) Close() error { return nil }
func (n noopBatchResults) Err() error   { return nil }
func (t noopTx) LargeObjects() pgx.LargeObjects                                                { return pgx.LargeObjects{} }
func (t noopTx) Prepare(ctx context.Context, name, sql string) (*pgconn.StatementDescription, error) {
	return nil, errors.New("noopTx: Prepare not implemented")
}
func (t noopTx) Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}
func (t noopTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return emptyRows{}, nil
}
func (t noopTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return errorRow{err: nil}
}
func (t noopTx) Conn() *pgx.Conn { return nil }

// Satisfy the pgx.Tx interface; these are needed by older versions of pgx.
// Use a blank _ to ensure the interface is satisfied at compile-time.
var _ pgx.Tx = noopTx{}
var _ io.Closer = noopCloser{}

type noopCloser struct{}

func (noopCloser) Close() error { return nil }

func (m *DBPoolMock) Begin(ctx context.Context) (pgx.Tx, error) {
	if m.InjectedErr != nil {
		return noopTx{}, m.InjectedErr
	}
	if m.BeginFunc != nil {
		return m.BeginFunc(ctx)
	}
	// Return a safe no-op Tx instead of (nil, nil) to prevent nil-pointer panics in callers.
	return noopTx{}, fmt.Errorf("BeginFunc not set")
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
