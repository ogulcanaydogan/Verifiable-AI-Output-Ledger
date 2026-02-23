package store

import (
	"context"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5"
)

type advisoryLockConn interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Release()
}

type postgresWriterFenceLease struct {
	mu       sync.Mutex
	conn     advisoryLockConn
	lockID   int64
	released bool
}

// AcquireWriterFence acquires a PostgreSQL advisory lock and returns a lease
// that must be held for process lifetime.
func (s *PostgresStore) AcquireWriterFence(ctx context.Context, lockID int64) (WriterFenceLease, error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquiring writer fence connection: %w", err)
	}

	lease, err := acquireWriterFenceOnConn(ctx, conn, lockID)
	if err != nil {
		conn.Release()
		return nil, err
	}
	return lease, nil
}

func acquireWriterFenceOnConn(ctx context.Context, conn advisoryLockConn, lockID int64) (WriterFenceLease, error) {
	var locked bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, lockID).Scan(&locked); err != nil {
		return nil, fmt.Errorf("acquiring writer fence advisory lock: %w", err)
	}
	if !locked {
		return nil, ErrWriterFenceNotAcquired
	}

	return &postgresWriterFenceLease{
		conn:   conn,
		lockID: lockID,
	}, nil
}

func (l *postgresWriterFenceLease) Release(ctx context.Context) error {
	l.mu.Lock()
	if l.released {
		l.mu.Unlock()
		return nil
	}
	conn := l.conn
	lockID := l.lockID
	l.conn = nil
	l.released = true
	l.mu.Unlock()

	if conn == nil {
		return nil
	}

	var unlocked bool
	err := conn.QueryRow(ctx, `SELECT pg_advisory_unlock($1)`, lockID).Scan(&unlocked)
	conn.Release()
	if err != nil {
		return fmt.Errorf("releasing writer fence advisory lock: %w", err)
	}
	if !unlocked {
		return fmt.Errorf("writer fence advisory unlock returned false for lock_id=%d", lockID)
	}
	return nil
}
