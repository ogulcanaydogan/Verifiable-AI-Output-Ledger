package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

type fakeFenceRow struct {
	scanFn func(dest ...any) error
}

func (r fakeFenceRow) Scan(dest ...any) error {
	if r.scanFn == nil {
		return nil
	}
	return r.scanFn(dest...)
}

type fakeFenceConn struct {
	tryLockValue bool
	tryLockErr   error
	unlockValue  bool
	unlockErr    error
	released     int
	queryCalls   []string
}

func (c *fakeFenceConn) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	c.queryCalls = append(c.queryCalls, sql)
	switch {
	case strings.Contains(sql, "pg_try_advisory_lock"):
		return fakeFenceRow{
			scanFn: func(dest ...any) error {
				if c.tryLockErr != nil {
					return c.tryLockErr
				}
				if len(dest) != 1 {
					return fmt.Errorf("expected single destination")
				}
				target, ok := dest[0].(*bool)
				if !ok {
					return fmt.Errorf("expected *bool destination")
				}
				*target = c.tryLockValue
				return nil
			},
		}
	case strings.Contains(sql, "pg_advisory_unlock"):
		return fakeFenceRow{
			scanFn: func(dest ...any) error {
				if c.unlockErr != nil {
					return c.unlockErr
				}
				if len(dest) != 1 {
					return fmt.Errorf("expected single destination")
				}
				target, ok := dest[0].(*bool)
				if !ok {
					return fmt.Errorf("expected *bool destination")
				}
				*target = c.unlockValue
				return nil
			},
		}
	default:
		return fakeFenceRow{
			scanFn: func(dest ...any) error {
				return fmt.Errorf("unexpected query: %s", sql)
			},
		}
	}
}

func (c *fakeFenceConn) Release() {
	c.released++
}

func TestAcquireWriterFenceOnConnSuccessAndRelease(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	conn := &fakeFenceConn{
		tryLockValue: true,
		unlockValue:  true,
	}

	lease, err := acquireWriterFenceOnConn(ctx, conn, 42)
	if err != nil {
		t.Fatalf("acquireWriterFenceOnConn returned error: %v", err)
	}
	if lease == nil {
		t.Fatal("expected non-nil lease")
	}

	if err := lease.Release(ctx); err != nil {
		t.Fatalf("lease release returned error: %v", err)
	}
	if conn.released != 1 {
		t.Fatalf("conn release count = %d, want 1", conn.released)
	}
}

func TestAcquireWriterFenceOnConnNotAcquired(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	conn := &fakeFenceConn{
		tryLockValue: false,
	}

	lease, err := acquireWriterFenceOnConn(ctx, conn, 99)
	if !errors.Is(err, ErrWriterFenceNotAcquired) {
		t.Fatalf("expected ErrWriterFenceNotAcquired, got: %v", err)
	}
	if lease != nil {
		t.Fatal("expected nil lease when lock is not acquired")
	}
}

func TestAcquireWriterFenceOnConnQueryError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	conn := &fakeFenceConn{
		tryLockErr: errors.New("query failed"),
	}

	lease, err := acquireWriterFenceOnConn(ctx, conn, 88)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "acquiring writer fence advisory lock") {
		t.Fatalf("unexpected error: %v", err)
	}
	if lease != nil {
		t.Fatal("expected nil lease")
	}
}

func TestPostgresWriterFenceLeaseReleaseIdempotent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	conn := &fakeFenceConn{
		unlockValue: true,
	}
	lease := &postgresWriterFenceLease{
		conn:   conn,
		lockID: 7,
	}

	if err := lease.Release(ctx); err != nil {
		t.Fatalf("first release returned error: %v", err)
	}
	if err := lease.Release(ctx); err != nil {
		t.Fatalf("second release returned error: %v", err)
	}
	if conn.released != 1 {
		t.Fatalf("conn release count = %d, want 1", conn.released)
	}
}

func TestPostgresWriterFenceLeaseReleaseUnlockFalse(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	conn := &fakeFenceConn{
		unlockValue: false,
	}
	lease := &postgresWriterFenceLease{
		conn:   conn,
		lockID: 11,
	}

	err := lease.Release(ctx)
	if err == nil {
		t.Fatal("expected unlock false error")
	}
	if !strings.Contains(err.Error(), "unlock returned false") {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn.released != 1 {
		t.Fatalf("conn release count = %d, want 1", conn.released)
	}
}
