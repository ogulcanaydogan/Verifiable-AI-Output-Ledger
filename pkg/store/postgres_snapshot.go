package store

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
)

func (s *PostgresStore) SaveMerkleSnapshot(ctx context.Context, snapshot *StoredMerkleSnapshot) error {
	if snapshot == nil {
		return fmt.Errorf("snapshot is required")
	}
	if snapshot.TreeSize < 0 {
		return fmt.Errorf("tree_size must be non-negative")
	}
	if snapshot.RootHash == "" {
		return fmt.Errorf("root_hash is required")
	}
	if len(snapshot.SnapshotPayload) == 0 {
		return fmt.Errorf("snapshot_payload is required")
	}

	compressedPayload, err := gzipCompress(snapshot.SnapshotPayload)
	if err != nil {
		return fmt.Errorf("compressing snapshot payload: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO merkle_snapshots (tree_size, root_hash, snapshot_payload)
		VALUES ($1, $2, $3)
	`, snapshot.TreeSize, snapshot.RootHash, compressedPayload)
	if err != nil {
		return fmt.Errorf("saving merkle snapshot: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetLatestMerkleSnapshot(ctx context.Context) (*StoredMerkleSnapshot, error) {
	var (
		treeSize          int64
		rootHash          string
		compressedPayload []byte
		createdAt         time.Time
	)

	err := s.pool.QueryRow(ctx, `
		SELECT tree_size, root_hash, snapshot_payload, created_at
		FROM merkle_snapshots
		ORDER BY id DESC
		LIMIT 1
	`).Scan(&treeSize, &rootHash, &compressedPayload, &createdAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying latest merkle snapshot: %w", err)
	}

	payload, err := gzipDecompress(compressedPayload)
	if err != nil {
		return nil, fmt.Errorf("decompressing merkle snapshot payload: %w", err)
	}

	return &StoredMerkleSnapshot{
		TreeSize:        treeSize,
		RootHash:        rootHash,
		SnapshotPayload: payload,
		CreatedAt:       createdAt,
	}, nil
}

func gzipCompress(in []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(in); err != nil {
		_ = gz.Close()
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func gzipDecompress(in []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(in))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	out, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return out, nil
}
