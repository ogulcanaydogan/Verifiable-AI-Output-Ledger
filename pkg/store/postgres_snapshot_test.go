package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestGzipCompressDecompressRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
	}{
		{"simple text", []byte("hello merkle snapshot")},
		{"empty", []byte{}},
		{"binary", []byte{0x00, 0x01, 0x02, 0xff, 0xfe}},
		{"json-like", []byte(`{"tree_size":42,"root_hash":"sha256:abc"}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			compressed, err := gzipCompress(tc.payload)
			if err != nil {
				t.Fatalf("gzipCompress error: %v", err)
			}
			got, err := gzipDecompress(compressed)
			if err != nil {
				t.Fatalf("gzipDecompress error: %v", err)
			}
			if !bytes.Equal(got, tc.payload) {
				t.Errorf("round-trip mismatch: got %q, want %q", got, tc.payload)
			}
		})
	}
}

func TestGzipCompressShrinksRepetitivePayload(t *testing.T) {
	payload := bytes.Repeat([]byte("verifiable-ai-output-ledger "), 256)

	compressed, err := gzipCompress(payload)
	if err != nil {
		t.Fatalf("gzipCompress error: %v", err)
	}
	if len(compressed) >= len(payload) {
		t.Errorf("expected compression to shrink repetitive payload: compressed=%d original=%d",
			len(compressed), len(payload))
	}

	got, err := gzipDecompress(compressed)
	if err != nil {
		t.Fatalf("gzipDecompress error: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Error("decompressed payload does not match original")
	}
}

func TestGzipDecompressRejectsInvalidData(t *testing.T) {
	if _, err := gzipDecompress([]byte("this is not gzip data")); err == nil {
		t.Error("expected error decompressing non-gzip data, got nil")
	}
}

func TestSaveMerkleSnapshotValidation(t *testing.T) {
	// Validation runs before any pool access, so a zero-value store with a nil
	// pool is sufficient to exercise the guard clauses without a database.
	s := &PostgresStore{}
	ctx := context.Background()

	cases := []struct {
		name     string
		snapshot *StoredMerkleSnapshot
		wantErr  string
	}{
		{"nil snapshot", nil, "snapshot is required"},
		{
			"negative tree size",
			&StoredMerkleSnapshot{TreeSize: -1, RootHash: "sha256:x", SnapshotPayload: []byte("p")},
			"tree_size must be non-negative",
		},
		{
			"empty root hash",
			&StoredMerkleSnapshot{TreeSize: 1, RootHash: "", SnapshotPayload: []byte("p")},
			"root_hash is required",
		},
		{
			"empty payload",
			&StoredMerkleSnapshot{TreeSize: 1, RootHash: "sha256:x", SnapshotPayload: nil},
			"snapshot_payload is required",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := s.SaveMerkleSnapshot(ctx, tc.snapshot)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestIsDuplicateKeyError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{
			"raw unique violation",
			errors.New("ERROR: duplicate key value violates unique constraint (SQLSTATE 23505)"),
			true,
		},
		{
			"wrapped unique violation",
			fmt.Errorf("inserting record: %w", errors.New("SQLSTATE 23505")),
			true,
		},
		{"unrelated error", errors.New("connection refused"), false},
		{"deadline exceeded", context.DeadlineExceeded, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDuplicateKeyError(tc.err); got != tc.want {
				t.Errorf("isDuplicateKeyError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestContainsString(t *testing.T) {
	cases := []struct {
		name   string
		s      string
		substr string
		want   bool
	}{
		{"full match", "23505", "23505", true},
		{"substring in middle", "SQLSTATE 23505 detail", "23505", true},
		{"substring at start", "23505 xyz", "23505", true},
		{"substring at end", "xyz 23505", "23505", true},
		{"not found", "23504", "23505", false},
		{"empty substr matches", "anything", "", true},
		{"substr longer than s", "23", "23505", false},
		{"both empty", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := containsString(tc.s, tc.substr); got != tc.want {
				t.Errorf("containsString(%q, %q) = %v, want %v", tc.s, tc.substr, got, tc.want)
			}
		})
	}
}

func TestSearchString(t *testing.T) {
	// searchString assumes len(s) >= len(substr) (its only caller guards that),
	// but it must still behave for the boundary and not-found cases.
	if !searchString("abc23505def", "23505") {
		t.Error("expected searchString to find embedded substring")
	}
	if searchString("abcdef", "xyz") {
		t.Error("expected searchString to report missing substring as false")
	}
	if !searchString("exact", "exact") {
		t.Error("expected searchString to match identical strings")
	}
}
