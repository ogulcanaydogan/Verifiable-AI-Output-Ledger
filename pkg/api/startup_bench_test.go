package api_test

import (
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ogulcanaydogan/vaol/pkg/api"
	vaolcrypto "github.com/ogulcanaydogan/vaol/pkg/crypto"
	"github.com/ogulcanaydogan/vaol/pkg/merkle"
	"github.com/ogulcanaydogan/vaol/pkg/signer"
	"github.com/ogulcanaydogan/vaol/pkg/store"
)

func BenchmarkServerStartupRestore(b *testing.B) {
	sig, err := signer.GenerateEd25519Signer()
	if err != nil {
		b.Fatalf("GenerateEd25519Signer: %v", err)
	}
	ver := signer.NewEd25519Verifier(sig.PublicKey())

	const totalRecords = 5000
	records := make([]*store.StoredRecord, 0, totalRecords)
	for i := 0; i < totalRecords; i++ {
		records = append(records, benchStartupStoredRecord(int64(i+1), i))
	}
	benchLogger := slog.New(slog.NewTextHandler(io.Discard, nil))

	b.Run("persisted_leaves_only", func(b *testing.B) {
		st := newStartupSequenceStore(records, nil)
		st.leaves = startupLeavesFromRecords(records)
		cfg := api.DefaultConfig()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			srv := api.NewServer(cfg, st, sig, []signer.Verifier{ver}, merkle.New(), nil, benchLogger)
			if err := srv.StartupError(); err != nil {
				b.Fatalf("startup error: %v", err)
			}
		}
	})

	b.Run("snapshot_plus_tail", func(b *testing.B) {
		st := newStartupSequenceStore(records, nil)
		st.leaves = startupLeavesFromRecords(records)
		st.snapshots = []*store.StoredMerkleSnapshot{
			startupSnapshotFromRecords(b, records, totalRecords-250),
		}
		cfg := api.DefaultConfig()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			srv := api.NewServer(cfg, st, sig, []signer.Verifier{ver}, merkle.New(), nil, benchLogger)
			if err := srv.StartupError(); err != nil {
				b.Fatalf("startup error: %v", err)
			}
		}
	})
}

func benchStartupStoredRecord(seq int64, index int) *store.StoredRecord {
	now := time.Unix(1700000000+int64(index), 0).UTC()
	return &store.StoredRecord{
		SequenceNumber:     seq,
		RequestID:          uuid.New(),
		TenantID:           "bench-tenant",
		Timestamp:          now,
		RecordHash:         vaolcrypto.SHA256Prefixed([]byte(fmt.Sprintf("bench-record-%d", index))),
		PreviousRecordHash: vaolcrypto.ZeroHash,
		MerkleLeafIndex:    int64(index),
	}
}
