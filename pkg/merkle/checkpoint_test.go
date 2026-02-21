package merkle

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ogulcanaydogan/vaol/pkg/signer"
)

func TestSignCheckpointValid(t *testing.T) {
	s, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer error: %v", err)
	}

	tree := New()
	for i := 0; i < 5; i++ {
		tree.Append([]byte(fmt.Sprintf("leaf-%d", i)))
	}

	cs := NewCheckpointSigner(s)
	cp, err := cs.SignCheckpoint(context.Background(), tree)
	if err != nil {
		t.Fatalf("SignCheckpoint error: %v", err)
	}

	if cp.TreeSize != 5 {
		t.Errorf("TreeSize = %d, want 5", cp.TreeSize)
	}
	if cp.RootHash != tree.Root() {
		t.Errorf("RootHash = %q, want %q", cp.RootHash, tree.Root())
	}
	if cp.Signature == "" {
		t.Error("Signature should not be empty")
	}
}

func TestSignCheckpointTimestamp(t *testing.T) {
	s, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer error: %v", err)
	}

	tree := New()
	tree.Append([]byte("leaf"))

	before := time.Now().UTC()
	cs := NewCheckpointSigner(s)
	cp, err := cs.SignCheckpoint(context.Background(), tree)
	if err != nil {
		t.Fatalf("SignCheckpoint error: %v", err)
	}
	after := time.Now().UTC()

	if cp.Timestamp.Before(before.Add(-time.Second)) || cp.Timestamp.After(after.Add(time.Second)) {
		t.Errorf("Timestamp %v not within expected range [%v, %v]", cp.Timestamp, before, after)
	}
}

func TestVerifyCheckpointValid(t *testing.T) {
	s, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer error: %v", err)
	}

	tree := New()
	for i := 0; i < 3; i++ {
		tree.Append([]byte(fmt.Sprintf("leaf-%d", i)))
	}

	cs := NewCheckpointSigner(s)
	cp, err := cs.SignCheckpoint(context.Background(), tree)
	if err != nil {
		t.Fatalf("SignCheckpoint error: %v", err)
	}

	verifier := signer.NewEd25519Verifier(s.PublicKey())
	if err := VerifyCheckpoint(context.Background(), cp, verifier); err != nil {
		t.Errorf("VerifyCheckpoint should pass: %v", err)
	}
}

func TestVerifyCheckpointTampered(t *testing.T) {
	s, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer error: %v", err)
	}

	tree := New()
	tree.Append([]byte("leaf"))

	cs := NewCheckpointSigner(s)
	cp, err := cs.SignCheckpoint(context.Background(), tree)
	if err != nil {
		t.Fatalf("SignCheckpoint error: %v", err)
	}

	cp.RootHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	verifier := signer.NewEd25519Verifier(s.PublicKey())
	if err := VerifyCheckpoint(context.Background(), cp, verifier); err == nil {
		t.Error("VerifyCheckpoint should fail with tampered root hash")
	}
}

func TestVerifyCheckpointWrongKey(t *testing.T) {
	signerA, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer A error: %v", err)
	}
	signerB, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer B error: %v", err)
	}

	tree := New()
	tree.Append([]byte("leaf"))

	cs := NewCheckpointSigner(signerA)
	cp, err := cs.SignCheckpoint(context.Background(), tree)
	if err != nil {
		t.Fatalf("SignCheckpoint error: %v", err)
	}

	// Verify with signer B's public key — should fail
	verifier := signer.NewEd25519Verifier(signerB.PublicKey())
	if err := VerifyCheckpoint(context.Background(), cp, verifier); err == nil {
		t.Error("VerifyCheckpoint should fail with wrong key")
	}
}

func TestVerifyCheckpointPreservesFields(t *testing.T) {
	s, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer error: %v", err)
	}

	tree := New()
	tree.Append([]byte("leaf"))

	cs := NewCheckpointSigner(s)
	cp, err := cs.SignCheckpoint(context.Background(), tree)
	if err != nil {
		t.Fatalf("SignCheckpoint error: %v", err)
	}

	originalSig := cp.Signature
	cp.RekorEntryID = "rekor-test-entry"

	verifier := signer.NewEd25519Verifier(s.PublicKey())
	_ = VerifyCheckpoint(context.Background(), cp, verifier)

	// Fields should be restored by the defer in VerifyCheckpoint
	if cp.Signature != originalSig {
		t.Errorf("Signature not restored: got %q, want %q", cp.Signature, originalSig)
	}
	if cp.RekorEntryID != "rekor-test-entry" {
		t.Errorf("RekorEntryID not restored: got %q, want rekor-test-entry", cp.RekorEntryID)
	}
}
