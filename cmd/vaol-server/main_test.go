package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ogulcanaydogan/vaol/pkg/signer"
	"github.com/ogulcanaydogan/vaol/pkg/store"
)

func TestBuildSignerEd25519Ephemeral(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	sig, verifiers, err := buildSignerAndVerifiers("ed25519", "", signer.SigstoreConfig{}, signer.KMSConfig{}, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if sig == nil {
		t.Fatal("expected non-nil signer")
	}
	if len(verifiers) != 1 {
		t.Fatalf("expected 1 verifier, got %d", len(verifiers))
	}
}

func TestBuildSignerEd25519FromPEM(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Generate a key and write it to a temp file.
	generated, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("generating signer: %v", err)
	}

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "key.pem")
	if err := signer.SavePrivateKeyPEM(generated.PrivateKey(), keyPath); err != nil {
		t.Fatalf("writing key: %v", err)
	}

	sig, verifiers, err := buildSignerAndVerifiers("ed25519", keyPath, signer.SigstoreConfig{}, signer.KMSConfig{}, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if sig == nil {
		t.Fatal("expected non-nil signer")
	}
	if len(verifiers) != 1 {
		t.Fatalf("expected 1 verifier, got %d", len(verifiers))
	}
	if sig.KeyID() != generated.KeyID() {
		t.Fatalf("key ID mismatch: got %q, want %q", sig.KeyID(), generated.KeyID())
	}
}

func TestBuildSignerEd25519BadKeyPath(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	_, _, err := buildSignerAndVerifiers("ed25519", "/nonexistent/key.pem", signer.SigstoreConfig{}, signer.KMSConfig{}, logger)
	if err == nil {
		t.Fatal("expected error for nonexistent key file")
	}
}

func TestBuildSignerSigstore(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := signer.SigstoreConfig{
		FulcioURL: "https://fulcio.example.com",
		RekorURL:  "https://rekor.example.com",
	}
	sig, verifiers, err := buildSignerAndVerifiers("sigstore", "", cfg, signer.KMSConfig{}, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if sig == nil {
		t.Fatal("expected non-nil signer")
	}
	if len(verifiers) != 1 {
		t.Fatalf("expected 1 verifier, got %d", len(verifiers))
	}
}

func TestBuildSignerKMSLocalECDSA(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	kmsCfg := signer.KMSConfig{
		Provider: signer.KMSProviderLocal,
		KeyURI:   "local://test-key",
	}
	sig, verifiers, err := buildSignerAndVerifiers("kms", "", signer.SigstoreConfig{}, kmsCfg, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if sig == nil {
		t.Fatal("expected non-nil signer")
	}
	if len(verifiers) != 1 {
		t.Fatalf("expected 1 verifier, got %d", len(verifiers))
	}
}

func TestBuildSignerKMSDefaultsApplied(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	// Empty provider and key URI should get defaults.
	kmsCfg := signer.KMSConfig{}
	sig, verifiers, err := buildSignerAndVerifiers("kms", "", signer.SigstoreConfig{}, kmsCfg, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if sig == nil {
		t.Fatal("expected non-nil signer")
	}
	if len(verifiers) != 1 {
		t.Fatalf("expected 1 verifier, got %d", len(verifiers))
	}
}

func TestBuildSignerUnsupportedMode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	_, _, err := buildSignerAndVerifiers("unknown-mode", "", signer.SigstoreConfig{}, signer.KMSConfig{}, logger)
	if err == nil {
		t.Fatal("expected error for unsupported mode")
	}
}

func TestBuildVariablesExist(t *testing.T) {
	// Verify that ldflags-injected variables have their defaults.
	if version == "" {
		t.Fatal("version should have a default value")
	}
	if commit == "" {
		t.Fatal("commit should have a default value")
	}
	if date == "" {
		t.Fatal("date should have a default value")
	}
}

func TestParseCommaSeparatedNonEmpty(t *testing.T) {
	t.Parallel()

	got := parseCommaSeparatedNonEmpty(" broker1:9092, ,broker2:9092,broker3:9092 ")
	want := []string{"broker1:9092", "broker2:9092", "broker3:9092"}

	if len(got) != len(want) {
		t.Fatalf("length mismatch: got %d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("index %d mismatch: got %q want %q", i, got[i], want[i])
		}
	}
}

type fakeWriterFenceLease struct {
	releases int
	err      error
}

func (l *fakeWriterFenceLease) Release(_ context.Context) error {
	l.releases++
	return l.err
}

type fakeWriterFenceStore struct {
	lease      store.WriterFenceLease
	err        error
	calls      int
	lastLockID int64
}

func (s *fakeWriterFenceStore) AcquireWriterFence(_ context.Context, lockID int64) (store.WriterFenceLease, error) {
	s.calls++
	s.lastLockID = lockID
	return s.lease, s.err
}

func TestParseWriterFenceMode(t *testing.T) {
	t.Parallel()

	cases := []struct {
		raw     string
		want    writerFenceMode
		wantErr bool
	}{
		{raw: "disabled", want: writerFenceModeDisabled},
		{raw: "best-effort", want: writerFenceModeBestEffort},
		{raw: "required", want: writerFenceModeRequired},
		{raw: " ReQuIrEd ", want: writerFenceModeRequired},
		{raw: "nope", wantErr: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.raw, func(t *testing.T) {
			t.Parallel()

			got, err := parseWriterFenceMode(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("mode = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAcquireWriterFenceDisabled(t *testing.T) {
	t.Parallel()

	lease, err := acquireWriterFence(context.Background(), struct{}{}, "disabled", 1, slog.Default())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if lease != nil {
		t.Fatal("expected nil lease")
	}
}

func TestAcquireWriterFenceRequiredWithoutSupport(t *testing.T) {
	t.Parallel()

	lease, err := acquireWriterFence(context.Background(), struct{}{}, "required", 1, slog.Default())
	if !errors.Is(err, store.ErrWriterFenceUnsupported) {
		t.Fatalf("expected ErrWriterFenceUnsupported, got %v", err)
	}
	if lease != nil {
		t.Fatal("expected nil lease")
	}
}

func TestAcquireWriterFenceBestEffortWithoutSupport(t *testing.T) {
	t.Parallel()

	lease, err := acquireWriterFence(context.Background(), struct{}{}, "best-effort", 1, slog.Default())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if lease != nil {
		t.Fatal("expected nil lease")
	}
}

func TestAcquireWriterFenceRequiredNotAcquired(t *testing.T) {
	t.Parallel()

	fakeStore := &fakeWriterFenceStore{err: store.ErrWriterFenceNotAcquired}
	lease, err := acquireWriterFence(context.Background(), fakeStore, "required", 77, slog.Default())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "required writer fence not acquired") {
		t.Fatalf("unexpected error: %v", err)
	}
	if lease != nil {
		t.Fatal("expected nil lease")
	}
	if fakeStore.calls != 1 || fakeStore.lastLockID != 77 {
		t.Fatalf("unexpected acquire invocation: calls=%d lockID=%d", fakeStore.calls, fakeStore.lastLockID)
	}
}

func TestAcquireWriterFenceBestEffortNotAcquired(t *testing.T) {
	t.Parallel()

	fakeStore := &fakeWriterFenceStore{err: store.ErrWriterFenceNotAcquired}
	lease, err := acquireWriterFence(context.Background(), fakeStore, "best-effort", 55, slog.Default())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if lease != nil {
		t.Fatal("expected nil lease")
	}
}

func TestAcquireWriterFenceRequiredSuccess(t *testing.T) {
	t.Parallel()

	expectedLease := &fakeWriterFenceLease{}
	fakeStore := &fakeWriterFenceStore{lease: expectedLease}

	lease, err := acquireWriterFence(context.Background(), fakeStore, "required", 999, slog.Default())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lease == nil {
		t.Fatal("expected non-nil lease")
	}
	if lease != expectedLease {
		t.Fatal("returned lease does not match expected lease")
	}
}
