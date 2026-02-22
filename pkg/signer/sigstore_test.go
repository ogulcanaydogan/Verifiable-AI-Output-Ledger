package signer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSigstoreSignVerifyRelaxed(t *testing.T) {
	cfg := DefaultSigstoreConfig()
	cfg.RekorURL = ""
	cfg.RequireRekor = false

	s := NewSigstoreSigner(cfg)
	v := NewSigstoreVerifier(cfg)

	payload := []byte("sigstore payload")
	sig, err := s.Sign(context.Background(), payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig.Cert == "" {
		t.Fatal("expected certificate")
	}
	if err := v.Verify(context.Background(), payload, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestSigstoreStrictRekorRoundTrip(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/log/entries":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"uuid": "entry-1"})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/log/entries/entry-1":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := DefaultSigstoreConfig()
	cfg.RekorURL = ts.URL
	cfg.RequireRekor = true

	s := NewSigstoreSigner(cfg)
	v := NewSigstoreVerifier(cfg)

	payload := []byte("strict sigstore payload")
	sig, err := s.Sign(context.Background(), payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig.RekorEntryID == "" {
		t.Fatal("expected rekor entry ID")
	}
	if err := v.Verify(context.Background(), payload, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestSigstoreStrictFailsWithoutRekorEntry(t *testing.T) {
	cfg := DefaultSigstoreConfig()
	cfg.RequireRekor = true
	cfg.RekorURL = "https://rekor.example.invalid"

	v := NewSigstoreVerifier(cfg)
	err := v.Verify(context.Background(), []byte("payload"), Signature{
		KeyID: "fulcio:https://issuer::oidc-bound",
		Sig:   "dGVzdA",
		Cert:  "dGVzdA",
	})
	if err == nil {
		t.Fatal("expected strict verification error for missing rekor entry")
	}
}

func TestSigstoreVerifyRejectsIssuerMismatch(t *testing.T) {
	cfg := DefaultSigstoreConfig()
	cfg.RekorURL = ""
	cfg.RequireRekor = false

	s := NewSigstoreSigner(cfg)
	payload := []byte("issuer-mismatch")
	sig, err := s.Sign(context.Background(), payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifyCfg := cfg
	verifyCfg.OIDCIssuer = "https://issuer.example.invalid"
	v := NewSigstoreVerifier(verifyCfg)
	err = v.Verify(context.Background(), payload, sig)
	if err == nil || !strings.Contains(err.Error(), "issuer mismatch") {
		t.Fatalf("expected issuer mismatch error, got: %v", err)
	}
}

func TestSigstoreVerifyRejectsIdentityMismatch(t *testing.T) {
	cfg := DefaultSigstoreConfig()
	cfg.RekorURL = ""
	cfg.RequireRekor = false

	s := NewSigstoreSigner(cfg)
	v := NewSigstoreVerifier(cfg)

	payload := []byte("identity-mismatch")
	sig, err := s.Sign(context.Background(), payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Tamper key-id identity binding while keeping signature/certificate unchanged.
	sig.KeyID = strings.Replace(sig.KeyID, "::ephemeral", "::different-identity", 1)
	err = v.Verify(context.Background(), payload, sig)
	if err == nil || !strings.Contains(err.Error(), "identity mismatch") {
		t.Fatalf("expected identity mismatch error, got: %v", err)
	}
}

func TestSigstoreVerifyRejectsTimestampOutsideCertWindow(t *testing.T) {
	cfg := DefaultSigstoreConfig()
	cfg.RekorURL = ""
	cfg.RequireRekor = false

	s := NewSigstoreSigner(cfg)
	v := NewSigstoreVerifier(cfg)

	payload := []byte("timestamp-window")
	sig, err := s.Sign(context.Background(), payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	sig.Timestamp = time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	err = v.Verify(context.Background(), payload, sig)
	if err == nil || !strings.Contains(err.Error(), "certificate validity check failed") {
		t.Fatalf("expected certificate validity window failure, got: %v", err)
	}
}
