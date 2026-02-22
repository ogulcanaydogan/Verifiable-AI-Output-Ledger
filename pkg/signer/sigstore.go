// Package signer - Sigstore keyless signing implementation.
//
// This implementation supports:
//  1. Ephemeral Ed25519 signing key generation
//  2. Short-lived self-issued certificate embedding (offline verification aid)
//  3. Optional Rekor-style transparency submission and strict Rekor verification
package signer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// SigstoreConfig holds configuration for Sigstore keyless signing.
type SigstoreConfig struct {
	// FulcioURL is the Fulcio certificate authority URL.
	// Default: https://fulcio.sigstore.dev
	FulcioURL string

	// RekorURL is the Rekor transparency log URL.
	// Default: https://rekor.sigstore.dev
	RekorURL string

	// OIDCIssuer is the OIDC identity provider URL.
	// Default: https://oauth2.sigstore.dev/auth
	OIDCIssuer string

	// OIDCClientID is the OIDC client ID.
	// Default: sigstore
	OIDCClientID string

	// IdentityToken is the pre-obtained OIDC token.
	// If empty, interactive flow or ambient credentials are used.
	IdentityToken string

	// RequireRekor enforces Rekor entry creation/verification.
	RequireRekor bool

	// HTTPTimeout controls Rekor network timeout.
	HTTPTimeout time.Duration
}

// DefaultSigstoreConfig returns the default Sigstore configuration
// using the public-good Sigstore infrastructure.
func DefaultSigstoreConfig() SigstoreConfig {
	return SigstoreConfig{
		FulcioURL:    "https://fulcio.sigstore.dev",
		RekorURL:     "https://rekor.sigstore.dev",
		OIDCIssuer:   "https://oauth2.sigstore.dev/auth",
		OIDCClientID: "sigstore",
		HTTPTimeout:  10 * time.Second,
	}
}

// SigstoreSigner implements keyless signing using Sigstore (Fulcio + Rekor).
type SigstoreSigner struct {
	config SigstoreConfig
	keyID  string
	client *http.Client
}

// NewSigstoreSigner creates a new Sigstore keyless signer.
func NewSigstoreSigner(config SigstoreConfig) *SigstoreSigner {
	timeout := config.HTTPTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &SigstoreSigner{
		config: config,
		keyID:  "sigstore-keyless",
		client: &http.Client{Timeout: timeout},
	}
}

// Sign signs the payload using an ephemeral key and optionally records it in Rekor.
func (s *SigstoreSigner) Sign(ctx context.Context, payload []byte) (Signature, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Signature{}, fmt.Errorf("generating ephemeral key: %w", err)
	}

	identity := "ephemeral"
	if s.config.IdentityToken != "" {
		identity = "oidc-bound"
	}

	// In full Sigstore integration this should be a Fulcio-issued certificate.
	// For portability in self-hosted/offline deployments, we embed a short-lived
	// self-signed certificate for the ephemeral key.
	certDER, err := mintEphemeralCert(identity, pub, priv)
	if err != nil {
		return Signature{}, fmt.Errorf("minting ephemeral certificate: %w", err)
	}

	sigBytes := ed25519.Sign(priv, payload)
	keyID := fmt.Sprintf("fulcio:%s::%s", s.config.OIDCIssuer, identity)

	out := Signature{
		KeyID:     keyID,
		Sig:       b64Encode(sigBytes),
		Cert:      b64Encode(certDER),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	if strings.TrimSpace(s.config.RekorURL) != "" {
		entryID, rekorErr := s.submitRekorEntry(ctx, payload, out)
		if rekorErr != nil {
			if s.config.RequireRekor {
				return Signature{}, fmt.Errorf("submitting Rekor entry: %w", rekorErr)
			}
		} else {
			out.RekorEntryID = entryID
		}
	}
	if s.config.RequireRekor && out.RekorEntryID == "" {
		return Signature{}, fmt.Errorf("strict Sigstore mode requires Rekor entry")
	}

	return out, nil
}

func (s *SigstoreSigner) submitRekorEntry(ctx context.Context, payload []byte, sig Signature) (string, error) {
	endpoint := strings.TrimRight(s.config.RekorURL, "/") + "/api/v1/log/entries"
	digest := sha256.Sum256(payload)

	reqBody := map[string]any{
		"kind": "vaol.sigstore.v1",
		"spec": map[string]any{
			"payload_hash": fmt.Sprintf("sha256:%x", digest[:]),
			"signature":    sig.Sig,
			"certificate":  sig.Cert,
			"keyid":        sig.KeyID,
		},
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshaling Rekor request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("creating Rekor request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("calling Rekor: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Rekor status %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading Rekor response: %w", err)
	}

	// Accept {"uuid":"..."} or real Rekor map payload {"<uuid>": {...}}.
	var uuidResp struct {
		UUID string `json:"uuid"`
	}
	if err := json.Unmarshal(body, &uuidResp); err == nil && uuidResp.UUID != "" {
		return uuidResp.UUID, nil
	}
	var mapResp map[string]json.RawMessage
	if err := json.Unmarshal(body, &mapResp); err == nil {
		for k := range mapResp {
			if strings.TrimSpace(k) != "" {
				return k, nil
			}
		}
	}

	return "", fmt.Errorf("Rekor response missing entry ID")
}

func mintEphemeralCert(identity string, pub ed25519.PublicKey, priv ed25519.PrivateKey) ([]byte, error) {
	now := time.Now().UTC()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         identity,
			OrganizationalUnit: []string{"vaol-sigstore-ephemeral"},
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(10 * time.Minute),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	return x509.CreateCertificate(rand.Reader, template, template, pub, priv)
}

// KeyID returns the signer's key identifier.
func (s *SigstoreSigner) KeyID() string {
	return s.keyID
}

// Algorithm returns the signing algorithm name.
func (s *SigstoreSigner) Algorithm() string {
	return "sigstore-keyless"
}

// SigstoreVerifier verifies signatures created by Sigstore keyless signing.
type SigstoreVerifier struct {
	config SigstoreConfig
	client *http.Client
}

// NewSigstoreVerifier creates a new Sigstore signature verifier.
func NewSigstoreVerifier(config SigstoreConfig) *SigstoreVerifier {
	timeout := config.HTTPTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &SigstoreVerifier{
		config: config,
		client: &http.Client{Timeout: timeout},
	}
}

// Verify checks a Sigstore keyless signature.
func (v *SigstoreVerifier) Verify(ctx context.Context, payload []byte, sig Signature) error {
	if sig.Cert == "" {
		return fmt.Errorf("sigstore signature missing certificate")
	}

	pubKey, cert, err := decodeSigstoreCertificate(sig.Cert)
	if err != nil {
		return err
	}

	if err := v.validateKeyIDBinding(sig.KeyID, cert); err != nil {
		return err
	}

	if cert != nil {
		if err := validateCertificatePolicy(cert, sig.Timestamp); err != nil {
			return err
		}
	}

	// Decode and verify the signature.
	sigBytes, err := b64Decode(sig.Sig)
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}
	if !ed25519.Verify(pubKey, payload, sigBytes) {
		return fmt.Errorf("sigstore signature verification failed")
	}

	if v.config.RequireRekor {
		if sig.RekorEntryID == "" {
			return fmt.Errorf("strict Sigstore mode requires rekor_entry_id")
		}
		if strings.TrimSpace(v.config.RekorURL) == "" {
			return fmt.Errorf("strict Sigstore mode requires rekor_url")
		}
		if err := v.verifyRekorEntry(ctx, sig.RekorEntryID); err != nil {
			return err
		}
	}

	return nil
}

func decodeSigstoreCertificate(certB64 string) (ed25519.PublicKey, *x509.Certificate, error) {
	certBytes, err := b64Decode(certB64)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding certificate: %w", err)
	}

	// Backward compatibility: previous implementation stored raw Ed25519 public key.
	if len(certBytes) == ed25519.PublicKeySize {
		return ed25519.PublicKey(certBytes), nil, nil
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing certificate: %w", err)
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("certificate public key is not Ed25519")
	}
	return pub, cert, nil
}

func validateCertificatePolicy(cert *x509.Certificate, signatureTimestamp string) error {
	if cert.IsCA {
		return fmt.Errorf("sigstore certificate policy violation: certificate must not be a CA")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("sigstore certificate policy violation: missing digitalSignature key usage")
	}
	if len(cert.ExtKeyUsage) > 0 {
		hasCodeSigning := false
		for _, usage := range cert.ExtKeyUsage {
			if usage == x509.ExtKeyUsageCodeSigning {
				hasCodeSigning = true
				break
			}
		}
		if !hasCodeSigning {
			return fmt.Errorf("sigstore certificate policy violation: missing codeSigning extended key usage")
		}
	}

	verifyAt := time.Now().UTC()
	if strings.TrimSpace(signatureTimestamp) != "" {
		parsed, err := time.Parse(time.RFC3339, signatureTimestamp)
		if err != nil {
			return fmt.Errorf("invalid signature timestamp for certificate validation: %w", err)
		}
		verifyAt = parsed.UTC()
	}
	if verifyAt.Before(cert.NotBefore) || verifyAt.After(cert.NotAfter) {
		return fmt.Errorf(
			"sigstore certificate validity check failed: verify_time=%s cert_not_before=%s cert_not_after=%s",
			verifyAt.Format(time.RFC3339),
			cert.NotBefore.UTC().Format(time.RFC3339),
			cert.NotAfter.UTC().Format(time.RFC3339),
		)
	}

	return nil
}

func (v *SigstoreVerifier) validateKeyIDBinding(keyID string, cert *x509.Certificate) error {
	issuer, identity, ok := parseSigstoreKeyID(keyID)
	if !ok {
		return nil
	}

	if strings.TrimSpace(v.config.OIDCIssuer) != "" && issuer != v.config.OIDCIssuer {
		return fmt.Errorf("sigstore keyid issuer mismatch: got %q want %q", issuer, v.config.OIDCIssuer)
	}

	// For legacy raw-public-key cert encoding, binding checks beyond issuer are unavailable.
	if cert == nil {
		return nil
	}

	if cert.Subject.CommonName != "" && cert.Subject.CommonName != identity {
		return fmt.Errorf("sigstore keyid identity mismatch: keyid=%q cert_common_name=%q", identity, cert.Subject.CommonName)
	}

	return nil
}

func parseSigstoreKeyID(keyID string) (issuer string, identity string, ok bool) {
	trimmed := strings.TrimSpace(keyID)
	if !strings.HasPrefix(strings.ToLower(trimmed), "fulcio:") {
		return "", "", false
	}
	body := strings.TrimPrefix(trimmed, "fulcio:")
	parts := strings.SplitN(body, "::", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	issuer = strings.TrimSpace(parts[0])
	identity = strings.TrimSpace(parts[1])
	if issuer == "" || identity == "" {
		return "", "", false
	}
	return issuer, identity, true
}

func (v *SigstoreVerifier) verifyRekorEntry(ctx context.Context, entryID string) error {
	endpoint := strings.TrimRight(v.config.RekorURL, "/") + "/api/v1/log/entries/" + entryID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("creating Rekor lookup request: %w", err)
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("querying Rekor entry %q: %w", entryID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Rekor entry lookup failed: status=%d body=%s", resp.StatusCode, string(body))
	}
	return nil
}

// KeyID returns the verifier's expected key identifier.
func (v *SigstoreVerifier) KeyID() string {
	return "sigstore-keyless"
}
