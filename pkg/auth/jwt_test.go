package auth

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifyAuthorizationHS256Required(t *testing.T) {
	verifier, err := NewVerifier(Config{
		Mode:        ModeRequired,
		Issuer:      "https://issuer.example",
		Audience:    "vaol-api",
		HS256Secret: "super-secret",
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	token, err := makeHS256Token(map[string]any{
		"iss":       "https://issuer.example",
		"aud":       "vaol-api",
		"sub":       "svc-app",
		"tenant_id": "acme-prod",
		"exp":       time.Now().Add(10 * time.Minute).Unix(),
	}, "super-secret")
	if err != nil {
		t.Fatalf("makeHS256Token: %v", err)
	}

	claims, err := verifier.VerifyAuthorization(context.Background(), "Bearer "+token)
	if err != nil {
		t.Fatalf("VerifyAuthorization: %v", err)
	}
	if claims.TenantID != "acme-prod" {
		t.Fatalf("tenant mismatch: got %q", claims.TenantID)
	}
	if claims.Subject != "svc-app" {
		t.Fatalf("subject mismatch: got %q", claims.Subject)
	}
	if claims.TokenHash == "" {
		t.Fatal("expected token hash")
	}
}

func TestVerifyAuthorizationOptionalNoToken(t *testing.T) {
	verifier, err := NewVerifier(Config{
		Mode:        ModeOptional,
		HS256Secret: "secret",
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	claims, err := verifier.VerifyAuthorization(context.Background(), "")
	if err != nil {
		t.Fatalf("VerifyAuthorization: %v", err)
	}
	if claims != nil {
		t.Fatalf("expected nil claims for no token in optional mode, got %+v", claims)
	}
}

func TestVerifyAuthorizationMissingTenantFails(t *testing.T) {
	verifier, err := NewVerifier(Config{
		Mode:        ModeRequired,
		Issuer:      "https://issuer.example",
		HS256Secret: "secret",
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	token, err := makeHS256Token(map[string]any{
		"iss": "https://issuer.example",
		"sub": "svc-app",
		"exp": time.Now().Add(10 * time.Minute).Unix(),
	}, "secret")
	if err != nil {
		t.Fatalf("makeHS256Token: %v", err)
	}

	if _, err := verifier.VerifyAuthorization(context.Background(), "Bearer "+token); err == nil {
		t.Fatal("expected error for missing tenant claim")
	}
}

func TestVerifyAuthorizationExpiredTokenFails(t *testing.T) {
	verifier, err := NewVerifier(Config{
		Mode:        ModeRequired,
		HS256Secret: "secret",
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	token, err := makeHS256Token(map[string]any{
		"sub":       "svc-app",
		"tenant_id": "acme",
		"exp":       time.Now().Add(-1 * time.Hour).Unix(),
	}, "secret")
	if err != nil {
		t.Fatalf("makeHS256Token: %v", err)
	}

	if _, err := verifier.VerifyAuthorization(context.Background(), "Bearer "+token); err == nil {
		t.Fatal("expected expiry error")
	}
}

func TestVerifyAuthorizationRS256JWKS(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	jwksPath := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(jwksPath, []byte(makeRSAJWKS("k1", &priv.PublicKey)), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	verifier, err := NewVerifier(Config{
		Mode:      ModeRequired,
		Issuer:    "https://issuer.example",
		Audience:  "vaol-api",
		JWKSFile:  jwksPath,
		ClockSkew: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	token, err := makeRS256Token("k1", map[string]any{
		"iss":       "https://issuer.example",
		"aud":       []string{"vaol-api"},
		"sub":       "svc-rs256",
		"tenant_id": "acme-rs",
		"exp":       time.Now().Add(15 * time.Minute).Unix(),
	}, priv)
	if err != nil {
		t.Fatalf("makeRS256Token: %v", err)
	}

	claims, err := verifier.VerifyAuthorization(context.Background(), "Bearer "+token)
	if err != nil {
		t.Fatalf("VerifyAuthorization: %v", err)
	}
	if claims.Subject != "svc-rs256" || claims.TenantID != "acme-rs" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func makeHS256Token(claims map[string]any, secret string) (string, error) {
	header := map[string]any{
		"alg": "HS256",
		"typ": "JWT",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(signingInput))
	signature := mac.Sum(nil)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func makeRS256Token(kid string, claims map[string]any, priv *rsa.PrivateKey) (string, error) {
	header := map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		"kid": kid,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func makeRSAJWKS(kid string, pub *rsa.PublicKey) string {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(bigIntFromInt(pub.E).Bytes())
	return fmt.Sprintf(`{"keys":[{"kid":"%s","kty":"RSA","alg":"RS256","use":"sig","n":"%s","e":"%s"}]}`, kid, n, e)
}

func bigIntFromInt(v int) *big.Int {
	return new(big.Int).SetInt64(int64(v))
}

func TestParseMode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input   string
		want    Mode
		wantErr bool
	}{
		{"required", ModeRequired, false},
		{"REQUIRED", ModeRequired, false},
		{"optional", ModeOptional, false},
		{"Optional", ModeOptional, false},
		{"disabled", ModeDisabled, false},
		{"", ModeDisabled, false},
		{"  ", ModeDisabled, false},
		{"invalid", "", true},
		{"none", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got, err := ParseMode(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseMode(%q) expected error, got nil", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseMode(%q) unexpected error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("ParseMode(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestInjectTrustedHeaders(t *testing.T) {
	t.Parallel()

	t.Run("nil claims returns request unchanged", func(t *testing.T) {
		t.Parallel()
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer tok")
		got := InjectTrustedHeaders(r, nil)
		if got.Header.Get("Authorization") != "Bearer tok" {
			t.Fatal("expected Authorization header to be preserved when claims is nil")
		}
	})

	t.Run("removes identity headers and injects verified claims", func(t *testing.T) {
		t.Parallel()
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer tok")
		r.Header.Set("X-Tenant-ID", "untrusted-tenant")
		r.Header.Set("X-VAOL-Tenant-ID", "untrusted-vaol")

		claims := &Claims{
			Issuer:    "https://issuer.example",
			Subject:   "svc-app",
			TenantID:  "acme-prod",
			TokenHash: "abc123",
		}
		got := InjectTrustedHeaders(r, claims)

		if got.Header.Get("Authorization") != "" {
			t.Error("expected Authorization header to be removed")
		}
		if got.Header.Get("X-Tenant-ID") != "" {
			t.Error("expected X-Tenant-ID to be removed")
		}
		if got.Header.Get("X-VAOL-Tenant-ID") != "acme-prod" {
			t.Errorf("expected X-VAOL-Tenant-ID=acme-prod, got %q", got.Header.Get("X-VAOL-Tenant-ID"))
		}
		if got.Header.Get("X-Auth-Source") != "jwt" {
			t.Errorf("expected X-Auth-Source=jwt, got %q", got.Header.Get("X-Auth-Source"))
		}
		if got.Header.Get("X-Auth-Token-Hash") != "abc123" {
			t.Errorf("expected X-Auth-Token-Hash=abc123, got %q", got.Header.Get("X-Auth-Token-Hash"))
		}
		if got.Header.Get("X-Auth-Issuer") != "https://issuer.example" {
			t.Errorf("expected X-Auth-Issuer, got %q", got.Header.Get("X-Auth-Issuer"))
		}
		if got.Header.Get("X-Auth-Subject") != "svc-app" {
			t.Errorf("expected X-Auth-Subject=svc-app, got %q", got.Header.Get("X-Auth-Subject"))
		}
	})

	t.Run("original request headers are not mutated", func(t *testing.T) {
		t.Parallel()
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer original")
		claims := &Claims{Subject: "svc", TokenHash: "h"}
		_ = InjectTrustedHeaders(r, claims)
		if r.Header.Get("Authorization") != "Bearer original" {
			t.Fatal("InjectTrustedHeaders must not mutate the original request")
		}
	})
}
