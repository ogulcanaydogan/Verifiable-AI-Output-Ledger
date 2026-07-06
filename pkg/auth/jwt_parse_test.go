package auth

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func b64url(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func TestParseNumericDate(t *testing.T) {
	want := time.Unix(1700000000, 0).UTC()
	cases := []struct {
		name string
		in   any
		ok   bool
	}{
		{"float64", float64(1700000000), true},
		{"json.Number", json.Number("1700000000"), true},
		{"json.Number invalid", json.Number("not-a-number"), false},
		{"int64", int64(1700000000), true},
		{"int", int(1700000000), true},
		{"numeric string", "1700000000", true},
		{"empty string", "", false},
		{"non-numeric string", "abc", false},
		{"unsupported type", []any{1}, false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseNumericDate(tc.in)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && !got.Equal(want) {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}
}

func TestParseBearerToken(t *testing.T) {
	cases := []struct {
		name, in, want string
		wantErr        bool
	}{
		{"valid", "Bearer abc.def.ghi", "abc.def.ghi", false},
		{"case-insensitive scheme", "bearer tok", "tok", false},
		{"empty header", "   ", "", true},
		{"wrong scheme", "Basic abc", "", true},
		{"single segment", "Bearer", "", true},
		{"empty token", "Bearer   ", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseBearerToken(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseJWTErrorPaths(t *testing.T) {
	validHeader := b64url(`{"alg":"HS256"}`)
	validPayload := b64url(`{"sub":"x"}`)
	cases := []struct {
		name  string
		token string
	}{
		{"wrong segment count", "a.b"},
		{"bad base64 header", "!!!." + validPayload + ".sig"},
		{"invalid json header", b64url("not-json") + "." + validPayload + ".sig"},
		{"missing alg", b64url(`{}`) + "." + validPayload + ".sig"},
		{"bad base64 payload", validHeader + ".!!!.sig"},
		{"bad base64 signature", validHeader + "." + validPayload + ".!!!"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, _, err := parseJWT(tc.token); err == nil {
				t.Fatalf("expected error for %q, got nil", tc.name)
			}
		})
	}

	// A well-formed token parses without error.
	header, payload, signing, sig, err := parseJWT(validHeader + "." + validPayload + "." + b64url("sig"))
	if err != nil {
		t.Fatalf("valid token: unexpected error %v", err)
	}
	if header.Alg != "HS256" {
		t.Fatalf("alg = %q, want HS256", header.Alg)
	}
	if string(payload) != `{"sub":"x"}` {
		t.Fatalf("payload = %s", payload)
	}
	if signing != validHeader+"."+validPayload {
		t.Fatalf("signing input = %q", signing)
	}
	if len(sig) == 0 {
		t.Fatal("expected non-empty signature bytes")
	}
}

func TestValidateTemporalClaims(t *testing.T) {
	verifier, err := NewVerifier(Config{Mode: ModeRequired, HS256Secret: "s"})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	now := time.Unix(1700000000, 0).UTC()

	t.Run("missing exp in required mode", func(t *testing.T) {
		if err := verifier.validateTemporalClaims(map[string]any{}, now); err == nil {
			t.Fatal("expected missing-exp error")
		}
	})
	t.Run("expired token", func(t *testing.T) {
		raw := map[string]any{"exp": float64(now.Add(-time.Hour).Unix())}
		if err := verifier.validateTemporalClaims(raw, now); err == nil {
			t.Fatal("expected expired error")
		}
	})
	t.Run("not yet valid (nbf)", func(t *testing.T) {
		raw := map[string]any{
			"exp": float64(now.Add(time.Hour).Unix()),
			"nbf": float64(now.Add(time.Hour).Unix()),
		}
		if err := verifier.validateTemporalClaims(raw, now); err == nil {
			t.Fatal("expected not-valid-before error")
		}
	})
	t.Run("issued in the future (iat)", func(t *testing.T) {
		raw := map[string]any{
			"exp": float64(now.Add(time.Hour).Unix()),
			"iat": float64(now.Add(time.Hour).Unix()),
		}
		if err := verifier.validateTemporalClaims(raw, now); err == nil {
			t.Fatal("expected issued-in-future error")
		}
	})
	t.Run("valid within window", func(t *testing.T) {
		raw := map[string]any{
			"exp": float64(now.Add(time.Hour).Unix()),
			"nbf": float64(now.Add(-time.Hour).Unix()),
			"iat": float64(now.Add(-time.Hour).Unix()),
		}
		if err := verifier.validateTemporalClaims(raw, now); err != nil {
			t.Fatalf("expected valid, got %v", err)
		}
	})
}
