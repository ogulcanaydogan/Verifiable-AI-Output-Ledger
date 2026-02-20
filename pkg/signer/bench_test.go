package signer

import (
	"context"
	"testing"
)

var benchPayload = []byte(`{"schema_version":"v1","request_id":"550e8400-e29b-41d4-a716-446655440000","timestamp":"2026-02-20T12:00:00Z","identity":{"tenant_id":"bench-tenant","subject":"bench-user","subject_type":"service"},"model":{"provider":"openai","name":"gpt-4o","version":"2025-03-01"},"prompt_context":{"user_prompt_hash":"sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"},"policy_context":{"policy_decision":"allow","policy_bundle_id":"bench-bundle","rule_ids":["rule-1"]},"output":{"output_hash":"sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef","mode":"hash_only"}}`)

func BenchmarkEd25519Sign(b *testing.B) {
	s, err := GenerateEd25519Signer()
	if err != nil {
		b.Fatalf("GenerateEd25519Signer: %v", err)
	}
	ctx := context.Background()
	payload := PAE(PayloadType, benchPayload)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.Sign(ctx, payload); err != nil {
			b.Fatalf("Sign: %v", err)
		}
	}
}

func BenchmarkEd25519Verify(b *testing.B) {
	s, err := GenerateEd25519Signer()
	if err != nil {
		b.Fatalf("GenerateEd25519Signer: %v", err)
	}
	ctx := context.Background()
	payload := PAE(PayloadType, benchPayload)
	sig, err := s.Sign(ctx, payload)
	if err != nil {
		b.Fatalf("Sign: %v", err)
	}
	v := NewEd25519Verifier(s.PublicKey())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := v.Verify(ctx, payload, sig); err != nil {
			b.Fatalf("Verify: %v", err)
		}
	}
}

func BenchmarkDSSESignEnvelope(b *testing.B) {
	s, err := GenerateEd25519Signer()
	if err != nil {
		b.Fatalf("GenerateEd25519Signer: %v", err)
	}
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := SignEnvelope(ctx, benchPayload, s); err != nil {
			b.Fatalf("SignEnvelope: %v", err)
		}
	}
}

func BenchmarkDSSEVerifyEnvelope(b *testing.B) {
	s, err := GenerateEd25519Signer()
	if err != nil {
		b.Fatalf("GenerateEd25519Signer: %v", err)
	}
	ctx := context.Background()
	env, err := SignEnvelope(ctx, benchPayload, s)
	if err != nil {
		b.Fatalf("SignEnvelope: %v", err)
	}
	v := NewEd25519Verifier(s.PublicKey())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := VerifyEnvelope(ctx, env, v); err != nil {
			b.Fatalf("VerifyEnvelope: %v", err)
		}
	}
}

func BenchmarkPAE(b *testing.B) {
	for i := 0; i < b.N; i++ {
		PAE(PayloadType, benchPayload)
	}
}

func BenchmarkEd25519KeyGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := GenerateEd25519Signer(); err != nil {
			b.Fatalf("GenerateEd25519Signer: %v", err)
		}
	}
}
