# Huntr Bug Bounty Registration Guide

> **URL:** https://huntr.com/
> **Time:** ~15 minutes
> **Cost:** Free
> **What you get:** Free AI/ML-focused bug bounty pipeline, community security researchers testing VAOL

---

## Why Huntr

Huntr specialises in AI/ML open source projects. They provide:
- Free bug bounty triage and management
- Community of security researchers focused on AI/ML tools
- Structured vulnerability reports
- CVE assignment for confirmed issues
- Complements VAOL's existing `SECURITY.md` disclosure policy

---

## Step-by-Step Registration

### 1. Create an account
Go to https://huntr.com/ and sign up (GitHub OAuth recommended).

### 2. Register your project
Navigate to the project registration / maintainer section and add:

- **Repository URL:** `https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger`
- **Project name:** VAOL (Verifiable AI Output Ledger)
- **Description:** Cryptographically verifiable, append-only audit ledger for AI/LLM inference decisions. Provides tamper-evident audit trails using DSSE envelopes, RFC 6962 Merkle trees, and OPA policy-as-code enforcement.
- **Category:** AI/ML Security Infrastructure
- **Language:** Go, Python, TypeScript
- **License:** Apache 2.0

### 3. Define scope

**In scope:**
- `pkg/signer/`: DSSE envelope signing (Ed25519, Sigstore, KMS)
- `pkg/verifier/`: Composite verification pipeline
- `pkg/merkle/`: RFC 6962 Merkle tree implementation
- `pkg/auth/`: JWT/OIDC authentication and tenant binding
- `pkg/policy/`: OPA engine and fail-closed wrapper
- `pkg/crypto/`: SHA-256 hashing, age encryption
- `pkg/record/`: JCS canonicalization and hash chaining
- `pkg/api/`, REST API server
- `pkg/grpc/`, gRPC API server
- `pkg/store/`: PostgreSQL storage backend
- `sdk/python/`: Python SDK
- `sdk/typescript/`: TypeScript SDK
- `cmd/vaol-server/`: Server binary
- `cmd/vaol-proxy/`: OpenAI-compatible proxy

**Out of scope:**
- `examples/`: Demo code only
- `tests/`: Test infrastructure
- `deploy/`: Deployment templates (Docker, Helm)
- `docs/`: Documentation
- `scripts/`: Operational scripts

### 4. Set severity guidelines

Reference VAOL's existing severity definitions from `SECURITY.md`:

| Severity | Examples |
|----------|----------|
| Critical | Signature forgery, verification bypass, cross-tenant data exposure |
| High | Tamper-evidence bypass, policy bypass, key-handling flaws |
| Medium | Denial-of-service in control plane, non-default misconfig risks |
| Low | Documentation gaps, hardening improvements without direct exploit |

### 5. Confirm and activate

Once registered, Huntr will list VAOL as an eligible target for their researcher community.

---

## Post-Registration

- Monitor incoming reports through Huntr dashboard
- Triage within 5 business days (matches SECURITY.md SLA)
- Huntr handles CVE assignment for confirmed issues
- Reference Huntr participation in grant applications as evidence of security commitment
