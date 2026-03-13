# GitHub Secure Open Source Fund, Application

> **URL:** https://resources.github.com/github-secure-open-source-fund/
> **Amount:** $10,000 direct funding + $10,000 Azure credits + 3-week security program
> **Deadline:** Rolling
> **Cost:** Free to apply

---

## Application Form Responses

### Project Name
VAOL (Verifiable AI Output Ledger)

### Repository URL
https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger

### Project Description
VAOL is a cryptographically verifiable, append-only audit ledger for AI/LLM inference decisions. It provides tamper-evident audit trails for regulated industries (healthcare, finance, legal, government) where organisations must prove the provenance, policy compliance, and integrity of every AI-generated output.

The system creates digitally signed records using DSSE envelopes with Ed25519, Sigstore keyless, or KMS/HSM signing. Records are hash-chained and anchored in RFC 6962 Merkle trees with verifiable inclusion proofs. Policy-as-code enforcement via OPA/Rego ensures compliance at decision time. Multi-tenant JWT/OIDC authentication provides secure access control.

VAOL includes a Go server, CLI verifier, OpenAI-compatible proxy, and Python/TypeScript SDKs with instrumentation for OpenAI, Anthropic, and LiteLLM.

### How does this project improve the security of the open source ecosystem?
VAOL addresses a critical gap in AI governance infrastructure: there's no standardised, open source way to create tamper-evident records of AI decisions. As AI systems are deployed in regulated environments, the ability to prove what an AI system said, when, under what policy, and that the record hasn't been altered becomes essential.

Without VAOL, organisations rely on application logs that can be modified or deleted, database records without cryptographic integrity guarantees, and no standardised way to prove policy compliance at inference time. VAOL solves this by providing zero-trust verification: clients can verify signatures and proofs without trusting the server.

The project's cryptographic design follows established standards (RFC 6962, RFC 8785, RFC 8032, DSSE) and implements fail-closed defaults. The codebase includes a threat model covering 16 attack vectors, security scanning in CI (gosec, govulncheck, Trivy), SBOM generation, and a formal vulnerability disclosure policy.

An independent security audit is the v1.0 release gate, making funding directly impactful.

### What would you use the funding for?
1. **Independent security/cryptography audit** (~$8,000): Professional review of the signing pipeline (DSSE, Ed25519, Sigstore, KMS), Merkle tree implementation (RFC 6962), hash chain integrity, JCS canonicalization (RFC 8785), and multi-tenant authorisation boundaries. This is the v1.0.0 release gate.

2. **CI/infrastructure hardening** (~$2,000): Extended fuzzing infrastructure for cryptographic components, reproducible build pipeline, enhanced SBOM and provenance generation.

Azure credits would fund:
- Extended CI runners for security-intensive test suites (tamper detection, E2E verification)
- Fuzzing infrastructure for cryptographic primitives
- Benchmark infrastructure for performance regression detection

### License
Apache License 2.0

### Primary Language
Go (server, CLI, proxy), Python (SDK), TypeScript (SDK)

### Current Security Practices
- **Threat Model:** 16 attack vectors documented with mitigations (`docs/threat-model.md`)
- **Cryptographic Design Document:** Detailed specification of all cryptographic operations (`docs/crypto-design.md`)
- **Security Scanning in CI:** gosec, govulncheck, Trivy filesystem scan
- **SBOM Generation:** Anchore SPDX JSON in CI
- **Vulnerability Disclosure Policy:** Private reporting to security@yapay.ai with 48h acknowledgement, 5-day triage, 10-day remediation plan SLAs (`SECURITY.md`)
- **Supply Chain Security:** All GitHub Actions pinned to commit SHAs, workflow pin policy enforced in CI
- **Code Review Gates:** Security-sensitive paths require 2+ approvals including CODEOWNER (`GOVERNANCE.md`)
- **Test Coverage:** Go race-detector tests, E2E tests, tamper detection tests, OPA policy tests, Python/TypeScript SDK tests
- **OpenSSF Scorecard:** GitHub Action added to CI

### Number of Contributors
Active maintainer-led project with contributor guidelines in CONTRIBUTING.md

### Has the project had a security audit before?
No. An independent security audit is the primary v1.0.0 release gate. The project has completed audit preparation:
- Audit readiness package (`docs/external-audit-readiness.md`)
- Control matrix (`docs/audit/control-matrix.md`)
- Statement of work template (`docs/audit/sow.md`)
- Remediation report template (`docs/audit/remediation-report-template.md`)
- Finding intake playbook (`docs/audit/finding-intake-playbook.md`)

---

## Supporting Materials to Link/Attach

- Repository: https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger
- Threat Model: `docs/threat-model.md`
- Cryptographic Design: `docs/crypto-design.md`
- Architecture: `docs/architecture.md`
- Audit Readiness: `docs/external-audit-readiness.md`
- Security Policy: `SECURITY.md`
- Governance: `GOVERNANCE.md`
- CI Pipeline: `.github/workflows/ci.yml`

---

## Submission Steps

1. Go to https://resources.github.com/github-secure-open-source-fund/
2. Click "Apply" or navigate to the Google Form
3. Fill in the form using the responses above
4. Submit
5. Record confirmation and update `TRACKING.md`
