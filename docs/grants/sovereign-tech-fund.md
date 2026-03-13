# Sovereign Tech Resilience Program, Application

> **URL:** https://www.sovereign.tech/programs/fund
> **Amount:** EUR 50,000+
> **Deadline:** 2026-03-25
> **Frame:** Digital sovereignty infrastructure for AI governance, EU AI Act compliance tooling

---

## Tender Response

### 1. Project Title

VAOL (Verifiable AI Output Ledger): Open Source Cryptographic Infrastructure for Sovereign AI Governance

### 2. Executive Summary

VAOL is an open source, cryptographically verifiable audit ledger that enables European organisations to independently verify AI decisions without reliance on proprietary infrastructure. As the EU AI Act mandates demonstrable AI governance for high-risk systems, organisations need open, auditable tooling to create tamper-evident records of AI inference decisions.

VAOL provides this capability through established cryptographic standards (DSSE digital signatures, RFC 6962 Merkle trees, RFC 8785 JSON canonicalization) implemented in Go with Python and TypeScript SDKs. The project is Apache 2.0 licensed, ensuring sovereign control over the complete verification stack.

Funding would enable an independent security/cryptography audit, which is the sole remaining gate for the v1.0.0 production release. This ensures European organisations can trust this infrastructure for regulated AI deployments.

### 3. Relevance to Digital Sovereignty

**The sovereignty problem:** European organisations deploying AI systems in healthcare, finance, legal, and government currently have no open source, standards-based way to create tamper-evident records of AI decisions. Without such infrastructure, they depend on:

- Proprietary cloud logging services controlled by non-European entities
- Application logs that can be silently modified or deleted
- AI providers' self-reported audit trails with no independent verification

**How VAOL enables sovereignty:**

1. **Self-hosted, open source:** Organisations run VAOL on their own infrastructure. No external service dependencies for core verification. Complete control over data residency.

2. **Zero-trust verification:** Clients can verify signatures and Merkle proofs independently without trusting the server. Auditors validate the entire chain offline using the CLI verifier.

3. **Standards-based cryptography:** Every cryptographic operation follows published standards (RFC 6962, RFC 8785, RFC 8032, DSSE). No proprietary algorithms or formats. Any competent auditor can verify the implementation against the specifications.

4. **Policy-as-code:** OPA/Rego policies are transparent, version-controlled, and auditable. Organisations define their own governance rules rather than depending on opaque platform policies.

5. **Privacy-preserving modes:** Hash-only mode allows verification without exposing prompt/output content, critical for GDPR compliance. Encrypted mode enables selective disclosure under court order or regulatory request.

**EU AI Act alignment:**

- **Article 12 (Record-keeping):** VAOL creates immutable, cryptographically chained records of AI inference decisions with model identity, policy context, and timestamps.
- **Article 13 (Transparency):** Merkle proofs enable third-party auditors to independently verify the completeness and integrity of AI decision records.
- **Article 14 (Human oversight):** Policy-as-code enforcement at decision time ensures human-defined governance rules are applied to every AI interaction.
- **Article 17 (Quality management):** The append-only ledger with hash chains provides a verifiable quality management record for AI system operation.

### 4. Technical Description

**Architecture:**
- **Server:** Go 1.24+ with REST and gRPC APIs, PostgreSQL storage, multi-tenant JWT/OIDC authentication
- **Signing:** DSSE envelopes with Ed25519 (RFC 8032), Sigstore keyless (OIDC-based), and cloud KMS/HSM backends (AWS, GCP, Azure)
- **Integrity:** SHA-256 hash chains with RFC 8785 JCS canonicalization, RFC 6962 Merkle trees with inclusion and consistency proofs
- **Policy:** OPA/Rego engine with fail-closed defaults; missing policy engine results in denial
- **SDKs:** Python 3.10+ (OpenAI, Anthropic, LiteLLM instrumentation), TypeScript 5.0+ (OpenAI instrumentation)
- **CLI:** Key generation, offline verification, audit bundle inspection
- **Proxy:** OpenAI-compatible transparent HTTP proxy for zero-code-change integration

**Current maturity:**
- 29 releases (v0.1.0 through v0.2.28)
- 13+ Go packages, 4 binaries, 2 SDKs
- Full CI pipeline: lint, test (Go race detector, Python, TypeScript, OPA), security scanning (gosec, govulncheck, Trivy), benchmarks, SBOM, E2E tamper detection
- Threat model covering 16 attack vectors
- Detailed cryptographic design document
- Formal governance model with security review gates

### 5. Security Audit Need

An independent security/cryptography audit is the sole remaining gate for the v1.0.0 production release. The project has completed all audit preparation:

- **Audit readiness package** with evidence bundle, control matrix, and SOW template
- **Scope definition:** DSSE signing pipeline, Merkle tree implementation, hash chain integrity, multi-tenant authorisation, OPA integration
- **Remediation process:** Finding intake playbook, remediation report template, public disclosure commitment

**Estimated audit cost:** EUR 35,000–50,000 for a thorough review of the cryptographic components and security-critical paths.

**Without this audit,** the project can't responsibly recommend production deployment in regulated environments. Organisations evaluating VAOL for EU AI Act compliance need assurance that the cryptographic primitives are correctly implemented.

### 6. Budget Breakdown

| Item | Amount (EUR) | Description |
|------|-------------|-------------|
| Security/cryptography audit | 40,000 | Independent review of signing, Merkle, hash chain, auth, policy engine |
| Audit remediation | 5,000 | Engineering time to address findings |
| Reproducible build infrastructure | 3,000 | Deterministic builds for supply chain verification |
| Documentation and compliance | 2,000 | Public audit report, updated threat model, compliance mapping |
| **Total** | **50,000** | |

### 7. Team

**Ogulcan Aydogan:** Project maintainer and primary developer. Background in machine learning engineering and security-sensitive system design. Responsible for architecture, cryptographic design, and governance model.

### 8. Timeline

| Phase | Duration | Deliverables |
|-------|----------|-------------|
| Audit firm selection and contracting | 2 weeks | Signed SOW, audit schedule |
| Audit execution | 4–6 weeks | Audit report with findings |
| Remediation | 2–3 weeks | Fixes for critical/high findings |
| Re-test and verification | 1–2 weeks | Clean re-test report |
| Public report and v1.0.0 release | 1 week | Public remediation report, v1.0.0 tag |

**Total:** 10–14 weeks from funding receipt to v1.0.0 release.

### 9. Impact

A security-audited VAOL v1.0 would provide the European open source ecosystem with:

1. **Trusted AI governance infrastructure:** The first open source, standards-based, independently audited cryptographic audit ledger for AI decisions
2. **EU AI Act compliance tooling:** Ready-to-deploy infrastructure for record-keeping, transparency, and human oversight requirements
3. **Sovereignty guarantee:** Self-hosted, no external dependencies, all cryptographic operations verifiable against published standards
4. **Reusable audit methodology:** Public audit report and remediation documentation that other projects can reference

---

## Supporting Materials Checklist

- [ ] Repository link: https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger
- [ ] README.md: project overview with architecture diagrams
- [ ] docs/threat-model.md: 16 attack vectors
- [ ] docs/crypto-design.md: complete cryptographic specification
- [ ] docs/architecture.md: system design
- [ ] docs/external-audit-readiness.md: audit preparation status
- [ ] GOVERNANCE.md: maintainer model, review gates
- [ ] SECURITY.md: vulnerability disclosure policy
- [ ] CHANGELOG.md: release history
- [ ] .github/workflows/ci.yml: CI pipeline
- [ ] .github/workflows/scorecard.yml: OpenSSF Scorecard

---

## Submission Steps

1. Navigate to https://www.sovereign.tech/programs/fund
2. Find the Resilience Program application form
3. Fill in using the tender response sections above
4. Attach/link supporting materials from checklist
5. Submit before **2026-03-25**
6. Record confirmation and update `TRACKING.md`
7. Set follow-up reminder for 2026-04-08
