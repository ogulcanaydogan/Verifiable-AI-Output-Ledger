# AISI Challenge Fund (UK), Application

> **URL:** https://find-government-grants.service.gov.uk/grants/aisi-challenge-fund-1
> **Amount:** GBP 50,000–200,000
> **Deadline:** 2026-03-31
> **Frame:** AI safety infrastructure, tamper-evident records of AI decisions for regulated environments

---

## Grant Application

### 1. Project Title

VAOL: Cryptographic Verification Infrastructure for AI Safety in Regulated Environments

### 2. Problem Statement

AI systems are now running in safety-critical domains: healthcare diagnostics, financial risk assessment, legal analysis, government decision-making. A fundamental accountability gap exists. **There's no standardised, open source way to create tamper-evident records that prove what an AI system decided, when, under what governance policy, and that nobody's tampered with the record.**

This gap creates concrete safety risks:

**Undetectable output manipulation:** Without cryptographic integrity guarantees, AI outputs can be silently modified between generation and consumption. In healthcare, a modified diagnostic recommendation could cause patient harm. In finance, altered risk assessments could mask systemic risks.

**Policy compliance blind spots:** Organisations can't prove that governance policies were enforced at the moment of AI inference. Post-hoc policy evaluation can't guarantee the same conditions existed at decision time.

**Audit trail fragility:** Application logs and database records lack cryptographic chaining. Records can be inserted, deleted, or reordered without detection. Auditors reviewing AI decision history have no way to verify completeness or integrity.

**Regulatory non-compliance:** The UK's AI regulatory framework, the EU AI Act, and sector-specific regulations (FCA, MHRA, ICO) increasingly require demonstrable AI governance. Organisations deploying AI in regulated environments need verifiable records, not just logs.

Current commercial solutions are proprietary and cloud-dependent. They don't provide zero-trust verification, so users must trust the service provider's infrastructure.

### 3. Technical Approach

VAOL (Verifiable AI Output Ledger) is an open source cryptographic audit ledger that solves these problems through layered verification:

**Layer 1, Digital Signatures (DSSE):**
Every AI inference decision is captured as a DecisionRecord containing identity (who made the request), model identity (which AI system responded), prompt hash, output hash, policy context, and metadata. This record is signed using DSSE (Dead Simple Signing Envelope) with Ed25519 (RFC 8032), Sigstore keyless signing, or cloud KMS/HSM backends. The signature proves authenticity and detects any modification.

**Layer 2, Hash Chaining:**
Each record includes the SHA-256 hash of its predecessor, creating an ordered chain. Records are canonicalized using RFC 8785 (JSON Canonicalization Scheme) before hashing, ensuring deterministic representation. Any insertion, deletion, or reordering breaks the chain.

**Layer 3, Merkle Tree (RFC 6962):**
Records are anchored in an append-only Merkle tree following RFC 6962 (Certificate Transparency). This provides:
- **Inclusion proofs:** Prove a specific record exists in the tree (O(log n) verification)
- **Consistency proofs:** Prove the tree has only grown (no records removed or altered)
- **Signed checkpoints:** Periodic commitments to the tree state that auditors can monitor

**Layer 4, Policy-as-Code (OPA/Rego):**
OPA/Rego policies are evaluated at decision time with fail-closed defaults. Missing policy engine results in denial. Policies are version-controlled and auditable. Example policies included: model allowlists, PHI redaction requirements, mandatory citations for RAG outputs, plaintext storage prevention.

**Layer 5, Privacy Preservation:**
Three privacy modes ensure VAOL can be deployed under data protection regulations:
- `hash_only` (default): Only SHA-256 digests stored, proving integrity without exposing content
- `encrypted`: age X25519 encrypted blobs with digest binding; content recoverable with key
- `plaintext`: Raw content for internal audit environments requiring full content review

**Zero-trust verification:** Clients can verify signatures and Merkle proofs entirely offline using the CLI tool or SDK methods. No need to trust the server.

### 4. Safety Impact

**Direct safety improvements:**

1. **Tamper detection for AI outputs:** Cryptographic signatures and hash chains make any modification to AI decision records detectable. In a healthcare deployment, a modified diagnostic recommendation would fail signature verification.

2. **Provenance guarantees:** Every AI output can be traced to a specific model version, policy context, and timestamp. Regulators and auditors can verify the complete provenance chain.

3. **Policy enforcement evidence:** OPA/Rego policies evaluated at decision time create verifiable evidence that governance rules were applied. Unlike retrospective compliance checks, this proves policy compliance existed at the moment of inference.

4. **Audit completeness verification:** Merkle consistency proofs allow auditors to verify that no records have been removed from the ledger. This addresses the risk of selective evidence destruction.

5. **Cross-organisation verification:** Third-party auditors can independently validate the entire chain using the open source CLI verifier and published cryptographic standards.

**Safety at scale:**
VAOL is designed for high-throughput environments with multi-tenant isolation, JWT/OIDC authentication, tenant-bound access control, and deterministic deny reason codes for cross-tenant access attempts.

### 5. Current Project Status

- **Maturity:** 29 releases (v0.1.0 through v0.2.28), Apache 2.0 licensed
- **Codebase:** 13+ Go packages, 4 binaries (server, CLI, proxy, ingest worker), 2 SDKs (Python, TypeScript)
- **CI pipeline:** Lint, test (Go race detector, Python, TypeScript, OPA), security scanning (gosec, govulncheck, Trivy), benchmarks, SBOM generation, E2E tamper detection tests
- **Documentation:** Architecture, cryptographic design, threat model (16 attack vectors), API reference, auditor guide, deployment guide, HA/DR playbooks
- **Audit preparation:** Evidence package, control matrix, SOW template, finding intake playbook, remediation report template

**v1.0.0 release gate:** An independent security/cryptography audit is the sole remaining requirement for production release.

### 6. Budget Breakdown

| Item | Amount (GBP) | Description |
|------|-------------|-------------|
| Independent security/cryptography audit | 45,000 | Professional review by a CREST/CHECK-accredited firm covering: DSSE signing pipeline, RFC 6962 Merkle implementation, hash chain integrity, multi-tenant authorisation, OPA integration, supply chain |
| Audit remediation engineering | 8,000 | Fix critical and high findings, regression tests, verifier updates |
| Reproducible builds and provenance | 4,000 | Deterministic build pipeline, SLSA provenance, enhanced SBOM |
| Compliance documentation | 3,000 | Public audit report, updated threat model, UK regulatory mapping (FCA, MHRA, ICO) |
| **Total** | **60,000** | |

For larger grant amounts (GBP 100K–200K), the scope expands to:

| Additional Item | Amount (GBP) | Description |
|----------------|-------------|-------------|
| Extended fuzzing and formal verification | 20,000 | Cryptographic primitive fuzzing, property-based testing |
| Sector-specific policy packs | 15,000 | Pre-built OPA policies for healthcare (MHRA), finance (FCA), legal |
| Integration testing with UK AI community | 10,000 | Compatibility testing with common UK deployment patterns |
| Community and documentation | 5,000 | Contributor onboarding, deployment guides for UK organisations |
| **Extended Total** | **110,000** | |

### 7. Team

**Ogulcan Aydogan:** Project maintainer and primary developer. Machine learning engineering background with focus on security-sensitive system design. Designed and implemented VAOL's cryptographic architecture, threat model, and governance framework.

### 8. Timeline

| Phase | Duration | Deliverables |
|-------|----------|-------------|
| Audit procurement | 2 weeks | Signed contract with CREST/CHECK firm |
| Audit execution | 6 weeks | Full audit report covering all scoped components |
| Remediation (critical/high) | 3 weeks | Fixes, regression tests, updated threat model |
| Re-test | 2 weeks | Clean re-test report |
| Public report + v1.0.0 release | 1 week | Published remediation report, v1.0.0 tag |
| UK regulatory mapping | 2 weeks | FCA, MHRA, ICO compliance documentation |

**Total:** 16 weeks from funding to v1.0.0 release with UK regulatory documentation.

### 9. Alignment with AISI Mission

VAOL directly supports the AI Safety Institute's mission to make AI safe:

- **Evaluation infrastructure:** VAOL provides the evidence layer that AI evaluation frameworks need: verifiable records of what AI systems actually produced, not just what they were supposed to produce.
- **Accountability tooling:** Cryptographic proofs create an unforgeable chain of accountability from AI output to human oversight.
- **Open infrastructure:** Apache 2.0 licensing ensures the UK AI safety ecosystem isn't dependent on proprietary governance tooling.
- **Standards-based:** Every cryptographic operation follows published IETF/RFC standards, enabling interoperability and independent verification.

---

## Supporting Materials Checklist

- [ ] Repository: https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger
- [ ] README.md: project overview with architecture diagrams
- [ ] docs/threat-model.md: 16 attack vectors with mitigations
- [ ] docs/crypto-design.md: DSSE, RFC 6962, RFC 8785, Ed25519/Sigstore/KMS
- [ ] docs/architecture.md: system design (13+ packages, 4 binaries, 2 SDKs)
- [ ] docs/external-audit-readiness.md: audit preparation status
- [ ] GOVERNANCE.md: maintainer model, security review gates
- [ ] SECURITY.md: vulnerability disclosure policy, response SLAs
- [ ] CHANGELOG.md: release history (v0.1.0 to v0.2.28)
- [ ] .github/workflows/ci.yml: CI with security scanning, SBOM
- [ ] .github/workflows/scorecard.yml: OpenSSF Scorecard

---

## Submission Steps

1. Navigate to https://find-government-grants.service.gov.uk/grants/aisi-challenge-fund-1
2. Review eligibility criteria and application form
3. Fill in using the sections above, adapting to their specific form fields
4. Attach/link supporting materials
5. Submit before **2026-03-31**
6. Record confirmation and update `TRACKING.md`
7. Set follow-up reminder for 2026-04-14
