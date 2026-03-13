# NLnet NGI Zero Commons Fund, Proposal

> **URL:** https://nlnet.nl/propose/
> **Amount:** EUR 5,000–50,000
> **Deadline:** 2026-04-01
> **BEST FIT: Grantees automatically receive security audit support, mentoring, testing expertise**
> **Frame:** Open source cryptographic infrastructure for AI accountability, EU AI Act/GDPR alignment

---

## NLnet Proposal Form

### Abstract (max 200 words)

VAOL (Verifiable AI Output Ledger) is an open source cryptographic audit ledger that creates tamper-evident records of AI/LLM inference decisions. It enables organisations to prove what an AI system decided, when, under what governance policy, and that the record hasn't been altered.

As the EU AI Act mandates demonstrable AI governance for high-risk systems, organisations need open, auditable infrastructure (not proprietary cloud services) to create verifiable AI decision records. VAOL addresses this through DSSE digital signatures (Ed25519, Sigstore, KMS), RFC 6962 Merkle trees with inclusion/consistency proofs, RFC 8785 JSON canonicalization, OPA/Rego policy-as-code enforcement, and privacy-preserving modes (hash-only, encrypted, plaintext) for GDPR compliance.

The project is Apache 2.0 licensed with Go server, Python/TypeScript SDKs, and a CLI verifier enabling zero-trust offline verification. After 29 releases and thorough audit preparation (evidence package, control matrix, SOW template), an independent security/cryptography audit is the sole v1.0 release gate.

We request EUR 46,000 primarily for this security audit, which NLnet's audit support programme is uniquely positioned to facilitate. A production-ready, audited VAOL enables the European open source ecosystem to deploy trustworthy AI governance infrastructure.

### Description of Work

#### Background and Problem

AI systems deployed in healthcare, finance, legal, and government face a critical accountability gap. Application logs can be modified. Database records lack cryptographic integrity. There's no standardised open source infrastructure for creating tamper-evident AI decision records that third parties can independently verify.

The EU AI Act (Articles 12–14, 17) requires record-keeping, transparency, human oversight, and quality management for high-risk AI systems. GDPR requires organisations to demonstrate compliance with data processing principles. These regulations need verifiable infrastructure, not trust-based logging.

#### What VAOL Does

VAOL is a cryptographic audit ledger with five verification layers:

1. **Digital signatures (DSSE):** Every AI inference is captured as a signed DecisionRecord containing identity, model, prompt hash, output hash, policy context. Signed with Ed25519 (RFC 8032), Sigstore keyless, or KMS/HSM.

2. **Hash chaining:** Each record includes the SHA-256 hash of its predecessor. Records are canonicalized via RFC 8785 (JCS) for deterministic hashing. Insertion, deletion, or reordering breaks the chain.

3. **Merkle tree (RFC 6962):** Records anchored in an append-only Merkle tree with inclusion proofs (prove a record exists) and consistency proofs (prove the tree only grew).

4. **Policy-as-code (OPA/Rego):** Policies evaluated at decision time with fail-closed defaults. Included policies: model allowlists, PHI redaction, mandatory citations, plaintext prevention.

5. **Privacy modes:** `hash_only` (GDPR-friendly, verifies integrity without content exposure), `encrypted` (selective disclosure), `plaintext` (full audit).

**Components:** Go server (REST + gRPC), CLI verifier, OpenAI-compatible proxy, Python SDK (OpenAI/Anthropic/LiteLLM instrumentation), TypeScript SDK, OPA policy library, Docker/Helm deployment.

#### Current Status

- 29 releases (v0.1.0 → v0.2.28), Apache 2.0
- 13+ Go packages, 4 binaries, 2 SDKs
- CI: lint, test (race detector, E2E, tamper detection, SDK tests, policy tests), security scanning (gosec, govulncheck, Trivy), benchmarks, SBOM
- Documentation: architecture, cryptographic design, threat model (16 attack vectors), API reference, auditor guide, deployment/HA/DR guides
- Audit preparation complete: evidence package, control matrix, SOW template, finding intake playbook, remediation templates

**The sole v1.0 release gate is an independent security/cryptography audit.**

#### What This Grant Would Fund

The grant directly funds the security audit that is the v1.0 release gate, plus supporting work:

**Milestone 1: Security Audit (EUR 35,000)**
- Independent review of: DSSE signing pipeline, RFC 6962 Merkle implementation, hash chain integrity, multi-tenant authorisation, OPA integration
- NLnet's audit support programme can facilitate auditor selection and engagement
- Deliverable: Audit report with findings classified by severity

**Milestone 2: Audit Remediation (EUR 5,000)**
- Fix all critical and high findings
- Regression tests for each finding
- Updated threat model
- Deliverable: Clean re-test report, public remediation report

**Milestone 3: v1.0 Release and Compliance Documentation (EUR 3,000)**
- v1.0.0 production release
- EU AI Act compliance mapping (Articles 12, 13, 14, 17)
- GDPR alignment documentation for privacy modes
- Deployment guide for European organisations
- Deliverable: Tagged v1.0.0 release, compliance documentation

**Milestone 4: Community Integration (EUR 3,000)**
- Sector-specific OPA policy packs (healthcare, finance)
- Integration guides for common European AI deployment patterns
- Contributor documentation and community onboarding
- Deliverable: Policy packs, integration documentation

### Requested Budget

**EUR 46,000**

| Milestone | Amount (EUR) | Deliverable |
|-----------|-------------|-------------|
| 1. Security audit | 35,000 | Audit report |
| 2. Remediation | 5,000 | Public remediation report, clean re-test |
| 3. v1.0 release + compliance docs | 3,000 | v1.0.0 tag, EU AI Act/GDPR mapping |
| 4. Community integration | 3,000 | Policy packs, integration guides |
| **Total** | **46,000** | |

### Milestones and Timeline

| # | Milestone | Duration | Deliverable |
|---|-----------|----------|-------------|
| 1 | Audit engagement (NLnet audit support) | Weeks 1–8 | Signed SOW, audit report |
| 2 | Remediation and re-test | Weeks 9–12 | Fixes, regression tests, re-test report |
| 3 | v1.0 release and compliance documentation | Weeks 13–14 | v1.0.0 tag, EU AI Act/GDPR docs |
| 4 | Community integration | Weeks 15-18 | Policy packs, guides |

**Total duration:** 18 weeks (4.5 months)

### Relevance to NGI Mission

VAOL directly supports the Next Generation Internet's vision of a more trustworthy, open internet:

**Trustworthiness:** Cryptographic verification enables zero-trust AI accountability. Users and auditors can verify AI decision records without trusting any single entity. The mathematics guarantees integrity.

**Openness:** Apache 2.0 licensing, standards-based cryptography (RFC 6962, RFC 8785, RFC 8032), and open governance ensure no vendor lock-in. The verification stack is entirely transparent and reproducible.

**Resilience:** Self-hosted deployment ensures European organisations maintain sovereignty over their AI governance infrastructure. No dependency on external services for core verification.

**Privacy:** Hash-only mode enables GDPR-compliant verification, proving integrity of AI decisions without storing or exposing personal data in prompts or outputs.

**Sustainability:** The security audit creates a production-ready foundation that other open source projects can build on. The public audit report and methodology contribute to the broader community's security knowledge.

### Comparable Projects

- **Sigstore:** Provides software supply chain signing; VAOL uses Sigstore as one of its signing backends but addresses a different domain (AI decision records, not software artifacts)
- **Certificate Transparency (RFC 6962):** VAOL implements RFC 6962 Merkle trees adapted for AI decision records rather than X.509 certificates
- **Rekor (Sigstore):** Transparency log for software signatures; VAOL is a transparency log for AI decisions with policy enforcement
- **ORAS/Notary:** Container artifact signing; different domain (containers vs. AI decisions)

None of these projects address AI decision accountability with integrated policy enforcement and privacy preservation.

### License

Apache License 2.0

### Repository

https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger

---

## Supporting Materials Checklist

- [ ] Repository: https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger
- [ ] README.md: project overview with architecture diagrams
- [ ] docs/threat-model.md: 16 attack vectors
- [ ] docs/crypto-design.md: DSSE, RFC 6962, RFC 8785, Ed25519/Sigstore/KMS
- [ ] docs/architecture.md: system design
- [ ] docs/external-audit-readiness.md: audit preparation, evidence package
- [ ] GOVERNANCE.md: maintainer model, review gates
- [ ] SECURITY.md: vulnerability disclosure policy, response SLAs
- [ ] CHANGELOG.md: release history
- [ ] .github/workflows/ci.yml: CI pipeline
- [ ] .github/workflows/scorecard.yml: OpenSSF Scorecard

---

## Submission Steps

1. Navigate to https://nlnet.nl/propose/
2. Fill in the proposal form using the sections above
3. For "Thematic fund": select **NGI Zero Commons Fund**
4. Paste the abstract, description, budget, milestones, and relevance sections
5. Link the repository and key documentation
6. Submit before **2026-04-01**
7. Record confirmation and update `TRACKING.md`
8. Set follow-up reminder for 2026-04-15

---

## Why NLnet is the Best Fit

1. **Automatic audit support:** NLnet grantees receive security audit facilitation, which is exactly what VAOL needs
2. **European focus:** NLnet understands EU AI Act and GDPR compliance needs
3. **Open source commitment:** NLnet funds free software infrastructure
4. **Mentoring and testing:** Additional support beyond just funding
5. **Budget range:** EUR 5K–50K matches our audit-focused request
6. **NGI Zero Commons:** Specifically for open source infrastructure that benefits the commons
