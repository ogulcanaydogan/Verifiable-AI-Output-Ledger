# OSTIF Outreach, Project Introduction Email

> **Contact:** amir@ostif.org
> **What:** Free security audit for critical open source projects (funded by Google, etc.)
> **When:** Rolling, send in April after Phase 2 applications

---

## Email Draft

**To:** amir@ostif.org
**Subject:** Security Audit Request: VAOL (Verifiable AI Output Ledger)

---

Hi Amir,

I'm the maintainer of VAOL (Verifiable AI Output Ledger), an open source cryptographic audit ledger for AI/LLM inference decisions. I'm writing to request OSTIF's consideration for a security audit.

**What VAOL does:**
VAOL provides tamper-evident audit trails for regulated industries where organisations must prove the provenance, policy compliance, and integrity of AI-generated outputs. It creates digitally signed records using DSSE envelopes (Ed25519, Sigstore keyless, KMS/HSM), chains them with SHA-256 hashes, and anchors them in RFC 6962 Merkle trees with verifiable inclusion proofs. Policy enforcement is handled via OPA/Rego with fail-closed defaults.

**Why this matters:**
As AI systems are deployed in healthcare, finance, legal, and government, there's no standardised open source infrastructure for creating cryptographically verifiable records of AI decisions. The EU AI Act and similar regulations will require organisations to demonstrate AI decision provenance. VAOL is designed to fill this gap.

**Audit scope:**
The critical components requiring review are:
- DSSE signing pipeline (Ed25519/RFC 8032, Sigstore, KMS backends)
- RFC 6962 Merkle tree implementation (inclusion/consistency proofs)
- Hash chain integrity (SHA-256 chaining, JCS canonicalization per RFC 8785)
- Multi-tenant authorisation boundaries (JWT/OIDC, tenant isolation)
- OPA policy engine integration (fail-closed enforcement)

**Current security posture:**
- Threat model covering 16 attack vectors (docs/threat-model.md)
- Detailed cryptographic design document (docs/crypto-design.md)
- CI pipeline with gosec, govulncheck, Trivy, SBOM generation
- All GitHub Actions pinned to commit SHAs
- Security-sensitive code paths require 2+ reviewer approvals
- Formal vulnerability disclosure policy with response SLAs (SECURITY.md)
- Audit readiness package prepared with control matrix and SOW template

**Repository:** https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger

An independent security audit is the v1.0.0 release gate. The project has completed all audit preparation work and is ready for external review.

I would be happy to provide any additional information or schedule a call to discuss further.

Best regards,
Ogulcan Aydogan
Maintainer, VAOL
https://github.com/ogulcanaydogan

---

## Submission Steps

1. Finalise email text above (personalise greeting if appropriate)
2. Send to amir@ostif.org
3. CC yourself for tracking
4. Set follow-up reminder for 2 weeks after sending
5. Update `TRACKING.md` with sent date
