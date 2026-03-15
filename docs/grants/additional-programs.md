# Additional Grant Programs - Quick Applications

> **Last updated:** 2026-03-15
> **Purpose:** Concise application materials for smaller/simpler programs

---

## 1. Coefficient Giving (Open Philanthropy)

> **URL:** https://coefficientgiving.org/apply-for-funding/
> **Type:** Rolling grants for AI safety research
> **Status:** Ready to apply
> **Deadline:** Rolling

### Expression of Interest (300 words)

We've built three open source tools that provide cryptographic oversight infrastructure for AI systems: a tamper-evident audit ledger (VAOL), an ML model supply chain attestation pipeline, and an OWASP LLM Top 10 detection firewall.

The gap we're filling: when AI safety mechanisms fail in production, there's currently no independent way to verify what happened. RLHF and output filtering are model-level interventions; we work at the infrastructure level, providing the audit trail and verification layer that makes AI system behavior accountable after the fact.

VAOL creates DSSE-signed audit records with SHA-256 hash chains and RFC 6962 Merkle trees. If someone tampers with an audit record, the cryptographic chain breaks. Our supply chain tool extends Sigstore/SLSA to ML models, so you can verify the model in production matches what passed safety evaluations. The firewall detects 16 attack categories that cause safety-trained models to behave unsafely.

All three projects are actively maintained (29 releases on VAOL, 21 CI workflows, OpenSSF Best Practices PASSING on all), open source (Apache 2.0 / MIT), and have no commercial backing. We've applied to NLnet, Sovereign Tech Fund, and OpenAI's Cybersecurity Grant for these projects.

What we'd use funding for: a third-party security audit of VAOL's signing pipeline ($80K), adversarial testing of supply chain attestation against 12 model tampering techniques ($40K), and compute for benchmark infrastructure ($30K). Total: $150,000 over 12 months.

The research question: can cryptographic verification methods provide meaningful oversight guarantees for frontier AI systems? Where exactly do they fail? We plan to publish formal analyses and adversarial evaluation results, not just ship software.

---

## 2. AI Alignment Foundation (AIAF)

> **URL:** https://www.aialignmentfoundation.org/approach/apply
> **Type:** Rolling grants for independent researchers
> **Status:** Ready to apply
> **Deadline:** Rolling

### Application Pitch

We're building open source infrastructure that makes AI system behavior verifiable. Not at the model level (RLHF, constitutional AI), but at the infrastructure level: tamper-evident audit trails for AI decisions.

**The alignment connection:** alignment research needs ground truth. If you can't verify what an AI system actually did vs. what it was reported to have done, you can't study alignment failures empirically. VAOL provides that ground truth through cryptographic audit trails.

Three projects, all open source:
- **VAOL** (Go, Apache 2.0): DSSE signatures, SHA-256 hash chains, RFC 6962 Merkle trees for AI inference decisions. 29 releases. github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger
- **LLM-Supply-Chain-Attestation** (Go, Apache 2.0): Sigstore/SLSA for ML models. Verifies model integrity from training to deployment. 7 releases.
- **Prompt-Injection-Firewall** (Go, Apache 2.0): Detects 16 OWASP LLM Top 10 attack categories. 4 releases.

**Funding request:** $50,000 for security audit + formal verification of VAOL's cryptographic properties.

---

## 3. Global Technology Risk (GTR) Foundation

> **URL:** https://www.gtr-foundation.org/
> **Type:** Grants for LLM auditing, interpretability, AI governance research
> **Status:** Ready to apply
> **Deadline:** Rolling

### Application Pitch

We maintain open source tooling for LLM auditing and AI governance infrastructure:

1. **VAOL**: Cryptographic audit trails for AI/LLM inference. Think "blockchain for AI decisions" but without the blockchain, just standard cryptography (DSSE, Merkle trees, hash chains).

2. **Prompt-Injection-Firewall**: Detection engine for attacks that bypass LLM safety mechanisms. Covers the OWASP LLM Top 10.

3. **AI-Regulation-Compliance-Scanner**: Automated scanning against EU AI Act, UK AI Regulation, and NIST AI RMF. Rule-driven, no black box, auditable.

These tools address the infrastructure gap in AI governance: regulators and auditors need verifiable records, not self-reported metrics.

**Funding request:** $75,000 for third-party security audit of VAOL's signing pipeline and adversarial testing of compliance scanner rules against edge cases.

---

## 4. Emergent Ventures (Mercatus Center, GMU)

> **URL:** https://www.mercatus.org/emergent-ventures
> **Type:** Grants and fellowships for ambitious projects
> **Status:** Ready to apply
> **Deadline:** Rolling

### Application Pitch

I'm building open source infrastructure for AI accountability, 10 projects covering supply chain security, content provenance, regulatory compliance, and cryptographic audit trails. All MIT or Apache 2.0, no commercial backing, solo maintainer.

The most impactful project is VAOL (Verifiable AI Output Ledger), which creates tamper-evident audit trails for AI decisions. It uses the same cryptographic primitives that Certificate Transparency uses for TLS certificates, but applied to AI inference logs. If a company claims their AI system didn't produce a harmful output, VAOL's hash chain and Merkle tree provide a cryptographic proof that the log hasn't been altered.

This matters because AI governance is becoming regulation-driven (EU AI Act, UK AI Safety Institute), and regulators need verifiable records. The alternative is companies self-reporting their AI systems' behavior, which is the same problem Certificate Transparency solved for CAs.

**What I'd use the grant for:** Full-time development for 6 months to get VAOL to v1.0, including a third-party security audit of the signing pipeline. The project is at v0.29 with 21 CI workflows and 5 OpenSSF badges across the portfolio.

---

## 5. Manifund (Public Listing)

> **URL:** https://manifund.org/
> **Type:** Public project listing for regranters
> **Status:** Ready to list
> **Deadline:** Rolling

### Project Listing Description

**Open Source AI Security Infrastructure (10 projects)**

Solo-maintained portfolio of 10 open source tools for AI security, governance, and accountability. Core projects: cryptographic audit trails for AI decisions (VAOL), ML model supply chain attestation (Sigstore/SLSA), prompt injection detection (OWASP LLM Top 10), AI content provenance tracking, and regulatory compliance scanning.

All MIT/Apache 2.0, no commercial backing. 29 releases on the main project, 85+ CI/CD workflows, 5 OpenSSF Best Practices badges at PASSING.

Funding need: $80,000 for security audits and formal verification across the core 3 projects (VAOL, Supply Chain, Firewall).

---

## 6. DigitalOcean Credits for Projects

> **URL:** https://www.digitalocean.com/open-source/credits-for-projects
> **Status:** Not eligible (need 100+ GitHub stars for lowest tier)
> **Note:** Revisit when repos gain more traction

---

## 7. Cloudflare Project Alexandria

> **URL:** https://developers.cloudflare.com/sponsorships/
> **Status:** Ready to apply (no star requirements found)
> **Note:** Free Pro plan + credits for OSS projects. Apply for VAOL and Provenance Tracker.

---

## Submission Priority

1. **Schmidt Sciences** (May 17 deadline, up to $5M) - separate doc
2. **CAIS Compute** (rolling, free GPUs) - separate doc in AI-Provenance-Tracker
3. **Coefficient Giving** (rolling, $150K ask)
4. **GTR Foundation** (rolling, $75K ask)
5. **AIAF** (rolling, $50K ask)
6. **Emergent Ventures** (rolling, 6-month FTE ask)
7. **Manifund** (rolling, public listing)
8. **Cloudflare** (rolling, free credits)
