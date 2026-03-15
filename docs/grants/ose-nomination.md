# Open Source Endowment, Self-Nomination

> **Program:** Open Source Endowment Foundation (OSE)
> **URL:** https://endowment.dev/funding/
> **Type:** Self-nomination for microgrant
> **Amount:** ~$5,000 per project (security/stability improvements)
> **Timeline:** First distribution Q2 2026
> **Status:** Ready to nominate
> **Deadline:** Rolling (nominations open now)

---

## Nomination Details

Submit self-nominations on the OSE website form for each project. The form asks for:

1. **Your name:** Ogulcan Aydogan
2. **Your email:** security@ogulcanaydogan.com
3. **GitHub repository URL:** (per project, see below)
4. **Optional comments:** (see below)
5. **Website link (optional):** https://github.com/ogulcanaydogan

---

## Projects to Nominate

### 1. Verifiable AI Output Ledger (VAOL)

**GitHub URL:** https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger
**Comments:** Cryptographic audit ledger for AI/LLM inference decisions. DSSE signing (Ed25519, Sigstore keyless, KMS/HSM), SHA-256 hash chains, RFC 6962 Merkle trees with verifiable inclusion proofs. 29 releases, 21 CI workflows, OpenSSF Best Practices PASSING. No corporate backing, solo maintainer. The $5K would fund a third-party security audit of the signing pipeline, which is the v1.0 release gate.

### 2. LLM-Supply-Chain-Attestation

**GitHub URL:** https://github.com/ogulcanaydogan/LLM-Supply-Chain-Attestation
**Comments:** Sigstore/SLSA attestation pipeline for ML model artifacts. Generates in-toto provenance, signs container images, verifies model integrity through the supply chain. 7 releases, 8 CI workflows. Solo maintainer, Apache 2.0. The $5K would fund SBOM tooling expansion and attestation verification benchmarks.

### 3. Prompt-Injection-Firewall

**GitHub URL:** https://github.com/ogulcanaydogan/Prompt-Injection-Firewall
**Comments:** OWASP LLM Top 10 detection engine for prompt injection, jailbreak, and data exfiltration attempts. 4 releases, CodeQL in CI. Solo maintainer, Apache 2.0. The $5K would fund adversarial testing and evasion resistance benchmarks across model families.

### 4. Sovereign-RAG-Gateway

**GitHub URL:** https://github.com/ogulcanaydogan/Sovereign-RAG-Gateway
**Comments:** Policy-first RAG governance layer with PHI/PII redaction, OPA enforcement, and audit logging. 19 releases, 11 CI workflows, MIT license. Solo maintainer. The $5K would fund integration testing with production RAG stacks and policy rule expansion.

### 5. AI-Provenance-Tracker

**GitHub URL:** https://github.com/ogulcanaydogan/AI-Provenance-Tracker
**Comments:** Multi-modal AI content detection (text, image, audio, video) with explainable scoring. C2PA verification, multi-provider consensus. 20 CI workflows, MIT license. Solo maintainer. The $5K would fund multi-language detection model training (Arabic, Farsi, Russian, Mandarin, Spanish).

---

## Submission Steps

1. Visit https://endowment.dev/funding/
2. Find the nomination form
3. Submit one nomination per project (5 nominations total)
4. Use the comments above for each project
5. Update this file and master tracker with submission dates
6. First distribution expected Q2 2026

---

## Notes

- Self-nominations are explicitly welcome
- Must be independent FOSS (no corporate/VC-funded) - all qualify
- Selection uses Value-Risk scoring: downloads, dependents, security posture, bus factor
- Our OpenSSF badges and scorecards strengthen the security posture signal
- OSE is a new foundation; this is their first distribution round
