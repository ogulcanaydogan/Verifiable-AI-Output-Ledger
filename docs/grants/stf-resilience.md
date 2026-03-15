# Sovereign Tech Fund, Resilience Program

> **Program:** Sovereign Tech Resilience (formerly Bug Resilience)
> **URL:** https://www.sovereign.tech/programs/bug-resilience
> **Apply:** https://apply.sovereigntechfund.de/entry-form/entrant/start?formSlug=NJBqDZom
> **Type:** Security audits, code reviews, bug bounties (in-kind, not cash)
> **Cost:** Free (funded by German Federal Ministry of Economic Affairs)
> **Status:** Ready to apply
> **Deadline:** Rolling (reviewed on ongoing basis)

---

## What This Program Covers

Three services, all free for accepted projects:

1. **Direct Contributions** via Neighbourhoodie Software: fixing known issues, improving documentation, reducing technical debt
2. **Bug and Fix Bounty** via YesWeHack: professional security researchers find and fix vulnerabilities in your codebase
3. **Code Audits** via OSTIF: formal security reviews of critical components

---

## Which Projects to Apply With

### 1. Verifiable AI Output Ledger (VAOL) - Primary

**Why it fits:** Cryptographic signing infrastructure (DSSE, Sigstore, Merkle trees) is exactly the type of "open digital base technology" they target. It's a library/protocol implementation, not a consumer app. Under-supplied in the AI governance space, solo maintainer (bus factor = 1).

**Audit scope:** DSSE signing pipeline, RFC 6962 Merkle tree, hash chain integrity, multi-tenant authorization, OPA policy enforcement.

**Note:** We already submitted to STF's main fund for VAOL. If that gets funded, Resilience services become automatically eligible.

### 2. LLM-Supply-Chain-Attestation

**Why it fits:** Supply chain signing for ML models. Implements Sigstore, in-toto, and SLSA standards. Core infrastructure for AI supply chain security. Solo maintainer.

**Audit scope:** Sigstore integration, attestation verification logic, SBOM generation pipeline.

### 3. Prompt-Injection-Firewall

**Why it fits:** Security middleware for LLM applications. Detects OWASP LLM Top 10 attacks. Protocol-level protection, not a user-facing app.

**Audit scope:** Detection bypass resistance, false positive/negative rates, input sanitization.

---

## Application Talking Points

When filling the STF Resilience form, emphasize:

- **Open digital base technology:** These are libraries and protocol implementations, not consumer applications
- **Societal relevance:** AI governance and security affects regulated industries, journalism, healthcare, government
- **Under-supplied:** Solo maintainer for all projects (bus factor = 1), no commercial backing
- **License compliance:** All projects use OSI-approved licenses (Apache 2.0 or MIT)
- **Not prototypes:** VAOL has 29 releases, RAG Gateway has 19 releases, all have production CI/CD
- **Existing STF relationship:** Already submitted 3 projects to STF's main fund

---

## Submission Steps

1. Visit https://apply.sovereigntechfund.de/entry-form/entrant/start?formSlug=NJBqDZom
2. Fill application form for VAOL first (strongest fit)
3. Submit additional applications for Supply Chain and PIF if form allows
4. Reference existing STF main fund applications (VAOL, Supply Chain ID: xAZqPQzy, RAG Gateway ID: LlKybxJo)
5. Update master tracker with submission dates

---

## Notes

- Program partners: Neighbourhoodie (contributions), YesWeHack (bounties), OSTIF (audits)
- This overlaps with our OSTIF outreach (pending email to amir@ostif.org) but through a funded channel
- STF Resilience acceptance would effectively deliver the security audit that VAOL needs for v1.0
- Waiting times vary by service capacity
- Projects previously funded by STF are auto-eligible without reapplication
