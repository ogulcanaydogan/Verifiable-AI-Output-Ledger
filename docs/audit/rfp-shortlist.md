# VAOL External Audit RFP Shortlist

This document is the working shortlist and scoring rubric for selecting an independent security/cryptography auditor for VAOL `v1.0.0`.

## 1. Mandatory Scope Coverage

Each candidate must explicitly cover all areas below in the statement of work:

1. DSSE signing and verifier profiles (`basic`, `strict`, `fips`) correctness.
2. Hash-chain and Merkle integrity, including checkpoint handling and startup restore.
3. Tenant isolation and authorization parity across REST and gRPC.
4. Policy fail-closed behavior and deterministic deny semantics.
5. Supply-chain controls (release provenance, SBOM, dependency scanning).

## 2. Candidate Scoring Rubric

Score each candidate 1-5 per category; weighted total determines ranking.

| Category | Weight | Notes |
|---|---:|---|
| Cryptography review depth | 30% | Prior reviews of DSSE, transparency logs, KMS/HSM integrations |
| Ledger/integrity systems expertise | 20% | Experience with append-only logs, Merkle proof systems |
| Regulated environment experience | 20% | HIPAA/SOC2/ISO27001 exposure and evidence practices |
| Open-source disclosure quality | 15% | Can provide public-safe remediation summaries |
| Delivery reliability and timeline | 15% | Ability to complete within target release window |

## 3. Candidate Shortlist Template

Populate this table before SOW finalization:

| Firm | Status | Score | Strengths | Risks | Proposed Start | Proposed End |
|---|---|---:|---|---|---|---|
| `<firm-1>` | evaluating | `0.0` |  |  |  |  |
| `<firm-2>` | evaluating | `0.0` |  |  |  |  |
| `<firm-3>` | evaluating | `0.0` |  |  |  |  |

## 4. Due-Diligence Questions

1. What cryptographic review methodology is used for signature envelope systems?
2. Do you provide exploitability-ranked findings and reproducible PoCs?
3. How are false positives handled and appealed?
4. What retest turnaround is guaranteed for critical/high findings?
5. Can you provide references for prior open-source security audits?

## 5. Selection Decision Record

Record final selection here:

1. Selected firm: `<name>`
2. Selection date: `<YYYY-MM-DD>`
3. Decision owner: `<name>`
4. Tie-break rationale: `<summary>`
5. Approved budget: `<amount and currency>`
