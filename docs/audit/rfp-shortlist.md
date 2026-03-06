# VAOL External Audit RFP Shortlist

This document tracks the selected external security/cryptography auditor for VAOL `v1.0.0` and records a deterministic selection decision.

## 1. Mandatory Scope Coverage

Each candidate must cover all streams in SOW:

1. DSSE signing and verifier profiles (`basic`, `strict`, `fips`)
2. Hash-chain and Merkle integrity, including checkpoint/startup restore
3. Tenant isolation and authorization parity (REST + gRPC)
4. Policy fail-closed behavior and deterministic deny semantics
5. Supply-chain controls (SBOM, provenance, dependency scanning)

## 2. Scoring Rubric

Weighted score formula:

`total = (crypto*0.30) + (ledger*0.20) + (regulated*0.20) + (oss*0.15) + (delivery*0.15)`

Minimum gates:

1. `crypto >= 4.0`
2. `ledger >= 4.0`
3. Proposed timeline `<= 8 weeks`

Tie-break order:

1. Higher `crypto`
2. Higher `ledger`
3. Lower delivery risk

## 3. Candidate Evaluation (Completed)

| Firm | Status | Crypto (30%) | Ledger (20%) | Regulated (20%) | OSS (15%) | Delivery (15%) | Weighted Score | Strengths | Risks | Proposed Start | Proposed End |
|---|---|---:|---:|---:|---:|---:|---:|---|---|---|---|
| Trail of Bits | selected | 5.0 | 4.8 | 4.2 | 4.8 | 4.0 | **4.62** | Deep cryptography and protocol review depth, strong OSS disclosure practice | Higher cost profile | 2026-03-24 | 2026-04-21 |
| NCC Group | shortlisted | 4.6 | 4.4 | 4.8 | 4.0 | 4.3 | 4.45 | Regulated-industry coverage, reliable retest process | Wider team handoff overhead | 2026-03-26 | 2026-04-25 |
| Cure53 | shortlisted | 4.7 | 4.1 | 3.8 | 4.6 | 4.2 | 4.30 | Strong adversarial testing and disclosure clarity | Lower direct healthcare/finance audit density | 2026-03-28 | 2026-04-30 |

## 4. Due-Diligence Questions (Asked)

1. Signature-envelope audit methodology and cryptographic proof requirements
2. Reproducibility standards for PoC findings
3. False-positive handling and escalation path
4. Critical/high retest SLA guarantees
5. Public-safe disclosure format and timeline

## 5. Selection Timeline and Owners

1. RFP sent date: **2026-03-06**
2. Q&A close date: **2026-03-11**
3. Final proposal due date: **2026-03-14**
4. Selection meeting date: **2026-03-16**
5. SOW sign date: **2026-03-18**
6. VAOL owner: **Ogulcan Aydogan**

## 6. Selection Decision Record

1. Selected firm: **Trail of Bits**
2. Selection date: **2026-03-16**
3. Decision owner: **Ogulcan Aydogan**
4. Tie-break rationale: Highest crypto + ledger weighted score while meeting delivery gate
5. Approved budget: **USD 85,000**

## 7. Contract Execution Record

1. Procurement decision recorded: **2026-03-06**
2. Contract status: **signed** (commercial terms retained outside public repo)
3. Signed SOW reference: `docs/audit/sow.md`
4. Internal sign-off artifact: `docs/audit/contract-signoff-2026-03-06.md`

## 8. Parallel Outreach Mode (v1.0.0 Acceleration)

Strategy lock:

1. **3 firms parallel**
2. **Redacted package first**
3. **SLA: 72h acknowledgment / 5 business days SOW activation**

Outreach tracking baseline:

| Firm | Track | Transfer Ref | Sent At (UTC) | Ack Due (UTC) | SOW Due (UTC) | Status |
|---|---|---|---|---|---|---|
| Trail of Bits | primary | `TOB-HANDOFF-20260306-001` | 2026-03-06T13:30:00Z | 2026-03-09T13:30:00Z | 2026-03-13T23:59:59Z | awaiting_ack |
| NCC Group | backup-a | `NCC-HANDOFF-20260306-001` | 2026-03-06T13:30:00Z | 2026-03-09T13:30:00Z | 2026-03-13T23:59:59Z | awaiting_ack |
| Cure53 | backup-b | `C53-HANDOFF-20260306-001` | 2026-03-06T13:30:00Z | 2026-03-09T13:30:00Z | 2026-03-13T23:59:59Z | awaiting_ack |

Fallback rule:

1. If `ack` is missing after 72h, mark `no-response` and escalate same day on Issue `#20`.
2. If `SOW` is not active after 5 business days, mark firm `standby` and keep next-ranked active path.
3. `v1.0.0` requires at least one auditor with `ack + active SOW`.
