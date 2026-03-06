# VAOL External Security/Cryptography Audit SOW

This SOW executes issue `#20` for the `v1.0.0` release gate.

## 1. Engagement Metadata

1. Auditor: **Trail of Bits**
2. Client: **VAOL maintainers**
3. Engagement window: **2026-03-24** to **2026-04-21**
4. Initial report due date: **2026-04-21**
5. Retest due date: **2026-05-05**

## 2. Systems In Scope

1. Go server components: `pkg/api`, `pkg/grpc`, `pkg/record`, `pkg/merkle`, `pkg/signer`, `pkg/verifier`, `pkg/store`
2. CLI verification workflows (`cmd/vaol-cli`)
3. SDK verification-relevant wrappers (Python/TypeScript)
4. Helm and Docker production deployment references

Out of scope unless separately approved:

1. Third-party cloud tenancy controls outside VAOL ownership
2. Downstream application-specific business logic not in this repo

## 3. Required Security Assertions

Auditor must provide explicit pass/fail assertions for:

1. Signature verification cannot be bypassed by payload/envelope mutation
2. Hash-chain and Merkle integrity detect truncation/tampering deterministically
3. Tenant isolation blocks cross-tenant read/export/proof leakage
4. Policy fail-closed behavior is enforced on dependency failure
5. Strict verification profile behavior is deterministic and documented

## 4. Required Evidence Inputs from VAOL

1. `docs/external-audit-readiness.md`
2. Threat model and architecture docs
3. Latest release notes and changelog
4. Test evidence artifacts (`go`, `python`, `typescript`, `demo_auditor`)
5. SBOM/provenance outputs and dependency scan results
6. Startup restore benchmark artifact from `scripts/check_startup_restore_bench.sh`

## 5. Deliverables

Auditor shall deliver:

1. Full confidential technical report
2. Findings list with severities (`Critical`, `High`, `Medium`, `Low`, `Info`)
3. Reproduction steps with affected versions/commits
4. Retest report for remediated findings
5. Executive summary suitable for sanitized public disclosure

Required machine-readable attachments:

1. Findings JSON/CSV export with stable finding IDs
2. Mapping of findings to affected files/commits
3. Retest status table keyed by finding ID

## 6. Severity and SLA

| Severity | Definition | Remediation target |
|---|---|---|
| Critical | Immediate integrity/security compromise | fix before `v1.0.0` + mandatory retest |
| High | Material risk in production security posture | fix before release or accepted dated remediation plan |
| Medium | Important hardening gap | scheduled backlog item with owner/date |
| Low | Minor issue | opportunistic fix |

## 7. Acceptance Criteria

Engagement completes only when:

1. Critical findings are remediated and retested
2. High findings are either retested as remediated or accepted with dated remediation plan
3. Public-safe remediation summary is published

## 8. Communication Cadence

1. Weekly status checkpoint during active assessment
2. Daily updates while critical findings remain open
3. Final readout meeting with remediation sign-off

## 9. Milestones and Exit Events

1. Kickoff complete: **2026-03-24**
2. Evidence package handoff complete: **2026-03-25**
3. Initial findings report delivered: **2026-04-21**
4. Critical remediation complete target: **2026-04-30**
5. High remediation plan accepted target: **2026-05-02**
6. Retest complete target: **2026-05-05**
7. Public remediation report published target: **2026-05-07**

## 10. Required VAOL Evidence Bundle for Auditor

At handoff, include:

1. `VAOL_AUDIT_RUN_MATRIX=1 ./scripts/build_audit_pack.sh` archive output
2. Latest release notes (`v0.2.28` and onward)
3. Startup restore benchmark artifact (`startup-restore-bench.txt`) showing pass status
4. Auditor demo artifacts from CI and local transcript bundle
