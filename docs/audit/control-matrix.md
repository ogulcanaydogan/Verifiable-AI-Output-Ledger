# VAOL Audit Control Matrix

This matrix maps key VAOL controls to evidence sources for external audit workflows.

## 1. Cryptographic Integrity Controls

| Control ID | Control | Evidence Source |
|---|---|---|
| CRYPTO-1 | DSSE signatures required and verified | `pkg/signer`, `pkg/verifier`, `tests/tamper` |
| CRYPTO-2 | Hash-chain integrity is deterministic | `pkg/record`, `pkg/verifier`, `tests/e2e` |
| CRYPTO-3 | Merkle inclusion/consistency proofs are verifiable | `pkg/merkle`, `pkg/verifier`, `tests/tamper` |
| CRYPTO-4 | Checkpoint signatures and anchor continuity validated | `pkg/api/startup.go`, `docs/dr-playbook.md` |

## 2. Access and Tenant Isolation Controls

| Control ID | Control | Evidence Source |
|---|---|---|
| AUTH-1 | JWT verification and claim binding enforced | `pkg/auth`, `pkg/api/auth_test.go` |
| AUTH-2 | Tenant context mismatch denied deterministically | `pkg/api`, `pkg/grpc`, tenant isolation tests |
| AUTH-3 | Cross-tenant read/export/proof blocked | `tests/e2e/tenant_isolation_test.go`, gRPC tests |

## 3. Policy and Governance Controls

| Control ID | Control | Evidence Source |
|---|---|---|
| POLICY-1 | Fail-closed mode available and production-default documented | `pkg/policy`, `docs/deployment-production-profile.md` |
| POLICY-2 | Decision reason code captured for auditability | `pkg/record`, API/gRPC handlers |
| POLICY-3 | Redaction/privacy mode controls present | `pkg/record`, policy packs, lifecycle tests |

## 4. Availability and Recovery Controls

| Control ID | Control | Evidence Source |
|---|---|---|
| HA-1 | Single-writer fencing supported for Postgres | `pkg/store/postgres_fencing.go`, `cmd/vaol-server` |
| HA-2 | Startup rebuild validation fail-closed | `pkg/api/startup.go`, startup tests |
| HA-3 | Snapshot+tail restore acceleration for large ledgers | `pkg/merkle/snapshot.go`, startup tests/bench |

## 5. Supply-Chain and Release Controls

| Control ID | Control | Evidence Source |
|---|---|---|
| SC-1 | CI security scanning gates are present | `.github/workflows/ci.yml` |
| SC-2 | SBOM artifacts produced in CI | `ci.yml` (`sbom` job) |
| SC-3 | Reproducible integration demo artifacts | `scripts/demo_auditor.sh`, uploaded artifacts |

## 6. Audit Findings Triage Policy

Severity handling policy for Issue `#20` and child findings:

1. `Critical`: must be fixed and retested before `v1.0.0` tag
2. `High`: must be fixed and retested before release, **or** accepted with signed dated remediation plan
3. `Medium`: backlog issue with owner and target date before `v1.1.0`
4. `Low`: backlog issue with owner and target date, may be grouped

Required fields per finding issue:

1. finding ID
2. severity
3. affected controls
4. owner
5. due date
6. evidence links (fix commit + test + retest)

## 7. Open Findings Register

Parallel outreach tracker: `docs/audit/multi-auditor-outreach-tracker.md`

Redacted sharing policy: `docs/audit/redacted-package-spec.md`

Track auditor findings and remediation status:

| Finding ID | Severity | Affected Control | Status | Owner | Target Date | Retest Evidence |
|---|---|---|---|---|---|---|
| _none yet_ |  |  |  |  |  |  |

## 8. Evidence Collection Commands

Run and archive these commands for each audit cycle:

1. Full audit evidence package:

```bash
VAOL_AUDIT_RUN_MATRIX=1 ./scripts/build_audit_pack.sh
```

2. Startup restore benchmark gate:

```bash
./scripts/check_startup_restore_bench.sh
```

3. Auditor reproducibility scenario:

```bash
./scripts/demo_auditor.sh
```

## 9. Weekly Audit Execution Cadence

Issue `#20` must receive a weekly status comment while external audit is active.

Required weekly update fields:

1. report week ending date
2. current finding counts by severity
3. critical/high remediation progress
4. retest requests sent/received
5. risk to `v1.0.0` target date

Weekly status log:

| Week Ending | Status Owner | Summary | Link |
|---|---|---|---|
| 2026-03-06 | Ogulcan Aydogan | Contract + evidence handoff baseline completed; awaiting auditor execution window | `#20` |


## 10. Daily Critical/High Cadence

During active remediation windows:

1. Every open `critical` finding must receive a daily progress comment in its issue.
2. Every open `high` finding must receive a daily progress comment in its issue.
3. Daily comment must include: blocker status, ETA confidence, and retest request status.
4. Any missed daily update is treated as release risk and escalated in Issue `#20`.
