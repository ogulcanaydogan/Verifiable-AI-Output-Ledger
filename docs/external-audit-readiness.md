# VAOL External Audit Readiness Package

This document defines the package required before commissioning an independent security/cryptography audit.

## 1. Audit Scope

Required audit streams:

1. Cryptography implementation review (DSSE, signer backends, verifier strict profiles)
2. Ledger integrity model review (hash chain, Merkle proofs/checkpoints, startup restore)
3. Multi-tenant authz review (REST + gRPC parity, cross-tenant controls)
4. Policy/governance enforcement review (fail-closed behavior, deterministic denies)

## 2. Evidence Package Checklist

Provide to auditor:

1. Threat model (current release)
2. Architecture and crypto design docs
3. API + protobuf contracts
4. Test evidence:
   1. unit/e2e/tamper reports
   2. strict verification reports
5. Release provenance artifacts:
   1. SBOM
   2. checksums
   3. signed release artifacts
6. Operational controls:
   1. DR playbook
   2. compliance operations baseline
   3. key rotation and retention evidence

## 3. Auditor Reproducibility Path

1. Deploy reference stack (Docker Compose or Helm production profile).
2. Run demo storyline:
   1. compliant request accepted
   2. non-compliant request denied
   3. export bundle
   4. offline strict verification
   5. tamper test deterministic failure
3. Validate checkpoint continuity and anchor evidence.

## 4. Exit Criteria for Audit Completion

1. All critical findings remediated and retested.
2. High findings have accepted remediation plan with deadlines.
3. Public remediation report produced for open-source consumers.
4. v1.0 tag gated on completed remediation evidence.

## 5. Execution Artifacts and Automation

Execution templates:

1. `docs/audit/rfp-shortlist.md`
2. `docs/audit/sow.md`
3. `docs/audit/control-matrix.md`
4. `docs/audit/remediation-report-template.md`

Evidence packaging helper:

```bash
./scripts/build_audit_pack.sh
```

To include a full local verification matrix in the package:

```bash
VAOL_AUDIT_RUN_MATRIX=1 ./scripts/build_audit_pack.sh
```

## 6. Current Execution Status (Issue #20)

1. Auditor selection completed and recorded in `docs/audit/rfp-shortlist.md`.
2. SOW baseline locked and signature status recorded in:
   1. `docs/audit/sow.md`
   2. `docs/audit/contract-signoff-2026-03-06.md`
3. Control-to-evidence mapping and triage policy finalized in `docs/audit/control-matrix.md`.
4. Public remediation reporting template finalized in `docs/audit/remediation-report-template.md`.
5. Latest checksum-locked handoff receipt: `docs/audit/handoff-receipt-2026-03-06.md`.
6. Latest matrix package baseline:
   1. `tmp/audit-pack/20260306T130202Z.tar.gz`
   2. `sha256: e8bf3864a9ccac094b5876cae35c24ee9d194a49ef9b16401a51604e4211514e`
7. Remaining blocker for closure: complete external auditor execution + remediation/retest + publish final public remediation report before `v1.0.0`.
