# VAOL Auditor Handoff Checklist

Use this checklist for each external auditor handoff package.

## 1. Package Integrity

1. Audit package archive generated with matrix mode:
   1. `VAOL_AUDIT_RUN_MATRIX=1 ./scripts/build_audit_pack.sh`
2. Archive SHA256 recorded in handoff receipt.
3. `meta/manifest.txt` includes branch + commit.
4. `meta/SHA256SUMS` exists in package.

## 2. Required Documents

1. `docs/external-audit-readiness.md`
2. `docs/audit/rfp-shortlist.md`
3. `docs/audit/sow.md`
4. `docs/audit/control-matrix.md`
5. `docs/audit/remediation-report-template.md`

## 3. Required Evidence Logs

1. `go-test-all.log`
2. `go-test-race-e2e-tamper.log`
3. `python-checks.log`
4. `typescript-checks.log`
5. `startup-restore-benchmark.log` and `startup-restore-bench.txt`
6. `demo-auditor.log`
7. `docker-build-server.log`
8. `docker-build-proxy.log`

## 4. External References to Include

1. Latest stable release page (`v0.2.28` or newer)
2. Latest green CI run on `main`
3. Latest release workflow run
4. Issue `#20` status link

## 5. Acceptance Before Sending

1. Package generated successfully with no failed command logs.
2. Demo storyline evidence includes tamper-fail behavior.
3. Startup restore benchmark status is `pass`.
4. Auditor contact, scope, and dates are aligned with `docs/audit/sow.md`.
