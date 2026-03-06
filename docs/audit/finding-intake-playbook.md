# VAOL Audit Finding Intake Playbook

This playbook defines the mandatory workflow after external auditor findings arrive.

## 1. Intake Trigger

Start this workflow when auditor delivers initial findings JSON/CSV and report.

## 2. Issue Creation Rules

For each finding, create a dedicated GitHub issue with:

1. finding ID
2. severity (`critical|high|medium|low|info`)
3. affected control IDs
4. owner
5. target remediation date
6. report reference
7. fix/test/retest evidence placeholders

Required labels:

1. `audit-finding`
2. `severity:critical|severity:high|severity:medium|severity:low|severity:info`

## 3. Cadence Rules

1. `critical` and `high` findings: daily status updates in finding issue.
2. Weekly aggregate status posted to Issue `#20`.
3. Any blocker to target date must be posted same day on Issue `#20`.

## 4. CLI Helper

Use helper script to open finding issues with standard body:

```bash
./scripts/create_audit_finding_issue.sh \
  --id F-001 \
  --severity critical \
  --control CRYPTO-1 \
  --owner "@ogulcanaydogan" \
  --due 2026-04-30 \
  --summary "DSSE verification bypass via envelope mutation" \
  --report-ref "audit-report-2026-04-21#F-001"
```

## 5. Release Gate Mapping

`v1.0.0` release cannot proceed until:

1. all `critical` findings are fixed and retested,
2. all `high` findings are fixed and retested, or have accepted dated remediation plans,
3. public remediation report is published.
