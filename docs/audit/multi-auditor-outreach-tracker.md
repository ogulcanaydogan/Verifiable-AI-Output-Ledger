# VAOL Multi-Auditor Outreach Tracker

This tracker is the source of truth for parallel auditor outreach under Issue `#20`.

## 1. Transfer Reference Convention

Use the following reference format per firm:

1. `TOB-HANDOFF-YYYYMMDD-001`
2. `NCC-HANDOFF-YYYYMMDD-001`
3. `C53-HANDOFF-YYYYMMDD-001`

## 2. SLA Policy

1. `ack` due: 72 hours after `sent_at_utc`
2. `SOW active` due: 5 business days after `sent_at_utc`
3. SLA miss action:
   1. mark firm `no-response` or `standby`
   2. post same-day update on Issue `#20`
   3. activate next available firm path

## 3. Outreach Status Table

| Firm | Transfer Ref | Package Tier | Sent At (UTC) | Ack Due (UTC) | SOW Due (UTC) | Ack Ref | SOW Ref | Status | Next Action |
|---|---|---|---|---|---|---|---|---|---|
| Trail of Bits | `TOB-HANDOFF-20260306-001` | redacted | 2026-03-06T13:30:00Z | 2026-03-09T13:30:00Z | 2026-03-13T23:59:59Z | pending | active contract (`docs/audit/sow.md`) | follow_up_sent | re-check response by 2026-03-12 |
| NCC Group | `NCC-HANDOFF-20260306-001` | redacted | 2026-03-06T13:30:00Z | 2026-03-09T13:30:00Z | 2026-03-13T23:59:59Z | pending | pending | follow_up_sent | re-check response by 2026-03-12 |
| Cure53 | `C53-HANDOFF-20260306-001` | redacted | 2026-03-06T13:30:00Z | 2026-03-09T13:30:00Z | 2026-03-13T23:59:59Z | pending | pending | follow_up_sent | re-check response by 2026-03-12 |

## 4. Escalation Matrix

1. 72h ack miss:
   1. status -> `no-response`
   2. Issue `#20` same-day escalation comment
2. 5 business day SOW miss:
   1. status -> `standby`
   2. promote next path as `active`
3. If all firms are `no-response`:
   1. keep Issue `#20` open
   2. continue `v0.2.x` only
   3. block `v1.0.0`

## 5. Latest Operational Checkpoint

1. `2026-03-10`: follow-up sent on all three outreach paths after the expired 72h acknowledgment window.
2. Current waiting state: `ack` still pending for all firms.
3. Next manual checkpoint: `2026-03-12`.

## 6. Completion Criteria

1. At least one firm has `ack_ref` populated.
2. At least one firm has active SOW.
3. Findings intake has started using `scripts/create_audit_finding_issue.sh`.
