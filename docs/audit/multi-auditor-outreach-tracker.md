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
| Trail of Bits | `TOB-HANDOFF-20260306-001` | redacted | 2026-03-06T13:30:00Z | 2026-03-09T13:30:00Z | 2026-03-13T23:59:59Z | signed contract record (`docs/audit/contract-signoff-2026-03-06.md`) | active contract (`docs/audit/sow.md`) | active_sow | continue execution path and run weekly checkpoint cadence |
| NCC Group | `NCC-HANDOFF-20260306-001` | redacted | 2026-03-06T13:30:00Z | 2026-03-09T13:30:00Z | 2026-03-13T23:59:59Z | pending | pending | standby | keep on standby; reactivate only if active path stalls |
| Cure53 | `C53-HANDOFF-20260306-001` | redacted | 2026-03-06T13:30:00Z | 2026-03-09T13:30:00Z | 2026-03-13T23:59:59Z | pending | pending | standby | keep on standby; reactivate only if active path stalls |

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
2. `2026-03-21` catch-up: no additional external acknowledgment has been recorded after the `2026-03-10` follow-up update.
3. `2026-03-30` overdue catch-up checkpoint: no additional external acknowledgment has been recorded since `2026-03-21`.
4. Trail of Bits path remains `ack + active SOW` via signed contract record (`docs/audit/contract-signoff-2026-03-06.md`) and active SOW (`docs/audit/sow.md`).
5. NCC Group and Cure53 remain `standby` after 5 business day SOW activation miss (`2026-03-13T23:59:59Z`).
6. Next manual checkpoint: `2026-04-06`.

## 6. Completion Criteria

1. At least one firm has `ack_ref` populated.
2. At least one firm has active SOW.
3. Findings intake has started using `scripts/create_audit_finding_issue.sh`.
