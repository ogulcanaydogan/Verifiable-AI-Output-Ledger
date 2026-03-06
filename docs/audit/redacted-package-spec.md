# VAOL Redacted Audit Package Spec

This document defines what can be shared before NDA/SOW finalization.

## 1. Purpose

Reduce response latency by sharing a safe, redacted package with multiple auditors in parallel.

## 2. Redacted Package Contents (Allowed Pre-NDA)

1. `docs/architecture.md`
2. `docs/threat-model.md`
3. `docs/external-audit-readiness.md`
4. `docs/releases/v1.0.0-audit-gate.md`
5. `docs/audit/rfp-shortlist.md` (sanitized)
6. `docs/audit/sow.md` (scope/SLA only; no private legal/commercial terms)
7. Sanitized benchmark and demo summaries (no secrets, no raw sensitive payloads)

## 3. Restricted Until NDA/SOW

1. Full evidence archives from `tmp/audit-pack/*`
2. Raw logs containing sensitive environment details
3. Internal commercial/legal attachments
4. Any tenant/customer-derived data

## 4. Upgrade Rule to Full Package

A firm may receive full package only when one is true:

1. NDA is signed, or
2. SOW is signed/active.

When upgraded, log reference must be posted in Issue `#20` and `docs/audit/handoff-receipt-2026-03-06.md`.

## 5. Integrity Requirement

Every shared package (redacted or full) must include:

1. package path
2. SHA256 digest
3. transfer reference ID
4. timestamp (UTC)
