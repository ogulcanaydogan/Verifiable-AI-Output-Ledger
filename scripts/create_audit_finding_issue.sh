#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<USAGE
Usage:
  $0 --id FINDING_ID --severity SEVERITY --control CONTROL_ID --owner OWNER --due YYYY-MM-DD --summary SUMMARY --report-ref REPORT_REF

Example:
  $0 --id F-001 --severity critical --control CRYPTO-1 --owner "@ogulcanaydogan" --due 2026-04-30 --summary "DSSE bypass" --report-ref "audit-report-2026-04-21#F-001"
USAGE
}

FINDING_ID=""
SEVERITY=""
CONTROL_ID=""
OWNER=""
DUE_DATE=""
SUMMARY=""
REPORT_REF=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --id) FINDING_ID="$2"; shift 2 ;;
    --severity) SEVERITY="$2"; shift 2 ;;
    --control) CONTROL_ID="$2"; shift 2 ;;
    --owner) OWNER="$2"; shift 2 ;;
    --due) DUE_DATE="$2"; shift 2 ;;
    --summary) SUMMARY="$2"; shift 2 ;;
    --report-ref) REPORT_REF="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "$FINDING_ID" || -z "$SEVERITY" || -z "$CONTROL_ID" || -z "$OWNER" || -z "$DUE_DATE" || -z "$SUMMARY" || -z "$REPORT_REF" ]]; then
  echo "Missing required argument(s)." >&2
  usage
  exit 1
fi

case "$SEVERITY" in
  critical|high|medium|low|info) ;;
  *) echo "Invalid severity: $SEVERITY" >&2; exit 1 ;;
esac

TMP_BODY="$(mktemp)"
trap 'rm -f "$TMP_BODY"' EXIT

cat > "$TMP_BODY" <<BODY
## Finding metadata

- **Finding ID**: ${FINDING_ID}
- **Severity**: ${SEVERITY}
- **Report reference**: ${REPORT_REF}
- **Affected control IDs**: ${CONTROL_ID}

## Risk summary

${SUMMARY}

## Remediation owner and timeline

- **Owner**: ${OWNER}
- **Target date**: ${DUE_DATE}

## Remediation plan

TBD

## Evidence links (mandatory before closure)

- **Fix commit/PR**: TBD
- **Test evidence**: TBD
- **Retest evidence**: TBD

## Status

- [ ] Fix implemented
- [ ] Tests passing
- [ ] Retest passed
- [ ] Linked in Issue #20 weekly summary
BODY

gh issue create \
  --title "[Audit Finding][${SEVERITY^^}] ${FINDING_ID} - ${SUMMARY}" \
  --body-file "$TMP_BODY" \
  --label "audit-finding" \
  --label "severity:${SEVERITY}"
