#!/usr/bin/env bash
# Usage: ./scripts/generate_report.sh <report_type> [period_hours] [framework]
# Example: ./scripts/generate_report.sh ACCESS_SUMMARY 24
#          ./scripts/generate_report.sh FRAMEWORK_SPECIFIC 168 GDPR

set -euo pipefail

WARDEN_URL="${WARDEN_URL:-http://localhost:3000}"

VALID_TYPES=(ACCESS_SUMMARY DENIED_ACCESS_SUMMARY ESCAPE_HATCH_AUDIT HONESTY_AUDIT FRAMEWORK_SPECIFIC RETENTION_COMPLIANCE)

usage() {
  echo "Usage: $0 <report_type> [period_hours] [framework]" >&2
  echo "  report_type: ${VALID_TYPES[*]}" >&2
  echo "  period_hours: integer, default 24" >&2
  echo "  framework: required when report_type=FRAMEWORK_SPECIFIC (HIPAA|PCI|SOX|GDPR)" >&2
}

if [ $# -lt 1 ]; then
  usage
  exit 2
fi

REPORT_TYPE="$1"
PERIOD_HOURS="${2:-24}"
FRAMEWORK="${3:-}"

# Validate report type
found=0
for t in "${VALID_TYPES[@]}"; do
  if [ "$t" = "$REPORT_TYPE" ]; then found=1; break; fi
done
if [ "$found" -ne 1 ]; then
  echo "error: unknown report_type '$REPORT_TYPE'" >&2
  usage
  exit 2
fi

# Validate hours
if ! [[ "$PERIOD_HOURS" =~ ^[0-9]+$ ]]; then
  echo "error: period_hours must be a non-negative integer, got '$PERIOD_HOURS'" >&2
  exit 2
fi

NOW=$(date +%s)
START=$(( NOW - PERIOD_HOURS * 3600 ))

if [ "$REPORT_TYPE" = "FRAMEWORK_SPECIFIC" ]; then
  if [ -z "$FRAMEWORK" ]; then
    echo "error: FRAMEWORK_SPECIFIC requires a framework argument" >&2
    exit 2
  fi
  BODY=$(printf '{"report_type":"%s","period_start":%d,"period_end":%d,"framework":"%s"}' \
    "$REPORT_TYPE" "$START" "$NOW" "$FRAMEWORK")
else
  BODY=$(printf '{"report_type":"%s","period_start":%d,"period_end":%d}' \
    "$REPORT_TYPE" "$START" "$NOW")
fi

RESP=$(curl -sS -w $'\n%{http_code}' -X POST \
  -H "Content-Type: application/json" \
  -d "$BODY" \
  "$WARDEN_URL/api/reports/generate")

HTTP_CODE=$(printf '%s' "$RESP" | tail -n1)
JSON=$(printf '%s' "$RESP" | sed '$d')

if [ "$HTTP_CODE" != "200" ]; then
  echo "error: server returned HTTP $HTTP_CODE" >&2
  echo "$JSON" >&2
  exit 1
fi

# Extract the markdown field. Prefer jq; fall back to python3.
if command -v jq >/dev/null 2>&1; then
  printf '%s' "$JSON" | jq -r '.markdown'
else
  printf '%s' "$JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['markdown'])"
fi
