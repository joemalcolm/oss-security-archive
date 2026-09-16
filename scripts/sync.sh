#!/usr/bin/env bash
# sync.sh — Rolling scheduled sync for oss-security via openwall scrape.
# Called by .github/workflows/sync.yml on a 4-hour cron. Wraps
# backfill-openwall.sh with a small rolling window (yesterday+today by
# default) so we catch anything posted since the previous sync,
# including messages that hit openwall's archive slightly late or
# straddle a timezone edge.
#
# All the actual pipeline lives in backfill-openwall.sh + its
# downstream scripts: --diff-against dedup, --save-failed for
# unparseable pages, structured warnings + metrics, ingest-direct
# with content-hash+MID dedup, subscriber-side sanitizer, etc.
# Nothing sync-specific except the date range.
#
# Env:
#   INBOX_DIR         public-inbox repo path (default: $(pwd)/inbox)
#   METRICS_LOG       tsv file for run metrics (default: metrics/imports.tsv)
#   SYNC_DAYS_BACK    days of overlap (default 1 = yesterday + today).
#                     Widen if a scheduled run was skipped or if
#                     backfilling a missed window.
#   FAIL_THRESHOLD_PCT  if set, exit non-zero when failure rate >N%;
#                     GHA marks the run failed and notifies. Sensible
#                     default for sync: 0 (any failure worth looking at).
set -euo pipefail

DAYS_BACK="${SYNC_DAYS_BACK:-1}"

# Portable date arithmetic — GNU date on Linux runners, BSD date on macOS.
END=$(date -u +%F)
if START=$(date -u -d "-${DAYS_BACK} days" +%F 2>/dev/null); then :; else
  START=$(date -u -v-"${DAYS_BACK}"d +%F)
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "==> sync: rolling window $START..$END"
exec "$SCRIPT_DIR/backfill-openwall.sh" "$START" "$END"
