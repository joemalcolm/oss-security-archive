#!/usr/bin/env bash
# publish-index.sh — regenerate index/ and status.json from the inbox.
# (DEC-ARCHIVE-007; see SPEC-index.md and scripts/export-index.pl.)
#
# The one step every workflow that changes the inbox runs after
# `public-inbox-index` and before `git add -A`:
#
#   export-index.pl  ->  verify-index.pl  ->  write-status.pl
#
# status.json is written whether or not the first two succeed. If either
# fails, index/ is rolled back to the last committed version (so a broken
# or half-written projection can never ride along in `git add -A`) and
# this script exits non-zero. Workflows run it with continue-on-error,
# commit as usual — new mail and the error status.json still get pushed —
# and then fail the job in a final step.
#
# Read-only with respect to the inbox. Never purges anything.
#
# Env (all optional):
#   INBOX_DIR        default: inbox
#   INDEX_DIR        default: index
#   INDEX_SOURCE     default: oss-security
#   INDEX_URL_SCHEME default: openwall
#   METRICS_LOG      default: metrics/imports.tsv
#   RUN_STARTED_AT   epoch seconds when the workflow run began; used for
#                    last_run.duration_s and to pick out this run's
#                    metrics line. Default: when this script started.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INBOX_DIR="${INBOX_DIR:-inbox}"
INDEX_DIR="${INDEX_DIR:-index}"
SOURCE="${INDEX_SOURCE:-oss-security}"
SCHEME="${INDEX_URL_SCHEME:-openwall}"
METRICS_LOG="${METRICS_LOG:-metrics/imports.tsv}"
STARTED="${RUN_STARTED_AT:-$(date +%s)}"

log=$(mktemp)
trap 'rm -f "$log"' EXIT

rollback() {   # index/ is a projection: discard it rather than publish it broken
  git rev-parse --is-inside-work-tree >/dev/null 2>&1 || return 0
  if git cat-file -e "HEAD:$INDEX_DIR/manifest.json" 2>/dev/null; then
    git checkout -q HEAD -- "$INDEX_DIR" && git clean -qfd -- "$INDEX_DIR" \
      && echo "    rolled $INDEX_DIR/ back to the committed version" >&2
  elif [[ -z "$(git ls-files -- "$INDEX_DIR" | head -1)" && -d "$INDEX_DIR" ]]; then
    rm -rf -- "${INDEX_DIR:?}"      # never committed: nothing to roll back to
    echo "    removed unpublished $INDEX_DIR/" >&2
  fi
}

fail() {   # fail <stage> — roll back, record the error in status.json, exit 1
  local stage="$1" why
  why=$(grep -m1 '^FAIL: ' "$log" || grep -v -e '^\[' -e '^$' "$log" | tail -1)
  why=$(printf '%s' "$why" | cut -c1-300)
  rollback
  perl "$SCRIPT_DIR/write-status.pl" --status error \
    --top-error "$stage: ${why:-failed}" \
    --index "$INDEX_DIR" --metrics "$METRICS_LOG" --started-at "$STARTED"
  exit 1
}

echo "==> export-index"
perl "$SCRIPT_DIR/export-index.pl" --inbox "$INBOX_DIR" --out "$INDEX_DIR" \
  --source "$SOURCE" --url-scheme "$SCHEME" 2>"$log" || { cat "$log" >&2; fail export-index; }
cat "$log" >&2

echo "==> verify-index"
perl "$SCRIPT_DIR/verify-index.pl" "$INDEX_DIR" --inbox "$INBOX_DIR" \
  2>"$log" || { cat "$log" >&2; fail verify-index; }

perl "$SCRIPT_DIR/write-status.pl" --status ok \
  --index "$INDEX_DIR" --metrics "$METRICS_LOG" --started-at "$STARTED"
