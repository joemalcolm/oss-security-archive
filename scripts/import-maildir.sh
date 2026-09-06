#!/usr/bin/env bash
# import-maildir.sh — Ingest a Maildir into the public-inbox repo.
# Iterates $MAILDIR/{cur,new}, runs each message through sanitize-headers.pl
# (drops subscriber-side header cruft above openwall's first hop — see
# DEC-ARCHIVE-003 in scripts/sanitize-headers.pl), then feeds each
# sanitized message into ingest-direct.pl which writes it straight to
# the public-inbox v2 repo via PublicInbox::V2Writable::add(),
# bypassing public-inbox-mda's delivery-policy prechecks that would
# otherwise reject HTML and attachment-bearing messages (DEC-ARCHIVE-005).
# Idempotent: public-inbox dedups on Message-ID, so re-runs are safe.
#
# @decision DEC-ARCHIVE-002
# @title Maildir is the canonical historical-ingest path
# @status accepted
# @rationale Openwall does not expose machine-readable mbox endpoints at any
#   granularity (verified 2026-05-15: /YYYY/mbox, /YYYY/MM/DD/mbox, and per-message
#   .eml/.mbox/?format=raw all return 404). HTML-only sources lose fidelity
#   (seclists.org strips Message-ID and obfuscates From; openwall.com preserves
#   Message-ID but obfuscates addresses). A user-supplied Maildir preserves
#   full RFC822 and is the highest-fidelity ingest path available.
#
# Usage: import-maildir.sh <MAILDIR>
# Env:
#   INBOX_DIR  public-inbox repo path (default: $(pwd)/inbox)
set -euo pipefail

MAILDIR="${1:-${MAILDIR:-}}"
INBOX_DIR="${INBOX_DIR:-$(pwd)/inbox}"
INBOX_NAME="${INBOX_NAME:-oss-security}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANITIZE="${SANITIZE:-$SCRIPT_DIR/sanitize-headers.pl}"
INGEST="${INGEST:-$SCRIPT_DIR/ingest-direct.pl}"

if [[ -z "$MAILDIR" ]]; then
  echo "Usage: $0 <MAILDIR>" >&2
  echo "  INBOX_DIR  inbox path (default: \$(pwd)/inbox)" >&2
  exit 1
fi

if [[ ! -d "$MAILDIR" ]]; then
  echo "Error: MAILDIR not a directory: $MAILDIR" >&2
  exit 1
fi

if [[ ! -d "$MAILDIR/cur" && ! -d "$MAILDIR/new" ]]; then
  echo "Error: $MAILDIR has no cur/ or new/ — not a Maildir" >&2
  exit 1
fi

if [[ ! -d "$INBOX_DIR" ]]; then
  echo "Error: INBOX_DIR not a directory: $INBOX_DIR" >&2
  echo "Hint: run ./scripts/setup-inbox.sh first." >&2
  exit 1
fi

if ! command -v perl >/dev/null 2>&1; then
  echo "Error: perl not found in PATH (required by sanitize-headers.pl)." >&2
  exit 1
fi

if [[ ! -f "$INGEST" ]]; then
  echo "Error: direct ingester not found at: $INGEST" >&2
  echo "Hint: set INGEST=/path/to/ingest-direct.pl to override." >&2
  exit 1
fi

# The direct-writer needs the PublicInbox::* modules from the
# public-inbox package. A quick check catches "you forgot to
# apt-install" up front instead of failing on every message.
if ! perl -e 'use PublicInbox::Config; use PublicInbox::InboxWritable; use PublicInbox::Eml; 1' 2>/dev/null; then
  echo "Error: PublicInbox::* Perl modules not installed." >&2
  echo "Install with: apt install public-inbox" >&2
  exit 1
fi

if [[ ! -f "$SANITIZE" ]]; then
  echo "Error: header sanitizer not found at: $SANITIZE" >&2
  echo "Hint: set SANITIZE=/path/to/sanitize-headers.pl to override." >&2
  exit 1
fi

# Maildir uses cur/ (delivered) and new/ (unread); tmp/ holds mid-delivery
# files and is deliberately skipped.
sources=()
[[ -d "$MAILDIR/cur" ]] && sources+=("$MAILDIR/cur")
[[ -d "$MAILDIR/new" ]] && sources+=("$MAILDIR/new")

total=$(find "${sources[@]}" -type f | wc -l | tr -d ' ')
echo "Found $total message(s) under $MAILDIR"
echo "Ingesting into $INBOX_DIR (sanitizing subscriber-side headers)..."

# Collect sanitizer residual reports across the whole run so we can tally
# at the end. Tally is purely informational — it tells us which stripped-
# pattern headers (e.g. X-Google-*) are leaking through below openwall's
# boundary, so we can decide whether to widen the strip policy.
RESIDUAL_LOG="$(mktemp)"
# Sanitized-message temp reused across the loop: we sanitize once per
# message into this file, then pipe it into mda. If mda fails, we can
# also cp it into the failed-msgs archive without re-running the
# sanitizer. Reusing one tempfile avoids 16k+ mktemp calls.
SANITIZED_TMP="$(mktemp)"
trap 'rm -f "$RESIDUAL_LOG" "$SANITIZED_TMP"' EXIT

# Per-run timestamp used for both the errors log filename and the
# failed-msgs directory. Same string ties the two together.
RUN_TS="$(date -u +%FT%TZ)"

# Failed-message archive: when METRICS_LOG is set, save the *sanitized*
# RFC822 of every failure to $(dirname METRICS_LOG)/failed-msgs/<RUN_TS>/
# so a future parser improvement can replay them without needing the
# source Maildir (which may not exist for ongoing scraped-sync runs).
# Overridable via FAILED_MSGS_DIR env if you want it somewhere else.
FAILED_MSGS_ROOT=""
if [[ -n "${METRICS_LOG:-}" ]]; then
  FAILED_MSGS_ROOT="${FAILED_MSGS_DIR:-$(dirname "$METRICS_LOG")/failed-msgs}"
fi

i=0
failed=0
# `set -o pipefail` (from `set -euo pipefail` above) means a nonzero exit
# from either the sanitizer or the direct-writer is caught by the `if !`.
#
# We used to pipe into `public-inbox-mda --no-precheck` and set
# `ORIGINAL_RECIPIENT="$LIST_ADDR"`, but mda enforces delivery-policy
# prechecks (rejects HTML-only mail, blocks attachment suffixes) that
# no flag can disable. For archive ingest — where HTML and attachments
# are valuable primary sources — that costs ~2% of the corpus (312 of
# 16,980 messages on the first run). `scripts/ingest-direct.pl` calls
# PublicInbox::V2Writable::add() directly, which is what
# public-inbox-watch uses for maildir ingest. Same dedup semantics
# (Message-ID) so idempotent re-runs still work. See DEC-ARCHIVE-005.
LIST_ADDR="${LIST_ADDR:-oss-security@lists.openwall.com}"
#
# Both stderrs land in $RESIDUAL_LOG. The tally awk-filter only picks
# `RESIDUAL\t...` lines so unrelated chatter doesn't pollute it, but it
# means we can post-hoc surface the distinct mda errors at the end if
# anything failed — far better than the previous `2>/dev/null` which
# turned mda's "I don't know that option" into a silent 100% failure
# loop.
while IFS= read -r -d '' f; do
  i=$((i + 1))
  # Sanitize once into $SANITIZED_TMP, then feed to the direct
  # ingester. Two-stage so we can archive the sanitized bytes on
  # failure without re-running the sanitizer.
  perl "$SANITIZE" --report <"$f" > "$SANITIZED_TMP" 2>>"$RESIDUAL_LOG" || true
  if ! perl "$INGEST" "$INBOX_NAME" <"$SANITIZED_TMP" 2>>"$RESIDUAL_LOG"; then
    failed=$((failed + 1))
    echo "warn: failed to import $f" >&2
    if [[ -n "$FAILED_MSGS_ROOT" ]]; then
      # Lazy-create the per-run subdir the first time we actually need it.
      [[ -d "$FAILED_MSGS_ROOT/$RUN_TS" ]] || mkdir -p "$FAILED_MSGS_ROOT/$RUN_TS"
      # Filename: keep the source Maildir basename so later inspection
      # can trace back to the origin file when possible. Some Maildir
      # filenames have `:` which is fine on ext4/APFS but strip flags
      # for portability.
      out_name="$(basename "$f")"
      out_name="${out_name%%:*}"
      cp "$SANITIZED_TMP" "$FAILED_MSGS_ROOT/$RUN_TS/${out_name}.eml"
    fi
  fi
  if (( i % 500 == 0 )); then
    echo "  progress: $i / $total ($failed failed)"
  fi
done < <(find "${sources[@]}" -type f -print0)

echo "Done. Imported $((i - failed)) / $i message(s); $failed failed."

# Filter that separates real errors from noise in $RESIDUAL_LOG:
#   - drop `RESIDUAL\t…` lines (those go to the residual tally)
#   - drop git's background auto-pack chatter (informational, appears
#     during successful commits under mda, not related to failures)
#   - drop empty lines
# Kept as a function so both the on-screen summary, the metrics-line
# top_err lookup, and the persisted errors-log all use the same rule.
filter_errors() {
  grep -v '^RESIDUAL' "$1" \
    | grep -v -E '^(Auto packing the repository|See "git help gc")' \
    | grep -v '^[[:space:]]*$'
}

if [[ -s "$RESIDUAL_LOG" ]]; then
  RESIDUAL_COUNT=$(awk -F'\t' '$1 == "RESIDUAL"' "$RESIDUAL_LOG" | wc -l | tr -d ' ')
  if [[ "$RESIDUAL_COUNT" -gt 0 ]]; then
    echo
    echo "Residual subscriber-pattern headers retained below openwall boundary"
    echo "(may indicate strip policy should be widened):"
    awk -F'\t' '$1 == "RESIDUAL" {print $2}' "$RESIDUAL_LOG" \
      | sort | uniq -c | sort -rn
  fi

  if [[ "$failed" -gt 0 ]]; then
    echo
    echo "Distinct error messages from this run (top 10, git-noise filtered):"
    filter_errors "$RESIDUAL_LOG" | sort | uniq -c | sort -rn | head -10
  fi
fi

# ---- ongoing-monitoring hooks --------------------------------------------
#
# METRICS_LOG (env, optional): append one TSV line per run so successive
#   invocations build a trend. Same file is safe for one-time and
#   scheduled use. Format (tab-separated):
#     ISO-timestamp  script  total  imported  failed  top_err_n  top_err_msg
#   The intent is scheduled ongoing-sync: keep this file in the repo
#   under metrics/ and commit each run; `tail -20 metrics/imports.tsv`
#   gives a live health-of-import view without opening any workflow log.
#
# FAIL_THRESHOLD_PCT (env, optional): if set to an integer 0..100, this
#   script exits non-zero when (failed / total) * 100 exceeds it. The
#   intended use is a scheduled workflow: exit non-zero → GHA marks the
#   run failed → GitHub notifies the maintainer per their normal
#   Actions notification settings. No API calls, no extra secrets.
#   For daily ongoing-sync a threshold of 0 (any failure) is reasonable
#   because a healthy day is a handful of messages, all of which should
#   succeed. For bulk one-time ingest use 5-10 or leave unset.
if [[ -n "${METRICS_LOG:-}" ]]; then
  mkdir -p "$(dirname "$METRICS_LOG")"

  # Per-run full errors log — same directory as the metrics file. Only
  # created when there were actual failures. Contains everything
  # filter_errors() surfaces plus a header with counters, so `git log`
  # over this directory tells the story of every failing run.
  if [[ "$failed" -gt 0 && -s "$RESIDUAL_LOG" ]]; then
    ERRORS_DIR="$(dirname "$METRICS_LOG")/errors"
    mkdir -p "$ERRORS_DIR"
    ERRORS_FILE="$ERRORS_DIR/${RUN_TS}.log"
    {
      echo "# import-maildir run at $RUN_TS"
      echo "# total=$i imported=$((i - failed)) failed=$failed"
      echo "# (git background auto-pack chatter filtered out)"
      echo
      echo "== Distinct error messages (all, sorted by count) =="
      filter_errors "$RESIDUAL_LOG" | sort | uniq -c | sort -rn
      echo
      echo "== Full filtered log =="
      filter_errors "$RESIDUAL_LOG"
    } > "$ERRORS_FILE"
    echo "Full errors log at $ERRORS_FILE"
    if [[ -n "$FAILED_MSGS_ROOT" && -d "$FAILED_MSGS_ROOT/$RUN_TS" ]]; then
      msg_count=$(find "$FAILED_MSGS_ROOT/$RUN_TS" -type f -name '*.eml' | wc -l | tr -d ' ')
      echo "Failed messages ($msg_count) saved under $FAILED_MSGS_ROOT/$RUN_TS/"
    fi
  fi

  # Metrics line — use filter_errors so a top-1 of "Auto packing the
  # repository" doesn't sneak in.
  top_count=0
  top_msg="none"
  if [[ -s "$RESIDUAL_LOG" && "$failed" -gt 0 ]]; then
    top_line=$(filter_errors "$RESIDUAL_LOG" | sort | uniq -c | sort -rn | head -1)
    if [[ -n "$top_line" ]]; then
      top_count=$(echo "$top_line" | awk '{print $1}')
      top_msg=$(echo "$top_line" | sed -E 's/^[[:space:]]*[0-9]+[[:space:]]+//' \
                                 | tr '\t\n' '  ')
    fi
  fi
  printf '%s\timport-maildir\t%d\t%d\t%d\t%d\t%s\n' \
    "$RUN_TS" \
    "$i" \
    "$((i - failed))" \
    "$failed" \
    "$top_count" \
    "$top_msg" \
    >> "$METRICS_LOG"
  echo
  echo "Metrics line appended to $METRICS_LOG"
fi

if [[ -n "${FAIL_THRESHOLD_PCT:-}" && "$i" -gt 0 ]]; then
  # Integer arithmetic; rounds toward zero.
  fail_pct=$(( 100 * failed / i ))
  if (( fail_pct > FAIL_THRESHOLD_PCT )); then
    echo
    echo "FAIL: ${fail_pct}% failed (${failed}/${i}) exceeds FAIL_THRESHOLD_PCT=${FAIL_THRESHOLD_PCT}%" >&2
    exit 3
  fi
fi

echo
echo "Next: public-inbox-index $INBOX_DIR"
