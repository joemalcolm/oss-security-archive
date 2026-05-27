#!/usr/bin/env bash
# import-maildir.sh — Ingest a Maildir into the public-inbox repo.
# Iterates $MAILDIR/{cur,new}, runs each message through sanitize-headers.pl
# (drops subscriber-side header cruft above openwall's first hop — see
# DEC-ARCHIVE-003 in scripts/sanitize-headers.pl), then pipes to
# public-inbox-mda.
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
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANITIZE="${SANITIZE:-$SCRIPT_DIR/sanitize-headers.pl}"

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

if ! command -v public-inbox-mda >/dev/null 2>&1; then
  echo "Error: public-inbox-mda not found in PATH." >&2
  echo "Install with: apt install public-inbox  (or brew install public-inbox)" >&2
  exit 1
fi

if ! command -v perl >/dev/null 2>&1; then
  echo "Error: perl not found in PATH (required by sanitize-headers.pl)." >&2
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
trap 'rm -f "$RESIDUAL_LOG"' EXIT

i=0
failed=0
# `set -o pipefail` (from `set -euo pipefail` above) means a nonzero exit
# from either the sanitizer or public-inbox-mda is caught by the `if !`.
while IFS= read -r -d '' f; do
  i=$((i + 1))
  if ! perl "$SANITIZE" --report <"$f" 2>>"$RESIDUAL_LOG" \
       | public-inbox-mda --inbox "$INBOX_DIR" 2>/dev/null; then
    failed=$((failed + 1))
    echo "warn: failed to import $f" >&2
  fi
  if (( i % 500 == 0 )); then
    echo "  progress: $i / $total ($failed failed)"
  fi
done < <(find "${sources[@]}" -type f -print0)

echo "Done. Imported $((i - failed)) / $i message(s); $failed failed."

if [[ -s "$RESIDUAL_LOG" ]]; then
  echo
  echo "Residual subscriber-pattern headers retained below openwall boundary"
  echo "(may indicate strip policy should be widened):"
  awk -F'\t' '$1 == "RESIDUAL" {print $2}' "$RESIDUAL_LOG" \
    | sort | uniq -c | sort -rn
fi

echo
echo "Next: public-inbox-index $INBOX_DIR"
