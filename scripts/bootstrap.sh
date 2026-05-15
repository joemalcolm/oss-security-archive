#!/usr/bin/env bash
# bootstrap.sh — Download historical mbox archives from Openwall and import
# into the public-inbox repo via public-inbox-mda. Rate-limited to be
# respectful of Openwall's servers (5-second pause between year downloads).
#
# @decision DEC-ARCHIVE-001
# @title Use year-granularity mbox downloads for bootstrap
# @status accepted
# @rationale Openwall exposes one mbox per year at /YYYY/mbox. Downloading
#   at year granularity minimises the number of HTTP requests during bootstrap
#   while still being resumable (re-run a single year if interrupted).
#   public-inbox-mda deduplicates on Message-ID, so re-importing a year is safe.
#
# Usage: ./bootstrap.sh [--all | YEAR | START_YEAR END_YEAR]
set -euo pipefail

INBOX_DIR="${INBOX_DIR:-$(pwd)/inbox}"
BASE_URL="https://www.openwall.com/lists/oss-security"
USER_AGENT="oss-security-archive-bot/1.0 (+https://github.com/joemalcolm/oss-security-archive)"
DELAY=5  # seconds between downloads

download_and_import() {
  local year=$1
  local url="${BASE_URL}/${year}/mbox"
  local tmpfile
  tmpfile=$(mktemp)

  echo "Downloading $year mbox from $url..."
  if curl -fsSL -A "$USER_AGENT" -o "$tmpfile" "$url"; then
    local size
    size=$(du -h "$tmpfile" | cut -f1)
    echo "Importing $year (${size})..."
    public-inbox-mda < "$tmpfile" \
      --inbox "$INBOX_DIR" \
      || echo "Warning: some messages may have failed to import for $year"
    echo "Done with $year."
  else
    echo "Warning: could not download $year mbox (may not exist yet)."
  fi

  rm -f "$tmpfile"
}

# Parse arguments
if [[ "${1:-}" == "--all" ]]; then
  # oss-security started around 2008
  for year in $(seq 2008 "$(date +%Y)"); do
    download_and_import "$year"
    sleep "$DELAY"
  done
elif [[ $# -eq 1 ]]; then
  download_and_import "$1"
elif [[ $# -eq 2 ]]; then
  for year in $(seq "$1" "$2"); do
    download_and_import "$year"
    sleep "$DELAY"
  done
else
  echo "Usage: $0 [--all | YEAR | START_YEAR END_YEAR]"
  echo "  --all          Import all years (2008-present)"
  echo "  YEAR           Import a single year"
  echo "  START END      Import a range of years"
  exit 1
fi

echo ""
echo "Bootstrap complete. Now run:"
echo "  public-inbox-index $INBOX_DIR"
echo "to build search indexes."
