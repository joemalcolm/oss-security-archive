#!/usr/bin/env bash
# sync.sh — Fetch recent oss-security posts and ingest into public-inbox.
# Called by .github/workflows/sync.yml on a 4-hour schedule.
# Fetches today's and yesterday's daily mbox to handle timezone edge cases.
set -euo pipefail

INBOX_DIR="${INBOX_DIR:-$(pwd)/inbox}"
BASE_URL="https://www.openwall.com/lists/oss-security"
USER_AGENT="oss-security-archive-bot/1.0 (+https://github.com/joemalcolm/oss-security-archive)"

# Fetch today's and yesterday's mbox to catch timezone edge cases
for offset in 0 1; do
  # BSD date (macOS) and GNU date (Linux) compatible
  date_str=$(date -u -d "-${offset} days" +%Y/%m/%d 2>/dev/null \
    || date -u -v-${offset}d +%Y/%m/%d)
  url="${BASE_URL}/${date_str}/mbox"

  echo "Fetching $url..."
  tmpfile=$(mktemp)
  if curl -fsSL -A "$USER_AGENT" -o "$tmpfile" "$url" 2>/dev/null; then
    if [[ -s "$tmpfile" ]]; then
      echo "Importing posts from ${date_str}..."
      public-inbox-mda < "$tmpfile" --inbox "$INBOX_DIR" 2>/dev/null || true
    else
      echo "No posts for ${date_str}."
    fi
  else
    echo "Could not fetch ${date_str} (may be empty or not yet published)."
  fi
  rm -f "$tmpfile"
done

# Rebuild indexes
echo "Rebuilding indexes..."
public-inbox-index "$INBOX_DIR" 2>/dev/null || true

# Report whether new commits landed in the epoch git repo
if git -C "${INBOX_DIR}/git/0.git" log --oneline -1 --since="6 hours ago" \
    2>/dev/null | grep -q .; then
  echo "New posts ingested."
else
  echo "No new posts since last sync."
fi
