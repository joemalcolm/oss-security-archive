#!/usr/bin/env bash
# setup-inbox.sh — Initialize a public-inbox v2 repository for oss-security.
# Run this once before bootstrap.sh. Creates the inbox directory structure,
# writes public-inbox.config, and prepares the git epoch repos.
set -euo pipefail

INBOX_DIR="${1:-$(pwd)/inbox}"
INBOX_NAME="oss-security"
INBOX_ADDR="oss-security@lists.openwall.com"
INBOX_URL="https://www.openwall.com/lists/oss-security/"

echo "Initializing public-inbox at $INBOX_DIR..."

public-inbox-init -V2 "$INBOX_NAME" "$INBOX_DIR" \
  "$INBOX_URL" "$INBOX_ADDR"

echo "Inbox initialized. Run bootstrap.sh to import historical data."
echo "Run 'public-inbox-index $INBOX_DIR' after import to build search indexes."
