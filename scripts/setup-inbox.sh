#!/usr/bin/env bash
# setup-inbox.sh — Prepare a public-inbox v2 repository for oss-security.
#
# Two responsibilities:
#   1. Create the on-disk v2 layout ($INBOX_DIR/{all.git,git/0.git,...})
#      if it doesn't already exist.
#   2. Register the inbox in ~/.public-inbox/config so ingest-direct.pl,
#      public-inbox-mda, lei, etc. can find it by name.
#
# Idempotent: safe to re-run against an already-initialized inbox. This
# matters because every fresh container/CI runner needs step 2 even
# when step 1 was done in a previous run and persisted via the bind
# mount. Every workflow that ingests should call this first.
set -euo pipefail

INBOX_DIR="${1:-$(pwd)/inbox}"
INBOX_NAME="oss-security"
INBOX_ADDR="oss-security@lists.openwall.com"
INBOX_URL="https://www.openwall.com/lists/oss-security/"
GIT_CONFIG="${HOME}/.public-inbox/config"

# Step 1: create the on-disk v2 structure if missing. We detect an
# already-initialized inbox by looking for the epoch repo, which is a
# reliable v2 marker. `public-inbox-init` on an existing dir would
# error out; we skip it in that case.
if [[ ! -d "$INBOX_DIR/all.git" ]]; then
  echo "Initializing public-inbox v2 structure at $INBOX_DIR..."
  public-inbox-init -V2 "$INBOX_NAME" "$INBOX_DIR" \
    "$INBOX_URL" "$INBOX_ADDR"
else
  echo "Inbox already initialized at $INBOX_DIR (skipping public-inbox-init)."
fi

# Step 2: register the inbox in ~/.public-inbox/config, unconditionally.
# `public-inbox-init` writes this file on step-1 runs, but on skip we
# still need to populate it — CI runners get a fresh $HOME each job.
# Using `git config` (public-inbox config is git-config format) is
# safely idempotent: identical writes are no-ops.
mkdir -p "$(dirname "$GIT_CONFIG")"
git config -f "$GIT_CONFIG" "publicinbox.$INBOX_NAME.inboxdir" "$INBOX_DIR"
git config -f "$GIT_CONFIG" "publicinbox.$INBOX_NAME.address"  "$INBOX_ADDR"
git config -f "$GIT_CONFIG" "publicinbox.$INBOX_NAME.url"      "$INBOX_URL"
echo "  registered inbox '$INBOX_NAME' in $GIT_CONFIG"

# Disable mda's spam-check invocation. public-inbox-mda's spam-check path
# defaults to invoking `spamc` (SpamAssassin's client). The Debian package
# expects spamc on PATH but doesn't install spamassassin itself, so without
# this override mda fails per-message with "spamc: command not found".
# The `--no-precheck` flag on mda does NOT skip this — it only skips the
# header-validation precheck. The spam-check is controlled by the
# `publicinboxmda.spamcheck` config key, which we set to `none`.
# The messages we ingest are openwall's curated archive; further spam
# filtering at archive time is unwanted anyway.
git config -f "$GIT_CONFIG" publicinboxmda.spamcheck none
echo "  set publicinboxmda.spamcheck=none"

echo "Inbox ready. Run 'public-inbox-index $INBOX_DIR' after import to build search indexes."
