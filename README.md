# oss-security-archive

A [public-inbox](https://public-inbox.org/) mirror of the [oss-security](https://www.openwall.com/lists/oss-security/) mailing list.

## Quick start

```bash
# Clone and build indexes
git clone https://github.com/joemalcolm/oss-security-archive.git
cd oss-security-archive
public-inbox-index inbox

# Search for a CVE
lei q -I inbox "CVE-2026-7168"

# Search by author
lei q -I inbox "f:daniel@haxx.se"

# Output as JSON
lei q -I inbox -f json "CVE-2026"
```

## Querying without public-inbox

`index/` is a flat JSON projection of the archive, regenerated on every sync: one row per message (duplicates already resolved), decoded plain-text bodies, and a CVE → messages map. No tooling needed beyond `jq`, and no clone either — every file is reachable under `https://raw.githubusercontent.com/joemalcolm/oss-security-archive/main/`.

```bash
# First mention of a CVE on the list (cves/ is sharded by the CVE's own year)
jq '."CVE-2026-86089"[0]' index/oss-security/cves/2026.json

# Every message that mentions it (messages/ and bodies/ are sharded by posting year)
jq -c 'select(.cve_ids | index("CVE-2024-3094")) | {date, from, subject, url}' index/oss-security/messages/2024.jsonl

# The decoded body of one message
jq -r 'select(.message_id == "20240329155126.kjjfduxw2yrlxgzm@awork3.anarazel.de") | .body' index/oss-security/bodies/2024.jsonl

# A whole thread
jq -c 'select(.thread_root == "20240329155126.kjjfduxw2yrlxgzm@awork3.anarazel.de") | {date, from}' index/oss-security/messages/2024.jsonl

# What's there, and whether the archive is healthy
curl -s https://raw.githubusercontent.com/joemalcolm/oss-security-archive/main/index/oss-security/manifest.json | jq '{generated_at, total_messages, total_cves}'
curl -s https://raw.githubusercontent.com/joemalcolm/oss-security-archive/main/status.json | jq '{last_success_at, freshness, problems}'
```

`manifest.json` lists every file with its row count and sha256, so a consumer can fetch only the shards that changed. Row fields: `message_id`, `date` (ISO 8601 UTC) with `date_source` (`date` unless the header was unusable), `from`, `subject`, `in_reply_to`, `thread_root`, `url`, `provenance` (`maildir` = full-fidelity subscriber copy, `openwall-scrape` = reconstructed from openwall's HTML, addresses elided), `cve_ids`, `body_sha` (cache key for the body), `duplicates` / `body_conflict` (other stored copies of the same Message-ID, and whether any of them really differs). The schema is specified in [SPEC-index.md](SPEC-index.md); validate a copy with `perl scripts/verify-index.pl index/oss-security`.

## Bootstrap

Run the bootstrap workflow from GitHub Actions, or locally:

```bash
sudo apt install public-inbox xapian-tools  # or brew install
./scripts/setup-inbox.sh inbox
./scripts/bootstrap.sh 2020 2026
public-inbox-index inbox
```

## How it works

A GitHub Action runs every 4 hours, fetches new posts from Openwall's mbox endpoint, and ingests them via `public-inbox-mda`. Indexes (Xapian full-text + SQLite metadata) are rebuilt locally by each consumer — they are not committed to git.

See [CLAUDE.md](CLAUDE.md) for detailed architecture and maintenance instructions.
