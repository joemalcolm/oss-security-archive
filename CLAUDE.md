# CLAUDE.md — oss-security-archive

## Purpose

This repo is a public-inbox mirror of the oss-security mailing list (https://www.openwall.com/lists/oss-security/). It stores every post as a git-native email object, with Xapian full-text search and SQLite metadata indexes.

Anyone can clone, search, and build on this archive.

## What is public-inbox?

public-inbox (https://public-inbox.org/) is a mailing list archival system that stores emails in git repositories. Key properties:
- Each email is a git blob in mbox format (one commit per message or batch)
- Full archive is clonable via `git clone`
- Xapian provides full-text search (`lei q "CVE-2026"`)
- SQLite stores structured metadata (date, from, subject, Message-ID, threading)
- Indexes are local — generated from git data, not committed
- Handles Message-ID collisions via content-based blob hashing
- Standard tools: `public-inbox-init`, `public-inbox-mda`, `public-inbox-index`, `lei`

## Architecture

```
.github/workflows/
  sync.yml           — Scheduled ingest (every 4 hours) + manual dispatch
  bootstrap.yml      — Manual workflow for historical mbox import
scripts/
  sync.sh            — Fetch recent posts, ingest via public-inbox-mda
  bootstrap.sh       — Download and import historical mbox archives
  setup-inbox.sh     — Initialize public-inbox repo structure
```

The git data lives in the default public-inbox v2 format. public-inbox manages storage internally.

## Setup

### Prerequisites
- `public-inbox` package installed (Perl, available via apt/brew)
- `git` 2.40+
- `xapian-core` for full-text indexing

### Initialize
```bash
./scripts/setup-inbox.sh
```
This creates the public-inbox v2 epoch repositories and config.

### Bootstrap historical data
Openwall provides mbox downloads at `https://www.openwall.com/lists/oss-security/YYYY/mbox`:
```bash
# Import a single year
./scripts/bootstrap.sh 2024

# Import a range
./scripts/bootstrap.sh 2020 2026

# Import all available history
./scripts/bootstrap.sh --all
```

Each mbox is downloaded and fed to `public-inbox-mda`. Rate limited to be friendly to Openwall's servers. One mbox per year, typically 5-50 MB each.

After bootstrap, build indexes:
```bash
public-inbox-index --reindex inbox
```

### Ongoing sync
The GitHub Action runs `scripts/sync.sh` every 4 hours:
1. Fetches the latest day's mbox from Openwall
2. Pipes new messages through `public-inbox-mda`
3. Rebuilds indexes
4. Pushes new git objects

## Querying the archive

### Full-text search with lei
```bash
# Find posts mentioning a specific CVE
lei q -I inbox "CVE-2026-7168"

# Find posts by a specific author
lei q -I inbox "f:daniel@haxx.se"

# Find posts from a date range
lei q -I inbox "dt:2026-04-01..2026-04-30"

# Output as JSON
lei q -I inbox -f json "CVE-2026"
```

### Walking git objects directly
For consumers that don't have public-inbox installed:
```bash
git -C inbox/git/0.git log --format='%H' | while read hash; do
  git -C inbox/git/0.git show "$hash:m" 2>/dev/null  # raw email content
done
```

## Message-ID Handling

Email Message-IDs should be globally unique but broken clients sometimes generate duplicates. public-inbox handles this gracefully:
- Internally uses git blob SHA (content-based hash) as the canonical identifier
- Two messages with the same Message-ID but different content get separate blobs
- The SQLite index tracks both; queries by Message-ID return all matching blobs

## Openwall Archive URLs

- Year mbox: `https://www.openwall.com/lists/oss-security/YYYY/mbox`
- Daily mbox: `https://www.openwall.com/lists/oss-security/YYYY/MM/DD/mbox`
- Atom feed: `https://www.openwall.com/lists/oss-security/atom.xml` (recent posts)
- Web archive: `https://www.openwall.com/lists/oss-security/YYYY/MM/DD/N`

## Rate Limiting

Be respectful of Openwall's servers:
- Bootstrap: 1 mbox download at a time, 5-second pause between years
- Sync: fetch today's and yesterday's daily mbox, at most 6 times/day
- User-Agent: `oss-security-archive-bot/1.0 (+https://github.com/joemalcolm/oss-security-archive)`

## Indexes

public-inbox generates two types of indexes from the git data:

### Xapian (full-text search)
- Indexes subject, body, from, message-id
- Enables `lei q "CVE-2026-7168"` to find posts instantly
- Stored in `inbox/xap15/` directory (not committed to git)
- Rebuilt with `public-inbox-index inbox`

### SQLite (structured metadata)
- Date, From, Subject, Message-ID, In-Reply-To, References
- Threading reconstruction
- Stored in `inbox/over.sqlite3` (not committed to git)
- Rebuilt with `public-inbox-index inbox`

Both indexes are regenerated from git data. Any consumer who clones the repo can rebuild them locally. The indexes are listed in `.gitignore`.
