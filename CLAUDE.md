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
  sync.yml               — Scheduled ingest (every 4 hours) + manual dispatch
  bootstrap.yml          — Manual workflow for historical mbox import (broken — see below)
  import-maildir.yml     — Manual workflow for Maildir import (canonical historical path)
  backfill-openwall.yml  — Manual workflow for one-year HTML scrape backfill
scripts/
  sync.sh                — Fetch recent posts, ingest via public-inbox-mda
  bootstrap.sh           — (broken — preserved for reference; see DEC-ARCHIVE-001)
  setup-inbox.sh         — Initialize public-inbox repo structure
  import-maildir.sh      — Ingest a Maildir (DEC-ARCHIVE-002)
  sanitize-headers.pl    — Strip subscriber-side headers pre-ingest (DEC-ARCHIVE-003)
  openwall-scrape.pl     — Scrape openwall HTML and emit RFC822 to a Maildir (DEC-ARCHIVE-004)
  backfill-openwall.sh   — Wrap openwall-scrape.pl into the maildir-import pipeline
  ingest-direct.pl       — Write RFC822 directly to public-inbox via V2Writable::add,
                           bypassing mda's delivery-policy prechecks (DEC-ARCHIVE-005)
```

### Direct writer vs. `public-inbox-mda` (DEC-ARCHIVE-005)

`public-inbox-mda` is a Postfix-style delivery agent. It enforces content policies appropriate for real mail delivery — reject HTML-only messages, block a suffix list of attachment types (zip / images / vendor formats), spam-check via spamc — none of which are configurable off (spam is via `publicinboxmda.spamcheck = none`; the body-format prechecks have no knob). For archive ingest of an 18-year security list where HTML and attachment-bearing messages are valuable primary sources, that costs roughly 2% of the corpus (verified 2026-09-05: 312 of 16,980 first-pass failures were legitimate messages mda refused on policy grounds, not parsing failures).

`ingest-direct.pl` calls `PublicInbox::V2Writable::add()` — the same primitive `public-inbox-watch` uses for maildir-based ingest — with no delivery-policy filtering. It still dedups on Message-ID internally, so re-runs are idempotent. `import-maildir.sh` and `backfill-openwall.sh` both route through it now; `ingest-direct.pl` needs the `public-inbox` Debian package installed (for `PublicInbox::Config`, `::InboxWritable`, `::Eml`).

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

**Note (2026-05-15):** The HTTP-mbox bootstrap path documented below does not work — Openwall does not actually serve `/YYYY/mbox`, `/YYYY/MM/DD/mbox`, or any other machine-readable mbox endpoint (all return 404). `scripts/bootstrap.sh` is preserved for reference but produces an empty inbox. The current canonical historical-ingest path is **Maildir import** (see next subsection). Once a sync source is settled (see DEC-ARCHIVE-002 in `scripts/import-maildir.sh`), `bootstrap.sh` and `sync.sh` will be rewritten against the new source.

(Historical, broken — kept for context.) Openwall was assumed to provide mbox downloads at `https://www.openwall.com/lists/oss-security/YYYY/mbox`:
```bash
# Import a single year
./scripts/bootstrap.sh 2024

# Import a range
./scripts/bootstrap.sh 2020 2026

# Import all available history
./scripts/bootstrap.sh --all
```

After bootstrap, build indexes:
```bash
public-inbox-index --reindex inbox
```

### Import from a Maildir (canonical historical-ingest path)

If you have a Maildir of oss-security messages (e.g., a subscriber's archive), ingest it directly:

```bash
INBOX_DIR=$(pwd)/inbox ./scripts/import-maildir.sh /path/to/Maildir
public-inbox-index inbox
```

The script iterates `cur/` and `new/`, runs each message through `scripts/sanitize-headers.pl`, then pipes to `public-inbox-mda`. It is **idempotent** — `public-inbox-mda` dedups on Message-ID, so re-running with the same Maildir produces no new commits.

**Header sanitization (DEC-ARCHIVE-003).** A subscriber's Maildir copy of a list message carries header blocks added by their own infrastructure on top of the canonical message: their MX's `Received` chain, locally-added `Authentication-Results` / `ARC-*` / `DKIM-Signature`, their spam filter's `X-Spam-*`, plus `Delivered-To` / `X-Original-To` / `Return-Path` that reveal the subscriber's address. The sanitizer strips this cruft so the archived message matches what every other subscriber received. The boundary is the first `Received:` whose `by` clause names openwall — everything from that hop onward (openwall's internal Receives plus the sender's own chain) is preserved verbatim. If no openwall hop is found (unusual for a list message), the message is passed through unchanged. See the comment header of `scripts/sanitize-headers.pl` for the full stripped-name list.

In CI, the `Import Maildir` workflow takes an HTTPS URL to a `.tar.gz` of the Maildir:
```bash
gh workflow run import-maildir.yml -f maildir_url="https://example.com/oss-security.tar.gz"
```
The tarball must contain a directory with `cur/` and `new/` somewhere within the first few levels; the workflow auto-locates it.

### Backfill from openwall HTML (DEC-ARCHIVE-004)

For dates not covered by the Maildir (i.e., pre-2015-03-16 and the ~1% gaps within Maildir range), the canonical source is openwall.com's HTML rendering of each message. `scripts/openwall-scrape.pl` walks `/lists/oss-security/YYYY/MM/DD/N` pages, reconstructs RFC822, and writes each message to a Maildir; `scripts/backfill-openwall.sh` then feeds that Maildir through the regular `import-maildir.sh` pipeline.

```bash
# One year at a time, locally:
INBOX_DIR=$(pwd)/inbox ./scripts/backfill-openwall.sh 2014-01-01 2014-12-31

# Or via the workflow:
gh workflow run backfill-openwall.yml -f year=2014
```

**Fidelity caveats:** Openwall's HTML obfuscates `From`/`To`/`Cc` by elision (e.g., `user@...domain.tld`) — this is lossy and preserved as-is. Message-IDs are ROT13-obfuscated; the scraper reverses this so dedup against Maildir-imported messages works. Body text is preserved; URLs in the body that openwall wrapped in `<a href>` are unwrapped to plain text. **Threading is not reconstructed in v1**: openwall renders only `Message-ID`/`Date`/`From`/`To`/`Subject`, not `In-Reply-To`/`References` — its `[thread-prev]`/`[thread-next]` nav links carry the structure, and a follow-up pass can parse those and synthesize the missing headers. Every scraped message carries `X-Archive-Source: openwall-scrape` plus `X-Archive-Source-URL: <openwall page URL>` so consumers can distinguish backfill from full-fidelity messages, and so a future un-obfuscation pass (if the list owner ever permits) can identify what to re-ingest.

Rate-limited to ~1.5s/request by default (override with `DELAY=2.0 ./scripts/backfill-openwall.sh ...`). The scraper writes `$maildir/.scrape-state` so a re-run picks up where it stopped.

### Ongoing sync
The GitHub Action runs `scripts/sync.sh` every 4 hours:
1. Fetches the latest day's mbox from Openwall
2. Pipes new messages through `public-inbox-mda`
3. Rebuilds indexes
4. Pushes new git objects

**Note (planned rewrite):** the current `sync.sh` still targets the non-existent `/YYYY/MM/DD/mbox` endpoint (DEC-ARCHIVE-001) and does nothing useful. Once the one-time Maildir import + Openwall backfill land, `sync.sh` should be rewritten to call `scripts/backfill-openwall.sh <yesterday> <today>` — i.e. use the same HTML-scrape mechanism against a 2-day window so we catch anything published since the last run. Idempotent thanks to Message-ID dedup at ingest.

### Ongoing-run monitoring

Both `import-maildir.sh` and `backfill-openwall.sh` honor two env vars for post-import observability. These are intended for the scheduled sync workflow but also work fine for one-time runs:

- **`METRICS_LOG=path/to/imports.tsv`** — append one tab-separated line per run: ISO timestamp, script name, per-run counters (total/imported/failed, or scrape-warning counts for the backfill wrapper), and the top-1 error class. Commit this file so `git log metrics/imports.tsv` shows import health over time and `tail -20 metrics/imports.tsv` gives a live readout without opening any workflow log.
- **`FAIL_THRESHOLD_PCT=N`** — `import-maildir.sh` exits 3 when `(failed / total) * 100` exceeds N. GHA marks the run failed; GitHub sends the maintainer the standard Actions failure notification. No custom secrets, no API calls. Sensible defaults: `0` for scheduled sync (any failure is worth investigating when a healthy day is a handful of messages), `5-10` for bulk one-time ingest.

Example wiring for the future `sync.yml` rewrite:

```yaml
env:
  METRICS_LOG: metrics/imports.tsv
  FAIL_THRESHOLD_PCT: 0
run: |
  ./scripts/backfill-openwall.sh \
    "$(date -u -d 'yesterday' +%F)" \
    "$(date -u +%F)"
  # commit metrics/imports.tsv alongside the inbox commit
```

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
