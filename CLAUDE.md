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
  export-index.pl        — Project the inbox into index/ as flat JSON, one row per
                           Message-ID (DEC-ARCHIVE-007)
  verify-index.pl        — Validate index/ (runs in CI after every export)
  write-status.pl        — Write status.json (ops health document, repo root)
  publish-index.sh       — export → verify → status; the step workflows call
  resanitize-epoch.pl    — Rewrite an epoch so every stored message passes the
                           current sanitizer; git + Perl only (DEC-ARCHIVE-008)
  scrub-history.sh       — Drop inbox/ and index/ from the outer repo's history
                           (fresh clone + git filter-repo), re-add the current
                           inbox as one snapshot; prints the force-push, never runs it
index/                   — Generated projection for consumers. Never hand-edit.
status.json              — Generated ops health document.
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

**Header sanitization (DEC-ARCHIVE-003).** A subscriber's Maildir copy of a list message carries header blocks added by their own infrastructure on top of the canonical message: their MX's `Received` chain, locally-added `Authentication-Results` / `ARC-*` / `DKIM-Signature`, their spam filter's `X-Spam-*`, plus `Delivered-To` / `X-Original-To` / `Return-Path` that reveal the subscriber's address. The sanitizer strips this cruft so the archived message matches what every other subscriber received. The boundary is the first `Received:` that is either a hop whose `by` clause names openwall, a hop whose `from` clause names openwall (the subscriber's MX writing down the gateway hop — stripped too), or ezmlm's own `Received: (qmail N invoked by uid N); DATE` stamp — everything from that hop onward (openwall's internal Receives plus the sender's own chain) is preserved verbatim. If no openwall hop is found (unusual for a list message), the message is passed through unchanged. Independently of the boundary, `X-Rspamd-*` / `X-Spamd-*` are stripped wherever they appear: an rspamd milter appends them at the *bottom* of the header block, so position can't catch them. See the comment header of `scripts/sanitize-headers.pl` for the full stripped-name list.

**Gap found 2026-09-19 (DEC-ARCHIVE-008).** On the current mail path the relay writes no `Received: from …openwall` of its own, so the only openwall hop is the qmail stamp; the sanitizer had no rule for it and passed 1,641 messages (2025–2026) through verbatim, relay headers included. The qmail rule and the anywhere-rule above close the gap. To apply a sanitizer fix to messages already stored, run `perl scripts/resanitize-epoch.pl --inbox inbox --dry-run`, then without `--dry-run`: it replays the epoch through `sanitize()` keeping author/committer/timestamps/order byte-identical, verifies every new blob against the original before swapping, moves the old epoch and stale indexes to a gitignored `tmp/resanitize-<stamp>/`, and splits packs under 40 MB so GitHub accepts them. Needs only git and Perl. Run it with no ingest in flight, from a clean pull, and commit + push `inbox/` straight away (the local-vs-workflow rule below). The index follows on the next workflow run: only `blob` ids change. The outer repo's history keeps the old packs until `scripts/scrub-history.sh --yes` is run: it works in a fresh clone, removes `inbox/` and `index/` from every historical commit with `git filter-repo`, re-adds the current inbox as a single snapshot commit, and prints the `git push --force` for you to run (never pushes itself). Done 2026-09-19; the history before the snapshot commit therefore has no inbox at any revision, and the inbox's own git history lives inside the epoch packs where it always did. `inbox/inbox.lock` is tracked on purpose even though `.gitignore` lists it: public-inbox decides an inbox is v2 by that file's presence, and without it every ingest fails with "not a git repository: inbox". After any such force-push: delete stale remote branches (they pin the old packs), re-clone or hard-reset + `reflog expire` + `gc --prune=now` every checkout, and ask GitHub Support to purge cached commits.

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

### Local-vs-workflow divergence — operating rule

Any time a local ingest AND a workflow push both modify the archive, the two branches advance `inbox/git/0.git/refs/heads/master` (plus `inbox/git/0.git/info/refs`) to different commits. `git pull` then refuses to fast-forward with:

```
error: Your local changes to the following files would be overwritten by merge:
  inbox/git/0.git/info/refs
  inbox/git/0.git/refs/heads/master
Please commit your changes or stash them before you merge.
```

Or, if you did commit locally first, a merge conflict on those same files — which is unmergeable in text (each ref points at one commit, not a diffable payload).

**Operating rule:** always `git pull` **before** any local `perl scripts/ingest-direct.pl` or `scripts/backfill-openwall.sh` invocation, and always `git add inbox && git commit && git push` **immediately after**. Local ingests that sit uncommitted are the direct cause of this conflict, since the next workflow push races them.

**Recovery when it happens anyway:**

- If your local changes are just runtime ref state from an ingest whose *content* you're okay losing (e.g. a message that's also in the workflow's push, or one you can re-run from `metrics/failed-msgs/`):
   ```bash
   git checkout -- inbox   # drop local runtime state
   git pull                 # fast-forward to workflow's version
   ```
- If your local ingest has content the workflow doesn't (a message you manually recovered from `metrics/failed-msgs/` that isn't in the workflow's push): easier to just re-do the ingest after pulling. `git checkout -- inbox && git pull`, then re-run the recovery sweep — it's idempotent and will re-catch the same messages.

**Longer-term fix:** the recovery sweep should live inside the workflow itself. Every backfill run's `Backfill` step would first walk `metrics/failed-msgs/*/*.eml` from previous runs, re-attempt any that succeed on retry, then proceed to the fresh scrape. All ingest happens on the runner, no local drift ever gets created, and the file conflict class disappears. About 10 lines added to `backfill-openwall.yml`'s `Backfill` step. Not urgent while backfill volume is one year per hour; worth doing before ongoing-sync goes live (where every 4-hour run would compound the drift risk).

## Published index (DEC-ARCHIVE-007)

`index/` is a flat JSON projection of the inbox for consumers that don't have public-inbox (first consumer: vulntools / `cvetools`). Full contract in `SPEC-index.md`; rationale in the header of `scripts/export-index.pl`.

```
index/
  manifest.json           schema, built_from (epoch → commit), per-file count + sha256, totals
  messages/YYYY.jsonl     one row per Message-ID; YYYY = posting year (UTC), sorted by (date, message_id)
  bodies/YYYY.jsonl       decoded plain-text bodies, same rows in the same order
  cves/YYYY.json          CVE ID → [mentions in date order]; YYYY = the CVE's own year
status.json               ops health (last run, freshness, counts, problems)
```

**It is a projection.** Deterministic, regenerated in full on every workflow run (~20 s for 48k messages), never hand-edited, safe to `rm -rf index` and rebuild. Two runs on the same inbox are byte-identical except `manifest.generated_at`, so an ordinary sync only produces a git diff in the current year's `messages/` + `bodies/`, the `cves/` files that gained a mention, `manifest.json` and `status.json`. `.gitattributes` marks `index/**/*.jsonl` as `-diff` so `git log -p` stays readable.

```bash
# what the workflows run, after public-inbox-index and before git add -A
bash scripts/publish-index.sh

# or the pieces
perl scripts/export-index.pl --inbox inbox --out index --source oss-security --url-scheme openwall
perl scripts/verify-index.pl index
```

Needs `public-inbox` plus `libhtml-format-perl` (HTML-only mail → text). `libcpanel-json-xs-perl` is optional but makes the validator ~25× faster than core `JSON::PP`.

**The index papers over duplicates; it does not fix them.** The inbox stores ~13.5k Message-IDs twice (maildir+scrape and scrape+scrape pairs). The exporter groups every stored copy by Message-ID and emits one row: best provenance wins (`maildir` > `upstream` > anything with an `X-Archive-Source`, e.g. `openwall-scrape`), then the latest commit. Losing copies are listed in the row's `duplicates`. `manifest.total_stored − total_messages` is the live dedup backlog, deliberately visible. The exporter is read-only on the inbox — purging the stored duplicates is a separate task (`scripts/purge-dedup-scraped.pl`, `scripts/dedup-rebuild.pl`), and because consumers only see `index/`, it can happen later with no downstream effect.

Things worth knowing before touching the exporter:

- **`body_conflict`** means "these copies are really different messages", not "the bytes differ" — a scraped copy never has equal bytes. Comparison masks addresses (openwall elides them in bodies too), collapses whitespace, undoes mbox `>From` escaping, and accepts one body being a prefix of the other (openwall renders later text parts — inline patches, list footers — into the same page). That takes ~6.3k byte-level mismatches down to ~30 real ones (charset damage in the scrape, plus genuine Message-ID reuse such as `<20150804123051.GA27639@lakka.kapsi.fi>`).
- **`url`** for a maildir row borrows the scraped twin's `X-Archive-Source-URL` when there is one, so it is an exact permalink; only messages with no scraped copy fall back to the day-level URL (UTC day, which can be off by one from openwall's).
- **`thread_root`** unions public-inbox's `tid` (from `over.sqlite3`) with the messages' own `References`/`In-Reply-To`. A from-scratch `public-inbox-index` skips same-Message-ID copies ("is a duplicate"), so `tid` alone can miss the winning copy; and the union means a missing or stale `over.sqlite3` yields the same output. Root = earliest message in the thread whose parent isn't in the archive. Scraped messages carry no threading headers and are their own roots until the `[thread-prev]` synthesis pass lands.
- **`in_reply_to`** is the first ID in `In-Reply-To`, else the *last* ID in `References` (the RFC 5322 parent; ~120 messages have only `References`).
- **`date`** is the `Date:` header unless it is missing, unparseable, or more than two days ahead of the list's own evidence of when the message arrived. That evidence is tried in order: the topmost openwall `Received:` (a `by …openwall.com` clause, or ezmlm's `(qmail N invoked by uid N); DATE` form) → the `YYYY/MM/DD` in `X-Archive-Source-URL` → the commit timestamp. Commit is last on purpose: on a backfilled archive it is the ingest date, which would put an old message with a bad `Date:` into the current year's shard and poison first-mention dates. `date_source` (`date` | `received` | `source_url` | `commit`) is on every row, and `verify-index.pl` prints the fallback tally. Today: 4 rows, all `received` (mail that arrived with no `Date:` at all).
- **Message-IDs ending `@z`** were generated by public-inbox at ingest for mail that arrived without one; they are treated as ordinary IDs. The `synthetic_mid` path exists for inboxes where even that is absent.
- **`cves/`** is faithful to the text: typos and examples in posts produce shards like `cves/2107.json` and `cves/1066.json`. Consumers should filter by plausible year if they care.
- JSON is written by hand in the exporter (fixed key order, fixed escaping) so output doesn't depend on which JSON module a host has.

**Failure handling.** `publish-index.sh` always writes `status.json`. If export or verify fails it rolls `index/` back to the committed version, writes `last_run.status = "error"` with `top_error` set and `last_success_at` unchanged, and exits non-zero. Workflows run that step with `continue-on-error`, commit as usual (new mail and the error status still get pushed), then a final step fails the job so GitHub sends the normal failure notification.

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
