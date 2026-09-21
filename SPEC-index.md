# SPEC-index.md — Published index for consumers

Status: **implemented 2026-09-17 as DEC-ARCHIVE-007; pending first green `sync.yml` run** (workflow wiring is in `tmp/index-workflows.patch` until applied). Owner: this repo. First consumer: vulntools (`cvetools`). Next decision number: DEC-ARCHIVE-008. Implementation notes at the end of this file.

## Why

Consumers need a flat, searchable projection of the archive without installing public-inbox or walking git history. This repo already has public-inbox installed and a warm index every sync run, so it is the cheapest place to produce that projection once, correctly, for everyone. vulntools currently has a git-walk importer that parses RFC 822 in TypeScript; it cannot decode MIME and cannot resolve the duplicate-Message-ID problem below, so it is being deleted in favour of consuming `index/`.

Two things only this repo can do right, which is why the export lives here and not in the consumer:

1. **Decode bodies properly.** `PublicInbox::Eml` handles charsets, quoted-printable, base64, multipart. Consumers get plain UTF-8 text.
2. **Resolve duplicate Message-IDs.** Measured 2026-09-17 on `inbox/git/0.git`: 47,836 stored messages, 13,531 Message-IDs stored twice (10,993 maildir+scrape pairs of the same message, differing only because the scrape elides `From`; 2,536 scrape+scrape pairs). ~34.3k unique messages. Resolution needs all copies of a Message-ID visible at once; a commit-by-commit walk can't do it. **This spec papers over the duplicates at export time. It does not purge them** — that stays a separate, later task (see `scripts/purge-dedup-scraped.pl` warnings).

Everything in `index/` is a projection: deterministic, regenerated on every sync run, never hand-edited, safe to delete and rebuild.

## Deliverables

1. `scripts/export-index.pl` — the exporter.
2. `scripts/verify-index.pl` — the validator (also run in CI).
3. `sync.yml` (and `backfill-openwall.yml`, `import-maildir.yml`): a step after `public-inbox-index` that runs the exporter, then the validator, before `git add -A`.
4. `status.json` at repo root, written in the same step.
5. Docs: a section in `CLAUDE.md`, a "Querying without public-inbox" section in `README.md`, `@decision DEC-ARCHIVE-007` in the exporter header.

## Layout

```
index/<source>/           one directory per list (oss-security today); added 2026-09-19 before any consumer integrated
  manifest.json
  messages/YYYY.jsonl     message → metadata + CVE IDs; YYYY = posting year (Date header, UTC)
  cves/YYYY.json          CVE ID → messages;            YYYY = the CVE's own year
  bodies/YYYY.jsonl       decoded plain-text bodies;    YYYY = posting year
status.json               ops health document (repo root, not under index/; one per repo, not per list)
```

Shard keys are chosen so a routine 4-hour run rewrites only the current year's `messages/` and `bodies/` files, plus whichever `cves/` files gained an entry. Do not shard messages by CVE year — a message can mention CVEs from several years or none.

## Exporter: `scripts/export-index.pl`

```
export-index.pl --inbox <dir> --out <dir> --source <name> [--url-scheme openwall|lore|none] [--jobs N]
```

Perl, because `PublicInbox::Eml`, `PublicInbox::Over`, `PublicInbox::Msgmap` are already installed on the runner (Debian `public-inbox` package). Must be portable to any public-inbox v2 inbox — `--source` and `--url-scheme` are the only list-specific inputs. It will later be run against third-party inboxes (lore.kernel.org) from a separate indexer repo.

### Step 1 — enumerate stored messages

For every epoch under `<inbox>/git/*.git`, every commit on `master` is one stored message at path `m` (v2 stores each message as a modification of that single path; there are no deletion commits in this archive today, but handle `d` if present by treating the message as removed). Collect for each: epoch number, commit, blob OID of `m`, raw bytes.

Prefer public-inbox's own modules over re-implementing: `over.sqlite3` gives `num`, `tid` (thread id), `ds`, subject, and `msgmap.sqlite3` gives `mid ↔ num`. If `--jobs` parallelism makes the module route awkward, `git cat-file --batch` over `<commit>:m` is acceptable — it is what the measurement above used and takes ~1 min for 48k messages.

### Step 2 — parse each message with `PublicInbox::Eml`

Extract:

- `message_id` — header value with `<>` stripped, whitespace-folded. **Handle folded headers** (`Message-ID:` on one line, `<id>` on the next); a naive line parser misses ~96 of them.
- `date` — RFC 5322 `Date` → ISO 8601 UTC. If unparseable, fall back to the commit timestamp and set `"date_source": "commit"`.
- `from`, `subject` — decoded (RFC 2047) to UTF-8, as archived. Do **not** attempt to un-elide scrape-obfuscated addresses.
- `in_reply_to` — first Message-ID in `In-Reply-To`, else first in `References`, else null.
- `provenance` — `X-Archive-Source` header value (`openwall-scrape`) if present, else `maildir`. For a third-party inbox with neither, `upstream`.
- `source_url` — `X-Archive-Source-URL` if present.
- `body` — see Bodies below.
- `cve_ids` — every match of `/\bCVE-\d{4}-\d{4,}\b/i` in subject + decoded body, uppercased, deduplicated, sorted.

### Step 3 — resolve duplicates: one row per Message-ID

Group by `message_id`. Choose the canonical copy by, in order: provenance rank `maildir` > `upstream` > `openwall-scrape`; then the latest commit. Emit **one row**, with the losers listed in `duplicates`.

Messages with no `Message-ID` at all (none exist today; keep it defensive): synthesize `message_id = sha256(date . "\0" . from . "\0" . subject . "\0" . body)[0:32] . "@synthetic." . source` and set `synthetic_mid: true`. Not the blob OID — that changes if headers are ever re-sanitized; a content hash survives it.

Compare decoded bodies across the copies. If any duplicate's body differs from the canonical body (not just headers), set `"body_conflict": true` on the row — consumers use it to decide whether to show a disambiguation page.

### Step 4 — threading

`thread_root` = Message-ID of the root of the thread the canonical copy belongs to, using public-inbox's `tid` (which resolves `References` chains). If the message is its own root, `thread_root == message_id`. Scrape-sourced messages have no `In-Reply-To`/`References`; they will be their own roots until the planned `[thread-prev]` synthesis pass — that is expected and not this spec's problem.

### Step 5 — URL

`url`:
- `--url-scheme openwall`: `source_url` if present, else `https://www.openwall.com/lists/oss-security/YYYY/MM/DD` from `date`.
- `--url-scheme lore`: `https://lore.kernel.org/<source>/<message_id>/`.
- `--url-scheme none`: null.

### Step 6 — bodies

Plain text only:
- first `text/plain` part of a multipart, charset- and transfer-encoding-decoded to UTF-8, `\r\n` normalised to `\n`;
- HTML-only messages: convert to text (`HTML::FormatText` or equivalent), no markup retained;
- attachments dropped; signatures and quoted lines **left in** (quote collapsing is a consumer rendering concern);
- bodies over 256 KB truncated at a line boundary with `"truncated": true`.

`body_sha` = first 12 hex chars of `sha256(body)`. Consumers use it as an immutable cache key, so it must be a pure function of the body bytes emitted.

### Step 7 — write files

`messages/YYYY.jsonl`, one object per line, sorted by `(date, message_id)`:

```json
{"message_id":"444ae456-3665-45d1-9f51-0325d35cb2c6@gpg.fail","synthetic_mid":false,"epoch":0,"blob":"<oid>","duplicates":[{"blob":"<oid>","provenance":"openwall-scrape"}],"body_conflict":false,"date":"2026-09-15T23:48:31Z","from":"\"Lexi Groves\" <contact@....fail>","subject":"Re: Retrospective by 'gpg.fail' authors","in_reply_to":null,"thread_root":"444ae456-3665-45d1-9f51-0325d35cb2c6@gpg.fail","url":"https://www.openwall.com/lists/oss-security/2026/09/16/1","provenance":"openwall-scrape","cve_ids":["CVE-2026-86089"],"body_sha":"9f2c1a0b7e3d"}
```

`cves/YYYY.json`, one object, keys sorted, entries in `date` order (first entry = first mention):

```json
{"CVE-2026-86089":[{"message_id":"...","date":"2026-09-15T21:02:11Z","url":"...","thread_root":"..."}]}
```

`bodies/YYYY.jsonl`, one object per line, same order as `messages/YYYY.jsonl`:

```json
{"message_id":"...","body":"...","truncated":false}
```

`manifest.json`:

```json
{
  "schema": 1,
  "source": "oss-security",
  "generated_at": "2026-09-17T00:07:11Z",
  "built_from": {"0": "<epoch 0 master commit>"},
  "messages": {"2008": {"count": 812, "sha256": "<sha256 of file>"}, "...": {}},
  "cves":     {"2019": {"count": 1431, "sha256": "..."}, "...": {}},
  "bodies":   {"2008": {"count": 812, "bytes": 3140221, "sha256": "..."}, "...": {}},
  "total_messages": 34305,
  "total_stored": 47836,
  "total_cves": 30117
}
```

`total_messages` = rows emitted (unique Message-IDs). `total_stored` = raw stored messages. The difference is the live dedup backlog and is meant to be visible.

JSON encoding: UTF-8, no pretty-printing in `.jsonl`, keys in the order shown, `Cpanel::JSON::XS` or `JSON::PP` with `canonical` so output is byte-stable.

### Determinism

Running the exporter twice on the same inbox must produce byte-identical files (excluding `generated_at`). Unchanged years must produce no git diff. This is what keeps the repo small: a routine run should change `messages/<thisyear>.jsonl`, `bodies/<thisyear>.jsonl`, a few `cves/*.json`, `manifest.json`, `status.json` — nothing else.

Full regeneration every run is acceptable (~1–2 min for 48k messages). An optional cache keyed by blob OID (e.g. `.export-cache/` gitignored, or a runner cache) can skip re-parsing unchanged blobs; not required for v1.

## Validator: `scripts/verify-index.pl`

Exit non-zero on any of:
- any file fails to parse;
- duplicate `message_id` across all `messages/*.jsonl`;
- a `cves/*.json` entry references a `message_id` not present in `messages/`;
- a `bodies/` row without a matching `messages/` row or vice versa, or out of order;
- `manifest.json` `count`/`sha256` disagrees with any file;
- `total_messages` ≠ rows emitted, or `total_stored` ≠ stored messages counted independently;
- any row where `body_sha` ≠ sha256 of the body in `bodies/`;
- `date` not parseable ISO 8601, or year of `date` ≠ file's YYYY.

Also print a one-line summary: stored, unique, duplicates, body_conflicts, cves, bytes.

## `status.json` (repo root)

Written by the same workflow step, schema per the ops plan:

```json
{
  "schema": 1,
  "system": "oss-security-archive",
  "generated_at": "<same as manifest>",
  "last_success_at": "<generated_at of this run if exporter+validator passed>",
  "last_run": {"status": "ok", "duration_s": 212, "imported": 14, "failed": 0, "top_error": null},
  "freshness": {"expected_interval_s": 14400, "source_lag_s": <now − newest message date>},
  "counts": {"messages": 34305, "stored": 47836, "duplicates": 13531},
  "problems": [],
  "links": {"logs": "https://github.com/joemalcolm/oss-security-archive/actions", "index": "https://raw.githubusercontent.com/joemalcolm/oss-security-archive/main/index/oss-security/manifest.json"}
}
```

`last_run` counters come from the line `sync.sh` appended to `metrics/imports.tsv` this run. If the exporter or validator fails, still write `status.json` with `last_run.status = "error"`, `top_error` set, and `last_success_at` left at the previous value — then fail the job.

## Workflow wiring

In `sync.yml`, between "Build indexes" and "Commit and push":

```yaml
      - name: Export index
        run: |
          perl scripts/export-index.pl --inbox inbox --out index/oss-security --source oss-security --url-scheme openwall
          perl scripts/verify-index.pl index/oss-security
          scripts/write-status.sh   # or inline; reads metrics/imports.tsv + index/oss-security/manifest.json
```

Same step in `backfill-openwall.yml` and `import-maildir.yml`, since they also change the inbox. The existing commit-message logic is unchanged; `index/` and `status.json` ride in the same commit as the inbox.

Add a `.gitattributes` entry `index/**/*.jsonl -diff` so `git log -p` stays usable, and confirm the pack stays reasonable after a week of runs (`git count-objects -vH`).

## Out of scope for this task

- Purging the scraped duplicates from the inbox (separate task; the index makes it safe to do later without downstream effect).
- Un-eliding scrape-obfuscated `From` addresses (list-owner question).
- Synthesizing `In-Reply-To` for scraped messages from Openwall `[thread-prev]` links (separate task; when it lands, `thread_root` improves automatically).
- Any change to ingest scripts.

## Acceptance

- `sync.yml` green with `index/` and `status.json` committed.
- `verify-index.pl` passes; summary shows `unique ≈ 34.3k`, `stored = 47836` (± whatever synced since), `duplicates ≈ 13.5k`.
- Spot check three known maildir+scrape pairs: the emitted row has `provenance: maildir`, an un-elided `from`, and one entry in `duplicates` with `provenance: openwall-scrape`.
- Running the exporter twice locally yields no diff except `generated_at`.
- `curl https://raw.githubusercontent.com/joemalcolm/oss-security-archive/main/index/oss-security/manifest.json` returns the manifest.
- README shows: `jq '."CVE-2026-86089"[0]' index/oss-security/cves/2026.json` as the no-tools way to find a CVE's first mention.

## Implementation notes (2026-09-17)

Where the implementation is more specific than, or departs from, the text above. Details in CLAUDE.md § Published index.

- **`in_reply_to`** falls back to the *last* Message-ID in `References` (the RFC 5322 parent), not the first (which is the thread root). ~120 messages are affected. One-line change in `parse_message` if the first was really intended.
- **`body_conflict`** compares normalised bodies (addresses masked, whitespace collapsed, `>From` unescaped, prefix accepted). Byte comparison flags ~6.3k of the ~11k maildir+scrape pairs purely because openwall elides addresses inside bodies and inlines later text parts; normalised, ~30 remain and they are real.
- **`url`** for a maildir winner uses its scraped duplicate's `X-Archive-Source-URL` when one exists (exact permalink) before falling back to the day URL.
- **`thread_root`** = `tid` from `over.sqlite3` unioned with the messages' own `References`/`In-Reply-To`, because a from-scratch reindex leaves same-Message-ID copies out of `over`. Output is identical with or without `over.sqlite3` today.
- **`date`** fallback order (2026-09-18): `Date:` header → topmost openwall `Received:` (by-clause or ezmlm qmail form) → `YYYY/MM/DD` from `X-Archive-Source-URL` → commit timestamp last, since on a backfilled archive the commit is the ingest date. A `Date:` more than two days ahead of that derived date is discarded. `date_source` (`date`|`received`|`source_url`|`commit`) is emitted on every row; `verify-index.pl` prints the fallback tally. Currently 4 rows fall back, all `received`.
- **Provenance default** (`maildir` vs `upstream`) follows `--url-scheme` (openwall → `maildir`), overridable with `--default-provenance`.
- **`cves/YYYY.json`** is one JSON object written one CVE per line, so a new mention is a one-line git delta.
- **Added** `scripts/write-status.pl` and `scripts/publish-index.sh` (export → verify → status, with rollback of `index/` on failure). Workflows run it `continue-on-error`, commit, then fail the job — otherwise the error `status.json` required above would never be pushed.
- **Workflow deps**: `libhtml-format-perl` (required for HTML-only mail), `libcpanel-json-xs-perl` (validator speed).
- "No Message-ID at all" does occur upstream (7 messages), but public-inbox appended a generated `<…@z>` ID at ingest, so the synthetic path is still unused here.
- Measured on `aeac4ccf` (2026-09-17): stored 47,841 · unique 34,278 · duplicates 13,563 (11,026 maildir+scrape, 2,536 scrape+scrape, 1 maildir+maildir) · body_conflicts 28 · CVEs 21,732 · index 96 MB (largest shard 7 MB) · export 19 s, verify 3 s on 2 cores.
- **Index path** (2026-09-19, DEC-ARCHIVE-009): everything lives under `index/<source>/` (`index/oss-security/`), not a bare `index/`, so the same repo can index further lists without a breaking path change. Done before vulntools integrated. `status.json` stays at the root.
- **Epoch location** (2026-09-20, DEC-ARCHIVE-010): the inbox epoch is the repository `joemalcolm/oss-security-inbox`; `manifest.built_from` commit ids refer to it. Consumers of `index/` are unaffected.
