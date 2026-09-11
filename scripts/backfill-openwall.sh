#!/usr/bin/env bash
# backfill-openwall.sh — thin wrapper around openwall-scrape.pl that
# pipes its Maildir output through the existing import-maildir.sh
# (sanitizer + dedup + ingest).
#
# Reuses the maildir-import pipeline verbatim. For openwall-scraped
# messages — which have no `Received:` chain because we reconstructed
# them from HTML — the sanitizer's "no openwall hop found" passthrough
# kicks in and the messages flow through unchanged.
#
# Usage:
#   backfill-openwall.sh <START_DATE> <END_DATE> [--reverse]
#
# Env:
#   INBOX_DIR      public-inbox repo path (default: $(pwd)/inbox)
#   DELAY          seconds between HTTP requests (default 1.5)
#   SAVE_FAILED    directory to store raw HTML of pages that fetched
#                  200 but couldn't be parsed. Passed to openwall-scrape
#                  as --save-failed. Cheap disk, saves a re-fetch if a
#                  future scraper improvement can reprocess.
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 START_DATE END_DATE [--reverse]" >&2
  echo "  dates are YYYY-MM-DD, inclusive" >&2
  exit 2
fi

START="$1"
END="$2"
REVERSE=""
if [[ "${3:-}" == "--reverse" ]]; then
  REVERSE="--reverse"
fi

INBOX_DIR="${INBOX_DIR:-$(pwd)/inbox}"
DELAY="${DELAY:-1.5}"
SAVE_FAILED="${SAVE_FAILED:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRAPER="$SCRIPT_DIR/openwall-scrape.pl"
IMPORTER="$SCRIPT_DIR/import-maildir.sh"

# Per-run timestamp used for scrape-warning log and scrape-failed HTML
# directory. Same string across both so a single run's artifacts are
# easy to correlate.
RUN_TS="$(date -u +%FT%TZ)"

# When METRICS_LOG is set (i.e. we're in monitored mode — sync workflow
# or explicit local metrics run), persist the scraper's stderr warning
# stream and the raw HTML of any unparseable pages alongside the
# metrics file. Mirrors the metrics/errors + metrics/failed-msgs
# pattern in import-maildir.sh so backfill and ingest failures live in
# parallel trees under the same metrics/ root.
#
# Layout:
#   $(dirname METRICS_LOG)/
#     imports.tsv                       ← existing per-run line
#     scrape-warnings/<RUN_TS>.log      ← full SCRAPE_WARN dump (this run)
#     scrape-failed-html/<RUN_TS>/*.html ← unparseable pages (this run)
#
# When METRICS_LOG is not set (ad-hoc local run), we don't persist —
# stderr still shows the tally.
PERSIST_SCRAPE_WARN=""
if [[ -n "${METRICS_LOG:-}" ]]; then
  METRICS_ROOT="$(dirname "$METRICS_LOG")"
  PERSIST_SCRAPE_WARN="$METRICS_ROOT/scrape-warnings/$RUN_TS.log"
  # If the caller didn't set SAVE_FAILED, wire the metrics-side path in
  # by default. An explicit SAVE_FAILED still wins (lets you dump
  # elsewhere for one-off debugging).
  if [[ -z "$SAVE_FAILED" ]]; then
    SAVE_FAILED="$METRICS_ROOT/scrape-failed-html/$RUN_TS"
  fi
fi

for tool in perl public-inbox-mda; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Error: $tool not found in PATH" >&2
    exit 1
  fi
done

if [[ ! -d "$INBOX_DIR" ]]; then
  echo "Error: INBOX_DIR not a directory: $INBOX_DIR" >&2
  exit 1
fi

# Scratch Maildir we'll throw away after ingest.
SCRATCH="$(mktemp -d)"
mkdir -p "$SCRATCH"/{cur,new,tmp}
# Structured-warning log from openwall-scrape.pl (SCRAPE_WARN lines).
# Everything else on the scraper's stderr passes through to the user.
SCRAPE_WARN_LOG="$(mktemp)"
trap 'rm -rf "$SCRATCH" "$SCRAPE_WARN_LOG"' EXIT

echo "==> Scraping openwall $START..$END ${REVERSE:+(reverse) }into $SCRATCH"
# Split scraper stderr: SCRAPE_WARN\t… lines to $SCRAPE_WARN_LOG so we
# can tally them at the end; anything else (info lines like per-day
# counts) still shows up live on our stderr. Pattern: perl process
# substitution to filter, then tee.
{
  scraper_opts=(
    --start "$START"
    --end   "$END"
    --maildir "$SCRATCH"
    --delay "$DELAY"
  )
  [[ -n "$REVERSE" ]] && scraper_opts+=("$REVERSE")
  [[ -n "$SAVE_FAILED" ]] && scraper_opts+=(--save-failed "$SAVE_FAILED")
  perl "$SCRAPER" "${scraper_opts[@]}" 2> >(
    tee >(grep -a '^SCRAPE_WARN' >> "$SCRAPE_WARN_LOG") >&2
  )
}

echo
echo "==> Ingesting scraped messages via import-maildir.sh"
# Propagate METRICS_LOG explicitly so the inner import-maildir.sh
# appends its own per-run line to the same metrics/imports.tsv file.
# Without this, the backfill's ingest step ran in a subshell that
# inherited METRICS_LOG via env, so it "worked" — but only when
# METRICS_LOG was set in the outer env. The workflow's Backfill step
# doesn't set METRICS_LOG on the outer bash env unless we do it
# explicitly there too (see backfill-openwall.yml).
INBOX_DIR="$INBOX_DIR" METRICS_LOG="${METRICS_LOG:-}" \
  "$IMPORTER" "$SCRATCH"

# End-of-run tally of scrape-time warnings. import-maildir.sh already
# prints its own residual and error summaries; this one adds the
# scrape-side view (fetch failures, unparseable pages, synthesized
# dates, etc.).
scrape_warn_total=0
if [[ -s "$SCRAPE_WARN_LOG" ]]; then
  echo
  echo "Scrape-time warnings (top 20 by category):"
  # awk 'NR<=20' instead of `head -20` — see the analogous note in
  # import-maildir.sh. Under set -o pipefail, `head` closing early
  # SIGPIPEs upstream sort/uniq and would fail the whole script,
  # skipping public-inbox-index / commit / push.
  awk -F'\t' '$1 == "SCRAPE_WARN" {print $2}' "$SCRAPE_WARN_LOG" \
    | sort | uniq -c | sort -rn | awk 'NR<=20'
  scrape_warn_total=$(wc -l < "$SCRAPE_WARN_LOG" | tr -d ' ')
  echo "  ($scrape_warn_total structured warning(s) total)"
fi

# Persist the SCRAPE_WARN log alongside metrics/imports.tsv when in
# monitored mode. Full dump (all lines, tab-separated) + a header
# summarizing the run. Only written when there are warnings — an
# all-clean year doesn't need a file.
if [[ -n "$PERSIST_SCRAPE_WARN" && "$scrape_warn_total" -gt 0 ]]; then
  mkdir -p "$(dirname "$PERSIST_SCRAPE_WARN")"
  {
    echo "# backfill-openwall run at $RUN_TS"
    echo "# date-range=$START..$END scrape-warnings=$scrape_warn_total"
    echo
    echo "== Top categories =="
    awk -F'\t' '$1 == "SCRAPE_WARN" {print $2}' "$SCRAPE_WARN_LOG" \
      | sort | uniq -c | sort -rn
    echo
    echo "== Full SCRAPE_WARN log (category<TAB>detail) =="
    awk -F'\t' '$1 == "SCRAPE_WARN" {print $2 "\t" $3}' "$SCRAPE_WARN_LOG"
  } > "$PERSIST_SCRAPE_WARN"
  echo "Full scrape-warning log at $PERSIST_SCRAPE_WARN"
  if [[ -d "$SAVE_FAILED" ]]; then
    html_count=$(find "$SAVE_FAILED" -type f -name '*.html' 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$html_count" -gt 0 ]]; then
      echo "Unparseable pages ($html_count) saved under $SAVE_FAILED/"
    fi
  fi
fi

# ---- ongoing-monitoring hook --------------------------------------------
# METRICS_LOG (env, optional): mirror the pattern in import-maildir.sh but
# track scrape-side counters instead of ingest counters. Successive
# backfill runs (per year) build a trend in the same file. Format:
#   ISO-timestamp  script  date-range  scrape-warnings  top-warn-cat  top-warn-count
if [[ -n "${METRICS_LOG:-}" ]]; then
  mkdir -p "$(dirname "$METRICS_LOG")"
  top_cat="none"
  top_count=0
  if [[ "$scrape_warn_total" -gt 0 ]]; then
    # `awk 'NR==1'` instead of `head -1` for the same SIGPIPE reason
    # as above.
    read -r top_count top_cat < <(
      awk -F'\t' '$1 == "SCRAPE_WARN" {print $2}' "$SCRAPE_WARN_LOG" \
        | sort | uniq -c | sort -rn \
        | awk 'NR==1 {print $1, $2}'
    )
    top_cat="${top_cat:-none}"
    top_count="${top_count:-0}"
  fi
  printf '%s\tbackfill-openwall\t%s..%s\t%d\t%s\t%d\n' \
    "$RUN_TS" "$START" "$END" \
    "$scrape_warn_total" "$top_cat" "$top_count" \
    >> "$METRICS_LOG"
  echo "Scrape metrics line appended to $METRICS_LOG"
fi
