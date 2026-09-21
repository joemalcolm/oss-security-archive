#!/usr/bin/env bash
# scrub-history.sh — rewrite the OUTER repo's history so no past commit
# still carries the pre-sanitize epoch packs (DEC-ARCHIVE-008, step 3).
#
# HISTORICAL. Run once on 2026-09-19. Since DEC-ARCHIVE-010 the epoch is
# its own repository and inbox/git/ is not tracked here, so this script
# has nothing left to scrub; a future redaction is a force-push of the
# epoch repo (see resanitize-epoch.pl). Kept for the record.
#
# What it does, in a FRESH clone (git filter-repo insists on one):
#   1. clone <remote> into <workdir>
#   2. copy the current inbox/ aside
#   3. git filter-repo --invert-paths on inbox/ and index/  — every
#      historical version of the epoch objects (all of which contained the
#      unsanitized blobs) and of the index (whose first bodies/2018.jsonl
#      carried a non-list message) is dropped from every commit; commits
#      that only touched those paths disappear; everything else keeps its
#      history (scripts, docs, workflows, metrics)
#   4. re-add the copied inbox/ as ONE snapshot commit on top
#   5. print the push commands. It never pushes: the force-push is yours.
#
# index/ is not re-added — it is a projection; the next sync run (or a
# manual `gh workflow run sync.yml`) regenerates it from the clean inbox.
#
# Afterwards, on the remote, old commits remain reachable by hash until
# GitHub garbage-collects them; ask GitHub Support to purge cached views
# (docs: "Removing sensitive data from a repository"). Every existing
# clone still has the old objects; re-clone or `git fetch && git reset
# --hard origin/main && git reflog expire --expire=now --all && git gc
# --prune=now`. Stale branches on the remote must be deleted too: they
# keep the old packs alive (`git push origin --delete <branch>`).
#
# Usage:
#   scripts/scrub-history.sh --yes [--remote <url>] [--workdir <dir>]
#
# Requires: git, git-filter-repo (brew install git-filter-repo /
# pip install git-filter-repo). Do NOT run while a sync workflow is in
# flight: a run that checked out the old history would push old packs
# back on top of the rewrite (its rebase-retry would succeed).
set -euo pipefail

REMOTE=""; WORKDIR=""; YES=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes) YES=1 ;;
    --remote) REMOTE="$2"; shift ;;
    --workdir) WORKDIR="$2"; shift ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done
[[ -z "$REMOTE" ]] && REMOTE="$(git config --get remote.origin.url 2>/dev/null || true)"
[[ -z "$REMOTE" ]] && { echo "no --remote and no origin in the current repo" >&2; exit 2; }
[[ -z "$WORKDIR" ]] && WORKDIR="$(dirname "$(pwd)")/oss-security-archive-scrub-$(date -u +%Y%m%dT%H%M%SZ)"
command -v git-filter-repo >/dev/null 2>&1 || git filter-repo --version >/dev/null 2>&1 \
  || { echo "git-filter-repo is not installed (brew install git-filter-repo)" >&2; exit 2; }
[[ -e "$WORKDIR" ]] && { echo "$WORKDIR already exists" >&2; exit 2; }

echo "remote:  $REMOTE"
echo "workdir: $WORKDIR"
if [[ $YES -ne 1 ]]; then
  echo "This rewrites every commit on every branch of that remote's history. Re-run with --yes." >&2
  exit 2
fi

echo "==> 1. fresh clone"
git clone --quiet --no-local "$REMOTE" "$WORKDIR"
cd "$WORKDIR"
default_branch="$(git rev-parse --abbrev-ref HEAD)"
before_head="$(git rev-parse HEAD)"
before_commits="$(git rev-list --count HEAD)"
before_size="$(git count-objects -vH | awk '/size-pack/ {print $2 $3}')"
echo "    $default_branch @ $before_head ($before_commits commits, $before_size)"
git branch -r | sed 's/^ *//' | grep -v -e HEAD -e "origin/$default_branch\$" | sed 's|^origin/|    other remote branch (delete it after the push): |' || true

echo "==> 2. snapshot current inbox/"
snap="$WORKDIR.inbox-snapshot"
cp -a inbox "$snap"
git ls-files inbox | sort > "$snap.tracked"     # exact tracked file list, for the re-add check
epoch_head="$(git --git-dir="$snap/git/0.git" rev-parse refs/heads/master)"
epoch_count="$(git --git-dir="$snap/git/0.git" rev-list --count --first-parent refs/heads/master)"
echo "    epoch 0 master $epoch_head ($epoch_count messages)"

echo "==> 3. filter-repo: drop inbox/ and index/ from all history"
git filter-repo --quiet --path inbox/ --path index/ --invert-paths
after_commits="$(git rev-list --count HEAD)"
leftover="$(git rev-list --objects --all | grep -c ' inbox/\| index/' || true)"
[[ "$leftover" == "0" ]] || { echo "BUG: $leftover inbox/index objects survived the filter" >&2; exit 1; }
echo "    $before_commits -> $after_commits commits; no inbox/ or index/ objects remain in history"

echo "==> 4. re-add inbox/ as a single snapshot"
cp -a "$snap" inbox
git add -A inbox
# .gitignore lists inbox/inbox.lock, but it must stay tracked: public-inbox
# decides an inbox is v2 by that file's presence (PublicInbox::Inbox::version).
# A plain `git add -A` drops it and every later ingest fails with
# "not a git repository: inbox" (learned the hard way, 2026-09-19).
git add -f inbox/inbox.lock
diff <(git diff --cached --name-only --diff-filter=A -- inbox | sort) "$snap.tracked" >/dev/null \
  || { echo "BUG: re-added inbox/ file list differs from the original tracked list:" >&2
       diff <(git diff --cached --name-only --diff-filter=A -- inbox | sort) "$snap.tracked" >&2; exit 1; }
git commit --quiet -m "inbox: re-add epoch 0 as a single snapshot after history scrub (DEC-ARCHIVE-008)

History before this commit no longer contains inbox/ or index/ at any
revision: every earlier version of the epoch packs held messages that
scripts/sanitize-headers.pl (pre-2026-09-19) had let through with the
subscriber's relay headers, and the first index/ carried a non-list
message. Epoch 0 master here is $epoch_head ($epoch_count messages),
identical to what the last pre-scrub commit ($before_head) shipped.
index/ is regenerated by the next sync run."
[[ "$(git --git-dir=inbox/git/0.git rev-parse refs/heads/master)" == "$epoch_head" ]] \
  || { echo "BUG: re-added epoch head differs" >&2; exit 1; }
git gc --quiet --prune=now
after_size="$(git count-objects -vH | awk '/size-pack/ {print $2 $3}')"
echo "    $(git rev-parse --short HEAD): epoch 0 master $epoch_head; repo $before_size -> $after_size"

cat <<EOT

Ready in $WORKDIR. Nothing has been pushed. Review, then:

  cd "$WORKDIR"
  git remote add origin "$REMOTE"
  git push --force origin $default_branch
  # delete any other remote branch listed above, e.g.:
  #   git push origin --delete feat/maildir-import
  gh workflow run sync.yml          # regenerates index/ now rather than in <4h

Then: re-clone (or hard-reset + reflog expire + gc) every other checkout,
and ask GitHub Support to purge the cached old commits. Delete
$snap when done.
EOT
