#!/usr/bin/env bash
# inbox-repo.sh — the epoch lives in its own repository (DEC-ARCHIVE-010).
#
# @decision DEC-ARCHIVE-010
# @title The public-inbox epoch is a git repository of its own, not files
#        committed inside this one
# @status accepted
# @rationale Until 2026-09-20 inbox/git/0.git — a bare git repo — was
#   committed as ordinary files here. That fought git at every level:
#   every repack of the epoch committed a fresh generation of packs (a
#   108 MiB inbox had grown this repo to 335 MiB in weeks), refs/heads/
#   master and info/refs were unmergeable single values (the old
#   "local-vs-workflow divergence" rule), GitHub's 100 MB file cap forced
#   pack splitting, and removing a message meant rewriting two histories.
#   public-inbox's own model is that the epoch IS the repo (that is how
#   lore.kernel.org mirrors work: clone the epoch, public-inbox-init,
#   public-inbox-index). So epoch 0 now lives at
#   https://github.com/joemalcolm/oss-security-inbox (branch master, as
#   public-inbox expects); this repo keeps the small v2 scaffolding
#   (inbox/all.git, inbox/inbox.lock, inbox/description), the scripts,
#   the workflows, metrics/, index/ and status.json. Each message is one
#   small commit; pushes are incremental; history rewrites are ordinary.
#   index/<source>/manifest.json `built_from` records the epoch commit
#   an index was built from, which is the link between the two repos.
#
# Subcommands (run from the repo root):
#   fetch    clone the epoch into inbox/git/0.git if absent, else fetch
#            and fast-forward master. Public repo: no credentials needed.
#   push     push inbox/git/0.git master to the epoch repo. Needs
#            INBOX_PUSH_TOKEN (a fine-grained PAT with Contents: write on
#            the epoch repo) in CI; locally your normal git credentials
#            (SSH URL via INBOX_REPO_PUSH_URL) work. Refuses a
#            non-fast-forward: if someone pushed first, fetch, re-run the
#            ingest (idempotent) and push again.
#   status   print local vs remote master.
#   reset    point local master at the remote's (discards unpushed local
#            ingests; re-run them afterwards — ingest is idempotent).
#
# Env:
#   INBOX_REPO           default https://github.com/joemalcolm/oss-security-inbox.git
#   INBOX_REPO_PUSH_URL  default $INBOX_REPO (set to the SSH URL locally)
#   INBOX_PUSH_TOKEN     CI only; sent as an Authorization header for the
#                        push, never written to any git config
#   INBOX_DIR            default inbox
#   INBOX_EPOCH          default 0
set -euo pipefail

INBOX_REPO="${INBOX_REPO:-https://github.com/joemalcolm/oss-security-inbox.git}"
PUSH_URL="${INBOX_REPO_PUSH_URL:-$INBOX_REPO}"
INBOX_DIR="${INBOX_DIR:-inbox}"
EPOCH="${INBOX_EPOCH:-0}"
GD="$INBOX_DIR/git/$EPOCH.git"
BRANCH=master        # public-inbox v2 reads/writes refs/heads/master

usage() { echo "usage: $0 fetch|push|status|reset" >&2; exit 2; }
[[ $# -eq 1 ]] || usage

auth_args=()
if [[ -n "${INBOX_PUSH_TOKEN:-}" ]]; then
  # Same mechanism actions/checkout uses; scoped to github.com, per-command.
  b64="$(printf 'x-access-token:%s' "$INBOX_PUSH_TOKEN" | base64 | tr -d '\n')"
  auth_args=(-c "http.https://github.com/.extraheader=AUTHORIZATION: basic $b64")
fi

case "$1" in
  fetch)
    if [[ -d "$GD/objects" ]]; then
      before="$(git --git-dir="$GD" rev-parse --verify -q refs/heads/$BRANCH || echo none)"
      git --git-dir="$GD" fetch --quiet "$INBOX_REPO" "+refs/heads/$BRANCH:refs/remotes/inbox/$BRANCH"
      remote="$(git --git-dir="$GD" rev-parse refs/remotes/inbox/$BRANCH)"
      if [[ "$before" == none ]] || git --git-dir="$GD" merge-base --is-ancestor "$before" "$remote"; then
        git --git-dir="$GD" update-ref "refs/heads/$BRANCH" "$remote"
        echo "epoch $EPOCH: $before -> $remote"
      elif git --git-dir="$GD" merge-base --is-ancestor "$remote" "$before"; then
        echo "epoch $EPOCH: local $before is ahead of remote $remote (unpushed local ingest)"
      else
        echo "epoch $EPOCH: local $before and remote $remote have diverged — resolve by hand" >&2
        exit 1
      fi
    else
      mkdir -p "$(dirname "$GD")"
      git clone --quiet --bare --branch "$BRANCH" "$INBOX_REPO" "$GD"
      # public-inbox expects a plain bare repo; the clone's remote-tracking
      # config is harmless but the mirror refspec would be confusing.
      git --git-dir="$GD" config --unset-all remote.origin.fetch || true
      echo "epoch $EPOCH: cloned $(git --git-dir="$GD" rev-parse refs/heads/$BRANCH)"
    fi
    # inbox/all.git/refs/ is not tracked (git keeps no empty dirs); the
    # importer needs it to recognise all.git as a repo. Same heal as
    # setup-inbox.sh, done here so `fetch` alone yields a usable inbox.
    mkdir -p "$INBOX_DIR/all.git/refs/heads" "$GD/refs/heads"
    git --git-dir="$GD" update-server-info
    ;;
  push)
    [[ -d "$GD/objects" ]] || { echo "no epoch at $GD (run: $0 fetch)" >&2; exit 1; }
    local_head="$(git --git-dir="$GD" rev-parse refs/heads/$BRANCH)"
    # Plain (non-force) push: a rejected non-fast-forward means another
    # writer got there first; never overwrite their messages.
    git --git-dir="$GD" ${auth_args[@]+"${auth_args[@]}"} push --quiet "$PUSH_URL" "refs/heads/$BRANCH:refs/heads/$BRANCH"
    echo "epoch $EPOCH: pushed $local_head"
    ;;
  status)
    l="$(git --git-dir="$GD" rev-parse --verify -q refs/heads/$BRANCH 2>/dev/null || echo none)"
    r="$(git ls-remote "$INBOX_REPO" "refs/heads/$BRANCH" | cut -f1)"
    echo "local  $l ($(git --git-dir="$GD" rev-list --count refs/heads/$BRANCH 2>/dev/null || echo 0) messages)"
    echo "remote $r"
    ;;
  reset)
    git --git-dir="$GD" fetch --quiet "$INBOX_REPO" "+refs/heads/$BRANCH:refs/remotes/inbox/$BRANCH"
    r="$(git --git-dir="$GD" rev-parse refs/remotes/inbox/$BRANCH)"
    git --git-dir="$GD" update-ref "refs/heads/$BRANCH" "$r"
    git --git-dir="$GD" update-server-info
    echo "epoch $EPOCH: master reset to remote $r (re-run public-inbox-index $INBOX_DIR)"
    ;;
  *) usage ;;
esac
