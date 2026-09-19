#!/usr/bin/env perl
#
# resanitize-epoch.pl — rewrite a public-inbox v2 epoch so that every
# stored message is passed through the CURRENT scripts/sanitize-headers.pl.
#
# @decision DEC-ARCHIVE-008
# @title Re-sanitize stored messages by rewriting the epoch, not the inbox
# @status accepted
# @rationale DEC-ARCHIVE-003's sanitizer had a gap (no boundary when the
#   only openwall hop is ezmlm's `(qmail N invoked by uid N)` stamp), so
#   1,641 Maildir-imported messages from 2025–2026 were archived with the
#   subscriber's relay headers intact: Authentication-Results naming the
#   relay, X-Rspamd-*/X-Spamd-* verdicts (including the VERP address, i.e.
#   the subscription address), X-Greylist. The sanitizer is fixed; this
#   script applies the fix retroactively. It is a plain git history
#   rewrite of the epoch: every commit is replayed in order with the SAME
#   author, committer, timestamps and subject, and only the blob at `m`
#   replaced by sanitize(blob). Nothing else changes — message order,
#   commit times (which the index's `date_source: commit` fallback and its
#   "latest commit wins" tie-break depend on), and bodies are preserved
#   byte for byte, which the script verifies before swapping anything in.
#   It needs only git and Perl (no public-inbox), so it can run wherever
#   the checkout is. The previous epoch is moved to a gitignored backup
#   path, never deleted. Xapian/over/msgmap are moved aside too: they
#   reference the old blobs and are rebuilt by `public-inbox-index`.
#   The outer repo's history still contains the old packs; scrubbing that
#   is a separate decision (git filter-repo + force-push).
#   Measured 2026-09-19: 1,724 of 47,861 stored messages change — the
#   1,641 leaked ones plus ~85 older messages whose SENDER's rspamd left
#   X-Rspamd-*/X-Spamd-* verdicts that the new anywhere-rule also drops
#   (transport noise, no archival value; accepted).
#
# Usage:
#   resanitize-epoch.pl --inbox inbox [--epoch 0] [--drop <oid>]...
#                       [--dry-run] [--backup-dir <dir>] [--max-pack-size 40m]
#
#   --drop <oid>   additionally omit the stored message with this blob id
#                  (for the odd non-list message that ended up in the
#                  Maildir). Repeatable. Printed loudly; never implicit.
#   --dry-run      report what would change; write nothing.
#
# Run it from the repo root, with no ingest running (stop or wait out the
# scheduled sync), then commit `inbox/` and push immediately — see the
# local-vs-workflow rule in CLAUDE.md. The next workflow run rebuilds the
# index; every messages/*.jsonl row's `blob` changes, nothing else does.
#
# Exit codes: 0 ok, 1 failure (nothing swapped), 2 usage error.

use strict;
use warnings;
use Getopt::Long qw(GetOptions);
use Digest::SHA qw(sha1_hex);
use File::Basename qw(dirname);
use File::Path qw(make_path remove_tree);
use File::Copy qw(copy);
use POSIX qw(strftime);
use FindBin qw($RealBin);

my $SANITIZER = "$RealBin/sanitize-headers.pl";
{   # the pre-2026-09-19 sanitizer was CLI-only and would parse our @ARGV
    open(my $fh, '<', $SANITIZER) or die "$SANITIZER: $!";
    local $/;
    <$fh> =~ /^package SanitizeHeaders;/m
        or die "$SANITIZER is too old (no SanitizeHeaders::sanitize); update it first\n";
}
require $SANITIZER;

my %o = (epoch => 0, 'max-pack-size' => '40m', drop => []);
GetOptions(\%o, 'inbox=s', 'epoch=i', 'drop=s@', 'dry-run', 'backup-dir=s',
           'max-pack-size=s', 'help|h')
    && defined $o{inbox} && !$o{help}
    or do { print STDERR "usage: $0 --inbox <dir> [--epoch N] [--drop <oid>]... ",
            "[--dry-run] [--backup-dir <dir>] [--max-pack-size 40m]\n"; exit 2 };

my $INBOX = $o{inbox};
my $OLD   = "$INBOX/git/$o{epoch}.git";
-d "$OLD/objects" or die "no epoch repo at $OLD\n";
my %DROP = map { /\A[0-9a-f]{40,64}\z/ ? ($_ => 1) : die "--drop $_: not an object id\n" } @{ $o{drop} };
my $STAMP = strftime('%Y%m%dT%H%M%SZ', gmtime);
my $BACKUP = $o{'backup-dir'} // "$INBOX/../tmp/resanitize-$STAMP";
my $NEW = "$OLD.resanitize-tmp";

sub run { system(@_) == 0 or die "command failed (@_)\n" }
sub git_old { my @c = ('git', "--git-dir=$OLD", @_); open(my $fh, '-|', @c) or die "git: $!"; $fh }
sub blob_oid { sha1_hex("blob " . length($_[0]) . "\0" . $_[0]) }

# Refuse to rewrite on top of uncommitted inbox state: a local ingest that
# was never pushed would be silently folded into the rewrite.
if (!$o{'dry-run'} && system('git rev-parse --is-inside-work-tree >/dev/null 2>&1') == 0) {
    my $dirty = qx(git status --porcelain -- "$INBOX");
    die "uncommitted changes under $INBOX — commit/push or discard them first:\n$dirty"
        if length $dirty;
}

# ---- 1. enumerate commits, oldest first, with their `m` blob -----------------
my $head = qx(git --git-dir="$OLD" rev-parse --verify -q refs/heads/master);
chomp $head; $head or die "$OLD has no refs/heads/master\n";

my (@commits, %blob_of);
{
    my $fh = git_old(qw(log --reverse --first-parent --root --raw --no-abbrev
                        --no-renames -m --format=C%x20%H), $head);
    my $c;
    while (<$fh>) {
        if (/\AC ([0-9a-f]+)$/) { $c = $1; push @commits, $c }
        elsif (/\A:\d+ \d+ [0-9a-f]+ ([0-9a-f]+) [AM]\t(m|d)$/) {
            die "commit $c touches path 'd' (a removal); this script only handles append-only epochs\n"
                if $2 eq 'd';
            $blob_of{$c} = $1;
        }
    }
    close $fh or die "git log failed\n";
}
for (@commits) { defined $blob_of{$_} or die "commit $_ does not store a message at 'm'\n" }
printf STDERR "%d commits in %s\n", scalar @commits, $OLD;

# ---- 2. commit metadata (exact author/committer/dates/subject) ---------------
my %meta;
{
    my $fh = git_old(qw(log --reverse --first-parent --root --date=raw
        --format=%H%x1f%an%x1f%ae%x1f%ad%x1f%cn%x1f%ce%x1f%cd%x1f%B%x1e), $head);
    local $/ = "\x1e";
    while (my $rec = <$fh>) {
        chomp $rec; $rec =~ s/\A\n//;
        next unless length $rec;
        my @f = split /\x1f/, $rec, 8;
        $meta{ $f[0] } = \@f;
    }
    close $fh or die "git log (meta) failed\n";
}

# ---- 3. sanitize every blob; verify the change is header-only ---------------
my (%new_blob, $changed, $dropped, $bytes_before, $bytes_after);
{
    require IPC::Open2;
    my $pid = IPC::Open2::open2(my $r, my $w, 'git', "--git-dir=$OLD", 'cat-file', '--batch');
    binmode $r; binmode $w;
    for my $c (@commits) {
        my $oid = $blob_of{$c};
        print $w "$oid\n"; $w->flush;
        my $hdr = readline($r) // die "cat-file died\n";
        $hdr =~ /\A[0-9a-f]+ blob (\d+)$/ or die "cat-file: $hdr";
        my ($len, $raw) = ($1, '');
        while ($len > length $raw) {
            read($r, $raw, $len - length($raw), length $raw) or die "short read $oid\n";
        }
        read($r, my $lf, 1);
        if ($DROP{$oid}) { $dropped++; next }
        my ($san) = SanitizeHeaders::sanitize($raw, 0);
        if ($san ne $raw) {
            $changed++;
            my ($h1, $b1) = split(/\r?\n\r?\n/, $raw, 2);
            my ($h2, $b2) = split(/\r?\n\r?\n/, $san, 2);
            ($b1 // '') eq ($b2 // '')
                or die "BUG: sanitizer changed the body of $oid; refusing to continue\n";
            length($san) < length($raw)
                or die "BUG: sanitizer grew $oid; refusing to continue\n";
        }
        $new_blob{$c} = $san;
        $bytes_before += length $raw; $bytes_after += length $san;
    }
    close $w; close $r; waitpid($pid, 0);
}
printf STDERR "sanitize: %d of %d messages change (%d bytes removed); %d dropped by --drop\n",
    $changed // 0, scalar @commits, ($bytes_before - $bytes_after), $dropped // 0;
for my $oid (sort keys %DROP) {
    warn "W: --drop $oid is not a stored message in this epoch\n"
        unless grep { $blob_of{$_} eq $oid } @commits;
}
if ($o{'dry-run'}) { print STDERR "dry run: nothing written\n"; exit 0 }
if (!$changed && !$dropped) { print STDERR "nothing to do\n"; exit 0 }

# ---- 4. replay into a fresh bare repo via fast-import ------------------------
-e $NEW and die "$NEW already exists (previous run interrupted?) — move it away first\n";
run('git', 'init', '-q', '--bare', $NEW);
copy("$OLD/config", "$NEW/config") or die "copy config: $!";
# git-init boilerplate the old epoch never carried; it would otherwise be
# swept up by the outer repo's `git add -A`.
remove_tree("$NEW/hooks");
unlink("$NEW/description", "$NEW/info/exclude");
{
    open(my $fi, '|-', 'git', "--git-dir=$NEW", 'fast-import', '--quiet', '--done')
        or die "fast-import: $!";
    binmode $fi;
    my ($mark, $prev) = (0, undef);
    for my $c (@commits) {
        next unless exists $new_blob{$c};
        my ($an, $ae, $ad, $cn, $ce, $cd, $msg) = @{ $meta{$c} }[1 .. 7];
        $msg //= ''; $msg =~ s/\n*\z/\n/;
        my $b = ++$mark;
        print $fi "blob\nmark :$b\ndata ", length($new_blob{$c}), "\n", $new_blob{$c}, "\n";
        my $cm = ++$mark;
        print $fi "commit refs/heads/master\nmark :$cm\n",
                  "author $an <$ae> $ad\n", "committer $cn <$ce> $cd\n",
                  "data ", length($msg), "\n", $msg,
                  (defined $prev ? "from :$prev\n" : ''),
                  "M 100644 :$b m\n\n";
        $prev = $cm;
    }
    print $fi "done\n";
    close $fi or die "fast-import failed\n";
}
# Pack sizes matter: the epoch's object files are committed to the outer
# repo, and GitHub refuses files over 100 MB. Split the packs.
run('git', "--git-dir=$NEW", '-c', 'repack.writeBitmaps=false', 'repack', '-a', '-d', '-q',
    "--max-pack-size=$o{'max-pack-size'}");
run('git', "--git-dir=$NEW", 'update-server-info');
run('git', "--git-dir=$NEW", 'commit-graph', 'write', '--reachable');

# ---- 5. verify the new epoch before touching the old one --------------------
{
    my $n_new = qx(git --git-dir="$NEW" rev-list --count --first-parent refs/heads/master);
    chomp $n_new;
    my $expect = @commits - ($dropped // 0);
    $n_new == $expect or die "new epoch has $n_new commits, expected $expect\n";
    my %want = map { blob_oid($new_blob{$_}) => 1 } grep { exists $new_blob{$_} } @commits;
    open(my $fh, '-|', 'git', "--git-dir=$NEW", qw(log --first-parent --raw --no-abbrev
         --root --format= refs/heads/master)) or die "git log (verify): $!";
    my $seen = 0;
    while (<$fh>) {
        /\A:\d+ \d+ [0-9a-f]+ ([0-9a-f]+) [AM]\tm$/ or next;
        $want{$1} or die "new epoch stores unexpected blob $1\n";
        $seen++;
    }
    close $fh;
    $seen == $expect or die "new epoch stores $seen blobs, expected $expect\n";
    print STDERR "verified: $seen commits, every blob == sanitize(original)\n";
}

# ---- 6. swap: old epoch + stale indexes into the backup dir ------------------
make_path($BACKUP);
rename($OLD, "$BACKUP/$o{epoch}.git") or die "move $OLD aside: $!";
rename($NEW, $OLD) or die "move $NEW into place: $! (old epoch is at $BACKUP/$o{epoch}.git)";
for my $stale (glob("$INBOX/xap*"), glob("$INBOX/msgmap.sqlite3*"), glob("$INBOX/over.sqlite3*")) {
    my $base = $stale; $base =~ s{.*/}{};
    rename($stale, "$BACKUP/$base") or warn "W: could not move $stale aside: $!\n";
}
my $newhead = qx(git --git-dir="$OLD" rev-parse refs/heads/master); chomp $newhead;
print STDERR <<"EOT";
done: $OLD rewritten (master $head -> $newhead)
  previous epoch and indexes: $BACKUP  (gitignored; delete when satisfied)
  next: git add -A inbox && git commit && git push   (before the next sync run)
        public-inbox-index $INBOX   (if you use lei/public-inbox locally)
EOT
