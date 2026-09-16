#!/usr/bin/env perl
#
# dedup-rebuild.pl — rebuild the archive dropping openwall-scrape
# duplicates of Maildir-originated messages. Replacement for the
# broken purge-dedup-scraped.pl (see that file's warning header).
#
# @decision DEC-ARCHIVE-006
# @title Fresh-rebuild via V2Writable is the safe cleanup path
# @status accepted
# @rationale purge-dedup-scraped.pl attempted to use PublicInbox::
#   V2Writable::purge() in a shared-importer batching pattern —
#   each purge invalidates internal state that subsequent purges in
#   the same session depend on, and the alternates-linked all.git
#   ends up with dangling refs. Correct alternative: don't purge in
#   place at all. Enumerate a keep-set, populate a fresh inbox by
#   replaying keep-set messages through V2Writable::add(), then swap
#   the fresh inbox for the old one. add() is well-supported for
#   shared-importer batching (that's how public-inbox-watch works),
#   so this pattern has none of the purge pathology. Cost: one
#   full-archive read pass + one full-archive write pass, ~30-60 min
#   for ~40k messages. Idempotent, atomic swap, keeps a backup.
#
# Usage:
#   dedup-rebuild.pl <old-inbox-dir> <new-inbox-name>
#
# Preconditions:
#   1. <new-inbox-name> already exists in ~/.public-inbox/config,
#      pointing at a FRESH empty inbox directory. Caller creates it:
#         mkdir /path/to/new-inbox
#         public-inbox-init -V2 <name> /path/to/new-inbox <url> <addr>
#   2. Old inbox at <old-inbox-dir> is not being written to
#      concurrently. Stop scheduled sync workflows first.
#   3. Enough disk for two copies of the archive during rebuild.
#
# Keep rule:
#   - keep every message that lacks `X-Archive-Source: openwall-scrape`
#     (i.e. every Maildir-imported message)
#   - keep openwall-scrape messages whose Message-ID has no Maildir
#     counterpart in the archive (real net-new from openwall scrapes:
#     pre-Maildir years, Maildir gap-fill)
#   - drop openwall-scrape messages whose Message-ID matches a Maildir
#     message (the ~9,923 lower-fidelity duplicates)

use strict;
use warnings;
use PublicInbox::Config;
use PublicInbox::InboxWritable;
use PublicInbox::Eml;

my $old_dir  = $ARGV[0] or die "usage: $0 <old-inbox-dir> <new-inbox-name>\n";
my $new_name = $ARGV[1] or die "usage: $0 <old-inbox-dir> <new-inbox-name>\n";
my $epoch    = "$old_dir/git/0.git";
-d $epoch or die "no epoch repo at $epoch\n";

my $cfg = PublicInbox::Config->new
    or die "cannot load public-inbox config\n";
my $new_ibx = $cfg->lookup_name($new_name)
    or die "no inbox '$new_name' in config (create + init it first)\n";
$new_ibx = PublicInbox::InboxWritable->new($new_ibx);

# ---- Pass 1: build set of MIDs that have a Maildir version ----------
# One pass over the old archive, extract each commit's MID and note
# whether it's flagged as openwall-scrape. Anything WITHOUT the
# X-Archive-Source: openwall-scrape header is a Maildir message; its
# MID goes into the set.
print STDERR "pass 1: enumerate Maildir MIDs from $epoch\n";
my %maildir_mids;
my $total_seen = 0;
open my $log, "-|", "git", "-C", $epoch, "log", "--format=%H"
    or die "git log: $!";
while (my $c = <$log>) {
    chomp $c;
    $total_seen++;
    open my $show, "-|", "git", "-C", $epoch, "show", "$c:m" or next;
    my ($mid, $is_scraped) = ('', 0);
    while (my $line = <$show>) {
        last if $line =~ /^\r?\n\z/;
        if ($line =~ /^[Mm]essage-[Ii][Dd]:\s*(.+?)\s*\r?$/) {
            $mid = $1;
        }
        elsif ($line =~ /^X-Archive-Source:\s*openwall-scrape/) {
            $is_scraped = 1;
        }
    }
    close $show;
    $maildir_mids{$mid} = 1 if length $mid && !$is_scraped;
    print STDERR "  scanned $total_seen commits\n" if $total_seen % 5000 == 0;
}
close $log;
printf STDERR "  pass 1 done: %d commits scanned, %d Maildir MIDs collected\n",
    $total_seen, scalar(keys %maildir_mids);

# ---- Pass 2: replay keep-set into fresh inbox -----------------------
# Iterate the old archive again. For each commit:
#   - if not openwall-scrape → keep (Maildir message, add unconditionally)
#   - if openwall-scrape AND MID in maildir_mids → drop
#   - if openwall-scrape AND MID NOT in maildir_mids → keep (real net-new)
# Add each keep-message via V2Writable::add() on a shared importer
# session; call done() once at the end (single packfile write).
print STDERR "pass 2: replay keep-set into $new_ibx->{inboxdir}\n";
my $imp = $new_ibx->importer;
my ($added, $dropped, $malformed) = (0, 0, 0);
open my $log2, "-|", "git", "-C", $epoch, "log", "--format=%H"
    or die "git log (pass 2): $!";
while (my $c = <$log2>) {
    chomp $c;
    open my $show, "-|", "git", "-C", $epoch, "show", "$c:m" or next;
    local $/;
    my $raw = <$show>;
    close $show;
    unless (defined $raw && length $raw) {
        $malformed++;
        next;
    }
    my $is_scraped = ($raw =~ /^X-Archive-Source:\s*openwall-scrape\b/m);
    if ($is_scraped) {
        # Extract MID for the dedup check
        my ($mid) = $raw =~ /^[Mm]essage-[Ii][Dd]:\s*(.+?)\s*\r?$/m;
        if (defined $mid && exists $maildir_mids{$mid}) {
            $dropped++;
            print STDERR "  progress: added=$added dropped=$dropped\n"
                if ($added + $dropped) % 5000 == 0;
            next;
        }
    }
    my $eml = PublicInbox::Eml->new(\$raw);
    eval { $imp->add($eml) };
    if ($@) {
        warn "  add failed on $c: $@";
        $malformed++;
        next;
    }
    $added++;
    print STDERR "  progress: added=$added dropped=$dropped\n"
        if ($added + $dropped) % 5000 == 0;
}
close $log2;
$imp->done;
printf STDERR "  pass 2 done: added=%d, dropped=%d, malformed=%d\n",
    $added, $dropped, $malformed;
print  STDERR "  next: public-inbox-index $new_ibx->{inboxdir}\n";
print  STDERR "  then swap: mv $old_dir ${old_dir}.pre-dedup && ";
print  STDERR         "mv $new_ibx->{inboxdir} $old_dir\n";
