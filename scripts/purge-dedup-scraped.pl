#!/usr/bin/env perl
#
# purge-dedup-scraped.pl — remove openwall-scraped messages whose
# Message-ID also appears in a non-scraped (Maildir-imported) message
# in the same archive.
#
# !!! WARNING — DO NOT USE AS-IS !!!
# The shared-importer batching in pass 3 corrupts the archive's git
# object graph: subsequent purge() calls reference SHAs invalidated
# by prior calls in the same session, and the alternates-linked
# `all.git` ends up with dangling refs. Symptom: many `W: <sha> is
# not a blob (type=)` warnings during subsequent `public-inbox-index
# --reindex`. Recovery: `git checkout -- inbox && git clean -fdx
# inbox` to revert the working tree.
#
# The correct approach requires either (a) one subprocess-per-message
# public-inbox-purge invocation (slow but safe), or (b) a
# git-filter-repo pass that rebuilds the epoch repo from scratch
# with the offending commits dropped, followed by a full reindex.
# Neither is implemented here yet. Left in the tree for reference
# in case someone wants to pick it up; not wired into any workflow.
#
# Background: PublicInbox's V2Writable::add() dedups on
# content-hash, not Message-ID alone. Same-MID + different-body is
# treated as "different messages" (a feature for handling broken
# senders that reuse IDs). But an openwall-scraped copy of a
# subscriber-delivered message will always differ in body — openwall
# elides addresses, drops the Received chain, and we inject tracer
# headers — so every backfill-year that overlaps the Maildir coverage
# window (2015-Mar-16 onward) landed as duplicate storage rather than
# dedup'd. This script identifies those duplicates and removes only
# the scraped-side copies, preserving the higher-fidelity Maildir
# versions.
#
# Design: O(N) single-pass over the epoch repo. Pass 1 builds an
# in-memory index (msgid → [(commit_sha, is_scraped)]). Pass 2
# identifies msgids that have both a scraped and a non-scraped
# entry — those are the duplicates. Pass 3 calls
# PublicInbox::V2Writable::purge() for each victim, keeping ONE
# importer session open across all calls so the packfile gets
# rewritten once at ->done() instead of N times.
#
# Usage: perl purge-dedup-scraped.pl <inbox-name>
# Idempotent: safe to re-run; a second pass will find nothing to
# purge because the first pass already removed the duplicates.

use strict;
use warnings;
use PublicInbox::Config;
use PublicInbox::InboxWritable;
use PublicInbox::Eml;

my $inbox_name = shift @ARGV or die "usage: $0 <inbox-name>\n";
my $cfg = PublicInbox::Config->new
    or die "cannot load ~/.public-inbox/config\n";
my $ibx = $cfg->lookup_name($inbox_name)
    or die "no inbox named '$inbox_name'\n";
$ibx = PublicInbox::InboxWritable->new($ibx);

my $inbox_dir = $ibx->{inboxdir};
my $epoch     = "$inbox_dir/git/0.git";
-d $epoch or die "$epoch not found\n";

# ---- Pass 1: build msgid → [(commit_sha, is_scraped)] index ------------
my %index;
my $scanned = 0;
my $with_mid = 0;
open my $log, "-|", "git", "-C", $epoch, "log", "--format=%H"
    or die "git log: $!";
while (my $c = <$log>) {
    chomp $c;
    $scanned++;
    open my $show, "-|", "git", "-C", $epoch, "show", "$c:m"
        or next;
    my ($mid, $is_scraped) = ("", 0);
    while (my $line = <$show>) {
        last if $line =~ /^\r?\n\z/;   # end of headers
        if ($line =~ /^[Mm]essage-[Ii][Dd]:\s*(.+?)\s*\r?$/) {
            $mid = $1;
        }
        elsif ($line =~ /^X-Archive-Source:\s*openwall-scrape/) {
            $is_scraped = 1;
        }
    }
    close $show;
    if (length $mid) {
        push @{ $index{$mid} }, [$c, $is_scraped];
        $with_mid++;
    }
    print STDERR "  scanned $scanned commits\n" if $scanned % 2000 == 0;
}
close $log;
printf STDERR "  pass 1 done: %d commits, %d with Message-ID, %d unique MIDs\n",
    $scanned, $with_mid, scalar(keys %index);

# ---- Pass 2: identify duplicates ----------------------------------------
my @purge_commits;
my $dup_mids = 0;
for my $mid (keys %index) {
    my @e = @{ $index{$mid} };
    next unless @e > 1;
    my $has_scraped = grep { $_->[1] } @e;
    my $has_other   = grep { !$_->[1] } @e;
    next unless $has_scraped && $has_other;
    $dup_mids++;
    push @purge_commits, map { $_->[0] } grep { $_->[1] } @e;
}
printf STDERR "  pass 2 done: %d duplicated MIDs; purging %d scraped commits\n",
    $dup_mids, scalar(@purge_commits);
exit 0 unless @purge_commits;

# ---- Pass 3: purge in one importer session ------------------------------
my $imp = $ibx->importer;
my $done = 0;
for my $c (@purge_commits) {
    open my $show, "-|", "git", "-C", $epoch, "show", "$c:m"
        or do { warn "skip $c: $!"; next };
    local $/;
    my $raw = <$show>;
    close $show;
    next unless defined $raw && length $raw;
    my $eml = PublicInbox::Eml->new(\$raw);
    eval { $imp->purge($eml) };
    if ($@) {
        warn "purge $c failed: $@";
    } else {
        $done++;
    }
    print STDERR "  purged $done / ", scalar(@purge_commits), "\n"
        if $done % 500 == 0;
}
$imp->done;
print STDERR "  pass 3 done: $done purged.\n";
print STDERR "Now run: public-inbox-index --reindex $inbox_dir\n";
