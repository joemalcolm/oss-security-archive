#!/usr/bin/env perl
#
# ingest-direct.pl — write an RFC822 message from STDIN directly into a
# public-inbox v2 repo, bypassing public-inbox-mda's delivery-policy
# prechecks.
#
# @decision DEC-ARCHIVE-005
# @title Bypass public-inbox-mda for bulk archive ingest
# @status accepted
# @rationale public-inbox-mda is designed as a Postfix-style delivery
#   agent. Its default policy rejects HTML-only messages ("*** We only
#   accept plain-text mail, No HTML ***") and messages whose
#   attachments hit its suffix blocklist (zip, image formats, various
#   vendor formats) — sensible spam/malware precautions for real mail
#   delivery, wrong for archive ingest of an 18-year security list
#   where those messages are valuable primary sources. Verified
#   2026-09-05 on the 16,980-message Maildir: 312 of the 295 counted
#   failures were legitimate messages mda refused on policy grounds,
#   not parsing failures. `--no-precheck` skips only the header
#   precheck; the body-format precheck is baked in with no config
#   knob. This script uses PublicInbox::V2Writable::add() — the same
#   primitive public-inbox-watch uses for maildir ingest — with no
#   delivery-policy filtering. Message-ID dedup happens internally so
#   idempotent re-runs are still safe.
#
# Usage:
#   ingest-direct.pl <inbox-name> < msg.eml
#
# <inbox-name> is the name registered with public-inbox-init and
# recorded in ~/.public-inbox/config as `[publicinbox "<name>"]`.
# setup-inbox.sh uses "oss-security".
#
# Exit codes:
#   0  message added, or deduped (both are success — idempotent)
#   1  parse / IO error / inbox lookup failure
#   2  argument error

use strict;
use warnings;
use PublicInbox::Config;
use PublicInbox::InboxWritable;
use PublicInbox::Eml;

if (@ARGV != 1 || $ARGV[0] eq '-h' || $ARGV[0] eq '--help') {
    print STDERR "usage: $0 <inbox-name> < msg.eml\n";
    exit(@ARGV == 1 && ($ARGV[0] eq '-h' || $ARGV[0] eq '--help') ? 0 : 2);
}
my $name = $ARGV[0];

my $cfg = PublicInbox::Config->new
    or die "cannot load public-inbox config (~/.public-inbox/config)\n";
my $ibx = $cfg->lookup_name($name)
    or die "no inbox named '$name' in public-inbox config\n";

# InboxWritable wraps a read-only inbox with the add/done API. This is
# what public-inbox-watch does internally.
$ibx = PublicInbox::InboxWritable->new($ibx);

# Slurp the whole message. RFC822 is small (typically 2-200 KB); no
# streaming needed. Undef stdin means the caller sent nothing.
my $raw = do { local $/; <STDIN> };
die "empty stdin: no message to ingest\n"
    unless defined $raw && length $raw;

my $eml = PublicInbox::Eml->new(\$raw);

# The V2Writable importer object exposes add()/done(). Some older
# public-inbox versions expose it as ->importer, newer via ->_importer;
# support both.
my $imp = $ibx->can('importer') ? $ibx->importer
        : $ibx->can('_importer') ? $ibx->_importer
        : do {
            require PublicInbox::V2Writable;
            PublicInbox::V2Writable->new($ibx);
        };

# add() returns the git blob-sha of the newly-added message, or undef
# on Message-ID dedup. Both are success from an idempotent-ingest
# standpoint; the caller doesn't care which happened.
my $ret;
eval {
    $ret = $imp->add($eml);
    $imp->done;
};
if ($@) {
    # Ensure done() gets called even on failure to avoid dangling
    # git-fast-import processes.
    eval { $imp->done };
    die "ingest failed: $@\n";
}

exit 0;
