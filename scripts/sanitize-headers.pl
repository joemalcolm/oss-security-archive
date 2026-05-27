#!/usr/bin/env perl
#
# sanitize-headers.pl — strip subscriber-side headers from a Maildir message
# before public-inbox ingest.
#
# Reads an RFC822 message on STDIN, writes the sanitized message on STDOUT.
# Exit status is non-zero only on internal Perl errors; malformed or
# unexpected input is passed through unchanged.
#
# @decision DEC-ARCHIVE-003
# @title Strip subscriber-side headers during Maildir ingest
# @status accepted
# @rationale A subscriber's copy of a list message carries header blocks
#   added by their own infrastructure on top of the canonical message that
#   openwall sent out: the user's MX `Received` chain, locally-added
#   `Authentication-Results` / `ARC-*` / `DKIM-Signature`, the user's spam
#   filter's `X-Spam-*`, plus `Delivered-To` / `X-Original-To` /
#   `Return-Path` that reveal the subscriber's address. These are
#   personal-infrastructure artefacts that contribute nothing to the
#   archive and leak the subscriber's mail setup, so we drop them. The
#   canonical message (everything from openwall's first internal hop
#   downward, which is identical to what every other subscriber received)
#   is preserved verbatim.
#
# Boundary detection
#   The first `Received:` header whose `by` clause names openwall is taken
#   as the boundary — that is the first hop performed by openwall's
#   infrastructure. Header blocks above this boundary that match the
#   "subscriber-side" name list are stripped; everything from the boundary
#   onward, plus any non-matching headers above it (e.g. `List-*`, `From`,
#   `Subject`, `Date`, `Message-ID`), is kept.
#
#   If no openwall-`by` Received header is found, the message is passed
#   through unchanged. This is the conservative fallback — better to
#   over-include than to mis-strip a non-list message that ended up in
#   the Maildir.
#
# Stripped (above the boundary only):
#   Received, Received-SPF, Authentication-Results, ARC-*,
#   DKIM-Signature, DKIM-Filter, Delivered-To, X-Original-To,
#   Return-Path, X-Received, X-Spam*, X-Virus*, X-ClamAV*, X-Amavis*,
#   X-Google*, X-Gm-*, X-MS-*, X-Microsoft-*, X-Forefront-*
#
# Usage:
#   perl sanitize-headers.pl [--report] < in.eml > out.eml
#   ./sanitize-headers.pl   [--report] < in.eml > out.eml   # if +x is set
#
# --report (-r): in addition to the normal stripping, emit one
#   `RESIDUAL\t<header-name>` line on STDERR per header *below* the openwall
#   boundary whose name matches the strip set, EXCEPT `Received` itself
#   (which is expected below the boundary by design). Useful for auditing
#   whether subscriber-pattern headers (e.g. X-Google-*, DKIM-Signature
#   added by an intermediate hop) are leaking through and the policy
#   should be widened.

use strict;
use warnings;

# ---- argv -------------------------------------------------------------------
my $report = 0;
for my $arg (@ARGV) {
    if ($arg eq '--report' || $arg eq '-r') { $report = 1 }
    elsif ($arg eq '--help' || $arg eq '-h') {
        print STDERR "usage: $0 [--report] < in.eml > out.eml\n";
        exit 0;
    }
    else {
        print STDERR "$0: unknown argument: $arg\n";
        exit 2;
    }
}

# ---- slurp ------------------------------------------------------------------
my $msg = do { local $/; <STDIN> };
$msg = '' unless defined $msg;

# Split into physical lines, preserving terminators. /^/m splits on the start
# of each line in multiline mode; each element keeps its trailing \n (or \r\n).
my @lines = split /^/m, $msg;

# ---- locate the header/body separator (first empty line) --------------------
my $body_start = scalar @lines;
for (my $i = 0; $i < @lines; $i++) {
    if ($lines[$i] =~ /^\r?\n\z/) {
        $body_start = $i;
        last;
    }
}
my @header_lines = $body_start > 0 ? @lines[0 .. $body_start - 1] : ();
my @body_lines   = $body_start < @lines ? @lines[$body_start .. $#lines] : ();

# ---- group physical lines into logical header blocks ------------------------
# A header that spans multiple physical lines is "folded" — continuation
# lines start with whitespace (RFC 5322 §2.2.3).
my @blocks;
for my $line (@header_lines) {
    if ($line =~ /^[\t ]/ && @blocks) {
        push @{ $blocks[-1] }, $line;
    } else {
        push @blocks, [$line];
    }
}

sub hname {
    my ($block) = @_;
    return '' unless @$block;
    my ($n) = $block->[0] =~ /^([^:\s]+)\s*:/;
    return defined $n ? lc $n : '';
}

sub btext { return join '', @{ $_[0] } }

# ---- find the openwall boundary ---------------------------------------------
# Returns the substring of $text that lives in the "by ..." clause of a
# Received header. The clause runs until the next standard sub-keyword
# (from/via/with/id/for/;) or the end of the header.
sub by_clause {
    my ($text) = @_;
    if ($text =~ m{
        \b by \s+ (.+?)
        (?= \s+ (?: from | via | with | id | for | ; ) \s | \z )
    }isx) {
        return $1;
    }
    return '';
}

my $boundary;
for (my $i = 0; $i < @blocks; $i++) {
    next unless hname($blocks[$i]) eq 'received';
    if (by_clause(btext($blocks[$i])) =~ /openwall/i) {
        $boundary = $i;
        last;
    }
}

# Fallback: no openwall hop. Pass through verbatim.
if (!defined $boundary) {
    print $msg;
    exit 0;
}

# ---- strip subscriber-side headers above the boundary -----------------------
my %strip_exact = map { $_ => 1 } qw(
    received
    received-spf
    authentication-results
    delivered-to
    x-original-to
    return-path
    dkim-signature
    dkim-filter
    x-received
);

sub is_strip {
    my ($block) = @_;
    my $n = hname($block);
    return 1 if exists $strip_exact{$n};
    return 1 if $n =~ /^arc-/;
    return 1 if $n =~ /^x-spam/;
    return 1 if $n =~ /^x-virus/;
    return 1 if $n =~ /^x-clamav/;
    return 1 if $n =~ /^x-amavis/;
    return 1 if $n =~ /^x-google/;
    return 1 if $n =~ /^x-gm-/;
    return 1 if $n =~ /^x-ms-/;
    return 1 if $n =~ /^x-microsoft-/;
    return 1 if $n =~ /^x-forefront-/;
    return 0;
}

my @out;
for (my $i = 0; $i < @blocks; $i++) {
    if ($i < $boundary && is_strip($blocks[$i])) {
        next;
    }
    if ($report && $i >= $boundary && is_strip($blocks[$i])) {
        # Don't report `Received` itself — the boundary contract is that
        # every Received from openwall's hop down is kept, so flagging
        # them as residual would drown out the useful signal (a real
        # 16k-message run would produce ~80k Received-residual lines).
        my $n = hname($blocks[$i]);
        if ($n ne 'received') {
            my ($orig) = $blocks[$i]->[0] =~ /^([^:\s]+)\s*:/;
            $orig = '' unless defined $orig;
            print STDERR "RESIDUAL\t$orig\n";
        }
    }
    push @out, $blocks[$i];
}

for my $b (@out) { print @$b }
print @body_lines;
