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
#   The boundary is the first `Received:` header (top-down) that is one of:
#     (a) a hop whose `by` clause names openwall — openwall's MTA wrote it;
#         boundary = that header (kept);
#     (b) a hop whose `from` clause names openwall — the subscriber's MX
#         wrote it when it received from openwall; boundary = the header
#         after it (it is stripped along with everything above);
#     (c) ezmlm's own delivery stamp, `Received: (qmail N invoked by uid
#         N); DATE`, which has neither clause — boundary = that header
#         (kept). Added 2026-09-19: on a mail path where the subscriber's
#         relay writes no `Received: from ...openwall` of its own, (c) is
#         the only openwall hop there is. Without it the sanitizer fell
#         through to the pass-through fallback and 1,641 Maildir messages
#         (2025–2026) were archived with the relay's Authentication-
#         Results, X-Rspamd-*/X-Spamd-* and X-Greylist headers intact.
#   Header blocks above the boundary whose name matches the
#   "subscriber-side" list are stripped; everything from the boundary
#   onward, plus any non-matching headers above it (e.g. `List-*`, `From`,
#   `Subject`, `Date`, `Message-ID`), is kept.
#
#   If no boundary is found, the message is passed through unchanged
#   (except for the "anywhere" set below). This is the conservative
#   fallback — better to over-include than to mis-strip a non-list message
#   that ended up in the Maildir.
#
# Stripped (above the boundary only):
#   Received, Received-SPF, Authentication-Results, ARC-*,
#   DKIM-Signature, DKIM-Filter, Delivered-To, X-Original-To,
#   Return-Path, X-Received, X-Greylist, X-Spam*, X-Virus*, X-ClamAV*,
#   X-Amavis*, X-Google*, X-Gm-*, X-MS-*, X-Microsoft-*, X-Forefront-*
#
# Stripped anywhere in the header block, boundary or not:
#   X-Rspamd-*, X-Spamd-*. An rspamd milter appends its verdict at the
#   END of the headers, below every Received, so position can't catch
#   it; and openwall never emits these, so nothing canonical is lost.
#
# Usage:
#   perl sanitize-headers.pl [--report] < in.eml > out.eml
#   ./sanitize-headers.pl   [--report] < in.eml > out.eml   # if +x is set
#
#   From Perl (scripts/resanitize-epoch.pl does this):
#     require './scripts/sanitize-headers.pl';
#     my ($out, $residual) = SanitizeHeaders::sanitize($raw, $report);
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

package SanitizeHeaders;

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
    x-greylist
);

sub hname {
    my ($block) = @_;
    return '' unless @$block;
    my ($n) = $block->[0] =~ /^([^:\s]+)\s*:/;
    return defined $n ? lc $n : '';
}

sub btext { return join '', @{ $_[0] } }

# Returns the substring of $text that lives in the "by ..." or "from ..."
# clause of a Received header. Each clause runs until the next standard
# sub-keyword (from/by/via/with/id/for/;) or end of header.
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
sub from_clause {
    my ($text) = @_;
    if ($text =~ m{
        \b from \s+ (.+?)
        (?= \s+ (?: by | via | with | id | for | ; ) \s | \z )
    }isx) {
        return $1;
    }
    return '';
}

# ezmlm/qmail delivery stamp: "Received: (qmail 1913 invoked by uid 550); ..."
sub is_qmail_stamp {
    my ($text) = @_;
    return $text =~ /\A[^:]*:\s*\(qmail\s+\d+\s+invoked\b/i;
}

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

sub is_strip_anywhere {
    my ($block) = @_;
    my $n = hname($block);
    return 1 if $n =~ /^x-rspamd-/;
    return 1 if $n =~ /^x-spamd-/;
    return 0;
}

# sanitize($raw_message, $report) -> ($sanitized_message, \@residual_names)
# Pure function of its input; never dies on odd input.
sub sanitize {
    my ($msg, $report) = @_;
    $msg = '' unless defined $msg;
    my @residual;

    # Split into physical lines, preserving terminators. /^/m splits on
    # the start of each line in multiline mode; each element keeps its
    # trailing \n (or \r\n).
    my @lines = split /^/m, $msg;

    # locate the header/body separator (first empty line)
    my $body_start = scalar @lines;
    for (my $i = 0; $i < @lines; $i++) {
        if ($lines[$i] =~ /^\r?\n\z/) {
            $body_start = $i;
            last;
        }
    }
    my @header_lines = $body_start > 0 ? @lines[0 .. $body_start - 1] : ();
    my @body_lines   = $body_start < @lines ? @lines[$body_start .. $#lines] : ();

    # group physical lines into logical header blocks. A header that spans
    # multiple physical lines is "folded" — continuation lines start with
    # whitespace (RFC 5322 §2.2.3).
    my @blocks;
    for my $line (@header_lines) {
        if ($line =~ /^[\t ]/ && @blocks) {
            push @{ $blocks[-1] }, $line;
        } else {
            push @blocks, [$line];
        }
    }

    # find the openwall boundary — cases (a), (b), (c) in the header
    # comment. First matching Received (top-down) wins.
    my $boundary;
    for (my $i = 0; $i < @blocks; $i++) {
        next unless hname($blocks[$i]) eq 'received';
        my $text = btext($blocks[$i]);
        if (by_clause($text) =~ /openwall/i) {
            $boundary = $i;
            last;
        }
        if (from_clause($text) =~ /openwall/i) {
            $boundary = $i + 1;
            last;
        }
        if (is_qmail_stamp($text)) {
            $boundary = $i;
            last;
        }
    }

    my @out;
    for (my $i = 0; $i < @blocks; $i++) {
        next if is_strip_anywhere($blocks[$i]);
        if (defined $boundary) {
            if ($i < $boundary && is_strip($blocks[$i])) {
                next;
            }
            if ($report && $i >= $boundary && is_strip($blocks[$i])) {
                # Don't report `Received` itself — the boundary contract is
                # that every Received from openwall's hop down is kept, so
                # flagging them as residual would drown out the useful
                # signal (a real 16k-message run would produce ~80k
                # Received-residual lines).
                my $n = hname($blocks[$i]);
                if ($n ne 'received') {
                    my ($orig) = $blocks[$i]->[0] =~ /^([^:\s]+)\s*:/;
                    push @residual, defined $orig ? $orig : '';
                }
            }
        }
        push @out, $blocks[$i];
    }

    return (join('', map { @$_ } @out) . join('', @body_lines), \@residual);
}

package main;

# ---- CLI --------------------------------------------------------------------
unless (caller) {
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
    my $msg = do { local $/; <STDIN> };
    my ($out, $residual) = SanitizeHeaders::sanitize($msg, $report);
    print STDERR "RESIDUAL\t$_\n" for @$residual;
    print $out;
}

1;
