#!/usr/bin/env perl
#
# write-status.pl — write the ops health document (status.json, repo root)
# described in SPEC-index.md. Called by scripts/publish-index.sh after the
# exporter + validator, on success AND on failure.
#
# Usage:
#   write-status.pl --status ok|error [--top-error <text>]
#                   [--index index] [--out status.json]
#                   [--metrics metrics/imports.tsv] [--started-at <epoch>]
#                   [--repo owner/name] [--system <name>] [--interval 14400]
#
# On --status error the previous last_success_at and counts are carried
# forward: a consumer can then see both "the last run broke" and "how old
# the data I'm looking at is". Core Perl only.

use strict;
use warnings;
use Getopt::Long qw(GetOptions);
use JSON::PP ();
use POSIX qw(strftime);
use Time::Local qw(timegm);

my %o = (index => 'index', out => 'status.json', metrics => 'metrics/imports.tsv',
         interval => 14400, system => 'oss-security-archive',
         repo => $ENV{GITHUB_REPOSITORY} || 'joemalcolm/oss-security-archive');
GetOptions(\%o, 'status=s', 'top-error=s', 'index=s', 'out=s', 'metrics=s',
           'started-at=i', 'repo=s', 'system=s', 'interval=i')
    && ($o{status} // '') =~ /\A(?:ok|error)\z/
    or die "usage: $0 --status ok|error [--top-error <text>] [--index dir] "
         . "[--out file] [--metrics tsv] [--started-at epoch]\n";

my $json = JSON::PP->new->utf8->allow_nonref;
sub load { my ($f) = @_; open(my $fh, '<:raw', $f) or return;
           local $/; eval { $json->decode(scalar <$fh>) } }
sub iso    { strftime('%Y-%m-%dT%H:%M:%SZ', gmtime $_[0]) }
sub uniso  { $_[0] =~ /\A(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)Z\z/
             ? timegm($6, $5, $4, $3, $2 - 1, $1) : undef }

my $now  = time;
my $ok   = $o{status} eq 'ok';
my $prev = load($o{out}) // {};
my $man  = load("$o{index}/manifest.json");

# This run's ingest counters: the last import-maildir line in the metrics
# log, provided it was written during this run. Format (import-maildir.sh):
#   ts \t import-maildir \t total \t imported \t failed \t top_count \t top_msg
my ($imported, $failed, $top) = (0, 0, undef);
if (open(my $fh, '<', $o{metrics})) {
    my @last;
    while (<$fh>) { chomp; my @f = split /\t/; @last = @f if ($f[1] // '') eq 'import-maildir' }
    my $ts = @last ? uniso($last[0]) : undef;
    if (defined $ts && (!defined $o{'started-at'} || $ts >= $o{'started-at'})) {
        ($imported, $failed) = ($last[3] + 0, $last[4] + 0);
        $top = $last[6] if $failed && defined $last[6] && $last[6] ne 'none';
    }
}

# Newest message date = last row of the newest messages shard (rows are
# date-sorted). Only meaningful when the index on disk is valid.
my $lag;
if ($ok && $man) {
    my ($y) = sort { $b cmp $a } keys %{ $man->{messages} // {} };
    if (defined $y && open(my $fh, '<:raw', "$o{index}/messages/$y.jsonl")) {
        my $lastline; $lastline = $_ while <$fh>;
        my $row = eval { $json->decode($lastline // 'null') };
        my $t = $row ? uniso($row->{date} // '') : undef;
        $lag = $now - $t if defined $t;
    }
}

my @problems;
push @problems, $o{'top-error'} // 'index export failed' unless $ok;
push @problems, "$failed message(s) failed ingest this run" if $failed;

my $generated = $ok && $man ? $man->{generated_at} : iso($now);
my $counts = $ok && $man
    ? [ messages => $man->{total_messages} + 0, stored => $man->{total_stored} + 0,
        duplicates => $man->{total_stored} - $man->{total_messages} ]
    : [ map { $_ => $prev->{counts}{$_} } qw(messages stored duplicates) ];

# Ordered key/value lists (not hashes) so the file reads in spec order.
my $doc = [
    schema          => 1,
    system          => $o{system},
    generated_at    => $generated,
    last_success_at => $ok ? $generated : $prev->{last_success_at},
    last_run        => [ status => $o{status},
                         duration_s => defined $o{'started-at'} ? $now - $o{'started-at'} : undef,
                         imported => $imported, failed => $failed,
                         top_error => $ok ? $top : ($o{'top-error'} // 'index export failed') ],
    freshness       => [ expected_interval_s => $o{interval} + 0, source_lag_s => $lag ],
    counts          => $counts,
    problems        => \@problems,
    links           => [ logs  => "https://github.com/$o{repo}/actions",
                         index => "https://raw.githubusercontent.com/$o{repo}/main/index/manifest.json" ],
];

sub emit {                      # $doc-style pair list -> pretty JSON object
    my ($pairs, $ind) = @_;
    my @out;
    for (my $i = 0; $i < @$pairs; $i += 2) {
        my ($k, $v) = @$pairs[$i, $i + 1];
        my $val = ref $v eq 'ARRAY' && $k ne 'problems' ? emit($v, "$ind  ")
                : $json->encode($v);
        push @out, "$ind  " . $json->encode("$k") . ": $val";
    }
    "{\n" . join(",\n", @out) . "\n$ind}";
}

open(my $fh, '>:raw', "$o{out}.tmp") or die "$o{out}.tmp: $!";
print $fh emit($doc, ''), "\n";
close $fh or die "close: $!";
rename("$o{out}.tmp", $o{out}) or die "rename: $!";
print "status.json: $o{status}", (@problems ? " (" . join('; ', @problems) . ")" : ''), "\n";
