#!/usr/bin/env perl
#
# verify-index.pl — validate an index/ tree written by export-index.pl
# (DEC-ARCHIVE-007, SPEC-index.md). Run in CI after every export; also
# usable by a consumer against a downloaded copy.
#
# Usage:
#   verify-index.pl <index-dir> [--inbox <dir>] [--max-errors N]
#
# --inbox defaults to the inbox/ beside the index tree (<index-dir>/../../inbox
# for index/<source>/, else <index-dir>/../inbox). When an inbox is available,
# total_stored is re-counted independently from git at the exact commits
# recorded in manifest.built_from (so it stays checkable after the inbox
# has moved on). Without one, that single check is skipped with a notice.
#
# Deliberately shares no code with the exporter, and needs nothing from
# public-inbox: core Perl plus any JSON decoder (Cpanel::JSON::XS or
# JSON::XS if present — much faster on bodies — else core JSON::PP).
#
# Exit codes: 0 valid, 1 invalid, 2 usage error.

use strict;
use warnings;
use Getopt::Long qw(GetOptions);
use Digest::SHA qw(sha256_hex);
use Encode ();
use Time::Local qw(timegm);

my %opt = ('max-errors' => 25);
GetOptions(\%opt, 'inbox=s', 'max-errors=i', 'help|h') && @ARGV == 1 && !$opt{help}
    or do { print STDERR "usage: $0 <index-dir> [--inbox <dir>] [--max-errors N]\n";
            exit($opt{help} ? 0 : 2) };
my $DIR = $ARGV[0];
# index/<source>/ sits two levels below the repo root; a bare index/ one.
my $INBOX = $opt{inbox} // (-d "$DIR/../../inbox" ? "$DIR/../../inbox" : "$DIR/../inbox");

my $JSON = do {
    my $j;
    for my $mod (qw(Cpanel::JSON::XS JSON::XS JSON::PP)) {
        (my $f = "$mod.pm") =~ s{::}{/}g;
        if (eval { require $f; 1 }) { $j = $mod->new->utf8; last }
    }
    $j or die "no JSON module available\n";
};

my $errors = 0;
sub bad {
    $errors++;
    print STDERR "FAIL: @_\n" if $errors <= $opt{'max-errors'};
}

sub slurp {
    my ($f) = @_;
    open(my $fh, '<:raw', $f) or do { bad("$f: $!"); return };
    local $/;
    scalar <$fh>;
}

sub parse_ts {
    $_[0] =~ /\A(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)Z\z/ or return;
    my $t = eval { timegm($6, $5, $4, $3, $2 - 1, $1) };
    defined $t ? ($t, $1) : ();
}

# ---------------------------------------------------------------- manifest
my $man = eval { $JSON->decode(slurp("$DIR/manifest.json") // '') }
    or do { print STDERR "FAIL: manifest.json does not parse: $@"; exit 1 };
bad("manifest.schema is not 1") unless ($man->{schema} // 0) == 1;
parse_ts($man->{generated_at} // '') or bad("manifest.generated_at is not ISO 8601 UTC");

# Every shard on disk must be in the manifest, and vice versa.
for my $kind (qw(messages cves ghsas bodies)) {
    my $ext = $kind =~ /\A(?:cves|ghsas)\z/ ? 'json' : 'jsonl';
    my %disk = map { m{/([^/]+)\.\Q$ext\E\z} ? ($1 => 1) : () } glob("$DIR/$kind/*");
    my %want = map { $_ => 1 } keys %{ $man->{$kind} // {} };
    bad("$kind/$_.$ext on disk but not in manifest") for grep { !$want{$_} } sort keys %disk;
    bad("$kind/$_.$ext in manifest but not on disk") for grep { !$disk{$_} } sort keys %want;
}

# ---------------------------------------------------------------- messages + bodies
my (%seen, %date_src, %ghsa_rows, $total_bytes, $rows, $dup_copies, $conflicts);
$total_bytes = -s "$DIR/manifest.json";

for my $y (sort keys %{ $man->{messages} // {} }) {
    my $mf = "$DIR/messages/$y.jsonl";
    my $bf = "$DIR/bodies/$y.jsonl";
    my $mraw = slurp($mf) // next;
    my $braw = slurp($bf) // next;
    $total_bytes += length($mraw) + length($braw);

    my $mm = $man->{messages}{$y};
    my $bm = $man->{bodies}{$y} // {};
    bad("messages/$y.jsonl sha256 disagrees with manifest")
        unless sha256_hex($mraw) eq ($mm->{sha256} // '');
    bad("bodies/$y.jsonl sha256 disagrees with manifest")
        unless sha256_hex($braw) eq ($bm->{sha256} // '');
    bad("bodies/$y.jsonl bytes disagrees with manifest")
        unless length($braw) == ($bm->{bytes} // -1);

    my @ml = split(/\n/, $mraw, -1); pop @ml if @ml && $ml[-1] eq '';
    my @bl = split(/\n/, $braw, -1); pop @bl if @bl && $bl[-1] eq '';
    bad("messages/$y.jsonl has ${\ scalar @ml} rows, manifest says $mm->{count}")
        unless @ml == ($mm->{count} // -1);
    bad("bodies/$y.jsonl has ${\ scalar @bl} rows, manifest says " . ($bm->{count} // '?'))
        unless @bl == ($bm->{count} // -1);
    bad("messages/$y.jsonl and bodies/$y.jsonl differ in length (${\ scalar @ml} vs ${\ scalar @bl})")
        unless @ml == @bl;

    my ($prev_ts, $prev_mid) = (-1, '');
    for my $i (0 .. $#ml) {
        my $where = "messages/$y.jsonl:" . ($i + 1);
        my $m = eval { $JSON->decode($ml[$i]) }
            or do { bad("$where does not parse"); next };
        my $mid = $m->{message_id};
        defined $mid && length $mid or do { bad("$where has no message_id"); next };
        bad("$where duplicate message_id <$mid> (also $seen{$mid})") if $seen{$mid};
        $seen{$mid} //= $where;

        my ($ts, $year) = parse_ts($m->{date} // '');
        if (!defined $ts) { bad("$where date '" . ($m->{date} // '') . "' is not ISO 8601 UTC") }
        else {
            bad("$where date $m->{date} is in the wrong shard") if $year ne $y;
            bad("$where out of (date, message_id) order")
                if $i && ($ts < $prev_ts || ($ts == $prev_ts && ($mid cmp $prev_mid) <= 0));
            ($prev_ts, $prev_mid) = ($ts, $mid);
        }
        ref $m->{duplicates} eq 'ARRAY' && ref $m->{cve_ids} eq 'ARRAY' && ref $m->{ghsa_ids} eq 'ARRAY'
            or bad("$where duplicates/cve_ids/ghsa_ids must be arrays");
        if (ref $m->{ghsa_ids} eq 'ARRAY') { $ghsa_rows{$_}{$mid} = 1 for @{ $m->{ghsa_ids} } }
        defined $m->{thread_root} or bad("$where has no thread_root");
        $rows++;
        $dup_copies += @{ $m->{duplicates} // [] };
        $conflicts++ if $m->{body_conflict};
        ($m->{date_source} // '') =~ /\A(?:date|received|source_url|commit)\z/
            ? $date_src{ $m->{date_source} }++
            : bad("$where date_source '" . ($m->{date_source} // '') . "' is not one of date|received|source_url|commit");

        # the body row at the same position must be the same message,
        # and must hash to body_sha
        next if $i > $#bl;
        my $b = eval { $JSON->decode($bl[$i]) }
            or do { bad("bodies/$y.jsonl:" . ($i + 1) . " does not parse"); next };
        if (($b->{message_id} // '') ne $mid) {
            bad("bodies/$y.jsonl:" . ($i + 1) . " is <" . ($b->{message_id} // '')
                . "> but messages row is <$mid> (missing row or out of order)");
            next;
        }
        my $sha = substr(sha256_hex(Encode::encode('UTF-8', $b->{body} // '')), 0, 12);
        bad("$where body_sha $m->{body_sha} != sha256(body) $sha")
            unless $sha eq ($m->{body_sha} // '');
    }
}
for my $y (sort keys %{ $man->{bodies} // {} }) {
    bad("bodies/$y.jsonl has no messages/$y.jsonl") unless $man->{messages}{$y};
}

# ---------------------------------------------------------------- cves
my $cves = 0;
for my $y (sort keys %{ $man->{cves} // {} }) {
    my $raw = slurp("$DIR/cves/$y.json") // next;
    $total_bytes += length $raw;
    bad("cves/$y.json sha256 disagrees with manifest")
        unless sha256_hex($raw) eq ($man->{cves}{$y}{sha256} // '');
    my $c = eval { $JSON->decode($raw) };
    ref $c eq 'HASH' or do { bad("cves/$y.json does not parse as an object"); next };
    bad("cves/$y.json has ${\ scalar keys %$c} CVEs, manifest says $man->{cves}{$y}{count}")
        unless keys(%$c) == ($man->{cves}{$y}{count} // -1);
    $cves += keys %$c;
    for my $id (sort keys %$c) {
        bad("cves/$y.json: $id does not belong in this shard") unless $id =~ /\ACVE-\Q$y\E-\d{4,}\z/;
        my $prev = -1;
        for my $e (@{ $c->{$id} }) {
            bad("cves/$y.json: $id references unknown message_id <$e->{message_id}>")
                unless $seen{ $e->{message_id} // '' };
            my ($ts) = parse_ts($e->{date} // '');
            bad("cves/$y.json: $id entries are not in date order")
                if !defined $ts || $ts < $prev;
            $prev = $ts // $prev;
        }
    }
}

# ---------------------------------------------------------------- ghsas
# One unsharded file (GHSA IDs have no year). Checked both ways against the
# rows' ghsa_ids: every mention listed must be a row naming that ID, and
# every row naming an ID must be listed under it.
my $ghsas = 0;
bad("manifest.ghsas must be exactly {\"all\": ...}")
    unless join(',', sort keys %{ $man->{ghsas} // {} }) eq 'all';
if (my $gm = $man->{ghsas}{all}) {
    my $raw = slurp("$DIR/ghsas/all.json");
    if (defined $raw) {
        $total_bytes += length $raw;
        bad("ghsas/all.json sha256 disagrees with manifest")
            unless sha256_hex($raw) eq ($gm->{sha256} // '');
        my $g = eval { $JSON->decode($raw) };
        if (ref $g eq 'HASH') {
            $ghsas = keys %$g;
            bad("ghsas/all.json has $ghsas IDs, manifest says " . ($gm->{count} // '?'))
                unless $ghsas == ($gm->{count} // -1);
            for my $id (sort keys %$g) {
                bad("ghsas/all.json: '$id' is not a canonical GHSA ID")
                    unless $id =~ /\AGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\z/;
                my ($prev, %listed) = (-1);
                for my $e (@{ $g->{$id} }) {
                    my $mid = $e->{message_id} // '';
                    $listed{$mid} = 1;
                    bad("ghsas/all.json: $id lists <$mid>, which has no such ghsa_id")
                        unless $ghsa_rows{$id}{$mid};
                    my ($ts) = parse_ts($e->{date} // '');
                    bad("ghsas/all.json: $id entries are not in date order")
                        if !defined $ts || $ts < $prev;
                    $prev = $ts // $prev;
                }
                bad("ghsas/all.json: $id is missing <$_>")
                    for grep { !$listed{$_} } sort keys %{ $ghsa_rows{$id} // {} };
            }
            bad("ghsas/all.json is missing $_ (named in ghsa_ids)")
                for grep { !exists $g->{$_} } sort keys %ghsa_rows;
        } else { bad("ghsas/all.json does not parse as an object") }
    }
}

# ---------------------------------------------------------------- totals
bad("manifest.total_messages=$man->{total_messages} but $rows rows emitted")
    unless ($man->{total_messages} // -1) == ($rows // 0);
bad("manifest.total_cves=$man->{total_cves} but $cves CVE keys found")
    unless ($man->{total_cves} // -1) == $cves;
bad("manifest.total_ghsas=" . ($man->{total_ghsas} // 'missing') . " but $ghsas GHSA keys found")
    unless ($man->{total_ghsas} // -1) == $ghsas;
bad("rows + duplicate copies = " . ($rows + $dup_copies) . " but manifest.total_stored=$man->{total_stored}")
    unless ($rows // 0) + ($dup_copies // 0) == ($man->{total_stored} // -1);

# Independent recount of stored messages, straight from git, at the commits
# the index claims to be built from: a stored message is a commit that
# writes path `m`; a removal writes path `d` (none exist today). Counted
# from --raw output rather than rev-list so a commit that touches neither
# (never produced by public-inbox, but possible by hand) is not miscounted.
if (-d "$INBOX/git") {
    my $stored = 0;
    for my $ep (sort { $a <=> $b } keys %{ $man->{built_from} // {} }) {
        my $gd = "$INBOX/git/$ep.git";
        my $at = $man->{built_from}{$ep};
        $at =~ /\A[0-9a-f]{40,64}\z/ or do { bad("built_from.$ep is not a commit id"); next };
        open(my $fh, '-|', 'git', "--git-dir=$gd", qw(log --first-parent --root --raw
             --no-abbrev --no-renames -m --format=), $at)
            or do { bad("cannot run git log in $gd"); next };
        my ($m, $d) = (0, 0);
        while (<$fh>) {
            $m++ if /\A:\d+ \d+ [0-9a-f]+ [0-9a-f]+ [AM]\tm$/;
            $d++ if /\A:\d+ \d+ [0-9a-f]+ [0-9a-f]+ [AM]\td$/;
        }
        close $fh or do { bad("cannot count commits at $at in $gd"); next };
        $stored += $m - $d;
    }
    bad("manifest.total_stored=$man->{total_stored} but git has $stored stored messages at built_from")
        unless $stored == ($man->{total_stored} // -1);
} else {
    print STDERR "note: no inbox at $INBOX — skipping the independent total_stored recount\n";
}

printf "%s: stored=%d unique=%d duplicates=%d body_conflicts=%d date_fallbacks=%d (%s) cves=%d ghsas=%d bytes=%d\n",
    $errors ? 'INVALID' : 'ok', $man->{total_stored} // 0, $rows // 0,
    ($man->{total_stored} // 0) - ($rows // 0), $conflicts // 0,
    ($rows // 0) - ($date_src{date} // 0),
    join(',', map { "$_=$date_src{$_}" } grep { $_ ne 'date' } sort keys %date_src) || 'none',
    $cves, $ghsas, $total_bytes // 0;
if ($errors) {
    print STDERR "... and ", $errors - $opt{'max-errors'}, " more\n" if $errors > $opt{'max-errors'};
    print STDERR "verify-index: $errors problem(s)\n";
    exit 1;
}
exit 0;
