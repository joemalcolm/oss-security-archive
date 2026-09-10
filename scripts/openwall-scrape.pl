#!/usr/bin/env perl
#
# openwall-scrape.pl — scrape openwall.com/lists/oss-security HTML pages
# and write each message as RFC822 to a Maildir for ingest via
# import-maildir.sh.
#
# @decision DEC-ARCHIVE-004
# @title Openwall HTML scrape is the canonical backfill path
# @status accepted (provisional, pending list-owner reply on obfuscation)
# @rationale Openwall does not serve mbox at any granularity (DEC-ARCHIVE-001
#   established that). The Maildir path (DEC-ARCHIVE-002) only covers from
#   2015-03-16 onward and ~99% within range. For the pre-2015 gap and the
#   ~1% within-range gap we have no full-fidelity source, so we scrape
#   openwall.com's HTML, which preserves Message-ID (rot13-obfuscated; we
#   reverse this) and the message body, but loses From/To addresses to
#   openwall's display-time elision. We tag every scraped message with
#   `X-Archive-Source: openwall-scrape` so consumers can distinguish
#   full-fidelity from backfill, and so a future un-obfuscation pass (if
#   the list owner permits) can identify what to re-ingest.
#
# Obfuscation schemes observed (verified 2026-05-28 against
# /lists/oss-security/2014/05/13/3):
#   - From / To / Cc: elision — `user@...domain.tld`. Lossy; preserved.
#   - Message-ID host: ROT13 — `host@wniryva.cad.erqung.pbz` is
#     `host@javelin.pnq.redhat.com` rot13'd. Reversible; we reverse it
#     so Message-IDs match the unobfuscated versions in Maildir imports
#     (public-inbox dedups on Message-ID).
#
# Known v1 limitation: openwall's rendered message HTML does NOT include
# In-Reply-To / References, only Message-ID/Date/From/To/Subject. The
# page nav has `[thread-prev]`/`[thread-next]` links from which threading
# can be reconstructed, but that's a follow-up. v1 scraped messages will
# appear unthreaded in public-inbox.
#
# Usage:
#   openwall-scrape.pl --start YYYY-MM-DD --end YYYY-MM-DD
#                      --maildir DIR [--reverse] [--delay SECONDS]
#                      [--save-failed DIR]
#
#   --start, --end : inclusive date range (UTC).
#   --maildir      : target Maildir; cur/, new/, tmp/ are created.
#   --reverse      : iterate dates newest→oldest (default oldest→newest).
#                    Within a day we always iterate messages 1..N in
#                    order so any future in-day threading reconstruction
#                    sees parents before children.
#   --delay        : seconds between requests (default 1.5). Be polite.
#   --save-failed  : directory to store raw HTML of pages that fetched
#                    200 but couldn't be parsed into a valid RFC822.
#                    Cheap disk cost; lets a future scraper improvement
#                    reprocess without re-fetching from openwall. Files
#                    are named `<YYYY>-<MM>-<DD>-<N>.html`.
#
# Resumability: writes $maildir/.scrape-state with the last-completed
# date. On re-run, dates already done (relative to the iteration order)
# are skipped. Delete the file to force a full re-scrape. Idempotent
# regardless thanks to Message-ID dedup at ingest time.
#
# Diagnostics: warnings for structural failures are emitted on stderr as
#   SCRAPE_WARN\t<category>\t<detail>
# where <category> is one of: fetch-fail, no-pre-block, no-message-id,
# no-headers, synthesized-date, save-failed. The backfill-openwall.sh
# wrapper aggregates these into a top-10 tally at end-of-run, mirroring
# import-maildir.sh's error-summary pattern. Info-level lines (per-day
# message counts, "done: N msgs across M days") remain unstructured.

use strict;
use warnings;
use Getopt::Long;
use LWP::UserAgent;
use HTML::Entities qw(decode_entities);
use Encode qw(encode);
use File::Path qw(make_path);
use Time::HiRes qw(sleep);
use POSIX qw(strftime mktime);
use Time::Local qw(timegm);

my $BASE_URL  = 'https://www.openwall.com/lists/oss-security';
my $UA_STRING = 'oss-security-archive-bot/1.0 '
              . '(+https://github.com/joemalcolm/oss-security-archive)';

# TLD table for maybe_reverse_rot13_host() (defined later, near
# rot13_msgid_hosts). MUST be initialized before the main loop starts —
# `my %H = ...` at file scope initializes only when execution reaches
# that statement, and if this were declared next to the sub that uses
# it (near the end of the file), the main loop would run first with an
# empty hash and every is_real_tld() call would return false, silently
# defeating the "reverse rot13'd hosts" branch. See comment near
# maybe_reverse_rot13_host() for what this contains and why.
my %REAL_TLDS = map { $_ => 1 } qw(
    com org net edu gov mil int arpa
    info biz name pro
    io me co dev app blog shop site cloud tech online store xyz sh ai
    aero coop museum jobs travel post asia cat mobi tel xxx
    us uk de fr jp cn au ca ru cz nl be pl kr in br mx ar cl es it ch
    se no fi dk gr pt ie il tr za ke ng tw hk sg my th vn id ph nz
    at hu ro bg hr rs si sk mk mt cy is li lu al ba md lt lv ee ua by
    tv cc eu bh om qa sa ae eg jo lb ma dz tn iq sy ye af pk ir
    to fm gg im je ky vg mo tc
);

# ---- argv -------------------------------------------------------------------
my ($start, $end, $maildir, $reverse, $help, $save_failed);
my $delay = 1.5;
GetOptions(
    'start=s'       => \$start,
    'end=s'         => \$end,
    'maildir=s'     => \$maildir,
    'reverse'       => \$reverse,
    'delay=f'       => \$delay,
    'save-failed=s' => \$save_failed,
    'help|h'        => \$help,
) or usage_exit(2);
usage_exit(0) if $help;
usage_exit(2) unless $start && $end && $maildir;

sub usage_exit {
    my $ec = shift;
    my $fh = $ec ? *STDERR : *STDOUT;
    print $fh <<USAGE;
usage: $0 --start YYYY-MM-DD --end YYYY-MM-DD --maildir DIR
                            [--reverse] [--delay SECONDS]
                            [--save-failed DIR]

Scrapes $BASE_URL within the date range and writes each message as
RFC822 into DIR/new/ for ingest via import-maildir.sh.
Structural failures emit `SCRAPE_WARN\\tcategory\\tdetail` on stderr.
USAGE
    exit $ec;
}

# Emit a structured warning that the wrapper can grep+aggregate.
sub scrape_warn {
    my ($category, $detail) = @_;
    $detail = '' unless defined $detail;
    # Squash tabs/newlines in detail so the tab-separated layout stays clean.
    $detail =~ s/[\t\r\n]+/ /g;
    print STDERR "SCRAPE_WARN\t$category\t$detail\n";
}

valid_date($start) or die "bad --start: $start (want YYYY-MM-DD)\n";
valid_date($end)   or die "bad --end: $end (want YYYY-MM-DD)\n";
$start le $end     or die "--start ($start) must be <= --end ($end)\n";

# ---- setup ------------------------------------------------------------------
for my $sub (qw(cur new tmp)) {
    my $d = "$maildir/$sub";
    make_path($d) unless -d $d;
}
if (defined $save_failed) {
    make_path($save_failed) unless -d $save_failed;
}
my $state_file = "$maildir/.scrape-state";
my $resume_after = read_state($state_file);

my $ua = LWP::UserAgent->new(
    agent   => $UA_STRING,
    timeout => 30,
);

# ---- main -------------------------------------------------------------------
my @dates = list_dates($start, $end, $reverse);
if ($resume_after) {
    # Skip dates "already done" in the current iteration order: any date
    # at or before $resume_after (in iteration sense, which depends on
    # $reverse). For forward order, "before" = <=; for reverse, "before"
    # = >=. We compare strings since YYYY-MM-DD sorts lexicographically.
    my $before = $reverse ? sub { $_[0] ge $resume_after }
                          : sub { $_[0] le $resume_after };
    my $kept = 0;
    @dates = grep { !$before->($_) || ++$kept && 0 } @dates;
    warn "resuming after $resume_after; "
       . scalar(@dates) . " date(s) remaining\n";
}

my $messages_written = 0;
my $days_with_data   = 0;
my $days_404         = 0;
my $msg_counter      = 0;
my $base_epoch       = time();

for my $date (@dates) {
    my $n = process_day($date);
    if (defined $n) {
        $days_with_data++ if $n > 0;
        $messages_written += $n;
    } else {
        $days_404++;
    }
    save_state($state_file, $date);
}

warn sprintf(
    "done: %d message(s) across %d day(s) with data (%d day(s) 404)\n",
    $messages_written, $days_with_data, $days_404,
);

# ---- date helpers -----------------------------------------------------------
sub valid_date {
    my ($s) = @_;
    return $s =~ /\A(\d{4})-(\d{2})-(\d{2})\z/
        && $2 >= 1 && $2 <= 12
        && $3 >= 1 && $3 <= 31;
}

# inclusive, returns list of YYYY-MM-DD strings
sub list_dates {
    my ($a, $b, $rev) = @_;
    my @out;
    my ($y, $m, $d) = $a =~ /^(\d{4})-(\d{2})-(\d{2})$/;
    my ($Y, $M, $D) = $b =~ /^(\d{4})-(\d{2})-(\d{2})$/;
    my $t  = timegm(0,0,12, $d, $m-1, $y);
    my $tE = timegm(0,0,12, $D, $M-1, $Y);
    while ($t <= $tE) {
        push @out, strftime("%Y-%m-%d", gmtime($t));
        $t += 86400;
    }
    return $rev ? reverse @out : @out;
}

# ---- HTTP -------------------------------------------------------------------
# Returns ($status_code, $body). On hard failure, returns (0, $err).
sub fetch_with_retry {
    my ($url) = @_;
    my $attempts = 0;
    my $backoff  = 2;
    my $last_code;
    while ($attempts < 4) {
        $attempts++;
        sleep($delay);
        my $resp = $ua->get($url);
        my $code = $resp->code;
        $last_code = $code;
        if ($code == 200) {
            # Empty-body 200 is a silent failure mode worth flagging;
            # openwall occasionally serves these under load.
            my $body = $resp->decoded_content;
            if (!defined $body || $body eq '') {
                scrape_warn('empty-200-body', $url);
                return (200, '');   # let the caller decide (parse_index → 0 msgs, scrape_one → parse-fail)
            }
            return (200, $body);
        }
        if ($code == 404) {
            return (404, '');
        }
        # 5xx or transport error: backoff
        warn "  fetch $url -> HTTP $code (attempt $attempts)\n";
        sleep($backoff);
        $backoff *= 2;
    }
    scrape_warn('fetch-fail', "$url http=$last_code attempts=$attempts");
    return (0, "gave up after $attempts attempts");
}

# ---- day index --------------------------------------------------------------
# Returns: undef if day 404 (no posts), or count of messages written.
sub process_day {
    my ($date) = @_;
    my ($y, $m, $d) = $date =~ /^(\d{4})-(\d{2})-(\d{2})$/;
    my $url = "$BASE_URL/$y/$m/$d/";
    my ($code, $body) = fetch_with_retry($url);
    if ($code == 404) {
        return undef;
    }
    if ($code != 200) {
        warn "skip $date: $body\n";
        return 0;
    }
    my @nums = parse_index($body);
    if (!@nums) {
        warn "  $date: 0 messages\n";
        return 0;
    }
    warn "  $date: ${\scalar @nums} message(s)\n";
    my $n = 0;
    for my $num (@nums) {
        if (scrape_one("$y/$m/$d", $num)) {
            $n++;
        }
    }
    return $n;
}

# Extract numbered message links from a day index page.
# The relevant <li> entries look like:
#   <li><a href="3">Subject…</a> (Author …)
# We match strictly: anchor href is a positive integer.
sub parse_index {
    my ($html) = @_;
    my @nums;
    while ($html =~ m{<li>\s*<a\s+href="(\d+)"}gi) {
        push @nums, $1;
    }
    # Sort numerically and dedupe, in case the page repeats.
    my %seen;
    return sort { $a <=> $b } grep { !$seen{$_}++ } @nums;
}

# ---- message scrape ---------------------------------------------------------
# $ymd = "YYYY/MM/DD", $num = integer. Returns 1 on success, 0 on skip.
sub scrape_one {
    my ($ymd, $num) = @_;
    my $url = "$BASE_URL/$ymd/$num";
    my ($code, $body) = fetch_with_retry($url);
    if ($code != 200) {
        # 404 on a message we saw in the index is unusual; log it.
        if ($code == 404) {
            scrape_warn('msg-404', "$ymd/$num");
        }
        return 0;
    }
    my $rfc822 = build_rfc822($body, $url);
    if (!defined $rfc822) {
        # build_rfc822 has already emitted a specific SCRAPE_WARN.
        # Optionally park the raw HTML so a later scraper improvement
        # can reprocess it without hitting openwall again.
        if (defined $save_failed) {
            (my $fn = "$ymd-$num.html") =~ s{/}{-}g;
            my $path = "$save_failed/$fn";
            if (open my $fh, '>', $path) {
                binmode $fh;
                print $fh $body;
                close $fh;
            } else {
                scrape_warn('save-failed', "$path: $!");
            }
        }
        return 0;
    }
    write_maildir($rfc822);
    return 1;
}

# Pull the <pre>…</pre> block, strip remaining HTML, decode entities,
# split header/body, rewrite Message-ID host (rot13), inject tracer
# headers. Returns the RFC822 string, or undef on parse failure.
sub build_rfc822 {
    my ($html, $source_url) = @_;

    # 1. Extract pre block. Openwall uses
    #    `<pre style="white-space: pre-wrap">…</pre>`
    #    Match permissively in case the style attribute varies.
    my ($pre) = $html =~ m{<pre\b[^>]*>(.*?)</pre>}is;
    if (!defined $pre) {
        scrape_warn('no-pre-block', $source_url);
        return undef;
    }

    # 2. Strip anchor tags but keep their text content
    #    (openwall renders URLs as <a href="X" rel="nofollow">X</a>).
    $pre =~ s{<a\b[^>]*>(.*?)</a>}{$1}gis;
    # 2b. Any other surviving tags (defensive — pre content shouldn't
    #     have them, but if blists ever wraps things in <span>/<b>
    #     etc. we don't want them landing in the archive).
    $pre =~ s{<[^>]+>}{}gs;

    # 3. Decode entities (&lt; &gt; &#64; &amp; etc.).
    $pre = decode_entities($pre);

    # 4. Trim a single leading newline that often follows the <pre> tag.
    $pre =~ s/\A\r?\n//;

    # 5. Split header section from body at the first blank line.
    my ($hdr_text, $body) = split /\r?\n\r?\n/, $pre, 2;
    if (!defined $hdr_text) {
        scrape_warn('no-header-body-split', $source_url);
        return undef;
    }
    $body = '' unless defined $body;

    # 6. Walk header lines (handling folded continuations) into pairs.
    my @hdrs = parse_headers($hdr_text);
    if (!@hdrs) {
        scrape_warn('no-headers', $source_url);
        return undef;
    }

    # 7. Sanity checks on the mandatory pieces.
    my %by_name = map { lc($_->[0]) => $_->[1] } @hdrs;
    if (!exists $by_name{'message-id'}) {
        # Without a Message-ID, public-inbox can't dedup. Rather than
        # let mda hash on content and pollute the archive with an
        # unrecoverable "fake" ID, drop the message and log. Rare.
        scrape_warn('no-message-id', $source_url);
        return undef;
    }

    # 7a. Rewrite the host portion of Message-ID (and any other rot13'd
    #     id-bearing headers we see) so they match the unobfuscated form.
    for my $h (@hdrs) {
        my $name = lc $h->[0];
        if ($name =~ /^(message-id|in-reply-to|references|resent-message-id)$/) {
            $h->[1] = rot13_msgid_hosts($h->[1]);
        }
    }

    # 7b. Defensive Date synthesis. If the page didn't include a Date
    #     header (some very old messages, some malformed originals),
    #     synthesize one from the URL's date at noon UTC — better than
    #     letting downstream mda die with "uninitialized value $date".
    #     Mark synthesized dates with a tracer header so we can find
    #     and reprocess them if the source ever coughs up the real one.
    my $date_synthesized = 0;
    if (!exists $by_name{'date'}) {
        my ($y, $m, $d) = $source_url =~ m{/(\d{4})/(\d{2})/(\d{2})/};
        if (defined $y) {
            my $ep = timegm(0, 0, 12, $d, $m - 1, $y);
            my $synth = strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime($ep));
            push @hdrs, ['Date', $synth];
            $date_synthesized = 1;
            scrape_warn('synthesized-date', $source_url);
        }
        # If we can't even parse a date out of the URL, let mda handle
        # the missing Date its own way — the message is still worth
        # ingesting for its body/subject.
    }

    # 8. Inject tracer headers identifying this as backfill.
    unshift @hdrs,
        ['X-Archive-Source',     'openwall-scrape'],
        ['X-Archive-Source-URL', $source_url];
    if ($date_synthesized) {
        push @hdrs, ['X-Archive-Synthesized-Date', 'from-url'];
    }

    # 9. Ensure a Content-Type so downstream tooling treats body as text.
    if (!grep { lc($_->[0]) eq 'content-type' } @hdrs) {
        push @hdrs, ['Content-Type', 'text/plain; charset=utf-8'];
    }

    # 10. Render. Body line endings: normalize to \n.
    $body =~ s/\r\n/\n/g;
    my $out = '';
    for my $h (@hdrs) {
        $out .= "$h->[0]: $h->[1]\n";
    }
    $out .= "\n$body";
    $out .= "\n" unless $out =~ /\n\z/;
    return $out;
}

# Returns list of [name, value]. Folded continuations (RFC 5322 §2.2.3,
# lines starting with whitespace) are joined with a single space.
sub parse_headers {
    my ($text) = @_;
    my @out;
    for my $line (split /\r?\n/, $text) {
        if ($line =~ /^[\t ]/ && @out) {
            $line =~ s/^\s+/ /;
            $out[-1][1] .= $line;
        }
        elsif ($line =~ /^([^:\s]+)\s*:\s*(.*)$/) {
            push @out, [$1, $2];
        }
        # else: skip junk lines silently
    }
    return @out;
}

# Within a header value, find substrings of the form `@host` and — IF the
# host was rot13-obfuscated by openwall's blists — reverse the rot13.
#
# CRITICAL: openwall does NOT rot13 every Message-ID host. Its blists
# obfuscator applies rot13 selectively — personal / small-org domains
# get rot13'd (`redhat.com` → `erqung.pbz`) but well-known public
# services stay in clear text (`googlegroups.com`, `github.com`,
# common list hosts). An earlier version of this function rot13'd
# every `@host` unconditionally, which SILENTLY corrupted the
# Message-ID of every message from a public host — dedup against
# Maildir data broke, threading broke, replies didn't link up.
# Verified 2026-09-11 on /2014/05/13/2: openwall serves
# `Message-Id: <…@googlegroups.com>` in clear; we were writing
# `@tbbtyrtebhcf.pbz`.
#
# Fix: detect whether the host is rot13'd by testing its top-level
# domain against a set of known real TLDs. Handy property of rot13:
# none of the common real TLDs round-trip to another real TLD
# (com↔pbz, org↔bet, net↔arg, io↔vb, uk↔hx, de↔qr, jp↔wc, …), so:
#   - current TLD is a real TLD → plaintext → leave alone
#   - rot13(current TLD) is a real TLD → obfuscated → reverse
#   - neither → unknown, conservative: leave alone
sub rot13 {
    my ($s) = @_;
    $s =~ tr/A-Za-z/N-ZA-Mn-za-m/;
    return $s;
}

# %REAL_TLDS is the curated list of real TLDs commonly seen in email
# Message-ID hosts, initialized at the TOP of the file so it's populated
# before the main loop runs. Not exhaustive — goal is to cover ~99% of
# oss-security list traffic without pulling in a Public Suffix List
# dependency. Unknown TLDs fall through to "leave alone" (safe default:
# preserving a possibly-still-rot13'd host is less bad than corrupting
# a plaintext one, because dedup ambiguity is fixable later while data
# corruption is not).
sub is_real_tld {
    my ($t) = @_;
    return defined $t && exists $REAL_TLDS{lc $t};
}

sub maybe_reverse_rot13_host {
    my ($host) = @_;
    my ($tld) = $host =~ /\.([A-Za-z0-9]+)$/;
    return $host unless defined $tld;
    return $host if is_real_tld($tld);   # already plaintext
    my $rev = rot13($host);
    my ($rev_tld) = $rev =~ /\.([A-Za-z0-9]+)$/;
    return $rev if is_real_tld($rev_tld); # rot13'd, reverse it
    return $host;                         # unknown, leave alone
}

sub rot13_msgid_hosts {
    my ($v) = @_;
    $v =~ s{(\@)([A-Za-z0-9.\-]+)}{$1 . maybe_reverse_rot13_host($2)}ge;
    return $v;
}

# ---- Maildir output ---------------------------------------------------------
sub write_maildir {
    my ($rfc822) = @_;
    $msg_counter++;
    my $fn = sprintf("%d.%06d_%d.openwall-scrape",
                     $base_epoch, $msg_counter, $$);
    my $path = "$maildir/new/$fn";
    open my $fh, '>', $path or die "open $path: $!\n";
    binmode $fh;
    # $rfc822 has Perl's internal character representation because
    # HTML::Entities::decode_entities() upgraded us out of raw bytes
    # (e.g. `&#8217;` → U+2019 RIGHT SINGLE QUOTATION MARK). Writing
    # that to a raw filehandle triggers `Wide character in print` and,
    # worse, the character-flag propagates through the pipeline into
    # PublicInbox::Import which then also warns (`Import.pm line 312`)
    # and may in edge cases break the git-fast-import stream. Explicit
    # UTF-8 encoding downgrades to bytes and keeps everything in
    # byte-land from here on. The synthesized Content-Type header on
    # scraped messages already declares `charset=utf-8`.
    print $fh encode('UTF-8', $rfc822);
    close $fh or die "close $path: $!\n";
}

# ---- state file -------------------------------------------------------------
sub read_state {
    my ($f) = @_;
    return undef unless -f $f;
    open my $fh, '<', $f or return undef;
    chomp(my $line = <$fh>);
    close $fh;
    return $line =~ /^\d{4}-\d{2}-\d{2}$/ ? $line : undef;
}

sub save_state {
    my ($f, $date) = @_;
    open my $fh, '>', $f or do { warn "state $f: $!\n"; return };
    print $fh "$date\n";
    close $fh;
}
