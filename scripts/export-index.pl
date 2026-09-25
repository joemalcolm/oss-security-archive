#!/usr/bin/env perl
#
# export-index.pl — project a public-inbox v2 inbox into flat, consumer-
# friendly JSON under index/ (see SPEC-index.md).
#
# @decision DEC-ARCHIVE-007
# @title Publish a deduplicated JSON index alongside the inbox
# @status accepted
# @rationale Consumers (first: vulntools/cvetools) need a searchable
#   projection of the archive without installing public-inbox or walking
#   git history. Two things can only be done correctly here, where
#   public-inbox is already installed and every stored copy of a message
#   is visible at once: (1) MIME/charset decoding of bodies via
#   PublicInbox::Eml, and (2) resolving duplicate Message-IDs — the inbox
#   holds ~13.5k maildir+scrape / scrape+scrape pairs. This exporter
#   PAPERS OVER those duplicates: it emits one row per Message-ID and
#   lists the losing copies in `duplicates`. It never writes to the inbox
#   and never purges anything; purge remains a separate, later task.
#   Output is a pure projection: deterministic, regenerated every run,
#   never hand-edited, safe to delete and rebuild.
#
# Usage:
#   export-index.pl --inbox <dir> --out <dir> --source <name>
#                   [--url-scheme openwall|lore|none] [--jobs N]
#                   [--default-provenance maildir|upstream]
#
# Portable to any public-inbox v2 inbox: --source and --url-scheme are the
# only list-specific inputs. --default-provenance (what to call a message
# with no X-Archive-Source header) defaults to `maildir` for the openwall
# scheme and `upstream` otherwise.
#
# Output notes (details in CLAUDE.md § Published index):
#
#   date         `Date:` header, else the topmost openwall `Received:`
#                stamp (by-clause naming openwall, or ezmlm's qmail form;
#                topmost Received of any kind for other inboxes), else the day in X-Archive-Source-URL, else the
#                commit timestamp; `date_source` names which one won
#                (date | received | source_url | commit). A Date: more than
#                two days ahead of the independent evidence is discarded.
#
#   ghsa_ids     GitHub advisory IDs (DEC-ARCHIVE-011), `GHSA-` + lowercase,
#                from subject + body; also collected into ghsas/all.json
#                (unsharded: GHSA IDs carry no year). Faithful to the text:
#                no CVE aliasing, unresolvable repo/draft advisories kept.
#
#   body_conflict "these copies are really different messages", not "the
#                bytes differ" — a scraped copy never has equal bytes.
#                Copies are compared after normalising both bodies:
#                  1. every address is masked: `@` followed by anything up
#                     to whitespace or one of <>()[]"',; is reduced to `@`
#                     (openwall elides addresses inside bodies too:
#                     user@...ain.tld);
#                  2. mbox From-escaping is undone: a line starting `>From `
#                     (any number of `>`) becomes `From `;
#                  3. all whitespace runs collapse to one space, and
#                     leading/trailing whitespace is dropped (re-flowing,
#                     format=flowed, trailing blank lines);
#                  4. the shorter normalised body being a prefix of the
#                     longer one counts as equal (openwall renders later
#                     text parts — inline patches, list footers — into the
#                     same page; we export only the first text/plain part).
#                Anything that still differs is a real conflict: charset
#                damage in the scrape, or genuine Message-ID reuse.
#
# Read-only with respect to <inbox>: git is only asked to log/cat-file,
# and over.sqlite3 is opened read-only through PublicInbox::Over.
#
# Exit codes: 0 ok, 1 runtime failure, 2 usage error.

use strict;
use warnings;
use Getopt::Long qw(GetOptions);
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use Digest::SHA qw(sha256_hex);
use Encode ();
use Storable qw(nstore retrieve);
use POSIX qw(strftime);
use Time::Local qw(timegm);
use IPC::Open2 qw(open2);
use PublicInbox::Eml;
use PublicInbox::MID qw(mids references $MID_EXTRACT);
use PublicInbox::MsgIter qw(msg_part_text);
use PublicInbox::MsgTime ();

use constant {
    SCHEMA        => 1,
    BODY_MAX      => 256 * 1024,      # bytes of UTF-8 emitted per body
    DATE_SKEW_MAX => 2 * 86400,       # Date: may lead the list's own evidence by this much
};

my %opt = ('url-scheme' => 'none', jobs => 0);
GetOptions(\%opt, 'inbox=s', 'out=s', 'source=s', 'url-scheme=s', 'jobs=i',
           'default-provenance=s', 'help|h') or usage(2);
usage(0) if $opt{help};
for (qw(inbox out source)) { defined $opt{$_} or usage(2) }
$opt{'url-scheme'} =~ /\A(?:openwall|lore|none)\z/ or usage(2);
my $DEFAULT_PROV = $opt{'default-provenance'}
    // ($opt{'url-scheme'} eq 'openwall' ? 'maildir' : 'upstream');
$DEFAULT_PROV =~ /\A(?:maildir|upstream)\z/ or usage(2);
my ($INBOX, $OUT, $SOURCE, $SCHEME) = @opt{qw(inbox out source url-scheme)};
$SOURCE =~ m{\A[A-Za-z0-9][A-Za-z0-9._-]*\z}
    or die "--source must be a plain name (got '$SOURCE')\n";
-d "$INBOX/git" or die "$INBOX does not look like a public-inbox v2 inbox (no git/)\n";
my $JOBS = $opt{jobs} > 0 ? $opt{jobs} : ncpu();

sub usage {
    print STDERR "usage: $0 --inbox <dir> --out <dir> --source <name> ",
        "[--url-scheme openwall|lore|none] [--jobs N] ",
        "[--default-provenance maildir|upstream]\n";
    exit $_[0];
}

sub ncpu {
    my $n = `nproc 2>/dev/null` || `sysctl -n hw.ncpu 2>/dev/null` || 1;
    $n =~ /(\d+)/ ? $1 : 1;
}

my %RANK = (maildir => 0, upstream => 1);    # everything else (scrapes): 2
sub rank { $RANK{$_[0]} // 2 }

my $T0 = time;
sub note { printf STDERR "[%4ds] %s\n", time - $T0, join('', @_) }

# ---------------------------------------------------------------- step 1
# Enumerate stored messages. In v2 every commit on master modifies the
# single path `m` (a stored message) or writes `d` (a removal: the blob at
# `d` is the message being removed).

my @epochs = sort { $a <=> $b } map { m{/(\d+)\.git\z} ? $1 : () }
             glob("$INBOX/git/*.git");
@epochs or die "no epochs under $INBOX/git\n";

my (@stored, %built_from);
for my $ep (@epochs) {
    my $gd = "$INBOX/git/$ep.git";
    my $head = qx(git --git-dir="$gd" rev-parse --verify -q refs/heads/master);
    chomp $head;
    next unless $head;                        # empty epoch
    $built_from{$ep} = $head;
    open(my $fh, '-|', 'git', "--git-dir=$gd", qw(log --reverse --root --raw
         --no-abbrev --no-renames -m --first-parent --format=C%x20%H%x20%ct),
         $head) or die "git log: $!";
    my ($commit, $ct, %removed, @ep);
    while (<$fh>) {
        if (/\AC ([0-9a-f]+) (\d+)$/) { ($commit, $ct) = ($1, $2) }
        elsif (/\A:\d+ \d+ [0-9a-f]+ ([0-9a-f]+) ([AM])\t([md])$/) {
            if ($3 eq 'm') {
                push @ep, { epoch => $ep + 0, commit => $commit,
                            ct => $ct + 0, blob => $1 };
            } else {
                $removed{$1} = 1;
            }
        }
    }
    close $fh or die "git log failed in $gd\n";
    # A removal can only refer to a message stored before it, and a
    # removed message is never re-added under the same blob in practice;
    # dropping every copy of a removed blob is the conservative reading.
    push @stored, grep { !$removed{$_->{blob}} } @ep;
}
$stored[$_]{seq} = $_ for 0 .. $#stored;
note(scalar(@stored), " stored messages in ", scalar(@epochs), " epoch(s)");

# ---------------------------------------------------------------- step 2
# Parse in parallel. Each worker owns a slice (seq % JOBS), its own
# `git cat-file --batch`, a Storable file of metadata, and a flat file of
# body bytes (so the parent never holds every body in memory).

my $TMP = tempdir('export-index-XXXXXX', TMPDIR => 1, CLEANUP => 1);
$JOBS = @stored if $JOBS > @stored;
$JOBS = 1 if $JOBS < 1;
my @pids;
for my $w (0 .. $JOBS - 1) {
    my $pid = fork // die "fork: $!";
    if (!$pid) { worker($w); exit 0 }
    push @pids, $pid;
}
for (@pids) { waitpid($_, 0); $? and die "worker $_ failed (status $?)\n" }

my @rec;
for my $w (0 .. $JOBS - 1) {
    my $part = retrieve("$TMP/meta.$w");
    $rec[$_->{seq}] = $_ for @$part;
}
for (0 .. $#stored) { defined $rec[$_] or die "worker lost message seq=$_\n" }
note("parsed");

sub worker {
    my ($w) = @_;
    $0 = "export-index worker $w";
    my (%cat, @out);
    open(my $bfh, '>:raw', "$TMP/body.$w") or die "body.$w: $!";
    my $off = 0;
    for my $s (@stored) {
        next unless $s->{seq} % $JOBS == $w;
        my $c = $cat{$s->{epoch}} //= do {
            my $pid = open2(my $r, my $wr, 'git',
                "--git-dir=$INBOX/git/$s->{epoch}.git", qw(cat-file --batch));
            binmode $r; binmode $wr;
            { r => $r, w => $wr, pid => $pid };
        };
        print { $c->{w} } "$s->{blob}\n";
        $c->{w}->flush;
        my $hdr = readline($c->{r}) // die "cat-file died\n";
        $hdr =~ /\A[0-9a-f]+ blob (\d+)$/ or die "cat-file: $hdr";
        my ($len, $raw) = ($1, '');
        while ($len > length $raw) {
            read($c->{r}, $raw, $len - length($raw), length $raw)
                or die "short read on $s->{blob}\n";
        }
        read($c->{r}, my $lf, 1);
        my $m = parse_message(\$raw, $s);
        my $body = delete $m->{body};
        print $bfh $body;
        @$m{qw(w off len)} = ($w, $off, length $body);
        $off += length $body;
        push @out, $m;
    }
    close $bfh or die "close body.$w: $!";
    for (values %cat) { close $_->{w}; close $_->{r}; waitpid($_->{pid}, 0) }
    nstore(\@out, "$TMP/meta.$w");
}

# Everything that leaves parse_message is UTF-8 *bytes*.
sub u8 {
    my ($s) = @_;
    return undef unless defined $s;
    if (!utf8::is_utf8($s)) {          # raw octets: valid UTF-8, else Latin-1
        my $c = $s;
        $s = $c if utf8::decode($c);
    }
    Encode::encode('UTF-8', $s);       # strict; unencodable -> U+FFFD
}

sub fold { my ($s) = @_; return undef unless defined $s;
           $s =~ s/\s+/ /g; $s =~ s/\A | \z//g; $s }

sub iso { strftime('%Y-%m-%dT%H:%M:%SZ', gmtime $_[0]) }

sub parse_message {
    my ($rawref, $s) = @_;
    my $eml = PublicInbox::Eml->new($rawref);
    my %m = (seq => $s->{seq}, epoch => $s->{epoch}, blob => $s->{blob});

    # Message-ID: PublicInbox::MID::mids handles folded headers and picks
    # out <...>; the first one is the message's own (v2 appends, never
    # prepends, when it has to invent an alternate).
    my ($mid) = @{ mids($eml) };
    $mid = u8(fold($mid)) if defined $mid;
    $m{mid} = $mid if defined $mid && length $mid;

    # Date -> epoch seconds. A `Date:` header that is missing, unparseable
    # or more than DATE_SKEW_MAX ahead of the best independent evidence of
    # when the list saw the message is replaced by that evidence, tried in
    # order: the topmost Received: stamped by openwall (the list's own
    # clock) -> the YYYY/MM/DD in X-Archive-Source-URL (a scraped copy's
    # archive page) -> the commit timestamp. The commit is deliberately
    # last: on a backfilled archive it is the ingest date (2026 for
    # everything), which would drop an old message with a bad Date: into
    # the current year's shard and poison first-mention dates.
    my $hdr_ts;
    for my $d ($eml->header_raw('Date')) {
        my $r = eval { PublicInbox::MsgTime::str2date_zone($d) };
        if ($r && $r->[0] && $r->[0] > 0) { $hdr_ts = $r->[0]; last }
    }
    my ($alt_ts, $alt_src);
    for my $r ($eml->header_raw('Received')) {
        # Openwall's own hops: a `by ...openwall.com` clause, or ezmlm's
        # `(qmail N invoked by uid N); DATE` form, which has no by-clause
        # at all. For a non-openwall inbox the topmost Received is used.
        next if $SCHEME eq 'openwall' && $r !~ /\bby\s+\S*openwall\.com\b/i
                                       && $r !~ /\A\s*\(qmail\s+\d+\s+invoked\b/i;
        $r =~ /;\s*([^;]+?)\s*\z/s or next;
        my $p = eval { PublicInbox::MsgTime::str2date_zone($1) };
        if ($p && $p->[0] && $p->[0] > 0) { ($alt_ts, $alt_src) = ($p->[0], 'received'); last }
    }
    if (!defined $alt_ts) {
        my $u = $eml->header_raw('X-Archive-Source-URL') // '';
        if ($u =~ m{/(\d{4})/(\d\d)/(\d\d)(?:/|\z)}) {
            my $t = eval { timegm(0, 0, 0, $3, $2 - 1, $1) };
            ($alt_ts, $alt_src) = ($t, 'source_url') if defined $t;
        }
    }
    ($alt_ts, $alt_src) = ($s->{ct}, 'commit') unless defined $alt_ts;
    if (defined $hdr_ts && $hdr_ts <= $alt_ts + DATE_SKEW_MAX) {
        @m{qw(ts date_source)} = ($hdr_ts, 'date');
    } else {
        @m{qw(ts date_source)} = ($alt_ts, $alt_src);
    }

    $m{from}    = u8(fold(scalar $eml->header('From')));
    $m{subject} = u8(fold(scalar $eml->header('Subject')));
    my $subj_chars = fold(scalar $eml->header('Subject')) // '';

    my @irt  = map { /$MID_EXTRACT/g } $eml->header_raw('In-Reply-To');
    my @refs = map { /$MID_EXTRACT/g } $eml->header_raw('References');
    my ($parent) = (@irt ? $irt[0] : $refs[-1]);
    $m{irt}  = u8(fold($parent)) if defined $parent;
    $m{refs} = [ map { u8(fold($_)) } @{ references($eml) } ];

    my $src = fold(scalar $eml->header_raw('X-Archive-Source'));
    $m{prov} = defined $src && length $src ? u8($src) : $DEFAULT_PROV;
    my $su = fold(scalar $eml->header_raw('X-Archive-Source-URL'));
    $m{source_url} = u8($su) if defined $su && length $su;

    # Body: first non-attachment text/plain part; failing that, the first
    # text/html part rendered to text. Headers must be read before this —
    # each_part($once=1) is allowed to consume the Eml.
    my ($plain, $html);
    $eml->each_part(sub {
        my ($part) = @{ $_[0] };
        return if defined $plain;
        my $cd = $part->header_raw('Content-Disposition') // '';
        return if $cd =~ /\A\s*attachment\b/i;
        my $ct = $part->content_type // 'text/plain';
        if ($ct =~ m!\A\s*text/plain\b!i) {
            my ($t) = msg_part_text($part, $ct);
            $plain = $t if defined $t;
        } elsif ($ct =~ m!\A\s*text/x?html\b!i) {
            $html //= eval { $part->body_str } // $part->body;
        }
    }, undef, 1);
    my $body = $plain // (defined $html ? html2text($html) : '');
    $body = u8($body);
    $body =~ s/\r\n/\n/g;

    my %cve;
    for (\$subj_chars, \$body) {
        $cve{uc $1} = 1 while $$_ =~ /\b(CVE-\d{4}-\d{4,})\b/gi;
    }
    $m{cves} = [ sort keys %cve ];

    # GitHub advisory IDs (DEC-ARCHIVE-011). GitHub's alphabet has no
    # vowels, 0, 1 or l, so prose can't false-match. Canonical form is
    # GitHub's own: `GHSA-` + lowercase. Most mentions sit inside
    # .../security/advisories/GHSA-... URLs; repo-level and draft advisories
    # are indexed too even though some never resolve. No GHSA<->CVE linking
    # here: the index records what the text says, consumers alias via OSV.
    my %ghsa;
    for (\$subj_chars, \$body) {
        $ghsa{'GHSA' . lc $1} = 1
            while $$_ =~ /\bGHSA((?:-[23456789cfghjmpqrvwx]{4}){3})\b/gi;
    }
    $m{ghsas} = [ sort keys %ghsa ];

    # Full-body digest (pre-truncation) is what duplicate copies are
    # compared on; body_sha is over the bytes actually emitted.
    $m{full_sha} = sha256_hex($body);
    if (length($body) > BODY_MAX) {
        my $cut = rindex($body, "\n", BODY_MAX - 1);
        if ($cut >= 0) { $cut++ }
        else {                                   # one giant line
            $cut = BODY_MAX;
            $cut-- while $cut > 0 && (ord(substr($body, $cut, 1)) & 0xC0) == 0x80;
        }
        substr($body, $cut) = '';
        $m{truncated} = 1;
    }
    $m{body_sha} = substr(sha256_hex($body), 0, 12);

    if (!defined $m{mid}) {
        $m{mid} = substr(sha256_hex(join("\0", iso($m{ts}), $m{from} // '',
                    $m{subject} // '', $body)), 0, 32) . "\@synthetic.$SOURCE";
        $m{synthetic} = 1;
    }
    $m{body} = $body;
    \%m;
}

my $HTML_OK;
sub html2text {
    my ($h) = @_;
    $HTML_OK //= eval { require HTML::FormatText; require HTML::TreeBuilder; 1 }
        or die "HTML-only message found but HTML::FormatText is missing ",
               "(apt install libhtml-format-perl)\n";
    utf8::decode($h) unless utf8::is_utf8($h);
    my $tree = HTML::TreeBuilder->new;
    $tree->parse_content($h);
    my $t = HTML::FormatText->new(leftmargin => 0, rightmargin => 72)->format($tree);
    $tree->delete;
    $t;
}

# ---------------------------------------------------------------- step 3
# One row per Message-ID. Winner: best provenance, then latest commit.

# Bodies live in the workers' flat files; fetch on demand.
my %bfh;
sub body_bytes {
    my ($m) = @_;
    my $fh = $bfh{ $m->{w} } //= do {
        open(my $f, '<:raw', "$TMP/body.$m->{w}") or die "body.$m->{w}: $!"; $f };
    seek($fh, $m->{off}, 0) or die "seek: $!";
    my $b = '';
    $m->{len} == 0 or read($fh, $b, $m->{len}) == $m->{len} or die "short body read\n";
    $b;
}

# body_conflict asks "are these really two different messages?", not "are
# the bytes equal?" — a scraped copy never has equal bytes. Openwall's HTML
# elides every address (user@...ain.tld), re-flows whitespace, and renders
# later text parts (inline patches, list footers) into the same page that
# we'd otherwise only see as separate MIME parts. So compare with addresses
# masked and whitespace collapsed, and accept one body being a prefix of
# the other. Anything that still differs is a genuine content conflict.
sub norm_body {
    my $b = body_bytes($_[0]);
    $b =~ s/\@[^\s<>()\[\]"',;]*/\@/g;
    $b =~ s/^>+(?=From )//mg;               # mbox From-escaping
    $b =~ s/\s+/ /g;
    $b =~ s/\A | \z//g;
    $b;
}
sub bodies_differ {
    my ($x, $y) = @_;
    return 0 if $x->{full_sha} eq $y->{full_sha};
    my ($p, $q) = sort { length $a <=> length $b } norm_body($x), norm_body($y);
    substr($q, 0, length $p) ne $p;
}

my %by_mid;
push @{ $by_mid{$_->{mid}} }, $_ for @rec;
my @rows;
for my $mid (keys %by_mid) {
    my ($win, @lose) = sort { rank($a->{prov}) <=> rank($b->{prov})
                              || $b->{seq} <=> $a->{seq} } @{ $by_mid{$mid} };
    $win->{dups} = \@lose;
    $win->{body_conflict} = (grep { bodies_differ($win, $_) } @lose) ? 1 : 0;
    push @rows, $win;
}
my %row = map { $_->{mid} => $_ } @rows;
note(scalar(@rows), " unique Message-IDs (", @rec - @rows, " duplicate copies)");

# ---------------------------------------------------------------- step 4
# Threading. public-inbox's tid is authoritative where present; but a
# from-scratch reindex skips same-Message-ID copies ("is a duplicate"),
# and a consumer may run this against a stale or missing over.sqlite3.
# So: union messages by their own References/In-Reply-To (which is what
# tid is derived from), then additionally union everything over.sqlite3
# says shares a tid. With a complete index the two agree.

my %uf;
sub find {
    my ($x) = @_;
    $uf{$x} //= $x;
    my $r = $x;
    $r = $uf{$r} while $uf{$r} ne $r;
    while ($uf{$x} ne $r) { my $n = $uf{$x}; $uf{$x} = $r; $x = $n }
    $r;
}
sub union { my ($a, $b) = (find($_[0]), find($_[1])); $uf{$a} = $b if $a ne $b }

for my $m (@rec) {
    union("m:$m->{mid}", "m:$_") for grep { defined && length } @{ $m->{refs} }, $m->{irt};
}
my $over_rows = 0;
my ($over_f) = sort { $b cmp $a } glob("$INBOX/xap*/over.sqlite3");
if ($over_f && -s $over_f) {
    eval {
        require PublicInbox::Over;
        my $dbh = PublicInbox::Over->new($over_f)->dbh;
        my $sth = $dbh->prepare('SELECT num, tid, ddd FROM over WHERE num > 0');
        $sth->execute;
        while (my $r = $sth->fetchrow_hashref) {
            my $smsg = PublicInbox::Over::load_from_row($r);
            next unless defined $smsg->{mid} && defined $smsg->{tid};
            my $mid = $smsg->{mid};
            utf8::encode($mid) if utf8::is_utf8($mid);
            next unless $row{$mid};
            union("m:$mid", "t:$smsg->{tid}");
            $over_rows++;
        }
        1;
    } or warn "W: could not read $over_f ($@); threading from References only\n";
}
note($over_rows ? "threading: tid for $over_rows messages from $over_f"
                : "threading: no usable over.sqlite3, using References only");

my %thread;
push @{ $thread{ find("m:$_->{mid}") } }, $_ for @rows;
for my $members (values %thread) {
    my @cand = grep { !defined $_->{irt} || $_->{irt} eq $_->{mid}
                      || !$row{ $_->{irt} } } @$members;
    @cand = @$members unless @cand;
    my ($root) = sort { $a->{ts} <=> $b->{ts} || $a->{mid} cmp $b->{mid} } @cand;
    $_->{root} = $root->{mid} for @$members;
}

# ---------------------------------------------------------------- step 5
for my $m (@rows) {
    $m->{irt} = undef if defined $m->{irt} && $m->{irt} eq $m->{mid};
    if ($SCHEME eq 'openwall') {
        # A maildir winner has no X-Archive-Source-URL of its own, but its
        # scraped twin does — that exact permalink beats a day-level URL.
        my ($u) = grep { defined } map { $_->{source_url} } $m, @{ $m->{dups} };
        $m->{url} = $u // strftime(
            'https://www.openwall.com/lists/oss-security/%Y/%m/%d', gmtime $m->{ts});
    } elsif ($SCHEME eq 'lore') {
        $m->{url} = "https://lore.kernel.org/$SOURCE/"
                  . PublicInbox::MID::mid_escape(Encode::decode('UTF-8', $m->{mid})) . '/';
    }
}

# ---------------------------------------------------------------- step 7
# Hand-rolled JSON so key order and escaping are ours alone: output is
# byte-identical whichever JSON module (if any) the host has. All strings
# are already UTF-8 bytes; everything that needs escaping is ASCII.

my %ESC = ("\\" => "\\\\", '"' => '\\"', "\n" => '\\n', "\r" => '\\r',
           "\t" => '\\t', "\x08" => '\\b', "\x0c" => '\\f');
sub js {
    my ($s) = @_;
    return 'null' unless defined $s;
    $s =~ s/([\\"\x00-\x1f])/$ESC{$1} \/\/ sprintf('\\u%04x', ord $1)/ge;
    qq("$s");
}
sub jb { $_[0] ? 'true' : 'false' }

sub message_line {
    my ($m) = @_;
    join('', '{"message_id":', js($m->{mid}),
        ',"synthetic_mid":', jb($m->{synthetic}),
        ',"epoch":', $m->{epoch},
        ',"blob":', js($m->{blob}),
        ',"duplicates":[', join(',', map {
            '{"blob":' . js($_->{blob}) . ',"provenance":' . js($_->{prov}) . '}'
        } @{ $m->{dups} }), ']',
        ',"body_conflict":', jb($m->{body_conflict}),
        ',"date":', js(iso($m->{ts})),
        ',"date_source":', js($m->{date_source}),
        ',"from":', js($m->{from}),
        ',"subject":', js($m->{subject}),
        ',"in_reply_to":', js($m->{irt}),
        ',"thread_root":', js($m->{root}),
        ',"url":', js($m->{url}),
        ',"provenance":', js($m->{prov}),
        ',"cve_ids":[', join(',', map { js($_) } @{ $m->{cves} }), ']',
        ',"ghsa_ids":[', join(',', map { js($_) } @{ $m->{ghsas} // [] }), ']',
        ',"body_sha":', js($m->{body_sha}), "}\n");
}

sub put {                                  # atomic write, returns sha256
    my ($path, $writer) = @_;
    open(my $fh, '>:raw', "$path.tmp") or die "$path.tmp: $!";
    my $sha = Digest::SHA->new(256);
    my $n = 0;
    $writer->(sub { print $fh $_[0] or die "write $path: $!";
                    $sha->add($_[0]); $n += length $_[0] });
    close $fh or die "close $path: $!";
    rename("$path.tmp", $path) or die "rename $path: $!";
    ($sha->hexdigest, $n);
}

make_path(map { "$OUT/$_" } qw(messages cves ghsas bodies));

my (%year, %cve_year, %ghsa);
for my $m (sort { $a->{ts} <=> $b->{ts} || $a->{mid} cmp $b->{mid} } @rows) {
    push @{ $year{ strftime('%Y', gmtime $m->{ts}) } }, $m;
    push @{ $cve_year{ substr($_, 4, 4) }{$_} }, $m for @{ $m->{cves} };
    push @{ $ghsa{$_} }, $m for @{ $m->{ghsas} // [] };
}

my (%man, $total_cves);
for my $y (sort keys %year) {
    my $list = $year{$y};
    my ($sha) = put("$OUT/messages/$y.jsonl", sub { $_[0]->(message_line($_)) for @$list });
    $man{messages}{$y} = { count => scalar @$list, sha256 => $sha };
    my ($bsha, $bytes) = put("$OUT/bodies/$y.jsonl", sub {
        for my $m (@$list) {
            $_[0]->('{"message_id":' . js($m->{mid}) . ',"body":' . js(body_bytes($m))
                  . ',"truncated":' . jb($m->{truncated}) . "}\n");
        }
    });
    $man{bodies}{$y} = { count => scalar @$list, bytes => $bytes, sha256 => $bsha };
}
# ID -> [mentions in date order], one ID per line: still a single JSON
# object, but a new mention costs a one-line git delta instead of
# rewriting the whole file.
sub put_id_map {
    my ($path, $c) = @_;
    my ($sha) = put($path, sub {
        my @ids = sort keys %$c;
        $_[0]->("{\n");
        for my $i (0 .. $#ids) {
            $_[0]->(js($ids[$i]) . ':[' . join(',', map {
                '{"message_id":' . js($_->{mid}) . ',"date":' . js(iso($_->{ts}))
                . ',"url":' . js($_->{url}) . ',"thread_root":' . js($_->{root}) . '}'
            } @{ $c->{ $ids[$i] } }) . ']' . ($i < $#ids ? ",\n" : "\n"));
        }
        $_[0]->("}\n");
    });
    $sha;
}
for my $y (sort keys %cve_year) {
    my $c = $cve_year{$y};
    $man{cves}{$y} = { count => scalar keys %$c, sha256 => put_id_map("$OUT/cves/$y.json", $c) };
    $total_cves += keys %$c;
}
# GHSA IDs carry no year, so there is nothing stable to shard on; ~600 IDs
# fit one small file. Keyed `all` in the manifest so consumers can treat
# every section as {shard => {count, sha256}} -> <kind>/<shard>.<ext>.
# If this ever outgrows one file, shard by the first suffix character.
# Always written, even when empty, so the manifest shape is fixed.
$man{ghsas}{all} = { count => scalar keys %ghsa, sha256 => put_id_map("$OUT/ghsas/all.json", \%ghsa) };
my $total_ghsas = keys %ghsa;

# Shards that no longer have any content (only possible after a purge or
# a date fix) must not linger: the index is a projection, not a log.
for my $kind (qw(messages cves ghsas bodies)) {
    for my $f (glob("$OUT/$kind/*")) {
        my ($y) = $f =~ m{/(\d{4}|all)\.jsonl?\z} or next;
        unlink $f or die "unlink $f: $!" unless $man{$kind}{$y};
    }
}

sub section {
    my ($kind, @keys) = @_;
    my $h = $man{$kind} // {};
    my @l = map { my $e = $h->{$_}; my $y = $_;
        "    \"$y\": {" . join(', ', map {
            "\"$_\": " . ($_ eq 'sha256' ? js($e->{$_}) : $e->{$_}) } @keys) . '}'
    } sort keys %$h;
    "  \"$kind\": {" . (@l ? "\n" . join(",\n", @l) . "\n  " : '') . '}';
}
put("$OUT/manifest.json", sub { $_[0]->(join(",\n",
    "{\n  \"schema\": " . SCHEMA,
    '  "source": ' . js($SOURCE),
    '  "generated_at": ' . js(iso(time)),
    '  "built_from": {' . join(', ', map { "\"$_\": " . js($built_from{$_}) }
                                     sort { $a <=> $b } keys %built_from) . '}',
    section('messages', qw(count sha256)),
    section('cves', qw(count sha256)),
    section('ghsas', qw(count sha256)),
    section('bodies', qw(count bytes sha256)),
    '  "total_messages": ' . scalar(@rows),
    '  "total_stored": ' . scalar(@stored),
    '  "total_cves": ' . ($total_cves // 0),
    '  "total_ghsas": ' . $total_ghsas) . "\n}\n") });

note(sprintf('wrote %s: stored=%d unique=%d duplicates=%d body_conflicts=%d cves=%d ghsas=%d',
    $OUT, scalar @stored, scalar @rows, @stored - @rows,
    scalar(grep { $_->{body_conflict} } @rows), $total_cves // 0, $total_ghsas));
