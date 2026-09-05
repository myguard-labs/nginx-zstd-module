use Test::Nginx::Socket;
use File::Temp qw(tempdir);

# Phase-2 static sidecar serving. Fixtures are REAL compressed files
# built in this prelude via the reference CLIs (zstd, brotli, gzip must
# be on PATH — the same tools the wire matrix uses), so every serve
# assertion compares against the exact bytes on disk.

our $src = "static fixture body: the compressible original content\n" x 30;

my $dir = tempdir(CLEANUP => 1);
my $f = "$dir/fixture";
open my $fh, '>', $f or die $!;
binmode $fh; print $fh $src; close $fh;

sub slurp { open my $h, '<', $_[0] or die "$_[0]: $!"; binmode $h; local $/; <$h> }

system("zstd -q -f -o $f.zst $f") == 0        or die "zstd fixture";
system("brotli -f -o $f.br $f") == 0          or die "brotli fixture";
system("gzip -c $f > $f.gz") == 0             or die "gzip fixture";
# oversized declared window: stdin = unpledged input size, so the level
# default window (128 MB at --long=27) is stamped into the header — the
# vite/Node production incident in fixture form
system("zstd -q -19 --long=27 < $f > $f.bigwin.zst") == 0 or die "bigwin";

our $zst    = slurp("$f.zst");
our $br     = slurp("$f.br");
our $gz     = slurp("$f.gz");
our $bigwin = slurp("$f.bigwin.zst");

# ── crafted zstd frame headers for the window-cap EDGES ─────────────
# the probe only reads headers and decline paths never serve, so the
# boundary fixtures are tiny hand-built byte strings instead of real
# 8 MB streams; pass-case files are served AS-IS (byte-compared), no
# decode expected
our $magic       = "\x28\xB5\x2F\xFD";
# descriptor path: window byte 0x68 -> 1<<(10+13) = 8 MB exactly
# (the limit is `>`, so this passes); 0x70 -> 16 MB (declines)
our $win8m_desc  = $magic . "\x00\x68";
our $win16m_desc = $magic . "\x00\x70";
# single-segment path: FHD 0xA0 = SS + 4-byte FCS; window = FCS
our $ss8m        = $magic . "\xA0" . pack("V", 8388608);
our $ss8m1       = $magic . "\xA0" . pack("V", 8388609);
# FHD 0x60 = SS + 2-byte FCS: 65535 + the RFC 8878 +256 offset = 65791
our $ss_fcs2     = $magic . "\x60\xFF\xFF";
our $magic_only  = $magic;                 # 4 bytes: header truncated
our $desc_trunc  = $magic . "\x00";        # 5 bytes: window byte missing
our $tiny3       = "\x28\xB5\x2F";         # under the 4-byte minimum
our $skippable   = "\x50\x2A\x4D\x18" . ("\x00" x 8);  # bare skippable, nothing after
# a leading skippable frame (RFC 8878 §3.2): magic + 4-byte LE skip
# length + that many payload bytes. The window guard must not be
# bypassable by prepending one (parent #159): the probe walks past the
# skippable frame to the first regular frame and checks ITS window.
our $skip4       = "\x50\x2A\x4D\x18" . pack("V", 4) . ("\xAA" x 4);
our $skip_bigwin = $skip4 . $win16m_desc;   # skippable + 16 MB -> declines
our $skip_ok     = $skip4 . $win8m_desc;    # skippable + 8 MB -> served (dcz shape)
# same dcz shape, padded past a directio 512 threshold so O_DIRECT engages:
# the skippable-frame walk moves the probe offset to 12 (unaligned), which
# a raw O_DIRECT read rejects with EINVAL — the #197 regression
our $skip_dio    = $skip_ok . ("\x5A" x 600);
# FHD 0x08 = Reserved_bit (RFC 8878 §3.1.1.1, "must be zero") + an
# otherwise-valid 8 MB window byte: the probe must reject on the bit
# BEFORE trusting anything else in the header (upstream #252)
our $reserved    = $magic . "\x08\x68";
# the skip-walk BOUND (parent #273): exactly MAX_SKIP_FRAMES (4) leading
# skippable frames before a valid frame is the documented boundary and
# must serve; a fifth is the hard decline
our $skip4x4_ok  = ($skip4 x 4) . $win8m_desc;
our $skip5_deny  = ($skip4 x 5) . $win8m_desc;

# 8 KB of randomness for the directio blocks (compressed output stays
# ~8 KB, comfortably over the directio threshold)
our $bigwin8k;
{
    my $src8k = "";
    open my $u, '<', '/dev/urandom' or die $!;
    read $u, $src8k, 8192; close $u;
    open my $w, '>', "$dir/rnd" or die $!;
    binmode $w; print $w $src8k; close $w;
    system("zstd -q -19 --long=27 < $dir/rnd > $dir/rnd.bigwin.zst") == 0
        or die "bigwin8k";
    $bigwin8k = slurp("$dir/rnd.bigwin.zst");
}


no_long_string();
log_level 'warn';
repeat_each(1);
plan 'no_plan';
run_tests();

__DATA__


=== TEST 1: on + AE br -> serves the .br sidecar byte-exact
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.br" => $::br ] ]
--- config
    location /st/ {
        compression_static on;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: br
--- response_headers
Content-Encoding: br
--- response_body eval
$::br
--- raw_response_headers_like: Vary: Accept-Encoding
--- no_error_log
[error]



=== TEST 2: default order prefers br when both sidecars exist
--- user_files eval
[ [ "st/hello.js" => $::src ],
  [ "st/hello.js.br" => $::br ],
  [ "st/hello.js.zst" => $::zst ] ]
--- config
    location /st/ {
        compression_static on;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd, br
--- response_headers
Content-Encoding: br
--- response_body eval
$::br
--- no_error_log
[error]



=== TEST 3: explicit order flips the preference
--- user_files eval
[ [ "st/hello.js" => $::src ],
  [ "st/hello.js.br" => $::br ],
  [ "st/hello.js.zst" => $::zst ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order zstd br gzip;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd, br
--- response_headers
Content-Encoding: zstd
--- response_body eval
$::zst
--- no_error_log
[error]



=== TEST 4: gzip sidecars are FIRST-CLASS — served with zero zlib involvement
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.gz" => $::gz ] ]
--- config
    location /st/ {
        compression_static on;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: gzip
--- response_headers
Content-Encoding: gzip
--- response_body eval
$::gz
--- no_error_log
[error]



=== TEST 5: the client's acceptance gates each coding in on mode
# .br exists but the client only accepts zstd, whose sidecar does not
# exist -> identity original
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.br" => $::br ] ]
--- config
    location /st/ {
        compression_static on;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Content-Encoding
--- response_body eval
$::src
--- no_error_log
[error]



=== TEST 6: no Accept-Encoding in on mode -> identity, Vary still emitted
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.br" => $::br ] ]
--- config
    location /st/ {
        compression_static on;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- raw_response_headers_like: Vary: Accept-Encoding
--- raw_response_headers_unlike: Content-Encoding
--- response_body eval
$::src
--- no_error_log
[error]



=== TEST 7: always serves the first EXISTING sidecar with no negotiation
# no Accept-Encoding at all; only .zst exists (order default br zstd
# gzip -> br probe misses, zstd probe hits)
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.zst" => $::zst ] ]
--- config
    location /st/ {
        compression_static always;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- response_headers
Content-Encoding: zstd
--- response_body eval
$::zst
--- raw_response_headers_unlike: Vary
--- no_error_log
[error]



=== TEST 8: the window cap declines an oversized .zst to the NEXT coding
# bigwin.zst declares a 128 MB window (browsers reject it before
# decoding); the unified probe loop lands on the .gz sidecar instead of
# identity — decline-and-log finding a BETTER answer, which the
# split-module world could not do
--- user_files eval
[ [ "st/hello.js" => $::src ],
  [ "st/hello.js.zst" => $::bigwin ],
  [ "st/hello.js.gz" => $::gz ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order zstd gzip;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd, gzip
--- response_headers
Content-Encoding: gzip
--- response_body eval
$::gz
--- error_log
declares a 134217728-byte decompression window
--- no_error_log
[alert]



=== TEST 9: a mistakenly-renamed non-zstd file is declined, not served
--- user_files eval
[ [ "st/hello.js" => $::src ],
  [ "st/hello.js.zst" => "this is not a zstd frame at all" ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order zstd;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Content-Encoding
--- response_body eval
$::src
--- error_log
is not a zstd frame
--- no_error_log
[alert]



=== TEST 10: static miss falls through to the dynamic filter
# no sidecars exist; compression (the filter) is on -> the response is
# dynamically compressed. The handler declined without touching any
# latch — the cooperation the unified design promises.
--- user_files eval
[ [ "st/hello.js" => $::src ] ]
--- config
    location /st/ {
        compression_static on;
        compression on;
        compression_min_length 1;
        compression_types application/javascript text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 11: unknown coding in compression_static_order is a config error
--- config
    location /st/ {
        compression_static_order zstd lzma;
        root html;
    }
--- must_die
--- error_log
unknown coding "lzma"
--- no_error_log
[alert]



=== TEST 12: duplicate coding in compression_static_order is a config error
--- config
    location /st/ {
        compression_static_order br zstd br;
        root html;
    }
--- must_die
--- error_log
duplicate coding "br"
--- no_error_log
[alert]



=== TEST 13: compression_static off is inert
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.br" => $::br ] ]
--- config
    location /st/ {
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: br
--- raw_response_headers_unlike: Content-Encoding
--- response_body eval
$::src
--- no_error_log
[error]



=== TEST 14: declared window of EXACTLY 8 MB passes (descriptor path)
# the cap is `>`, not `>=`: 1<<23 is the largest window every browser
# accepts, and it must serve. Crafted header, served as-is.
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.zst" => $::win8m_desc ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order zstd;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- response_body eval
$::win8m_desc
--- no_error_log
[error]



=== TEST 15: 16 MB descriptor window declines (first step above the cap)
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.zst" => $::win16m_desc ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order zstd;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Content-Encoding
--- response_body eval
$::src
--- error_log
declares a 16777216-byte decompression window
--- no_error_log
[alert]



=== TEST 16: single-segment window of EXACTLY 8 MB passes
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.zst" => $::ss8m ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order zstd;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- response_body eval
$::ss8m
--- no_error_log
[error]



=== TEST 17: single-segment 8 MB + 1 declines (the exact crossing byte)
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.zst" => $::ss8m1 ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order zstd;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Content-Encoding
--- response_body eval
$::src
--- error_log
declares a 8388609-byte decompression window
--- no_error_log
[alert]



=== TEST 18: the 2-byte FCS +256 offset parses and passes
# RFC 8878's 2-byte field is offset by 256; 0xFFFF -> window 65791
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.zst" => $::ss_fcs2 ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order zstd;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- response_body eval
$::ss_fcs2
--- no_error_log
[error]



=== TEST 19: a 4-byte file (magic only) is a truncated header, declined
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.zst" => $::magic_only ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order zstd;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Content-Encoding
--- response_body eval
$::src
--- error_log
frame header truncated
--- no_error_log
[alert]



=== TEST 20: a 5-byte file missing its window byte is truncated, declined
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.zst" => $::desc_trunc ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order zstd;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Content-Encoding
--- response_body eval
$::src
--- error_log
frame header truncated
--- no_error_log
[alert]



=== TEST 21: a 3-byte file is under the magic minimum, declined
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.zst" => $::tiny3 ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order zstd;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Content-Encoding
--- response_body eval
$::src
--- error_log
too small to be a zstd frame
--- no_error_log
[alert]



=== TEST 22a: a skippable lead does NOT exempt the regular frame's window (parent #159)
# the bug this closes: prepend one skippable frame ahead of an
# oversized-window regular frame and the 8 MB browser guard used to be
# bypassed entirely. The probe now walks past the skippable frame and
# checks the regular frame's window — 16 MB, so it DECLINES to identity.
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.zst" => $::skip_bigwin ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order zstd;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding:
--- response_body eval
$::src
--- error_log
declares a 16777216-byte decompression window



=== TEST 22b: a valid dcz-shape prefix (skippable + OK window) is served
# one skippable frame ahead of an 8 MB regular frame — the RFC 8878
# dictionary-prefix shape — passes the walk and is served as-is.
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.zst" => $::skip_ok ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order zstd;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- response_body eval
$::skip_ok
--- no_error_log
[error]



=== TEST 22c: a bare skippable frame with no following regular frame declines
# a skippable frame is not a servable stream on its own; the walk lands
# on non-frame bytes past it and declines to identity.
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.zst" => $::skippable ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order zstd;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding:
--- response_body eval
$::src
--- error_log
is not a zstd frame



=== TEST 22d: a short read that SUCCEEDED is an [error] with no errno, and is memoized
# parent #314 (A33-F4a): a sidecar whose skippable frame is followed by
# two stray bytes reads cleanly but leaves fewer than four bytes at the
# frame position. That is a property of the file, not a read failure:
# logged once at [error] with errno 0 (a [crit] with a stale ngx_errno
# was the old shape), memoized like any other malformed verdict, and
# served as identity. Same triple-include shape as TEST 44.
--- log_level: debug
--- user_files eval
[ [ "page/short.shtml" => '<!--#include virtual="/st/short.txt" --><!--#include virtual="/st/short.txt" --><!--#include virtual="/st/short.txt" -->' ],
  [ "st/short.txt" => "identity fallback
" ],
  [ "st/short.txt.zst" => "P*M" . (" " x 4) . "(µ" ] ]
--- config
    location /page/ {
        ssi on;
        default_type text/html;
        root html;
    }
    location /st/ {
        compression_static on;
        compression_static_order zstd;
        root html;
    }
--- request
GET /page/short.shtml
--- more_headers
Accept-Encoding: zstd
--- response_body_like eval
qr/^(?:identity fallback
){3}\s*$/
--- error_log eval
qr/\[error\] .*frame header\) returned \d+, client/
--- grep_error_log eval
qr/frame header\) returned|cached malformed verdict/
--- grep_error_log_out
frame header) returned
cached malformed verdict
cached malformed verdict
--- no_error_log
[crit]
[alert]


=== TEST 23: the window check runs UNDER DIRECTIO (aligned probe witness)
# the property the parent's #101 review pinned: oversized windows are a
# systematic build-pipeline product, so O_DIRECT must not skip the
# check. The debug line witnesses the aligned-probe path actually ran.
--- log_level: debug
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.zst" => $::bigwin8k ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order zstd;
        directio 512;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Content-Encoding
--- response_body eval
$::src
--- error_log eval
[qr/aligned probe on directio file/,
 qr/declares a 134217728-byte decompression window/]



=== TEST 24: directio_alignment 16k geometry still probes and declines
# probe size becomes max(4096, 16384); a short read at EOF is permitted
# so the ~8 KB sidecar still parses, and the window check still fires
--- log_level: debug
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.zst" => $::bigwin8k ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order zstd;
        directio 512;
        directio_alignment 16k;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Content-Encoding
--- response_body eval
$::src
--- error_log eval
[qr/16384-byte aligned probe on directio file/,
 qr/declares a 134217728-byte decompression window/]


=== TEST 25: a 200 sidecar serve advertises Accept-Ranges: bytes
# gzip_static parity: the handler opts in via r->allow_ranges — the
# pre-fix build cleared ranges and this header could not appear
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.gz" => $::gz ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order gzip;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: gzip
--- response_headers
Content-Encoding: gzip
Accept-Ranges: bytes
--- response_body eval
$::gz
--- no_error_log
[error]



=== TEST 26: byte ranges slice the sidecar's bytes (206 + Content-Range)
# the representation IS the encoded bytes and the validator is strong;
# the range filter only runs because the handler sets allow_ranges —
# unfixed code ignores Range and answers 200 with the full body
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.gz" => $::gz ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order gzip;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: gzip
Range: bytes=0-9
--- error_code: 206
--- response_headers eval
"Content-Range: bytes 0-9/" . length($::gz)
--- response_body eval
substr($::gz, 0, 10)
--- no_error_log
[error]



=== TEST 27: empty sidecar behind an SSI include ships silently
# in a subrequest in_file and last_buf are both 0; without b->sync the
# flagless zero-size buf trips the output chain's "zero size buf" alert
--- user_files eval
[ [ "page/x.shtml" => qq{before[<!--#include virtual="/inc/empty.txt" -->]after\n} ],
  [ "inc/empty.txt.gz" => "" ] ]
--- config
    location /page/ {
        ssi on;
        default_type text/html;   # the SSI filter only touches ssi_types
        root html;
    }
    location /inc/ {
        compression_static always;
        root html;
    }
--- request
GET /page/x.shtml
--- response_body
before[]after
--- no_error_log eval
qr/zero size buf/


=== TEST 28: dict bypass stands aside on AD + explicit dict token
# the static module alone (filter unconfigured): declining means
# identity — the negotiation it defers to lives in the other module
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.br" => $::br ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_dict_bypass on;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: br, dcz
Available-Dictionary: :AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:
--- raw_response_headers_unlike: Content-Encoding
--- response_body eval
$::src
--- no_error_log
[error]



=== TEST 29: default off — the sidecar wins despite AD (unchanged behavior)
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.br" => $::br ] ]
--- config
    location /st/ {
        compression_static on;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: br, dcz
Available-Dictionary: :AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:
--- response_headers
Content-Encoding: br
--- no_error_log
[error]



=== TEST 30: bypass without an Available-Dictionary serves the sidecar
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.br" => $::br ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_dict_bypass on;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: br, dcz
--- response_headers
Content-Encoding: br
--- no_error_log
[error]



=== TEST 31: bypass with AD but no dict token in AE serves the sidecar
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.br" => $::br ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_dict_bypass on;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: br
Available-Dictionary: :AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:
--- response_headers
Content-Encoding: br
--- no_error_log
[error]



=== TEST 32: bypass overrides always mode too
# always ignores Accept-Encoding for SIDECAR SELECTION, but standing
# aside for dictionary negotiation is the operator's explicit request
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.br" => $::br ] ]
--- config
    location /st/ {
        compression_static always;
        compression_static_dict_bypass on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: dcb
Available-Dictionary: :AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:
--- raw_response_headers_unlike: Content-Encoding
--- response_body eval
$::src
--- no_error_log
[error]



=== TEST 33a: compression_static on emits Vary by construction, no warn
# Parent #163: the negotiated static path calls
# ngx_http_compression_vary(), which emits Vary: Accept-Encoding itself,
# so "gzip_vary off" no longer means a missing Vary and there is nothing
# to warn about.
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.br" => $::br ] ]
--- config
    location /st/ {
        compression_static on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: br
--- response_headers
Content-Encoding: br
Vary: Accept-Encoding
--- no_error_log eval
[qr/"compression_static on" without/, qr/\[error\]/]


=== TEST 33b: compression_static always never varies (and never warns)
# "always" ignores Accept-Encoding, so its response is not a negotiated
# variant: it must NOT call the Vary helper and must carry no Vary.
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.br" => $::br ] ]
--- config
    location /st/ {
        compression_static always;
        root html;
    }
--- request
GET /st/hello.js
--- response_headers
Content-Encoding: br
Vary:
--- no_error_log eval
[qr/compression_static on/, qr/\[error\]/]


=== TEST 34: HEAD fast path keeps the negotiated headers, sends no body
# Parent #179: a HEAD returns after ngx_http_send_header(), skipping the
# body buffer allocations — but the Content-Encoding and the Vary line
# (set before the fast path) must be identical to what the GET produces.
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.br" => $::br ] ]
--- config
    location /st/ {
        compression_static on;
        root html;
    }
--- request
HEAD /st/hello.js
--- more_headers
Accept-Encoding: br
--- response_headers
Content-Encoding: br
Vary: Accept-Encoding
--- response_body
--- no_error_log
[error]


=== TEST 35: a skippable-prefixed .zst is served UNDER DIRECTIO (parent #197)
# The dcz-shape defect: the leading-skippable-frame walk moves the probe
# offset to the frame end (12 here — unaligned), which an O_DIRECT
# descriptor rejects with EINVAL unless the offset is rounded down to the
# block. Pre-fix this DECLINED every such file under directio (a 404 in
# "always" mode); with the aligned-offset probe it serves 200 +
# Content-Encoding: zstd. The debug line witnesses the aligned probe ran.
--- log_level: debug
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.zst" => $::skip_dio ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order zstd;
        directio 512;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- response_body eval
$::skip_dio
--- error_log
aligned probe on directio file
--- no_error_log
[error]

=== TEST 36: a directory named .zst earns no Vary (#202 mirror)
# The #202 contract: Vary is earned by a USABLE sidecar, not by the
# probe's attempt. Every listed coding here resolves to nothing usable
# — the .zst path is a directory — so the identity response carries no
# Vary and shared caches keep one unfragmented entry for a URI that
# has no variant.
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.zst/placeholder" => "x" ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order zstd;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Vary
--- response_body eval
$::src
--- no_error_log
[emerg]


=== TEST 37: a non-zstd .zst earns no Vary (#202 mirror)
# The frame probe declines it (wrong magic), and a declined sidecar is
# not a variant: identity, no Vary. The probe's own decline log line is
# expected — the block asserts no [emerg] rather than a silent log.
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.zst" => "definitely not zstd" ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order zstd;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Vary
--- response_body eval
$::src
--- no_error_log
[emerg]


=== TEST 38: an empty .zst earns no Vary (#202 mirror)
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.zst" => "" ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order zstd;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Vary
--- response_body eval
$::src
--- no_error_log
[emerg]


=== TEST 39: broken .zst + usable .br + non-accepting client -> Vary, identity
# The condition eilandert attached to the port: the probe runs
# INDEPENDENTLY of the client's weights. This client accepts nothing,
# but the walk still probes past the broken .zst, finds the usable
# .br, and emits Vary before declining — without that, this identity
# response would enter shared caches unpartitioned and poison the URI
# for every .br-accepting client behind the same cache.
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.zst" => "definitely not zstd" ],
  [ "st/hello.js.br" => $::br ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order zstd br;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- raw_response_headers_like: Vary: Accept-Encoding
--- raw_response_headers_unlike: Content-Encoding
--- response_body eval
$::src
--- no_error_log
[emerg]


=== TEST 40: reserved Frame_Header_Descriptor bit declines (upstream #252)
# RFC 8878 §3.1.1.1: bit 0x08 must be zero and every compliant decoder
# rejects the frame — serving it would suppress the usable identity
# fallback with bytes no client can use.
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.zst" => $::reserved ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order zstd;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Content-Encoding
--- response_body eval
$::src
--- error_log
reserved Frame_Header_Descriptor bit 0x08
--- no_error_log
[alert]


=== TEST 41: directio_alignment above 64k is CLAMPED for the probe (#208)
# The probe reads a frame header, not the body: an unbounded
# directio_alignment must not scale an 18-byte check into a
# multi-megabyte aligned allocation and O_DIRECT read per probed
# request. The witness names the size: 65536, not 4194304. The window
# check still fires through the clamped geometry.
--- log_level: debug
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.zst" => $::bigwin8k ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order zstd;
        directio 512;
        directio_alignment 4m;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Content-Encoding
--- response_body eval
$::src
--- error_log eval
[qr/65536-byte aligned probe on directio file/,
 qr/declares a 134217728-byte decompression window/]
--- no_error_log
[alert]


=== TEST 42: exactly FOUR leading skippable frames serve (#273)
# the walk's own comment promises "4 is generous headroom"; the old
# bound declined the frame AFTER the fourth skip one probe early
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.zst" => $::skip4x4_ok ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order zstd;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- response_body eval
$::skip4x4_ok
--- no_error_log
[error]


=== TEST 43: a FIFTH leading skippable frame is still the hard decline
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.zst" => $::skip5_deny ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order zstd;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Content-Encoding
--- response_body eval
$::src
--- error_log
more than 4 leading skippable frames
--- no_error_log
[alert]


=== TEST 44: a malformed sidecar's verdict is memoized per path and identity
# One SSI page includes the same malformed .zst three times: three
# static-handler subrequests in one worker, in one deterministic order.
# The first is probed and logged; the next two take the cycle-owned
# verdict cache (parent #287) instead of re-reading and re-logging a
# file that cannot have changed. The exact-count grep is the assertion:
# without the cache there are three probe lines and no cached ones.
--- log_level: debug
--- user_files
>>> page/memo.shtml
<!--#include virtual="/st/memo.txt" --><!--#include virtual="/st/memo.txt" --><!--#include virtual="/st/memo.txt" -->
>>> st/memo.txt
identity fallback
>>> st/memo.txt.zst
HELO malformed sidecar
--- config
    location /page/ {
        ssi on;
        default_type text/html;
        root html;
    }
    location /st/ {
        compression_static on;
        compression_static_order zstd;
        root html;
    }
--- request
GET /page/memo.shtml
--- more_headers
Accept-Encoding: zstd
--- response_body_like eval
qr/^(?:identity fallback\n){3}\s*$/
--- grep_error_log eval
qr/(?:is not a zstd frame|cached malformed verdict)/
--- grep_error_log_out
is not a zstd frame
cached malformed verdict
cached malformed verdict
--- no_error_log
[alert]


=== TEST 44a: a GOOD verdict is memoized under open_file_cache, for its validity
# parent #325: the same served .zst included three times from one SSI
# page. With open_file_cache configured the first include probes and
# the next two take the cached good verdict (debug witness) without
# touching the file; the body is the sidecar three times either way.
--- log_level: debug
--- user_files eval
[ [ "page/good.shtml" => '<!--#include virtual="/st/hello.js" --><!--#include virtual="/st/hello.js" --><!--#include virtual="/st/hello.js" -->' ],
  [ "st/hello.js" => $::src ], [ "st/hello.js.zst" => $::zst ] ]
--- config
    location /page/ {
        ssi on;
        default_type text/html;
        root html;
    }
    location /st/ {
        compression_static on;
        compression_static_order zstd;
        open_file_cache max=16 inactive=60s;
        open_file_cache_valid 60s;
        root html;
    }
--- request
GET /page/good.shtml
--- more_headers
Accept-Encoding: zstd
--- grep_error_log eval
qr/compression static probe:|cached good frame verdict/
--- grep_error_log_out
compression static probe:
compression static probe:
cached good frame verdict
compression static probe:
cached good frame verdict
--- no_error_log
[error]


=== TEST 44b: without open_file_cache no GOOD verdict is kept: every include probes
# Positive control for 44a: the cache's validity is open_file_cache_valid,
# and with no open_file_cache there is no validity to honour, so nothing
# is remembered and every request reads the frame header afresh.
--- log_level: debug
--- user_files eval
[ [ "page/good.shtml" => '<!--#include virtual="/st/hello.js" --><!--#include virtual="/st/hello.js" --><!--#include virtual="/st/hello.js" -->' ],
  [ "st/hello.js" => $::src ], [ "st/hello.js.zst" => $::zst ] ]
--- config
    location /page/ {
        ssi on;
        default_type text/html;
        root html;
    }
    location /st/ {
        compression_static on;
        compression_static_order zstd;
        root html;
    }
--- request
GET /page/good.shtml
--- more_headers
Accept-Encoding: zstd
--- grep_error_log eval
qr/compression static probe:|cached good frame verdict/
--- grep_error_log_out
compression static probe:
compression static probe:
compression static probe:
--- no_error_log
[error]
