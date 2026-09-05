use Test::Nginx::Socket;

# Phase-0 election matrix as a regression suite: the shell matrix from
# the PR validation, graduated. Needs a binary built with
# --add-module=<repo>/compression AND the core gzip module (the defer
# cases exercise the real handoff; the gzip-less build shape has its
# own compile-time coverage in CI-to-be).

no_long_string();
log_level 'warn';
repeat_each(1);
plan 'no_plan';
run_tests();

__DATA__


=== TEST 1: default order elects zstd when everything is acceptable
--- config
    location /t {
        compression on;
        compression_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd, br, gzip
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 2: zstd unacceptable, brotli next in the default order
--- config
    location /t {
        compression on;
        compression_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br, gzip
--- response_headers
Content-Encoding: br
--- no_error_log
[error]



=== TEST 3: gzip-only client -> DEFER, the core gzip filter compresses
# The Content-Encoding here is produced by core gzip, not this module:
# the election stands aside without touching the r->gzip_tested latch,
# and gzip's entire rule set (gzip_types included) applies downstream.
--- config
    location /t {
        compression on;
        compression_min_length 1;
        gzip on;
        gzip_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: gzip
--- response_headers
Content-Encoding: gzip
--- no_error_log
[error]



=== TEST 4: q=0 excludes a coding the order would otherwise elect
--- config
    location /t {
        compression on;
        compression_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd;q=0, br
--- response_headers
Content-Encoding: br
--- no_error_log
[error]



=== TEST 5: explicit order is honored over the default
--- config
    location /t {
        compression on;
        compression_order br zstd gzip;
        compression_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd, br
--- response_headers
Content-Encoding: br
--- no_error_log
[error]



=== TEST 6: gzip FIRST in an explicit order wins by deferral
--- config
    location /t {
        compression on;
        compression_order gzip zstd br;
        compression_min_length 1;
        gzip on;
        gzip_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: gzip, zstd, br
--- response_headers
Content-Encoding: gzip
--- no_error_log
[error]



=== TEST 7: gzip-first order falls through when the client never offers gzip
--- config
    location /t {
        compression on;
        compression_order gzip zstd br;
        compression_min_length 1;
        gzip on;
        gzip_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd, br
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 8: gzip absent from an explicit list is VETOED despite gzip on
# The concluded election latches r->gzip_tested, so a gzip-only client
# gets identity even though the core gzip filter would happily serve it.
--- config
    location /t {
        compression on;
        compression_order zstd br;
        compression_min_length 1;
        gzip on;
        gzip_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: gzip
--- raw_response_headers_unlike: Content-Encoding
--- response_body
election fixture body, long enough to compress meaningfully
--- no_error_log
[error]



=== TEST 9: compression off is the migration floor — core gzip untouched
--- config
    location /t {
        compression off;
        gzip on;
        gzip_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: gzip, zstd, br
--- response_headers
Content-Encoding: gzip
--- no_error_log
[error]



=== TEST 10: no Accept-Encoding -> identity, Vary still emitted
--- config
    location /t {
        compression on;
        compression_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- raw_response_headers_like: Vary: Accept-Encoding
--- raw_response_headers_unlike: Content-Encoding
--- response_body
election fixture body, long enough to compress meaningfully
--- no_error_log
[error]



=== TEST 11: "*" wildcard elects the first base coding in the order
--- config
    location /t {
        compression on;
        compression_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: *
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 12: compression_min_length gates small responses to identity
--- config
    location /t {
        compression on;
        compression_min_length 4096;
        default_type text/html;
        gzip_vary on;
        return 200 "small body\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd, br
--- raw_response_headers_unlike: Content-Encoding
--- response_body
small body
--- no_error_log
[error]



=== TEST 13: compression_types gates non-matching content types
# application/json is not in a text/css list, so the response stays
# identity. (text/html deliberately NOT used as the blocked type here —
# see TEST 13b.)
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/css;
        default_type application/json;
        gzip_vary on;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd, br
--- raw_response_headers_unlike: Content-Encoding
--- no_error_log
[error]



=== TEST 13b: text/html always passes the types gate (inherited quirk, pinned)
# ngx_http_types_slot force-seeds text/html into every types list —
# the documented gzip_types behavior ("responses with the text/html
# type are always compressed"), impossible to exclude. This module
# uses the standard slot ON PURPOSE, for semantic consistency with
# gzip_types/zstd_types/brotli_types; this block pins the inheritance
# so a future "fix" that breaks consistency announces itself. Found
# while writing TEST 13, which first used text/html as the blocked
# type and discovered it cannot be.
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/css;
        default_type text/html;
        gzip_vary on;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd, br
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 14: unknown coding in compression_order is a config error
--- config
    location /t {
        compression_order zstd lzma;
        return 200 "x";
    }
--- must_die
--- error_log
unknown coding "lzma"
--- no_error_log
[alert]



=== TEST 15: duplicate coding in compression_order is a config error
# the order list IS the enable set; a coding may appear once
--- config
    location /t {
        compression_order zstd br zstd;
        return 200 "x";
    }
--- must_die
--- error_log
duplicate coding "zstd"
--- no_error_log
[alert]



=== TEST 16: compression on without gzip_vary still emits Vary by construction
# Parent #163: the header filter emits Vary: Accept-Encoding itself, so
# "gzip_vary off" (the default) no longer ships a negotiated compressed
# body with no Vary — the shared-cache poisoning hazard — and there is
# nothing to warn about.
--- config
    location /t {
        compression on;
        compression_min_length 1;
        default_type text/html;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
Vary: Accept-Encoding
--- no_error_log eval
[qr/"gzip_vary" is off/, qr/\[error\]/]



=== TEST 17: compression WITH gzip_vary emits exactly one Vary line
# gzip_vary on -> nginx emits from r->gzip_vary and we push nothing;
# Test::Nginx folds duplicate field lines with ", ", so a single
# "Accept-Encoding" proves the two emitters did not both fire.
--- config
    location /t {
        compression on;
        compression_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- response_headers
Vary: Accept-Encoding
--- no_error_log eval
[qr/"gzip_vary" is off/, qr/\[error\]/]



=== TEST 18: a body exactly at the default min_length compresses
# the gate is `< min_length` (default 20): equality passes
--- config
    location /t {
        compression on;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "12345678901234567890";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 19: one byte under the default min_length stays identity
--- config
    location /t {
        compression on;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "1234567890123456789";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Content-Encoding
--- response_body chomp
1234567890123456789
--- no_error_log
[error]



=== TEST 20a: a 404 body is eligible (parent status-set parity)
# error responses are often the most-served compressible content on a
# busy origin; the parent zstd filter includes 403/404 deliberately
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 404 "this 404 body is long enough to compress\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- error_code: 404
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 20b: a 403 body is eligible
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 403 "this 403 body is long enough to compress\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- error_code: 403
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 20c: a 500 body is NOT eligible (outside the status set)
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 500 "this 500 body is long enough to compress\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- error_code: 500
--- raw_response_headers_unlike: Content-Encoding
--- no_error_log
[error]



=== TEST 20d: a 302 is NOT eligible (3xx outside 403/404 carve-outs)
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 302 "moved body text long enough to compress\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- error_code: 302
--- raw_response_headers_unlike: Content-Encoding
--- no_error_log
[error]



=== TEST 21a: application/wasm compresses by DEFAULT (parent-parity types)
# the phase-0 html-only default was a silent regression against the
# parent's rich default list (caught via issue #123's fork read);
# wasm is the canary — text-like content under a non-text media type
--- config
    location /t {
        compression on;
        default_type application/wasm;
        gzip_vary on;
        return 200 "wasm-shaped body long enough to clear min_length\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]


=== TEST 21b: application/octet-stream does NOT compress by default
# the default list is deliberate, not a wildcard
--- config
    location /t {
        compression on;
        default_type application/octet-stream;
        gzip_vary on;
        return 200 "octet-stream body long enough to clear min_length\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Content-Encoding
--- no_error_log
[error]


=== TEST 21c: an explicit compression_types still replaces the defaults
# text/plain is IN the default list but absent from this explicit one:
# it must not compress (the directive replaces, text/html seeding aside)
--- config
    location /t {
        compression on;
        compression_types text/css;
        default_type text/plain;
        gzip_vary on;
        return 200 "plain body long enough to clear the min_length gate\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Content-Encoding
--- no_error_log
[error]


=== TEST 22a: a quoted parameter cannot smuggle a coding token
# gzip;foo="bar,zstd" — the comma and the token live INSIDE a quoted
# string; a naive comma-splitter sees `zstd"` and elects zstd for a
# client that never offered it (vector from GetPageSpeed's fork suite,
# via issue #123; our parser already handled it — now it's pinned)
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "quoted-string vector body long enough here\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: gzip;foo="bar,zstd"
--- raw_response_headers_unlike: Content-Encoding
--- no_error_log
[error]


=== TEST 22b: ...and a real token after the quoted parameter still elects
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "quoted-string vector body long enough here\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: gzip;foo="bar,zstd", zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 23a: a declared body above compression_max_length stays identity
# the worker-protection ceiling (parents' zstd_max_length /
# brotli_max_length): known-size bodies above it skip compression
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_max_length 100;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "this body is comfortably longer than the one hundred byte compression_max_length ceiling configured above";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Content-Encoding
--- no_error_log
[error]


=== TEST 23b: under the ceiling compresses as usual
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_max_length 10k;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "this body sits well under the ten kilobyte ceiling\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]


=== TEST 23c: the RUNNING cap aborts an undeclared over-length stream
# SSI strips Content-Length, so the header gate sees nothing to reject;
# the body filter's running counter must catch the overage mid-stream
# and fail the request (compression already started — aborting protects
# the worker, completing one runaway response does not)
--- user_files eval
[ [ "p/page.shtml" => qq{<!--#include virtual="/p/big.html" -->\n} ],
  [ "p/big.html" => ("ssi cap fixture line\n" x 2000) ] ]
--- config
    location /p/ {
        ssi on;
        default_type text/html;   # the SSI filter only touches ssi_types
        compression on;
        compression_min_length 1;
        compression_max_length 2k;
        gzip_vary on;
        root html;
    }
--- request
GET /p/page.shtml
--- more_headers
Accept-Encoding: zstd
--- ignore_response
--- error_log
input exceeded compression_max_length


=== TEST 24a: $compression_ratio computation path (overflow-guard parity)
# log-phase variable; referencing it forces registration + the scaled
# division on a body big enough to make bytes_in*1000 large (the
# parent's 064895c overflow lesson)
--- user_files eval
[ [ "t/big.txt" => ("ratio fixture line with some repetition\n" x 1500) ] ]
--- config
    location /t/ {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        set $unused $compression_ratio;
        root html;
    }
--- request
GET /t/big.txt
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]


=== TEST 24b: ratio and byte counters land in the access log
# the variables are meaningful only at log phase; a second request
# reads the log line the first one wrote
--- http_config
    log_format ctest "ratio=$compression_ratio in=$compression_bytes_in out=$compression_bytes_out";
--- user_files eval
[ [ "t/body.txt" => ("countable fixture line\n" x 50) ] ]
--- config
    location /t/ {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        access_log logs/ctest.log ctest;
        root html;
    }
    location = /rlog {
        alias logs/ctest.log;
        default_type text/plain;
    }
--- request eval
["GET /t/body.txt", "GET /rlog"]
--- more_headers
Accept-Encoding: zstd
--- response_body_like eval
[qr/./, qr/ratio=\d+\.\d{3} in=1150 out=\d+/]



=== TEST 25a: HTTP/1.0 requests defer — identity by default
# the protocol floor (gzip_http_version parity, default 1.1): an
# RFC 1945-era client is gzip-at-best, so the election never runs and
# core gzip's own version rule applies (also 1.1 by default -> identity)
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "http/1.0 floor fixture body long enough to compress\n";
    }
--- request
GET /t HTTP/1.0
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Content-Encoding
--- no_error_log
[error]


=== TEST 25b: the floor is an operator choice — 1.0 compresses when lowered
--- config
    location /t {
        compression on;
        compression_http_version 1.0;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "http/1.0 floor fixture body long enough to compress\n";
    }
--- request
GET /t HTTP/1.0
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]


=== TEST 25c: the version skip is a DEFERRAL, not a veto
# core gzip below still applies its own rules: with gzip_http_version
# lowered, an HTTP/1.0 gzip client gets gzip from the core filter —
# "as good as it gets" working end to end
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        gzip on;
        gzip_min_length 1;
        gzip_types text/plain;
        gzip_http_version 1.0;
        default_type text/plain;
        gzip_vary on;
        return 200 "http/1.0 floor fixture body long enough to compress\n";
    }
--- request
GET /t HTTP/1.0
--- more_headers
Accept-Encoding: gzip, zstd
--- response_headers
Content-Encoding: gzip
--- no_error_log
[error]



=== TEST 26a: HEAD advertises the same Content-Encoding its GET would
# parent-audit find: the phase-0 header_only skip made HEAD and GET
# disagree about the representation; core gzip advertises on HEAD
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "head parity fixture body long enough to compress\n";
    }
--- request
HEAD /t
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]


=== TEST 26b: the compression flag works inside an if-block (LIF parity)
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        if ($arg_off) {
            compression off;
        }
        return 200 "if-block fixture body long enough to compress here\n";
    }
--- request
GET /t?off=1
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Content-Encoding
--- no_error_log
[error]


=== TEST 26c: ...and stays on outside the if-arm
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        if ($arg_off) {
            compression off;
        }
        return 200 "if-block fixture body long enough to compress here\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 27a: an upstream 206 is never compressed (status set)
# a 206 that reaches the filter already sliced must pass untouched —
# compressing the slice would corrupt the representation
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 206 "partial content fixture body long enough here\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- error_code: 206
--- raw_response_headers_unlike: Content-Encoding
--- no_error_log
[error]


=== TEST 27a2: Range + compressible = full 200, compressed (gzip parity)
# dynamic compression and byte ranges do not compose: once the filter
# sets Content-Encoding the range filter stands down, exactly like
# core gzip — the client gets the complete compressed representation
--- user_files eval
[ [ "r/plain.txt" => ("range fixture line\n" x 40) ] ]
--- config
    location /r/ {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /r/plain.txt
--- more_headers
Accept-Encoding: zstd
Range: bytes=0-9
--- error_code: 200
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]


=== TEST 27a3: without compression in play, the same range slices (206)
--- user_files eval
[ [ "r/plain.txt" => ("range fixture line\n" x 40) ] ]
--- config
    location /r/ {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /r/plain.txt
--- more_headers
Range: bytes=0-9
--- error_code: 206
--- raw_response_headers_unlike: Content-Encoding
--- response_body chomp
range fixt
--- no_error_log
[error]


=== TEST 27b: Content-Encoding is emitted exactly once on the wire
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "single content-encoding fixture body long enough\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- raw_response_headers_unlike eval
qr/Content-Encoding:.*Content-Encoding:/s
--- no_error_log
[error]


=== TEST 27c: a zero-length proxied body neither spins nor corrupts
# the parent's infinite-loop regression class: an empty upstream body
# through the filter must FINISH cleanly (an empty frame is valid)
--- config
    location /t {
        compression on;
        compression_min_length 0;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/empty;
    }
    location /empty {
        default_type text/plain;
        return 200 "";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- error_code: 200
--- no_error_log
[error]


=== TEST 28a: omitted compression_types includes text/wgsl
--- config
    location /t {
        compression on;
        default_type text/wgsl;
        gzip_vary on;
        return 200 "wgsl shader-shaped fixture body long enough to compress\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]


=== TEST 28b: omitted compression_types includes text/csv
--- config
    location /t {
        compression on;
        default_type text/csv;
        gzip_vary on;
        return 200 "csv,fixture,body,long,enough,to,compress,meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]


=== TEST 28c: omitted compression_types includes application/x-ndjson
--- config
    location /t {
        compression on;
        default_type application/x-ndjson;
        gzip_vary on;
        return 200 "{\"ndjson\":\"fixture body long enough to compress\"}\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]


=== TEST 28d: omitted compression_types includes application/json-seq
--- config
    location /t {
        compression on;
        default_type application/json-seq;
        gzip_vary on;
        return 200 "{\"jsonseq\":\"fixture body long enough to compress\"}\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]


=== TEST 29a: compression on without gzip_vary does NOT warn (parent #163)
--- config
    location /t {
        compression on;
        default_type text/html;
        return 200 "warn fixture body long enough to compress here\n";
    }
--- request
GET /t
--- no_error_log eval
[qr/gzip_vary/, qr/\[error\]/]


=== TEST 29b: compression on WITH gzip_vary does not warn
--- config
    location /t {
        compression on;
        default_type text/html;
        gzip_vary on;
        return 200 "warn fixture body long enough to compress here\n";
    }
--- request
GET /t
--- no_error_log eval
qr/gzip_vary/
