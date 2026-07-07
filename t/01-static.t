use Test::Nginx::Socket;
use File::Basename;
use lib 'lib';

my @dynamic_modules;
if (defined $ENV{'TEST_NGINX_BINARY'}) {
    my $nginx_dir = dirname($ENV{'TEST_NGINX_BINARY'});
    for my $module_name (qw(ngx_http_zstd_filter_module.so ngx_http_zstd_static_module.so)) {
        my $module_path = "$nginx_dir/$module_name";
        push @dynamic_modules, $module_path if -f $module_path;
    }
}

add_block_preprocessor(sub {
    my $block = shift;
    return if !@dynamic_modules;

    my $main_config = join "\n", map { "load_module $_;" } @dynamic_modules;
    $block->set_value("main_config", $main_config);
});

no_long_string();
log_level 'debug';
repeat_each(3);
plan 'no_plan';
run_tests();

# COVERAGE NOTES on gaps found by the git-history CI audit
# (kept above __DATA__ so they are not parsed into any test block):
#
# Gap 2 — f7e2ef3 ("clear Accept-Ranges in static module"):
# deliberately NOT covered by a black-box test here. The static
# handler serves a local file and never sets r->allow_ranges (in this
# nginx, only the upstream/proxy path sets it — see
# ngx_http_upstream.c, and ngx_http_range_filter_module.c bails unless
# r->allow_ranges). ngx_http_clear_accept_ranges() in the static
# module is therefore purely defensive: no request reachable through
# zstd_static alone makes the pre-fix and fixed builds differ
# (empirically verified — identical 200, no Accept-Ranges, no
# Content-Range, on both a pre-f7e2ef3 and a fixed .so). A Perl test
# asserting !Accept-Ranges would PASS on the buggy build too, i.e. be
# blind. Per the project's fail-first discipline we do not add a test
# that cannot fail on the unfixed code.
#
# Gap 3 — HTTP/2 transport axis (8281baa bug-B class):
# the build enables --with-http_v2_module but nothing tests the h2
# path. HTTP/2 in nginx requires TLS + ALPN/Upgrade negotiation; h2c
# (cleartext) does not work without Upgrade in nginx config. A Python
# test without TLS cannot easily drive the h2 path. The bug-B defect
# (empty-buffer, flush-state-machine, c->buffered accounting) is
# already well-covered by test_proxy_unbuffered_truncation.py
# (HTTP/1.1) and the matrix under ASAN; the h2-specific framing path
# would be redundant effort without adding coverage for a new code
# path. Left for future work when/if CI adds TLS test infrastructure.


__DATA__


=== TEST 1: zstd_static off
--- config
    location /test {
        zstd_static off;
        root ../../t/suite;
    }
--- request
GET /test
--- response_headers
Content-Length: 59738
ETag: "5be17d33-e95a"
!Content-Encoding
--- no_error_log
[error]



=== TEST 2: zstd_static off (with accept-encoding header)
--- config
    location /test {
        zstd_static off;
        root ../../t/suite;
    }
--- request
GET /test
Accept-Encoding: gzip,zstd
--- response_headers
Content-Length: 59738
ETag: "5be17d33-e95a"
!Content-Encoding
--- no_error_log
[error]



=== TEST 3: zstd_static on
--- config
    location /test {
        zstd_static on;
        root ../../t/suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: gzip, zstd
--- response_headers
Content-Length: 3717
ETag: "5be17d33-e85"
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 4: zstd_static on (without accept-encoding header)
--- config
    location /test {
        zstd_static on;
        root ../../t/suite;
    }
--- request
GET /test
--- response_headers
Content-Length: 59738
ETag: "5be17d33-e95a"
!Content-Encoding
--- no_error_log
[error]



=== TEST 5: zstd_static on (without zstd component in accept-encoding header)
--- config
    location /test {
        zstd_static on;
        root ../../t/suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: gzip, br
--- response_headers
Content-Length: 59738
ETag: "5be17d33-e95a"
!Content-Encoding
--- no_error_log
[error]



=== TEST 6: zstd_static always
--- config
    location /test {
        zstd_static always;
        root ../../t/suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: gzip, br
--- response_headers
Content-Length: 3717
ETag: "5be17d33-e85"
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 7: zstd_static always (without accept-encoding header)
--- config
    location /test {
        zstd_static always;
        root ../../t/suite;
    }
--- request
GET /test
--- response_headers
Content-Length: 3717
ETag: "5be17d33-e85"
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 8: zstd_static always (without zstd component in accept-encoding header)
--- config
    location /test {
        zstd_static always;
        root ../../t/suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: gzip, br
--- response_headers
Content-Length: 3717
ETag: "5be17d33-e85"
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 9: zstd_static always (file does not exist)
--- config
    location /test2 {
        zstd_static always;
        root ../../t/suite;
    }
--- request
GET /test2
--- more_headers
Accept-Encoding: gzip, br
--- error_code: 404



=== TEST 10: zstd_static on (file does not exist)
--- config
    location /test2 {
        zstd_static on;
        root ../../t/suite;
    }
--- request
GET /test2
--- more_headers
Accept-Encoding: gzip, br
--- error_code: 404



=== TEST 11: zstd_static off (file does not exist)
--- config
    location /test2 {
        zstd_static off;
        root ../../t/suite;
    }
--- request
GET /test2
--- more_headers
Accept-Encoding: gzip, br
--- error_code: 404



=== TEST 12: zstd_static on with quality value q=0 (reject)
--- config
    location /test {
        zstd_static on;
        root ../../t/suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: zstd;q=0, gzip;q=1
--- response_headers
Content-Length: 59738
ETag: "5be17d33-e95a"
!Content-Encoding
--- no_error_log
[error]



=== TEST 13: zstd_static on with quality value q=0.5 (accept lower)
--- config
    location /test {
        zstd_static on;
        root ../../t/suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: zstd;q=0.5
--- response_headers
Content-Length: 3717
ETag: "5be17d33-e85"
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 14: zstd_static always with q=0 (still serve zst)
--- config
    location /test {
        zstd_static always;
        root ../../t/suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: zstd;q=0
--- response_headers
Content-Length: 3717
ETag: "5be17d33-e85"
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 15: zstd_static on with gzip_vary and gzip support
--- config
    location /test {
        zstd_static on;
        gzip_vary on;
        root ../../t/suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: gzip, zstd
--- response_headers
Content-Length: 3717
ETag: "5be17d33-e85"
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 16: zstd_static on with gzip_vary but no zstd support
--- config
    location /test {
        zstd_static on;
        gzip_vary on;
        root ../../t/suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: gzip
--- response_headers
Content-Length: 59738
ETag: "5be17d33-e95a"
!Content-Encoding
--- no_error_log
[error]



=== TEST 17: zstd_static on - HEAD request
--- config
    location /test {
        zstd_static on;
        root ../../t/suite;
    }
--- request
HEAD /test
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Length: 3717
ETag: "5be17d33-e85"
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 18: zstd_static on - POST request (not GET/HEAD)
--- config
    location /test {
        zstd_static on;
        root ../../t/suite;
    }
--- request
POST /test
--- more_headers
Accept-Encoding: zstd
--- error_code: 405
--- response_headers
!Content-Encoding



=== TEST 19: zstd_dict_file loads and serves correctly (filter path)
# Regression for the untested zstd_dict_file feature, which had three
# distinct historical bug fixes with NO test: 0fb40d9 (CDict leak on
# cleanup), 50f27a8 (version-specific init error handling), f735a5d
# (cleanup handler size). This is the first test that exercises a
# dictionary at all: nginx must start with zstd_dict_file set and still
# produce a valid compressed response.
# zstd_dict_file is an http{}-context directive (NGX_HTTP_MAIN_CONF), so
# it goes in --- http_config, not --- main_config (global, before http{}).
# Relative paths resolve against the *configuration* prefix (conf/), while
# --- user_files land in <servroot>/html, so use the absolute servroot
# token Test::Nginx exports for this exact purpose.
--- http_config
    zstd_dict_file_unsafe on;
    zstd_dict_file $TEST_NGINX_SERVER_ROOT/html/zstd.dict;
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/src;
    }
    location /src {
        default_type text/plain;
        return 200 "dictionary compressed body, long enough to compress\n";
    }
--- user_files
>>> zstd.dict
the quick brown fox jumps over the lazy dog 0123456789 dictionary sample payload for zstd training corpus padding padding padding
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 20: zstd_static handles a long URI without buffer overflow
# Regression for 9789448 "buffer overflow when appending .zst extension".
# A long request path stresses the .zst path-build reservation made via
# ngx_http_map_uri_to_path(sizeof(".zst")). Missing file -> clean 404,
# no crash, no ASAN abort (the ASAN test job runs this binary too).
--- config
    location /s/ {
        zstd_static on;
        root ../../t/suite;
    }
--- request eval
"GET /s/" . ("a" x 2000) . "/nonexistent-resource-name"
--- error_code: 404
--- response_headers
!Content-Encoding
--- no_error_log
[alert]



=== TEST 21: zstd_static rejects a file whose contents are not a zstd frame
# Defence-in-depth: a .zst whose first 4 bytes are not the zstd magic
# (truncated download, mistakenly renamed text, `cp foo.txt foo.zst`)
# must NOT be served with Content-Encoding: zstd — the client would
# receive an undecodable body. The handler pread()s the leading 4
# bytes, checks them against ZSTD_MAGICNUMBER / ZSTD_MAGIC_SKIPPABLE_*,
# and declines on mismatch. The fixture below contains plain ASCII
# ("HELO ...") with no zstd magic; no uncompressed fallback file is
# placed alongside it, so the request falls through to a clean 404.
--- config
    location /bogus {
        zstd_static on;
        root html;
    }
--- user_files
>>> bogus.zst
HELO this is not a zstd frame
--- request
GET /bogus
--- more_headers
Accept-Encoding: zstd
--- error_code: 404
--- response_headers
!Content-Encoding
--- error_log
is not a zstd frame



=== TEST 22: zstd_static always does NOT set Vary even with gzip_vary on
# Locks intentional behaviour: in "always" mode the handler unconditionally
# serves the precompressed .zst and never sets r->gzip_vary. Vary:
# Accept-Encoding would mis-key shared caches for a response that does
# not actually vary on Accept-Encoding (the same .zst comes back no
# matter what the client sends), so the absence of Vary here is the
# correct contract. TEST 6-8 cover "always" without gzip_vary; this
# locks that adding gzip_vary on at the location does not flip the
# behaviour by accident.
--- config
    gzip_vary on;
    location /test {
        zstd_static always;
        root ../../t/suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: gzip, br
--- response_headers
Content-Length: 3717
ETag: "5be17d33-e85"
Content-Encoding: zstd
!Vary
--- no_error_log
[error]



=== TEST 23: zstd_static rejects an empty .zst file
# A zero-byte .zst cannot satisfy the 4-byte pread() magic check;
# the handler must decline rather than serve an empty body with
# Content-Encoding: zstd. TEST 21 covers the wrong-magic case;
# this locks the truncated-to-zero edge specifically. Like TEST 21,
# no uncompressed fallback is placed alongside empty.zst, so a
# benign ENOENT on the fallback path is expected and not asserted
# against.
--- config
    location /empty {
        zstd_static on;
        root html;
    }
--- user_files
>>> empty.zst
--- request
GET /empty
--- more_headers
Accept-Encoding: zstd
--- error_code: 404
--- response_headers
!Content-Encoding



=== TEST 24: zstd_static declines a directory-style request
# A request whose URI ends in "/" maps to a path with a trailing
# slash; appending ".zst" would produce ".../.zst". The handler
# short-circuits at the URI-suffix check (uri.data[uri.len - 1]
# == '/') and declines without touching the filesystem, so the
# request falls through to the normal directory-index machinery
# rather than being answered with Content-Encoding: zstd. The
# fallback then 403s the directory and logs the missing index file
# — that log line is from the regular static handler, not from
# zstd_static, and is expected here. The contract being locked is
# only !Content-Encoding (i.e. zstd_static did not falsely claim
# the response was zstd-encoded).
--- config
    location /dir/ {
        zstd_static on;
        root ../../t/suite;
    }
--- request
GET /dir/
--- more_headers
Accept-Encoding: zstd
--- error_code: 404
--- response_headers
!Content-Encoding



=== TEST 25: zstd_static on sets Vary even when declining for a non-accepting client
# Subtle behaviour at static.c:204 — when zstd_static is "on" and
# the .zst exists, the handler sets r->gzip_vary = 1 *before*
# declining for a client that does not accept zstd. That keeps the
# response cacheable by intermediaries that key on Vary, so a later
# request from a zstd-capable client through the same shared cache
# gets the encoded variant rather than the identity one. Without
# this, a CDN that saw the identity response first would pin all
# subsequent clients to it.
--- config
    gzip_vary on;
    location /test {
        zstd_static on;
        root ../../t/suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: gzip
--- response_headers
!Content-Encoding
Vary: Accept-Encoding
--- no_error_log
[error]



=== TEST 26: zstd_static serves a .zst under directio without a failed pread
# Regression for the O_DIRECT magic-probe bug. With "directio" active the
# open_file_cache opens the .zst with O_DIRECT; the 4-byte, unaligned
# magic pread() then fails EINVAL, wrongly declining every .zst above the
# threshold and spamming NGX_LOG_CRIT. The fix skips the probe when
# of.is_directio. Assert the precompressed frame is still served (200 +
# Content-Encoding: zstd) and no CRIT/[error] appears.
#
# NOTE: O_DIRECT support is filesystem-dependent (tmpfs may not honour it),
# so this deterministically catches the "declined + CRIT" regression only
# where O_DIRECT actually engages; everywhere else it still asserts correct
# serving. directio 1 = every file >= 1 byte is eligible (test.zst is 3717B).
--- config
    location /test {
        zstd_static on;
        directio 1;
        root ../../t/suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- error_code: 200
--- no_error_log
[error]
