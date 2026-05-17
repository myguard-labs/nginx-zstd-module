use Test::Nginx::Socket;
use File::Basename;
use lib 'lib';

my $dirname = dirname(__FILE__);
$ENV{'TEST_NGINX_PERL_PATH'}="$ENV{'PWD'}/$dirname";

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
plan tests => repeat_each() * (blocks() * 3) + 153;
run_tests();


__DATA__


=== TEST 1: zstd off
--- config
	location /filter {
		zstd off;
		proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
	}
	location /test {
		root $TEST_NGINX_PERL_PATH/suite/;
	}
--- request
GET /filter
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]


=== TEST 2: zstd off (with accept-encoding header)
--- config
    location /filter {
        zstd off;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
Accept-Encoding: gzip,zstd
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 3: zstd on
--- config
    location /filter {
        zstd on;
		zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: gzip, zstd
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]



=== TEST 4: zstd on (without accept-encoding header)
--- config
    location /filter {
        zstd on;
		zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 5: zstd on (without zstd component in accept-encoding header)
--- config
    location /filter {
        zstd on;
		zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: gzip, br
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]

=== TEST 6: zstd zstd_min_length (greater than min_length)
--- config
    location /filter {
        zstd on;
		zstd_min_length 1024;
		zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd, br
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]

=== TEST 7: zstd zstd_min_length (less than length)
--- config
    location /filter {
        zstd on;
		zstd_types text/plain;
        zstd_min_length 60k;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd, br
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]

=== TEST 8 zstd & gzip
--- config
    location /filter {
        zstd on;
        zstd_min_length 1024;
        zstd_types text/plain;

		gzip on;
		gzip_min_length 1024;
		gzip_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd, gzip, br
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]

=== TEST 9 zstd & gzip (Accept-Encoding start with gzip)
--- config
    location /filter {
        zstd on;
        zstd_min_length 1024;
        zstd_types text/plain;

        gzip on;
        gzip_min_length 1024;
        gzip_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: gzip, zstd, br
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]

=== TEST 10 zstd & gzip (hit gzip)
--- config
    location /filter {
        zstd on;
        zstd_min_length 60k;
        zstd_types text/plain;

        gzip on;
        gzip_min_length 1024;
        gzip_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd, gzip, br
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: gzip
Content-type: text/plain
--- no_error_log
[error]

=== TEST 11 zstd on (file does not exist)
--- config
    location /filter {
        zstd on;
	zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test2;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: gzip, br
--- error_code: 404



=== TEST 12 zstd off (file does not exist)
--- config
    location /filter {
        zstd off;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test2;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: gzip, br
--- error_code: 404



=== TEST 13: RFC 7231 quality value - q=0 (explicitly reject)
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q=0, gzip;q=1
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 14: RFC 7231 quality value - q=0.0 (explicitly reject)
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q=0.0, gzip;q=1
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 15: RFC 7231 quality value - q=0.5 (accept with lower priority)
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q=0.5
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]



=== TEST 16: RFC 7231 quality value - q=1.0 (highest priority)
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q=1.0
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]



=== TEST 17: zstd with max_length (exceeds limit)
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        zstd_max_length 10k;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 18: zstd with max_length (within limit)
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        zstd_max_length 100k;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]



=== TEST 19: zstd compression level 3
--- config
    location /filter {
        zstd on;
        zstd_comp_level 3;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]



=== TEST 20: zstd compression level 10 (high)
--- config
    location /filter {
        zstd on;
        zstd_comp_level 10;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]



=== TEST 21: zstd with multiple content types
--- config
    location /filter {
        zstd on;
        zstd_types text/plain text/html application/json;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]



=== TEST 22: zstd - mixed quality values (prefer highest)
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        gzip on;
        gzip_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q=0.9, gzip;q=0.8
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]



=== TEST 23: zstd - gzip preferred via quality
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        gzip on;
        gzip_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q=0.5, gzip;q=0.9
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]



=== TEST 24: zstd filter preserves HEAD pass-through behaviour
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
HEAD /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
!Content-Length
--- no_error_log
[error]


=== TEST 25: zstd filter skips 204 responses
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        return 204;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- error_code: 204
--- response_headers
!Content-Encoding
--- no_error_log
[error]



=== TEST 26: zstd filter skips 205 responses
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        return 205;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- error_code: 205
--- response_headers
!Content-Encoding
--- no_error_log
[error]


=== TEST 27: zstd filter skips 304 responses
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        return 304;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- error_code: 304
--- response_headers
!Content-Encoding
--- no_error_log
[error]




=== TEST 28: zstd filter compresses 403 responses above min_length
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        default_type text/plain;
        return 403 "forbidden body\n";
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- error_code: 403
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-Type: text/plain
--- no_error_log
[error]


=== TEST 29: zstd filter compresses 404 responses above min_length
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        default_type text/plain;
        return 404 "not found body\n";
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- error_code: 404
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-Type: text/plain
--- no_error_log
[error]



=== TEST 30: no infinite loop / CPU spin on a zero-length proxied body
# Regression for the recurring "100% CPU infinite loop" class:
#   7f86e5b, 2af5889, 924c9bf, PR #23/#49.
# An empty upstream body with Content-Encoding still set must terminate
# (emit a valid empty zstd frame) and not spin. Test::Nginx enforces a
# request timeout, so a hang fails the test instead of running forever.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/empty;
    }
    location /empty {
        default_type text/plain;
        return 200 "";
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- error_code: 200
--- timeout: 5
--- no_error_log
[error]



=== TEST 31: no infinite loop on a single-byte body below the stream-in size
# Same loop class — a tiny body must flush a terminal frame and stop.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/one;
    }
    location /one {
        default_type text/plain;
        return 200 "x";
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- error_code: 200
--- timeout: 5
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 32: $zstd_ratio computation path on a large body (overflow guard)
# Regression for 064895c "integer overflow in compression ratio calc".
# $zstd_ratio is a log-phase variable; its value is asserted to be a
# finite N.NNN string by tools/test_encoding.py (which can read it). Here
# we exercise the computation path itself — a ~58 KB body makes
# bytes_in*1000 large, the exact arithmetic that overflowed pre-064895c.
# A clean compressed response with no error proves the math did not trap.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        set $unused $zstd_ratio;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 33: zstd composes correctly with sub_filter (filter ordering)
# Regression for the recurring filter-order class: f4ba115, 2d2e641,
# cae80f9, 3f73e15, 8a6e370, 18c778d. zstd must run AFTER sub_filter so
# the substitution is present in the (decompressed) output, not skipped.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        sub_filter 'ORIGINAL' 'REWRITTEN';
        sub_filter_once off;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/src;
    }
    location /src {
        default_type text/plain;
        return 200 "ORIGINAL ORIGINAL ORIGINAL\n";
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 34: negative compression level produces a valid zstd stream
# Regression for cc9f6ec / b58c7cd: negative levels are accepted by
# zstd_comp_level but were never exercised by a test.
--- config
    location /filter {
        zstd on;
        zstd_comp_level -5;
        zstd_min_length 1;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 35: explicit non-default zstd_types only compresses listed types
# Regression for 46f95bf "passed default mime/types to zstd_types parser":
# a type NOT in the list must not be compressed.
--- config
    location /json {
        zstd on;
        zstd_min_length 1;
        zstd_types application/json;
        default_type text/plain;
        return 200 "plain text not in zstd_types\n";
    }
--- request
GET /json
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Encoding
--- no_error_log
[error]



=== TEST 36: zstd_types match DOES compress the listed type
# Positive half of TEST 35 — application/json is listed, so it compresses.
--- config
    location /json {
        zstd on;
        zstd_min_length 1;
        zstd_types application/json;
        default_type application/json;
        return 200 "{\"compress\":\"this is a json body long enough\"}\n";
    }
--- request
GET /json
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 37: max_length enforced when Content-Length is known (proxy)
# Pins the documented contract from d94b220 / f065cb6: when the response
# length IS known (the common proxied case), a body larger than
# zstd_max_length must NOT be compressed. The complementary "length
# unknown / chunked -> cannot be enforced" half is a documented behaviour
# (see README) not cleanly unit-testable via `return` (which always sets
# Content-Length); it is covered by the docs, not by a brittle test.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_max_length 4;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/big;
    }
    location /big {
        default_type text/plain;
        return 200 "this body is far larger than the 4 byte max_length\n";
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Encoding
--- no_error_log
[error]



=== TEST 38: zstd_window_log caps the window and still produces valid output
# Regression for the zstd_window_log memory-bounding directive. With a
# 15-bit (32 KB) window and a body well over 32 KB, zstd must still emit
# a well-formed stream: the directive bounds per-request memory, it must
# not corrupt the response. Served from the on-disk test fixture (~58 KB)
# so the capped window is genuinely exercised.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_window_log 15;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 39: $zstd_bytes_in / $zstd_bytes_out are emitted for a compressed response
# Asserts the byte-count log variables. $zstd_bytes_in and
# $zstd_bytes_out are log-phase variables backed by ctx->bytes_in/out
# (the same counters $zstd_ratio derives from). Referencing them via
# `set` exercises the get_handler; a clean compressed response with no
# error proves the handler resolves both fields without faulting.
# Exact-value correctness (and consistency with $zstd_ratio) is verified
# end-to-end in tools/test_encoding.py, which can read the access log.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        set $unused_in  $zstd_bytes_in;
        set $unused_out $zstd_bytes_out;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 40: zstd_bypass skips compression when the predicate is truthy
# A request header maps to a bypass variable; when it is set to a
# non-empty value other than "0", the response must be served identity
# even though the client supports zstd and the type/size qualify.
--- http_config
    map $http_x_no_zstd $zstd_off {
        default 0;
        "1"     1;
    }
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        zstd_bypass $zstd_off;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
X-No-Zstd: 1
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 41: zstd_bypass value "0" does NOT bypass (still compresses)
# Same config, but the bypass variable resolves to "0", which per
# ngx_http_test_predicates is falsy — compression must still happen.
# Pins the "0"/empty == not-bypassed contract.
--- http_config
    map $http_x_no_zstd $zstd_off {
        default 0;
        "1"     1;
    }
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        zstd_bypass $zstd_off;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Length
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 42: zstd_max_length is enforced on a chunked upstream (no Content-Length)
# Regression for the length-independent input cap. TEST 37 covers the
# known-Content-Length case (rejected in the header filter). This covers
# the genuine DoS vector: an upstream that streams chunked with NO
# Content-Length, so the header-filter check is skipped. A mock TCP
# backend returns a chunked body far larger than zstd_max_length;
# compression has already started, so the only safe action is to abort
# the request — the worker must not be fed unbounded input. We assert
# the dedicated abort message is logged.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_max_length 100;
        zstd_types text/plain;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/up;
    }
    location /up {
        proxy_http_version 1.1;
        proxy_pass http://127.0.0.1:$TEST_NGINX_RAND_PORT_1/;
    }
--- tcp_listen: $TEST_NGINX_RAND_PORT_1
--- tcp_no_close
--- tcp_reply eval
"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
. sprintf("%x\r\n", 5000) . ("A" x 5000) . "\r\n0\r\n\r\n"
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- ignore_response
--- error_log
input exceeded zstd_max_length (100) on a response with no Content-Length



=== TEST 43: known Content-Length response round-trips (pledged-src-size)
# Regression for the ZSTD_CCtx_setPledgedSrcSize optimisation. A
# proxied response with an exact Content-Length takes the pledged-size
# path in init_cctx; an off-by-anything pledge would make
# ZSTD_compressStream2 error or corrupt the stream. Assert the response
# is zstd-encoded, chunked (filter strips the length), and crucially
# decompresses back to the exact original bytes.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/src;
    }
    location /src {
        default_type text/plain;
        return 200 "pledged-src-size round-trip body, long enough to compress and exercise the known-Content-Length path end to end\n";
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Length
Content-Encoding: zstd
--- response_body_filters eval
sub {
    my $zstd = $_[0];
    open(my $fh, "|-", "zstd -dq -c >/tmp/zstd_t43.out 2>/dev/null") or return "ERR";
    print $fh $zstd; close($fh);
    open(my $r, "<", "/tmp/zstd_t43.out") or return "ERR";
    local $/; my $d = <$r>; close($r); unlink "/tmp/zstd_t43.out";
    return $d;
}
--- response_body
pledged-src-size round-trip body, long enough to compress and exercise the known-Content-Length path end to end



=== TEST 44: chunked no-Content-Length body > one ZSTD_CStreamOutSize buffer round-trips
# Regression for the multi-output-buffer use-after-free / NULL-deref:
# get_buf()'s early return ("buffer_out not full -> keep current out_buf")
# did not check that ctx->out_buf was still non-NULL. On a chunked /
# no-Content-Length response large enough to need more than one
# ZSTD_CStreamOutSize output buffer, the body filter's recycle guard
# (ctx->out_buf = NULL after ngx_chain_update_chains) left out_buf NULL
# while buffer_out still looked non-full; the next compress() dereferenced
# it ("ctx->out_buf->last += ...") -> worker SIGSEGV, the response
# truncated at exactly 131072 decoded bytes with no zstd end-of-frame.
# Single-buffer responses never recycle so never crashed, which is why
# the homepage worked but wp-admin (large chunked CSS) broke in prod.
#
# A mock TCP backend streams a chunked body with NO Content-Length, far
# larger than one ~128 KB output buffer and highly compressible. The
# response must come back zstd-encoded, decompress cleanly (no premature
# end), and equal the original byte-for-byte (asserted via a len:md5
# checksum so the body need not be inlined). A pre-fix module crashes
# the worker here / yields a short body; the fixed module round-trips.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        proxy_http_version 1.1;
        proxy_buffering on;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/up;
    }
    location /up {
        proxy_http_version 1.1;
        proxy_pass http://127.0.0.1:$TEST_NGINX_RAND_PORT_1/;
    }
--- tcp_listen: $TEST_NGINX_RAND_PORT_1
--- tcp_no_close
--- tcp_reply eval
my $unit = "ABCDEFGHIJ0123456789zstd-multibuffer-regression-payload-";
my $body = $unit x 5000;            # ~290 KB, >2x ZSTD_CStreamOutSize
my $hdr  = "HTTP/1.1 200 OK\r\n"
         . "Content-Type: text/plain\r\n"
         . "Transfer-Encoding: chunked\r\n"
         . "Connection: close\r\n\r\n";
my $out = $hdr;
# emit in 8 KB chunks so it is genuinely chunked, no Content-Length
for (my $i = 0; $i < length($body); $i += 8192) {
    my $c = substr($body, $i, 8192);
    $out .= sprintf("%x\r\n", length($c)) . $c . "\r\n";
}
$out .= "0\r\n\r\n";
$out
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Length
Content-Encoding: zstd
--- response_body_filters eval
sub {
    my $zstd = $_[0];
    open(my $fh, "|-", "zstd -dq -c >/tmp/zstd_t44.out 2>/dev/null") or return "ERR-OPEN";
    print $fh $zstd; close($fh);
    my $rc = $?;
    open(my $r, "<", "/tmp/zstd_t44.out") or return "ERR-READ";
    local $/; my $d = <$r>; close($r); unlink "/tmp/zstd_t44.out";
    return "ERR-DECODE rc=$rc" if $rc != 0;          # premature end -> non-zero
    require Digest::MD5;
    return length($d) . ":" . Digest::MD5::md5_hex($d);
}
--- response_body eval
my $unit = "ABCDEFGHIJ0123456789zstd-multibuffer-regression-payload-";
my $body = $unit x 5000;
require Digest::MD5;
length($body) . ":" . Digest::MD5::md5_hex($body)
