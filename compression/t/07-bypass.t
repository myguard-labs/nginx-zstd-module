use Test::Nginx::Socket;

# Phase-3 bypass predicates: compression_bypass (any predicate variable
# resolving non-empty and not "0" serves identity, stock
# ngx_http_test_predicates semantics) and compression_bypass_vary (the
# operator-named extra Vary field, emitted on BOTH the bypassed and the
# compressed response). The unified-module delta is pinned hard here:
# bypass VETOES the gzip token too, because in this module gzip is part
# of the stack -- the parents' standalone bypass falls through to core
# gzip, and TEST 6's positive control shows exactly that path working
# when bypass does NOT fire.

our $body = "bypass fixture body: compressible repeated text line\n" x 20;

no_long_string();
log_level 'warn';
repeat_each(1);
plan 'no_plan';
run_tests();

__DATA__


=== TEST 1: a truthy predicate serves identity
--- user_files eval
[ [ "b/a.txt" => $::body ] ]
--- config
    location /b/ {
        compression on;
        compression_bypass $arg_nocomp;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /b/a.txt?nocomp=1
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Content-Encoding
--- response_body eval
$::body
--- no_error_log
[error]


=== TEST 2: no predicate match compresses as usual
--- user_files eval
[ [ "b/a.txt" => $::body ] ]
--- config
    location /b/ {
        compression on;
        compression_bypass $arg_nocomp;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /b/a.txt
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]


=== TEST 3: "0" is falsy (stock predicate semantics)
--- user_files eval
[ [ "b/a.txt" => $::body ] ]
--- config
    location /b/ {
        compression on;
        compression_bypass $arg_nocomp;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /b/a.txt?nocomp=0
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]


=== TEST 4: several predicates -- any truthy one bypasses
--- user_files eval
[ [ "b/a.txt" => $::body ] ]
--- config
    location /b/ {
        compression on;
        compression_bypass $arg_a $arg_b;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /b/a.txt?b=yes
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Content-Encoding
--- response_body eval
$::body
--- no_error_log
[error]


=== TEST 5: compression_bypass_vary rides BOTH paths
# bypassed request: Vary names the driving header AND Accept-Encoding
# (round 5: the bypassed identity is still a variant of a negotiated
# URI -- without the AE dimension a cache can store it as the URI's
# baseline and key later compressed variants inconsistently), no
# Content-Encoding. The harness folds same-name lines with ", ".
--- user_files eval
[ [ "b/a.txt" => $::body ] ]
--- config
    location /b/ {
        compression on;
        compression_bypass $http_x_no_compression;
        compression_bypass_vary X-No-Compression;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /b/a.txt
--- more_headers
Accept-Encoding: zstd
X-No-Compression: 1
--- raw_response_headers_unlike: Content-Encoding
--- response_headers
Vary: Accept-Encoding, X-No-Compression
--- response_body eval
$::body
--- no_error_log
[error]


=== TEST 5b: ...and on the compressed response too
# two Vary lines on the wire (delegated Accept-Encoding + the literal
# bypass field); the harness folds same-name headers with ", ", so the
# folded expectation asserts BOTH are present
--- user_files eval
[ [ "b/a.txt" => $::body ] ]
--- config
    location /b/ {
        compression on;
        compression_bypass $http_x_no_compression;
        compression_bypass_vary X-No-Compression;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /b/a.txt
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
Vary: Accept-Encoding, X-No-Compression
--- no_error_log
[error]


=== TEST 6: bypass vetoes the gzip token (the unified-module delta)
# gzip is ON and the client accepts gzip; without the veto the
# parents' behavior applies -- bypass falls through and core gzip
# compresses anyway (TEST 6b shows that path live when bypass does
# not fire). With the veto the response is identity, which is what
# "do not compress this endpoint" has to mean when gzip is part of
# the stack.
--- user_files eval
[ [ "b/a.txt" => $::body ] ]
--- config
    location /b/ {
        compression on;
        compression_order zstd gzip;
        compression_bypass $arg_nocomp;
        compression_min_length 1;
        compression_types text/plain;
        gzip on;
        gzip_min_length 1;
        gzip_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /b/a.txt?nocomp=1
--- more_headers
Accept-Encoding: gzip
--- raw_response_headers_unlike: Content-Encoding
--- response_body eval
$::body
--- no_error_log
[error]


=== TEST 6b: positive control -- no bypass, gzip deferral compresses
--- user_files eval
[ [ "b/a.txt" => $::body ] ]
--- config
    location /b/ {
        compression on;
        compression_order zstd gzip;
        compression_bypass $arg_nocomp;
        compression_min_length 1;
        compression_types text/plain;
        gzip on;
        gzip_min_length 1;
        gzip_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /b/a.txt
--- more_headers
Accept-Encoding: gzip
--- response_headers
Content-Encoding: gzip
--- no_error_log
[error]


=== TEST 7: bypass_vary without a predicate warns at config load
--- user_files eval
[ [ "b/a.txt" => $::body ] ]
--- config
    location /b/ {
        compression on;
        compression_bypass_vary X-No-Compression;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /b/a.txt
--- error_log
"compression_bypass_vary" is set without a "compression_bypass" predicate


=== TEST 8: a direct $http_* bypass without bypass_vary warns (parent #185)
# the inverse misconfig: reading a request header directly in the
# predicate, with no compression_bypass_vary, lets a shared cache mix
# identity and compressed responses under one key.
--- user_files eval
[ [ "b/a.txt" => $::body ] ]
--- config
    location /b/ {
        compression on;
        compression_bypass $http_x_no_compression;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /b/a.txt
--- error_log
reads a request header or cookie directly without a "compression_bypass_vary"


=== TEST 8b: a direct $cookie_* bypass without bypass_vary warns
--- user_files eval
[ [ "b/a.txt" => $::body ] ]
--- config
    location /b/ {
        compression on;
        compression_bypass $cookie_nocompress;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /b/a.txt
--- error_log
reads a request header or cookie directly without a "compression_bypass_vary"


=== TEST 8c: a direct $http_* bypass WITH bypass_vary is silent
# pairing the predicate with a Vary field is the correct configuration —
# no warning.
--- user_files eval
[ [ "b/a.txt" => $::body ] ]
--- config
    location /b/ {
        compression on;
        compression_bypass $http_x_no_compression;
        compression_bypass_vary X-No-Compression;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /b/a.txt
--- no_error_log
reads a request header or cookie directly


=== TEST 8d: an indirect predicate ($request_uri) is silent
# only the literal $http_*/$cookie_* spellings are recognized; a
# URI-based predicate (already part of the cache key) never warns.
--- user_files eval
[ [ "b/a.txt" => $::body ] ]
--- config
    location /b/ {
        compression on;
        compression_bypass $arg_nocompress;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /b/a.txt
--- no_error_log
reads a request header or cookie directly


=== TEST 9: compression_bypass_vary rejects a comma-separated value (parent #168)
# the value becomes a literal Vary field-name; a list would emit a
# malformed Vary. Must be exactly one RFC 9110 token.
--- config
    location /b/ {
        compression on;
        compression_bypass_vary "Accept-Encoding, X-Custom";
    }
--- must_die
--- error_log
comma or semicolon


=== TEST 9b: compression_bypass_vary rejects a bare wildcard
--- config
    location /b/ {
        compression on;
        compression_bypass_vary *;
    }
--- must_die
--- error_log
bare wildcard


=== TEST 9c: compression_bypass_vary rejects a semicolon parameter
--- config
    location /b/ {
        compression on;
        compression_bypass_vary "X-Custom;q=1";
    }
--- must_die
--- error_log
comma or semicolon


=== TEST 9d: a valid field-name token loads (with a bypass predicate)
--- user_files eval
[ [ "b/a.txt" => $::body ] ]
--- config
    location /b/ {
        compression on;
        compression_bypass $http_x_no_compression;
        compression_bypass_vary X-No-Compression;
        compression_types text/plain;
        default_type text/plain;
        root html;
    }
--- request
GET /b/a.txt
--- error_code: 200
--- no_error_log
[error]


=== TEST 9e: compression_bypass_vary is duplicate in one block
--- config
    location /b/ {
        compression on;
        compression_bypass_vary X-One;
        compression_bypass_vary X-Two;
    }
--- must_die
--- error_log
is duplicate


=== TEST 10: Cache-Control no-transform serves identity (upstream #251)
# The gate only sees headers present BEFORE the filter chain runs, so
# the fixture arrives via a proxied origin — an add_header in the outer
# location would be added after our filter already decided.
--- config
    location /origin/ {
        compression off;
        add_header Cache-Control "no-transform";
        default_type text/plain;
        return 200 "no-transform fixture body: repeated compressible text\n";
    }
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        proxy_pass http://127.0.0.1:$server_port/origin/;
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Content-Encoding
--- response_body
no-transform fixture body: repeated compressible text
--- no_error_log
[error]


=== TEST 11: Cache-Control public still compresses (negative control)
--- config
    location /origin/ {
        compression off;
        add_header Cache-Control "public";
        default_type text/plain;
        return 200 "no-transform fixture body: repeated compressible text\n";
    }
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        proxy_pass http://127.0.0.1:$server_port/origin/;
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]


=== TEST 12: a quoted parameter VALUE of no-transform is not a directive
# extension="no-transform" names the string, not the directive — the
# walker cuts each segment at '='/';' and whole-token-compares, so this
# must keep compressing.
--- config
    location /origin/ {
        compression off;
        add_header Cache-Control "public, extension=\"no-transform\"";
        default_type text/plain;
        return 200 "no-transform fixture body: repeated compressible text\n";
    }
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        proxy_pass http://127.0.0.1:$server_port/origin/;
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]


=== TEST 13: OWS, a semicolon parameter, and mixed case still match
--- config
    location /origin/ {
        compression off;
        add_header Cache-Control " public ; max-age=60 , No-Transform ";
        default_type text/plain;
        return 200 "no-transform fixture body: repeated compressible text\n";
    }
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        proxy_pass http://127.0.0.1:$server_port/origin/;
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Content-Encoding
--- response_body
no-transform fixture body: repeated compressible text
--- no_error_log
[error]


=== TEST 14: no-transform on a SECOND Cache-Control line is honored
--- config
    location /origin/ {
        compression off;
        add_header Cache-Control "public";
        add_header Cache-Control "no-transform";
        default_type text/plain;
        return 200 "no-transform fixture body: repeated compressible text\n";
    }
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        proxy_pass http://127.0.0.1:$server_port/origin/;
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Content-Encoding
--- response_body
no-transform fixture body: repeated compressible text
--- no_error_log
[error]


=== TEST 15: no-transform vetoes the gzip token too (unified delta)
# Same reasoning as the compression_bypass veto: gzip is part of THIS
# stack, and a fall-through to core gzip (which ignores no-transform)
# would defeat the origin's directive.
--- config
    location /origin/ {
        compression off;
        add_header Cache-Control "no-transform";
        default_type text/plain;
        return 200 "no-transform fixture body: repeated compressible text\n";
    }
    location /t {
        compression on;
        gzip on;
        gzip_min_length 1;
        gzip_types text/plain;
        compression_min_length 1;
        compression_types text/plain;
        proxy_pass http://127.0.0.1:$server_port/origin/;
    }
--- request
GET /t
--- more_headers
Accept-Encoding: gzip
--- raw_response_headers_unlike: Content-Encoding
--- response_body
no-transform fixture body: repeated compressible text
--- no_error_log
[error]


=== TEST 16: no-transform vetoes gzip even when OUR types gate defers
# Round 5 (eilandert): the local eligibility gates are DEFERRALS to
# core gzip, so the whole-stack vetoes must run before them --
# compression_types application/json beside gzip_types text/plain used
# to answer a text/plain no-transform response with
# Content-Encoding: gzip, because the type mismatch deferred before
# the veto could latch gzip off.
--- config
    location /origin/ {
        compression off;
        add_header Cache-Control "no-transform";
        default_type text/plain;
        return 200 "no-transform fixture body: repeated compressible text\n";
    }
    location /t {
        compression on;
        compression_min_length 1;
        compression_types application/json;
        gzip on;
        gzip_min_length 1;
        gzip_types text/plain;
        proxy_pass http://127.0.0.1:$server_port/origin/;
    }
--- request
GET /t
--- more_headers
Accept-Encoding: gzip
--- raw_response_headers_unlike: Content-Encoding
--- response_body
no-transform fixture body: repeated compressible text
--- no_error_log
[error]


=== TEST 17: compression_bypass vetoes gzip even when OUR types gate defers
# Same tier-ordering pin for the operator's veto: a truthy bypass
# predicate must mean identity from the whole stack regardless of
# whether THIS location's types would have elected a coding.
--- config
    location /origin/ {
        compression off;
        default_type text/plain;
        return 200 "no-transform fixture body: repeated compressible text\n";
    }
    location /t {
        compression on;
        compression_bypass $arg_nocomp;
        compression_min_length 1;
        compression_types application/json;
        gzip on;
        gzip_min_length 1;
        gzip_types text/plain;
        proxy_pass http://127.0.0.1:$server_port/origin/;
    }
--- request
GET /t?nocomp=1
--- more_headers
Accept-Encoding: gzip
--- raw_response_headers_unlike: Content-Encoding
--- response_body
no-transform fixture body: repeated compressible text
--- no_error_log
[error]


=== TEST 20: a quoted extension value containing commas is NOT split (#274)
# x=",no-transform,y" -- the commas belong to the quoted string; the
# old scan split there and fabricated a matching segment out of the
# quoted text, a false compression opt-out
--- config
    location /origin/ {
        compression off;
        add_header Cache-Control "public, x=\",no-transform,y\"";
        default_type text/plain;
        return 200 "no-transform fixture body: repeated compressible text\n";
    }
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        proxy_pass http://127.0.0.1:$server_port/origin/;
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]


=== TEST 21: a real no-transform AFTER a comma-carrying quoted value matches
# the quote-aware scan must resume at the genuine segment boundary
--- config
    location /origin/ {
        compression off;
        add_header Cache-Control "x=\"a,b\", no-transform";
        default_type text/plain;
        return 200 "no-transform fixture body: repeated compressible text\n";
    }
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        proxy_pass http://127.0.0.1:$server_port/origin/;
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Content-Encoding
--- response_body
no-transform fixture body: repeated compressible text
--- no_error_log
[error]
