use Test::Nginx::Socket;
use File::Basename;
use IO::Compress::Gzip qw(gzip);
use lib 'lib';

my $dirname = dirname(__FILE__);
$ENV{'TEST_NGINX_PERL_PATH'}="$ENV{'PWD'}/$dirname";

my @dynamic_modules;
if (defined $ENV{'TEST_NGINX_BINARY'}) {
    my $nginx_dir = dirname($ENV{'TEST_NGINX_BINARY'});
    for my $module_name (qw(ngx_http_brotli_filter_module.so ngx_http_brotli_static_module.so)) {
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

# Static-module fixtures. hello.js.br is a committed brotli frame of
# hello.js (protected by .gitattributes -text); the .gz sibling for the
# fallback regression is generated here from core-perl IO::Compress.
our $src = do {
    local $/;
    open my $fh, '<', "$dirname/suite/hello.js" or die "hello.js: $!";
    binmode $fh; <$fh>;
};
our $br = do {
    local $/;
    open my $fh, '<', "$dirname/suite/hello.js.br" or die "hello.js.br: $!";
    binmode $fh; <$fh>;
};
our $gz;
gzip(\$src => \$gz) or die "gzip failed";

no_long_string();
log_level 'warn';
repeat_each(1);
plan 'no_plan';
run_tests();

__DATA__


=== TEST 1: explicit br token negotiates br
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        gzip_vary on;
        default_type text/html;
        return 200 "brotli filter body: negotiation matrix fixture text\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br
--- response_headers
Content-Encoding: br
Vary: Accept-Encoding
--- no_error_log
[error]



=== TEST 2: "*" wildcard matches br (RFC 9110 §12.5.3)
# The replaced substring-scan parser could not see the wildcard at all.
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        default_type text/html;
        return 200 "brotli filter body: negotiation matrix fixture text\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: *
--- response_headers
Content-Encoding: br
--- no_error_log
[error]



=== TEST 3: br;q=0 is an explicit refusal
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        default_type text/html;
        return 200 "brotli filter body: negotiation matrix fixture text\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br;q=0
--- response_headers
!Content-Encoding
--- no_error_log
[error]



=== TEST 4: ";Q=0" refusal is honored (weight name is case-insensitive)
# The old parser broke out of its q-scan into ACCEPT on the uppercase Q,
# compressing against an explicit refusal.
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        default_type text/html;
        return 200 "brotli filter body: negotiation matrix fixture text\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br;Q=0
--- response_headers
!Content-Encoding
--- no_error_log
[error]



=== TEST 5: quoted parameter value does not fabricate a br token
# `gzip;x="a, br"` contains the bytes ", br" inside gzip's parameter;
# the old substring scan matched them and compressed for a client that
# never asked for br.
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        default_type text/html;
        return 200 "brotli filter body: negotiation matrix fixture text\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: gzip;x="a, br"
--- response_headers
!Content-Encoding
--- no_error_log
[error]



=== TEST 6: a later duplicate explicit token wins
# "br;q=0, br" previously returned DECLINED on the first match without
# ever seeing the second token.
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        default_type text/html;
        return 200 "brotli filter body: negotiation matrix fixture text\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br;q=0, br
--- response_headers
Content-Encoding: br
--- no_error_log
[error]



=== TEST 7: malformed weight makes the element non-matching
# "br;q=x" previously fell into the break-means-accept path.
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        default_type text/html;
        return 200 "brotli filter body: negotiation matrix fixture text\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br;q=x
--- response_headers
!Content-Encoding
--- no_error_log
[error]



=== TEST 8: brotli_bypass truthy serves identity, with the declared Vary
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_bypass $http_x_no_br;
        brotli_bypass_vary X-No-Br;
        default_type text/html;
        return 200 "brotli filter body: negotiation matrix fixture text\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br
X-No-Br: 1
--- response_headers
!Content-Encoding
Vary: X-No-Br
--- no_error_log
[error]



=== TEST 9: brotli_bypass falsy still compresses (and carries the Vary)
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_bypass $http_x_no_br;
        brotli_bypass_vary X-No-Br;
        default_type text/html;
        return 200 "brotli filter body: negotiation matrix fixture text\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br
--- response_headers
Content-Encoding: br
Vary: X-No-Br, Accept-Encoding
--- no_error_log
[error]



=== TEST 10: brotli_bypass_vary without brotli_bypass warns at config load
--- config
    location /t {
        brotli on;
        brotli_bypass_vary X-No-Br;
        default_type text/html;
        return 200 "brotli filter body: negotiation matrix fixture text\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br
--- error_log
"brotli_bypass_vary" is set without a "brotli_bypass" predicate
--- no_error_log
[error]



=== TEST 11: declared length above brotli_max_length serves identity
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_max_length 32;
        default_type text/html;
        return 200 "brotli filter body: negotiation matrix fixture text\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br
--- response_headers
!Content-Encoding
--- no_error_log
[error]



=== TEST 12: declared length under brotli_max_length still compresses
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_max_length 4096;
        default_type text/html;
        return 200 "brotli filter body: negotiation matrix fixture text\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br
--- response_headers
Content-Encoding: br
--- no_error_log
[error]



=== TEST 12a: enabled without gzip_vary emits Vary by construction, no warn
# Parent #163: the response is br or identity by Accept-Encoding, so the
# header filter emits "Vary: Accept-Encoding" itself — correctness no
# longer depends on "gzip_vary on", and there is no gzip_vary-off warning.
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        default_type text/html;
        return 200 "brotli filter body: negotiation matrix fixture text\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br
--- response_headers
Content-Encoding: br
Vary: Accept-Encoding
--- no_error_log eval
[qr/"gzip_vary" is off/, qr/\[error\]/]



=== TEST 12b: enabled WITH gzip_vary does not warn
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        gzip_vary on;
        default_type text/html;
        return 200 "brotli filter body: negotiation matrix fixture text\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br
--- no_error_log eval
[qr/"gzip_vary" is off/, qr/\[error\]/]



=== TEST 12c: brotli_static always does not warn without gzip_vary
# "always" serves .br regardless of Accept-Encoding — the response
# genuinely does not vary, so the warning must stay quiet. The filter
# is off here so only the static module's check is in play.
--- config
    location /st/ {
        brotli_static always;
    }
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.br" => $::br ] ]
--- request
GET /st/hello.js
--- response_headers
Content-Encoding: br
--- no_error_log eval
[qr/brotli_static is enabled but/, qr/\[error\]/]



=== TEST 13: brotli_static serves the .br sibling
--- config
    location /st/ {
        brotli_static on;
    }
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.br" => $::br ] ]
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: br
--- response_headers
Content-Encoding: br
--- no_error_log
[error]



=== TEST 14: missing .br no longer suppresses the gzip_static fallback
# The regression the shared-header refactor fixed: the old
# check_eligility() latched r->gzip_ok = 0 before knowing whether a .br
# file exists, so a client accepting "br, gzip" with only a .gz on disk
# got identity. It must get the gzip_static response.
--- config
    location /st/ {
        brotli_static on;
        gzip_static on;
        gzip_vary on;
    }
--- user_files eval
[ [ "st/onlygz.js" => $::src ], [ "st/onlygz.js.gz" => $::gz ] ]
--- request
GET /st/onlygz.js
--- more_headers
Accept-Encoding: br, gzip
--- response_headers
Content-Encoding: gzip
--- no_error_log
[error]



=== TEST 15: brotli_static always ignores Accept-Encoding
--- config
    location /st/ {
        brotli_static always;
    }
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.br" => $::br ] ]
--- request
GET /st/hello.js
--- response_headers
Content-Encoding: br
--- no_error_log
[error]



=== TEST 16: a served .br sidecar advertises Accept-Ranges: bytes
# gzip_static parity: static-side byte ranges address the selected
# representation (RFC 9110 §14.2) — the .br bytes on disk — and only
# work by opting in via r->allow_ranges (the range filter bails
# without it). gzip_static has always set it; this module never did,
# so ranges silently never worked. Fails on the unfixed module: no
# opt-in, no header.
--- config
    location /st/ {
        brotli_static on;
        gzip_vary on;
    }
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.br" => $::br ] ]
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: br
--- response_headers
Content-Encoding: br
Accept-Ranges: bytes
--- no_error_log
[error]



=== TEST 17: byte ranges slice the .br sidecar's bytes (206 + Content-Range)
# The representation is the encoded bytes and the validator is strong,
# so a client can fetch, resume and concatenate ranges coherently —
# resumable downloads of precompressed assets, same as gzip_static.
# Unfixed code ignores Range and answers 200 with the full body.
--- config
    location /st/ {
        brotli_static on;
        gzip_vary on;
    }
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.br" => $::br ] ]
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: br
Range: bytes=0-9
--- error_code: 206
--- response_headers eval
"Content-Range: bytes 0-9/" . length($::br)
--- response_body eval
substr($::br, 0, 10)
--- no_error_log
[error]



=== TEST 18: an empty .br sidecar behind an SSI include ships silently
# In a subrequest in_file and last_buf are both 0, so an empty sidecar
# produces a flagless zero-size buf that trips the output chain's
# "zero size buf" alert without buf->sync (gzip_static sets it; this
# module didn't). brotli_static has no content probe, so an empty .br
# is servable and this path is live — unlike the sibling zstd module,
# whose frame probe rejects sub-4-byte files before serving.
--- config
    location /page/ {
        ssi on;
        default_type text/html;   # the SSI filter only touches ssi_types
    }
    location /inc/ {
        brotli_static always;
    }
--- user_files eval
[ [ "page/x.shtml" => qq{before[<!--#include virtual="/inc/empty.txt" -->]after\n} ],
  [ "inc/empty.txt.br" => "" ] ]
--- request
GET /page/x.shtml
--- response_body
before[]after
--- no_error_log eval
qr/zero size buf/



=== TEST 19: HEAD fast path keeps the negotiated headers, sends no body
# Parent nginx-zstd-module #179: a HEAD returns after ngx_http_send_header(),
# skipping the body buffer + ngx_file_t allocations — but Content-Encoding
# and the Vary line (set before the fast path) must match what the GET
# produces.
--- config
    location /st/ {
        brotli_static on;
    }
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.br" => $::br ] ]
--- request
HEAD /st/hello.js
--- more_headers
Accept-Encoding: br
--- response_headers
Content-Encoding: br
Vary: Accept-Encoding
Accept-Ranges: bytes
--- response_body
--- no_error_log
[error]

=== TEST 20: an origin Vary listing Accept-Encoding among tokens is not doubled
# zstd sibling #200 row n11: the by-construction push's dedup scan must
# tokenize the existing Vary value on commas — an exact-value compare
# misses "Accept-Encoding, Cookie" and doubles the token on a second
# line. gzip_vary stays off so the module's own push path runs.
--- config
    location /t {
        brotli on;
        brotli_min_length 1;
        brotli_types text/plain;
        default_type text/plain;
        add_header Vary "Accept-Encoding, Cookie";
        return 200 "brotli vary dedup fixture body long enough to compress\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br
--- response_headers
Content-Encoding: br
Vary: Accept-Encoding, Cookie
--- raw_response_headers_unlike eval
qr/Vary: Accept-Encoding\r/
--- no_error_log
[error]


=== TEST 21: a skipped foreign parameter negotiates at q=1 (lenient, deliberate)
# zstd sibling #201/m5 parity: an unrecognized parameter is skipped,
# not fatal to the element — the deliberate divergence from core
# gzip's parser, which drops the whole element.
--- config
    location /t {
        brotli on;
        brotli_min_length 1;
        brotli_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "brotli vary dedup fixture body long enough to compress\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br;foo=bar
--- response_headers
Content-Encoding: br
--- no_error_log
[error]


=== TEST 22: a skipped foreign parameter still honours its element's q=0
# The half that justifies the leniency: skipping "foo=bar" preserves
# the trailing q the client actually sent; core never sees it.
--- config
    location /t {
        brotli on;
        brotli_min_length 1;
        brotli_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "brotli vary dedup fixture body long enough to compress\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br;foo=bar;q=0
--- raw_response_headers_unlike: Content-Encoding
--- no_error_log
[error]

=== TEST 23: brotli_static on with no .br earns no Vary (#202 mirror)
# zstd siblings' #202, their round-4 ruling: Vary is earned by a
# USABLE .br (existence + regular file here — this module deliberately
# validates no content), not by the attempt. A URI with no .br at all
# is not a negotiated variant; the old early emission stamped Vary on
# its identity response and fragmented shared caches for nothing.
--- config
    location /st/ {
        brotli_static on;
    }
--- user_files eval
[ [ "st/hello.js" => $::src ] ]
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: br
--- raw_response_headers_unlike: Vary
--- response_body eval
$::src
--- no_error_log
[error]


=== TEST 24: usable .br + non-accepting client -> Vary, identity, no latch
# The ruling's condition: the probe runs before the acceptance check,
# so a client refusing br still learns the URI varies when a usable
# .br exists — without that, its identity response would enter shared
# caches unpartitioned and poison the URI for every br-accepting
# client behind the same cache. Exists to fail the naive
# acceptance-before-probe variant.
--- config
    location /st/ {
        brotli_static on;
    }
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.br" => $::br ] ]
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: gzip
--- raw_response_headers_like: Vary: Accept-Encoding
--- raw_response_headers_unlike: Content-Encoding
--- response_body eval
$::src
--- no_error_log
[error]


=== TEST 25: Cache-Control no-transform serves identity (parent #251)
# The gate only sees headers present BEFORE the filter chain runs, so
# the fixture arrives via a proxied origin — an add_header in the
# outer location would be added after this filter already decided.
--- config
    location /origin {
        add_header Cache-Control "no-transform";
        default_type text/html;
        return 200 "brotli filter body: no-transform fixture text line\n";
    }
    location /t {
        brotli on;
        brotli_min_length 8;
        proxy_pass http://127.0.0.1:$server_port/origin;
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br
--- raw_response_headers_unlike: Content-Encoding
--- response_body
brotli filter body: no-transform fixture text line
--- no_error_log
[error]


=== TEST 26: Cache-Control public still compresses (negative control)
--- config
    location /origin {
        add_header Cache-Control "public";
        default_type text/html;
        return 200 "brotli filter body: no-transform fixture text line\n";
    }
    location /t {
        brotli on;
        brotli_min_length 8;
        proxy_pass http://127.0.0.1:$server_port/origin;
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br
--- response_headers
Content-Encoding: br
--- no_error_log
[error]


=== TEST 27: a quoted parameter VALUE of no-transform is not a directive
# extension="no-transform" names the string, not the directive — the
# walker cuts each segment at '='/';' and whole-token-compares.
--- config
    location /origin {
        add_header Cache-Control "public, extension=\"no-transform\"";
        default_type text/html;
        return 200 "brotli filter body: no-transform fixture text line\n";
    }
    location /t {
        brotli on;
        brotli_min_length 8;
        proxy_pass http://127.0.0.1:$server_port/origin;
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br
--- response_headers
Content-Encoding: br
--- no_error_log
[error]


=== TEST 28: no-transform with OWS, a parameter, and a second line
# " public ; max-age=60 " on the first line, No-Transform (mixed case)
# on a SECOND Cache-Control line: caches read the union, so must we.
--- config
    location /origin {
        add_header Cache-Control " public ; max-age=60 ";
        add_header Cache-Control "No-Transform";
        default_type text/html;
        return 200 "brotli filter body: no-transform fixture text line\n";
    }
    location /t {
        brotli on;
        brotli_min_length 8;
        proxy_pass http://127.0.0.1:$server_port/origin;
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br
--- raw_response_headers_unlike: Content-Encoding
--- response_body
brotli filter body: no-transform fixture text line
--- no_error_log
[error]


=== TEST 29: a quoted extension value containing commas is NOT split (#274 twin)
--- config
    location /origin {
        add_header Cache-Control "public, x=\",no-transform,y\"";
        default_type text/html;
        return 200 "brotli filter body: no-transform fixture text line\n";
    }
    location /t {
        brotli on;
        brotli_min_length 8;
        proxy_pass http://127.0.0.1:$server_port/origin;
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br
--- response_headers
Content-Encoding: br
--- no_error_log
[error]


=== TEST 30: a real no-transform AFTER a comma-carrying quoted value matches
--- config
    location /origin {
        add_header Cache-Control "x=\"a,b\", no-transform";
        default_type text/html;
        return 200 "brotli filter body: no-transform fixture text line\n";
    }
    location /t {
        brotli on;
        brotli_min_length 8;
        proxy_pass http://127.0.0.1:$server_port/origin;
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br
--- raw_response_headers_unlike: Content-Encoding
--- response_body
brotli filter body: no-transform fixture text line
--- no_error_log
[error]


=== TEST 31: trailing junk after the coding name rejects the element
# "br x" is not a valid element: after the name and OWS only ';', ','
# or end may follow. The old walker fell through to the implied-q=1
# default and compressed for a header that names no valid coding.
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        default_type text/html;
        return 200 "brotli filter body: negotiation matrix fixture text\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br x
--- raw_response_headers_unlike: Content-Encoding
--- response_body
brotli filter body: negotiation matrix fixture text
--- no_error_log
[error]


=== TEST 32: a junk element does not mask a later clean token
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        default_type text/html;
        return 200 "brotli filter body: negotiation matrix fixture text\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br x, br
--- response_headers
Content-Encoding: br
--- no_error_log
[error]


=== TEST 33: br offered only on a second Accept-Encoding line elects br
# Multiple Accept-Encoding lines are one comma-joined field (RFC 9110
# section 5.3); reading only the first line refuses a client that
# advertised br in a way any joining intermediary would surface.
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        default_type text/html;
        return 200 "brotli filter body: negotiation matrix fixture text\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: identity
Accept-Encoding: br
--- response_headers
Content-Encoding: br
--- no_error_log
[error]


=== TEST 34: a refusal on a later line overrides an earlier allowance
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        default_type text/html;
        return 200 "brotli filter body: negotiation matrix fixture text\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br
Accept-Encoding: br;q=0
--- raw_response_headers_unlike: Content-Encoding
--- response_body
brotli filter body: negotiation matrix fixture text
--- no_error_log
[error]


=== TEST 35: static: br on a second line serves the precompressed file
--- config
    location /st/ {
        brotli_static on;
    }
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.br" => $::br ] ]
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: gzip
Accept-Encoding: br
--- response_headers
Content-Encoding: br
--- response_body eval
$::br
--- no_error_log
[error]


=== TEST 36: an empty first Accept-Encoding line does not mask a later one
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        default_type text/html;
        return 200 "brotli filter body: negotiation matrix fixture text\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding:
Accept-Encoding: br
--- response_headers
Content-Encoding: br
--- no_error_log
[error]


=== TEST 37: an empty parameter (br;;q=1) is malformed, not q=1
# RFC 9110 has no empty-parameter production; the old walker read the
# stray ';' as a skipped valueless parameter and accepted the element
# at the q=1 that followed (siblings' parent #142 rule, drifted here).
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        default_type text/html;
        return 200 "brotli filter body: negotiation matrix fixture text\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br;;q=1
--- raw_response_headers_unlike: Content-Encoding
--- response_body
brotli filter body: negotiation matrix fixture text
--- no_error_log
[error]


=== TEST 38: the malformed element does not poison a later clean token
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        default_type text/html;
        return 200 "brotli filter body: negotiation matrix fixture text\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br;;q=1, br
--- response_headers
Content-Encoding: br
--- no_error_log
[error]



=== TEST 39: brotli off everywhere: identity served, the variables still resolve
# zstd siblings' #182: with "brotli" off in every location the filter
# hooks are not installed at all. Black-box, that is indistinguishable
# from "installed and declining", which is the point of the change; what
# this block pins is that nothing else moved -- the response is identity
# with no Vary, and $brotli_ratio still registers (the variables are
# wired regardless of the hooks), so a log_format naming it loads.
--- http_config
    brotli off;
--- config
    location /t {
        add_header X-Ratio "r=$brotli_ratio";
        default_type text/html;
        return 200 "brotli filter body: negotiation matrix fixture text\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br
--- response_headers
!Content-Encoding
!Vary
X-Ratio: r=
--- response_body
brotli filter body: negotiation matrix fixture text
--- no_error_log
[error]



=== TEST 40: "brotli on" only inside an "if" block still installs the hooks
# The latch must fire for the NGX_HTTP_LIF_CONF conf a rewrite-phase
# "if" synthesizes, which the location-conf merge walk does not provably
# visit: http-level off, one if-block on. A latch that only saw
# main/srv/loc confs would leave the hooks uninstalled and serve identity
# here.
--- http_config
    brotli off;
--- config
    location /t {
        if ($arg_br) {
            brotli on;
        }
        brotli_min_length 8;
        default_type text/html;
        return 200 "brotli filter body: negotiation matrix fixture text\n";
    }
--- request
GET /t?br=1
--- more_headers
Accept-Encoding: br
--- response_headers
Content-Encoding: br
Vary: Accept-Encoding
--- no_error_log
[error]



=== TEST 41: brotli_static off everywhere: the sidecar is not served
# The static module's own latch: off in every location means the
# content-phase handler is never appended, and a .br sibling on disk is
# simply not consulted -- the request serves the identity file.
--- http_config
    brotli_static off;
    brotli off;
--- config
    location /st/ {
        root html;
    }
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.br" => $::br ] ]
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: br
--- response_headers
!Content-Encoding
--- response_body eval
$::src
--- no_error_log
[error]



=== TEST 42: a 410 Gone response is compressed like 403/404
# The status set is core gzip's plus 410, which nginx/nginx#1466
# proposes for gzip too: a removed resource's error page is as
# compressible as a 404's.
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        default_type text/html;
        return 410 "brotli filter body: this resource is gone for good\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br
--- error_code: 410
--- response_headers
Content-Encoding: br
Vary: Accept-Encoding
--- no_error_log
[error]



=== TEST 43: a 409 response stays uncompressed (the status set is a list, not a range)
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        default_type text/html;
        return 409 "brotli filter body: negotiation matrix fixture text\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br
--- error_code: 409
--- response_headers
!Content-Encoding
--- no_error_log
[error]
