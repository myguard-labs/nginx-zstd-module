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
Vary: X-No-Br
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



=== TEST 12a: enabled without gzip_vary warns at config load
# Whether the response is br or identity depends on Accept-Encoding;
# without Vary a shared cache can serve the compressed variant to a
# client that cannot decode it. Same check as the zstd siblings — it
# catches stale "gzip_vary off" workarounds in old configs.
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
--- error_log
"gzip_vary" is off
--- no_error_log
[error]



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
