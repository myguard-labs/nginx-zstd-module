use Test::Nginx::Socket;
use File::Basename;
use Digest::SHA qw(sha256);
use MIME::Base64 qw(encode_base64);
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

# The negotiation key is the SHA-256 of the committed dictionary fixture,
# computed here rather than hardcoded so a fixture edit cannot silently
# desynchronize the suite ("passing" against a stale hash).
my $dict_raw = do {
    local $/;
    open my $fh, '<', "$dirname/suite/dcz-dict" or die "dcz-dict: $!";
    binmode $fh;
    <$fh>;
};
our $dict_b64 = encode_base64(sha256($dict_raw), "");
our $bad_b64  = encode_base64("\x01" x 32, "");

no_long_string();
log_level 'warn';
repeat_each(1);
plan 'no_plan';
run_tests();

__DATA__


=== TEST 1: dcz negotiated when hash matches and dcz is accepted
# The full happy path: Available-Dictionary carries the SHA-256 of a
# configured dictionary and Accept-Encoding lists dcz explicitly, so the
# response commits to Content-Encoding: dcz and declares the
# Available-Dictionary cache key. Wire-format/byte-exactness assertions
# live in tools/test_dcz.py; this suite pins the negotiation contract.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: dcz
Vary: Available-Dictionary
--- no_error_log
[error]



=== TEST 2: no Available-Dictionary falls back to zstd, Vary still set
# A dictionary-less client on the same location gets plain zstd — and the
# response STILL varies on Available-Dictionary: which encoding this
# location serves depends on that request header for every client, so a
# shared cache must key both variants on it.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd, dcz
--- response_headers
Content-Encoding: zstd
Vary: Available-Dictionary
--- no_error_log
[error]



=== TEST 3: unknown dictionary hash falls back to zstd
# A hash we do not hold must never negotiate dcz — the client would
# receive a frame referencing a dictionary it cannot pair with ours.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::bad_b64:"
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 4: Available-Dictionary without dcz in Accept-Encoding
# Advertising a dictionary is not accepting the coding. Without an
# explicit dcz token the response must stay plain zstd.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 5: dcz;q=0 is an explicit refusal
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd, dcz;q=0\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 6: the "*" wildcard does not enable dcz
# RFC 9110's "*" matches any coding not explicitly listed, but only a
# client that actually holds the dictionary can decode dcz — the module
# requires the explicit token, so a wildcard-only request stays zstd.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd, *\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 7: Sec-Fetch-Site cross-site is refused
# RFC 9842 §8: dictionaries are same-origin-partitioned; compressing a
# cross-site response against one leaks it. Falls back to plain zstd.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:\nSec-Fetch-Site: cross-site"
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 8: Sec-Fetch-Site same-origin is allowed
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:\nSec-Fetch-Site: same-origin"
--- response_headers
Content-Encoding: dcz
--- no_error_log
[error]



=== TEST 9: malformed Available-Dictionary (not a byte sequence)
# RFC 8941 byte sequences are colon-delimited; anything else is treated
# as "no usable dictionary", never an error.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd, dcz
Available-Dictionary: not-a-structured-field
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 10: Available-Dictionary decoding to the wrong length
# ":aGk=:" is valid base64 ("hi") but not a SHA-256; must decline.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd, dcz
Available-Dictionary: :aGk=:
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 11: a location's own dictionary list replaces the inherited one
# Standard nginx array-directive semantics: the child declares its own
# zstd_dcz_dict_file, so the server-level dictionary the client
# advertises is no longer in scope and negotiation falls back to zstd.
--- config
    zstd on;
    zstd_min_length 16;
    zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;

    location /inherited {
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }

    location /own {
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/test;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request eval
["GET /inherited", "GET /own"]
--- more_headers eval
[
    "Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:",
    "Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:",
]
--- response_headers eval
[
    "Content-Encoding: dcz",
    "Content-Encoding: zstd",
]
--- no_error_log
[error]



=== TEST 12: an empty dictionary file is a config-load error
--- config
    location /t {
        zstd on;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-empty;
        default_type text/plain;
        return 200 "unreachable\n";
    }
--- request
GET /t
--- must_die
--- error_log
is empty
--- no_error_log
[alert]



=== TEST 13: two dictionaries with identical content are a config-load error
# The negotiation lookup would be ambiguous; almost certainly a copy that
# was meant to be a new version. Refuse to start rather than match the
# first silently.
--- config
    location /t {
        zstd on;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "unreachable\n";
    }
--- request
GET /t
--- must_die
--- error_log
has the same content as
--- no_error_log
[alert]
