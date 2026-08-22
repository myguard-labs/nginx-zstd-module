use Test::Nginx::Socket;
use File::Basename;
use File::Spec;
use Digest::SHA qw(sha256);
use MIME::Base64 qw(encode_base64);
use lib 'lib';

my $dirname = dirname(__FILE__);
# local: this process is the test run, but perlcritic is right that a bare
# assignment to %ENV leaks into anything that runs after it.
local $ENV{'TEST_NGINX_PERL_PATH'} = "$ENV{'PWD'}/$dirname";

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
    my $c = <$fh>;
    close $fh or die "dcz-dict: $!";
    $c;
};
our $dict_b64 = encode_base64(sha256($dict_raw), "");
our $bad_b64  = encode_base64("\x01" x 32, "");

# For the optional supplied-hash directive argument: the fixture's true
# hash as hex, and a deliberately different well-formed hash. Supplying
# the wrong one and negotiating against IT pins that the declared value
# is the negotiation key. (It does NOT prove the hashing pass was
# skipped — the branch overwrites dict->hash either way; the skip is
# pinned by the $zstd_dcz_dicts_hashed asserts in TESTs 21-23, closing
# issue #100's first item.)
our $dict_hex = unpack("H*", sha256($dict_raw));
our $odd_hex  = "01" x 32;
our $odd_b64  = encode_base64("\x01" x 32, "");

# A dictionary above the 8 MB dcz window cap but under the 10 MB hard
# limit, generated rather than committed (nobody wants an 8 MB fixture
# in-tree). Exposed to config blocks via $TEST_NGINX_DCZ_BIGDICT.
my $big_path = File::Spec->catfile(File::Spec->tmpdir(),
                                   "zstd-dcz-bigdict-$$.bin");
{
    open my $bf, '>', $big_path or die "bigdict: $!";
    binmode $bf;
    print {$bf} 'A' x (8 * 1024 * 1024 + 17);
    close $bf;
}
local $ENV{'TEST_NGINX_DCZ_BIGDICT'} = $big_path;
END { unlink $big_path if $big_path; }

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



=== TEST 12: identity fallback still varies on Available-Dictionary
# PR #92 review: a client sending "Accept-Encoding: dcz" (no zstd) with
# a hash we do not hold gets identity — but the SAME client holding a
# dictionary we DO hold would get dcz, so the identity variant is not
# invariant in Available-Dictionary. Without the Vary a shared cache
# keeps serving the stored identity body after the client acquires the
# right dictionary (silent compression loss). Guards the hoisting of
# the Vary push above the acceptance gate.
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
"Accept-Encoding: dcz\nAvailable-Dictionary: :$::bad_b64:"
--- response_headers
!Content-Encoding
Vary: Available-Dictionary
--- no_error_log
[error]



=== TEST 13: a dictionary above the 8 MB window cap warns at config load
# The frame stays well-formed (the RFC client guarantee is a floor of
# max(8 MB, 1.25 x dict)), but dictionary bytes beyond the window cannot
# be referenced — a silent ratio cliff the operator should hear about at
# load time, not discover in telemetry.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_DCZ_BIGDICT;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- error_log
larger than the 8 MB dcz compression window
--- no_error_log
[error]



=== TEST 14: an empty dictionary file is a config-load error
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



=== TEST 15: two dictionaries with the same hash are a config-load error
# The negotiation lookup would be ambiguous; for computed hashes that
# means identical content — almost certainly a copy that was meant to be
# a new version. Refuse to start rather than match the first silently.
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
has the same hash as
--- no_error_log
[alert]



=== TEST 16: supplied hash argument — correct value negotiates dcz
--- config eval
"    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file \$TEST_NGINX_PERL_PATH/suite/dcz-dict $::dict_hex;
        default_type text/plain;
        return 200 \"dcz negotiation body: shared-boilerplate compute render\n\";
    }"
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: dcz
Vary: Available-Dictionary
--- no_error_log
[error]



=== TEST 17: supplied hash is trusted verbatim as the negotiation key
# The directive declares a hash that is NOT the file's: negotiation must
# key on the declared value (client presenting it gets dcz). See the
# preamble note for what this does and does not prove.
--- config eval
"    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file \$TEST_NGINX_PERL_PATH/suite/dcz-dict $::odd_hex;
        default_type text/plain;
        return 200 \"dcz negotiation body: shared-boilerplate compute render\n\";
    }"
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::odd_b64:"
--- response_headers
Content-Encoding: dcz
--- no_error_log
[error]



=== TEST 18: supplied hash trusted verbatim — the file's true hash no longer matches
--- config eval
"    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file \$TEST_NGINX_PERL_PATH/suite/dcz-dict $::odd_hex;
        default_type text/plain;
        return 200 \"dcz negotiation body: shared-boilerplate compute render\n\";
    }"
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 19: supplied hash with the wrong length is a config-load error
# The dictionary path deliberately does NOT exist: the hash error must
# surface anyway, pinning that malformed literals are validated before
# ngx_open_file() rather than shadowed by the file error.
--- config
    location /t {
        zstd on;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/no-such-dict abc123;
        default_type text/plain;
        return 200 "unreachable\n";
    }
--- request
GET /t
--- must_die
--- error_log
invalid dcz dictionary hash
--- no_error_log
[alert]



=== TEST 20: supplied hash with non-hex characters is a config-load error
# Nonexistent path for the same reason as TEST 19.
--- config
    location /t {
        zstd on;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/no-such-dict zz23456789012345678901234567890123456789012345678901234567890123;
        default_type text/plain;
        return 200 "unreachable\n";
    }
--- request
GET /t
--- must_die
--- error_log
non-hex character
--- no_error_log
[alert]



=== TEST 21: supplied hash skips the load-time hashing pass entirely
# THE instrumentation test (issue #100 item 1): $zstd_dcz_dicts_hashed
# counts ngx_http_zstd_sha256() calls from the dictionary loader this
# config cycle. With a supplied hash it must be ZERO — restoring the
# unconditional hash call in front of the have_hash branch (the
# regression the negotiation tests cannot see) makes this "1" and fails
# here.
--- config eval
"    location /t {
        zstd on;
        zstd_dcz_dict_file \$TEST_NGINX_PERL_PATH/suite/dcz-dict $::dict_hex;
        default_type text/plain;
        return 200 \"hashed=\$zstd_dcz_dicts_hashed\n\";
    }"
--- request
GET /t
--- response_body
hashed=0
--- no_error_log
[error]



=== TEST 22: without a supplied hash the loader hashes the file once
# Positive control for TEST 21: the counter is not stuck at zero.
--- config
    location /t {
        zstd on;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "hashed=$zstd_dcz_dicts_hashed\n";
    }
--- request
GET /t
--- response_body
hashed=1
--- no_error_log
[error]



=== TEST 23: mixed supplied and computed entries count only the computed one
--- config eval
"    location /t {
        zstd on;
        zstd_dcz_dict_file \$TEST_NGINX_PERL_PATH/suite/dcz-dict $::dict_hex;
        zstd_dcz_dict_file \$TEST_NGINX_PERL_PATH/suite/test;
        default_type text/plain;
        return 200 \"hashed=\$zstd_dcz_dicts_hashed\n\";
    }"
--- request
GET /t
--- response_body
hashed=1
--- no_error_log
[error]



=== TEST 24: duplicate Sec-Fetch-Site fails closed
# The §8.3 cross-origin gate must not be decided by whichever line sorts
# first. Sec-Fetch-Site is not in nginx's headers_in table, so duplicates
# are chained rather than rejected and reach the module; a proxy that
# merges a client-supplied duplicate, or a smuggling desync, could
# otherwise prepend an agreeable value and switch the gate off. A browser
# never sends two, so more than one falls back to plain zstd.
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
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:\nSec-Fetch-Site: same-origin\nSec-Fetch-Site: cross-site"
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 25: duplicate Sec-Fetch-Site fails closed regardless of order
# The cross-site line first: still plain zstd, so the result does not
# depend on which duplicate the lookup happens to reach.
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
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:\nSec-Fetch-Site: cross-site\nSec-Fetch-Site: same-origin"
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 26: duplicate Available-Dictionary fails closed
# Same reasoning: a single-valued structured field, not deduplicated by
# nginx. Two of them is not a browser, and picking the first would let a
# second dictionary hash be smuggled past the operator's expectation.
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
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:\nAvailable-Dictionary: :$::dict_b64:\nSec-Fetch-Site: same-origin"
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]
