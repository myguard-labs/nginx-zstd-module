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
    for my $module_name (qw(ngx_http_brotli_filter_module.so ngx_http_brotli_static_module.so)) {
        my $module_path = "$nginx_dir/$module_name";
        push @dynamic_modules, $module_path if -f $module_path;
    }
}

add_block_preprocessor(sub {
    my $block = shift;

    if (@dynamic_modules) {
        my $main_config = join "\n", map { "load_module $_;" } @dynamic_modules;
        $block->set_value("main_config", $main_config);
    }

    # RFC 9842 section 8 secure-context gate (#158): dcb is only elected on
    # a secure context, and Test::Nginx::Socket has no TLS client — every
    # connection here is cleartext. So the negotiation blocks below, which
    # model a normal HTTPS deployment, run behind an http-level
    # brotli_dcb_assume_secure_transport (the TLS-terminating-proxy
    # acknowledgement) injected here. Blocks whose name contains
    # "secure-context" opt OUT and see the real fail-closed default.
    unless (defined($block->name) && $block->name =~ /secure-context/) {
        my $hc = $block->http_config;
        $hc = defined($hc) ? $hc : '';
        $block->set_value("http_config",
                          "brotli_dcb_assume_secure_transport on;\n$hc");
    }
});

# The negotiation key is the SHA-256 of the dictionary fixture, computed
# here rather than hardcoded so a fixture edit cannot silently
# desynchronize the suite. hello.js doubles as the dictionary; hello.js.br
# is unrelated to dcb (static-module fixture) but its SOURCE works fine
# as a second, different-content dictionary for the override test.
my $dict_raw = do {
    local $/;
    open my $fh, '<', "$dirname/suite/hello.js" or die "hello.js: $!";
    binmode $fh;
    <$fh>;
};
our $dict_b64 = encode_base64(sha256($dict_raw), "");
# DISTINCT from $odd_hex/$odd_b64 below (CodeRabbit on the graft):
# this one means "a hash the server does NOT hold", the odd pair
# means "a wrong hash the server DOES declare" -- one byte string
# must not play both roles.
our $bad_b64  = encode_base64("\x02" x 32, "");

# For the optional supplied-hash directive argument: the fixture's true
# hash as hex, and a deliberately different well-formed hash. Supplying
# the wrong one and negotiating against IT is the only observable proof
# the module trusts the argument instead of hashing the file.
our $dict_hex = unpack("H*", sha256($dict_raw));
our $odd_hex  = "01" x 32;
our $odd_b64  = encode_base64(pack("H*", $odd_hex), "");

# strict-walk fixtures (zstd siblings #165/#199/#316): an out-of-repo
# tempdir whose ABSOLUTE path goes into the config verbatim — a real
# directory, a dictionary inside it, a symlinked alias to the directory,
# and a world-writable and a sticky world-writable parent the walk must
# refuse as ancestors. A tempdir rather than t/suite deliberately: the
# walk's ownership and mode checks see real ext4 permissions there, not
# a mount's blanket 0777 metadata.
#
# NOT under /tmp: /tmp is 1777, and the walk vets every ancestor, so a
# fixture there would fail its positive control for /tmp's sake. The
# tempdir goes under $HOME and the whole ancestor chain is checked to be
# root- or self-owned and not group/world-writable; a host where it is
# not skips the walk tests (skip_eval) instead of failing them for a
# reason that is not what they test.
use File::Temp qw(tempdir);
use File::Basename qw(dirname);
our $walkdir;
our $have_walk = eval {
    my $base = $ENV{HOME};
    die "no HOME for a vetted fixture base\n" unless defined $base && -d $base;
    $walkdir = tempdir(DIR => $base, CLEANUP => 1);
    for (my $d = $walkdir; ; $d = dirname($d)) {
        my @st = stat($d) or die "stat $d: $!";
        die "ancestor $d owned by uid $st[4], neither root nor uid $>\n"
            if $st[4] != 0 && $st[4] != $>;
        die sprintf("ancestor %s is mode %04o, writable by group or other\n", $d, $st[2] & 07777)
            if $st[2] & 022;
        last if $d eq '/';
    }
    mkdir "$walkdir/real" or die "mkdir: $!";
    open my $h, '>', "$walkdir/real/w.dict" or die "spew: $!";
    print $h "strict walk fixture dictionary contents\n" x 20;
    close $h;
    symlink("$walkdir/real", "$walkdir/link") or die "symlink: $!";
    for my $arm (['open', 0777], ['sticky', 01777]) {
        my ($name, $mode) = @$arm;
        mkdir "$walkdir/$name" or die "mkdir $name: $!";
        open my $f, '>', "$walkdir/$name/w.dict" or die "spew $name: $!";
        print $f "strict walk fixture dictionary contents\n" x 20;
        close $f;
        chmod $mode, "$walkdir/$name" or die "chmod $name: $!";
        my @st = stat("$walkdir/$name");
        die "chmod $name did not stick\n" if ($st[2] & 07777) != $mode;
    }
    1;
} || 0;

no_long_string();
log_level 'warn';
repeat_each(1);
plan 'no_plan';
run_tests();

__DATA__


=== TEST 1: dcb negotiated when hash matches and dcb is accepted
# Wire-format/byte-exactness assertions live in tools/test_dcb.py; this
# suite pins the negotiation contract.
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        default_type text/html;
        return 200 "dcb negotiation body: hello widget compute render text\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: br, dcb\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: dcb
Vary: Accept-Encoding, Available-Dictionary, Sec-Fetch-Site
--- no_error_log
[error]



=== TEST 2: no Available-Dictionary falls back to br, Vary still set
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        default_type text/html;
        return 200 "dcb negotiation body: hello widget compute render text\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br, dcb
--- response_headers
Content-Encoding: br
Vary: Accept-Encoding, Available-Dictionary, Sec-Fetch-Site
--- no_error_log
[error]



=== TEST 3: unknown dictionary hash falls back to br
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        default_type text/html;
        return 200 "dcb negotiation body: hello widget compute render text\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: br, dcb\nAvailable-Dictionary: :$::bad_b64:"
--- response_headers
Content-Encoding: br
--- no_error_log
[error]



=== TEST 4: Available-Dictionary without dcb in Accept-Encoding
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        default_type text/html;
        return 200 "dcb negotiation body: hello widget compute render text\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: br\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: br
--- no_error_log
[error]



=== TEST 5: dcb;q=0 is an explicit refusal
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        default_type text/html;
        return 200 "dcb negotiation body: hello widget compute render text\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: br, dcb;q=0\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: br
--- no_error_log
[error]



=== TEST 6: the "*" wildcard does not enable dcb
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        default_type text/html;
        return 200 "dcb negotiation body: hello widget compute render text\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: br, *\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: br
--- no_error_log
[error]



=== TEST 7: Sec-Fetch-Site cross-site is refused
# The refused (cross-site) response falls back to br but MUST still carry
# Sec-Fetch-Site in Vary (parent #160): otherwise a shared cache could
# serve this br body to a same-origin request that would have gotten dcb,
# or the reverse — a hit on the wrong variant across the §8.3 partition.
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        default_type text/html;
        return 200 "dcb negotiation body: hello widget compute render text\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: br, dcb\nAvailable-Dictionary: :$::dict_b64:\nSec-Fetch-Site: cross-site"
--- response_headers
Content-Encoding: br
Vary: Accept-Encoding, Available-Dictionary, Sec-Fetch-Site
--- no_error_log
[error]



=== TEST 8: Sec-Fetch-Site same-origin is allowed
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        default_type text/html;
        return 200 "dcb negotiation body: hello widget compute render text\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: br, dcb\nAvailable-Dictionary: :$::dict_b64:\nSec-Fetch-Site: same-origin"
--- response_headers
Content-Encoding: dcb
--- no_error_log
[error]



=== TEST 9: malformed Available-Dictionary (not a byte sequence)
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        default_type text/html;
        return 200 "dcb negotiation body: hello widget compute render text\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br, dcb
Available-Dictionary: not-a-structured-field
--- response_headers
Content-Encoding: br
--- no_error_log
[error]



=== TEST 10: Available-Dictionary decoding to the wrong length
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        default_type text/html;
        return 200 "dcb negotiation body: hello widget compute render text\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br, dcb
Available-Dictionary: :aGk=:
--- response_headers
Content-Encoding: br
--- no_error_log
[error]



=== TEST 11: identity fallback still varies on Available-Dictionary
# A client sending "Accept-Encoding: dcb" (no br) with a hash we do not
# hold gets identity — but the SAME client holding a dictionary we DO
# hold would get dcb, so the identity variant is not invariant in
# Available-Dictionary. Guards the Vary push sitting above the
# acceptance gate (the dcz review finding, baked in from the start).
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        default_type text/html;
        return 200 "dcb negotiation body: hello widget compute render text\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: dcb\nAvailable-Dictionary: :$::bad_b64:"
--- response_headers
!Content-Encoding
Vary: Accept-Encoding, Available-Dictionary, Sec-Fetch-Site
--- no_error_log
[error]



=== TEST 12: a location's own dictionary list replaces the inherited one
--- config
    brotli on;
    brotli_min_length 8;
    brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;

    location /inherited {
        default_type text/html;
        return 200 "dcb negotiation body: hello widget compute render text\n";
    }

    location /own {
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js.br;
        default_type text/html;
        return 200 "dcb negotiation body: hello widget compute render text\n";
    }
--- request eval
["GET /inherited", "GET /own"]
--- more_headers eval
[
    "Accept-Encoding: br, dcb\nAvailable-Dictionary: :$::dict_b64:",
    "Accept-Encoding: br, dcb\nAvailable-Dictionary: :$::dict_b64:",
]
--- response_headers eval
[
    "Content-Encoding: dcb",
    "Content-Encoding: br",
]
--- no_error_log
[error]



=== TEST 13: an empty dictionary file is a config-load error
--- config
    location /t {
        brotli on;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/dcb-empty;
        default_type text/html;
        return 200 "unreachable\n";
    }
--- request
GET /t
--- must_die
--- error_log
is empty
--- no_error_log
[alert]



=== TEST 14: two dictionaries with the same hash are a config-load error
--- config
    location /t {
        brotli on;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        default_type text/html;
        return 200 "unreachable\n";
    }
--- request
GET /t
--- must_die
--- error_log
has the same hash as
--- no_error_log
[alert]



=== TEST 15: supplied hash argument — correct value negotiates dcb
--- config eval
"    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_dcb_dict_file \$TEST_NGINX_PERL_PATH/suite/hello.js $::dict_hex;
        default_type text/html;
        return 200 \"dcb negotiation body: hello widget compute render text\n\";
    }"
--- request
GET /t
--- more_headers eval
"Accept-Encoding: br, dcb\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: dcb
Vary: Accept-Encoding, Available-Dictionary, Sec-Fetch-Site
--- no_error_log
[error]



=== TEST 16: a supplied hash that is not the file's aborts config load
# zstd sibling #198, ported with its #220 companion: the literal is
# VERIFIED by default. The dictionary path exists and its contents are
# fine — only the declared hash is wrong — so nothing but the
# verification can reject this config. The old trusted-verbatim
# contract this block used to pin lives on behind
# brotli_dcb_dict_trust_hashes (TEST 28).
--- config eval
"    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_dcb_dict_file \$TEST_NGINX_PERL_PATH/suite/hello.js $::odd_hex;
        default_type text/html;
        return 200 \"unreachable\n\";
    }"
--- request
GET /t
--- must_die
--- error_log eval
qr/does not match the supplied hash "$::odd_hex": the file's SHA-256 is "$::dict_hex"/
--- no_error_log
[alert]



=== TEST 17: the verify pass is real — a correct literal is hashed, counted
# $brotli_dcb_dicts_hashed counts load-time SHA-256 passes. A verified
# literal reads 1 here; restoring the old trust-verbatim default (or
# substituting the literal without hashing) reads 0 and fails — the
# counter is what distinguishes verifying from trusting, closing the
# evidence gap the old TEST 16 comment admitted (nginx-zstd-module#100).
--- config eval
"    location /t {
        brotli_dcb_dict_file \$TEST_NGINX_PERL_PATH/suite/hello.js $::dict_hex;
        default_type text/plain;
        return 200 \"hashed=\$brotli_dcb_dicts_hashed\n\";
    }"
--- request
GET /t
--- response_body
hashed=1
--- no_error_log
[error]



=== TEST 18: supplied hash with the wrong length is a config-load error
# The dictionary path deliberately does NOT exist: the hash error must
# surface anyway, pinning that malformed literals are validated before
# ngx_open_file() rather than shadowed by the file error.
--- config
    location /t {
        brotli on;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/no-such-dict abc123;
        default_type text/html;
        return 200 "unreachable\n";
    }
--- request
GET /t
--- must_die
--- error_log
invalid dcb dictionary hash
--- no_error_log
[alert]



=== TEST 19: supplied hash with non-hex characters is a config-load error
# Nonexistent path for the same reason as TEST 18.
--- config
    location /t {
        brotli on;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/no-such-dict zz23456789012345678901234567890123456789012345678901234567890123;
        default_type text/html;
        return 200 "unreachable\n";
    }
--- request
GET /t
--- must_die
--- error_log
non-hex character
--- no_error_log
[alert]



=== TEST 20: secure-context default fail-closed — dcb declines over cleartext
# No acknowledgement (this block opts out of the injected one via its
# name), and Test::Nginx speaks cleartext, so RFC 9842 section 8 refuses
# the dictionary coding: the response falls back to plain br. The Vary
# line is still emitted (the location varies on Available-Dictionary).
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        default_type text/html;
        return 200 "dcb negotiation body: hello widget compute render text\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: br, dcb\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: br
Vary: Accept-Encoding, Available-Dictionary, Sec-Fetch-Site
--- no_error_log
[error]



=== TEST 21: secure-context X-Forwarded-Proto https does NOT re-enable dcb
# The gate is transport, never a client-settable header: a forwarded
# scheme claim on a directly reachable listener must not switch dcb back
# on over cleartext.
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        default_type text/html;
        return 200 "dcb negotiation body: hello widget compute render text\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: br, dcb\nAvailable-Dictionary: :$::dict_b64:\nX-Forwarded-Proto: https"
--- response_headers
Content-Encoding: br
--- no_error_log
[error]



=== TEST 22: secure-context acknowledgement at location level re-enables dcb
# Proves the opt-in path itself: this block opts out of the injected
# http-level ack and sets the directive in the location, so dcb elects —
# the TLS-terminating-proxy deployment.
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_dcb_assume_secure_transport on;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        default_type text/html;
        return 200 "dcb negotiation body: hello widget compute render text\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: br, dcb\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: dcb
Vary: Accept-Encoding, Available-Dictionary, Sec-Fetch-Site
--- no_error_log
[error]

=== TEST 23: strict_path declared AFTER a dict_file is a config error
# Order-dependent fail-open (zstd siblings' shape): the flag is read at
# parse time, so a load above the "on" line ran without the walk, the
# ownership check, or the writable-target check. Rejecting the ordering
# beats re-opening every dictionary post-parse (the TOCTOU window the
# fstat-after-open checks close).
--- skip_eval: 3: !$::have_walk
--- http_config eval
"brotli_dcb_dict_file $::walkdir/real/w.dict;
 brotli_dcb_dict_strict_path on;"
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
"brotli_dcb_dict_strict_path on" was declared AFTER
--- no_error_log
[alert]


=== TEST 24: strict_path declared BEFORE the dict_file loads and serves
# Positive control for TESTs 23/25/26: identical file, symlink-free
# absolute chain, sanctioned order — the walk verifies every component,
# the ownership and mode checks pass, and the server starts.
--- skip_eval: 3: !$::have_walk
--- http_config eval
"brotli_dcb_dict_strict_path on;
 brotli_dcb_dict_file $::walkdir/real/w.dict;"
--- config
    location /t { return 200 "ok\n"; }
--- request
GET /t
--- error_code: 200
--- response_body
ok
--- no_error_log
[error]


=== TEST 25: strict mode refuses a ".." path component
# zstd sibling #199 (M3): ".." would climb back above a component the
# walk already verified — refused rather than resolved.
--- skip_eval: 3: !$::have_walk
--- http_config eval
"brotli_dcb_dict_strict_path on;
 brotli_dcb_dict_file $::walkdir/real/../real/w.dict;"
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
contains a "." or ".." component
--- no_error_log
[alert]


=== TEST 26: strict mode refuses a symlinked INTERMEDIATE component
# zstd sibling #199 (M3): O_NOFOLLOW on a whole-path open guards only
# the leaf, so the classic "current -> releases/7" layout walked
# straight through the old check (which here was NO check at all). The
# component walk refuses the symlink where it sits; the same file
# loads through its real chain in TEST 24.
--- skip_eval: 3: !$::have_walk
--- http_config eval
"brotli_dcb_dict_strict_path on;
 brotli_dcb_dict_file $::walkdir/link/w.dict;"
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
a symlink at any component is refused
--- no_error_log
[alert]


=== TEST 26a: strict mode refuses a world-writable PARENT directory
# zstd sibling #316 (A33-F2): both leaf checks pass — the file is
# self-owned 0644 — but its parent is 0777, so any local user could
# rename() a different file into the leaf position; the walk refuses
# the ancestor, not the leaf. TEST 26c loads the identical file with
# strict off.
--- skip_eval: 3: !$::have_walk
--- http_config eval
"brotli_dcb_dict_strict_path on;
 brotli_dcb_dict_file $::walkdir/open/w.dict;"
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
directory component "open" of
writable by group or other
--- no_error_log
[alert]


=== TEST 26b: strict mode refuses a STICKY world-writable parent too
# zstd sibling #316: no sticky-bit exemption. A 1777 parent stops other
# users deleting the file, but still lets any of them create the next
# path component beside it — the steering the walk exists to refuse.
--- skip_eval: 3: !$::have_walk
--- http_config eval
"brotli_dcb_dict_strict_path on;
 brotli_dcb_dict_file $::walkdir/sticky/w.dict;"
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
directory component "sticky" of
no sticky-bit exemption
--- no_error_log
[alert]


=== TEST 26c: the same file under the world-writable parent loads with strict off
# Positive control for 26a/26b: default mode leaf-checks the file only,
# so the ancestor's mode is not its concern and the server starts.
--- skip_eval: 3: !$::have_walk
--- http_config eval
"brotli_dcb_dict_file $::walkdir/open/w.dict;"
--- config
    location /t { return 200 "ok\n"; }
--- request
GET /t
--- error_code: 200
--- response_body
ok
--- no_error_log
[error]


=== TEST 27: a non-regular dictionary path is FATAL, unconditionally
# zstd sibling #165: a directory (or FIFO/socket/device) was never a
# valid dictionary. Not gated on strict_path — ngx_is_file() rejects it
# before any read, where the old code fell into a read error at best.
--- http_config eval
"brotli_dcb_dict_file $::walkdir/real;"
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
is not a regular file
--- no_error_log
[alert]

=== TEST 28: trust_hashes on — the declared literal IS the negotiation key
# The opt-out's contract (zstd sibling #220), proven the only
# observable way: the literal deliberately does not match the file,
# and the client advertising the DECLARED value gets dcb — the exact
# config that is TEST 16's must_die under the default. The file's true
# hash correspondingly no longer matches (second request).
--- http_config
    brotli_dcb_dict_trust_hashes on;
--- config eval
"    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_dcb_dict_file \$TEST_NGINX_PERL_PATH/suite/hello.js $::odd_hex;
        default_type text/html;
        return 200 \"dcb negotiation body: hello widget compute render text\n\";
    }"
--- request eval
["GET /t", "GET /t"]
--- more_headers eval
["Accept-Encoding: br, dcb\nAvailable-Dictionary: :$::odd_b64:",
 "Accept-Encoding: br, dcb\nAvailable-Dictionary: :$::dict_b64:"]
--- response_headers eval
["Content-Encoding: dcb",
 "Content-Encoding: br"]
--- no_error_log
[error]



=== TEST 29: trust_hashes on — the hashing pass is actually skipped
# The perf contract, witnessed by the counter TEST 17 pins at 1 for
# the same line shape under the default: a trusted literal contributes
# ZERO. Substituting the literal after hashing anyway (trust as a
# no-op) produces the same negotiation key but reads 1 here.
--- http_config
    brotli_dcb_dict_trust_hashes on;
--- config eval
"    location /t {
        brotli_dcb_dict_file \$TEST_NGINX_PERL_PATH/suite/hello.js $::dict_hex;
        default_type text/plain;
        return 200 \"hashed=\$brotli_dcb_dicts_hashed\n\";
    }"
--- request
GET /t
--- response_body
hashed=0
--- no_error_log
[error]



=== TEST 30: trust_hashes on — a line without a literal is still hashed
# Trust changes what a SUPPLIED literal means, nothing else: an
# unhashed line has nothing to trust, so it is computed as always.
--- http_config
    brotli_dcb_dict_trust_hashes on;
--- config
    location /t {
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        default_type text/plain;
        return 200 "hashed=$brotli_dcb_dicts_hashed\n";
    }
--- request
GET /t
--- response_body
hashed=1
--- no_error_log
[error]



=== TEST 31: trust_hashes declared AFTER a literal line is a config error
# Same ordering trap and remedy as brotli_dcb_dict_strict_path: the
# flag is read at parse time, so a literal above the "on" line was
# verified — correct bytes, but the pass the directive exists to skip
# was silently paid. Reject rather than be quietly position-dependent.
--- http_config eval
"brotli_dcb_dict_file \$TEST_NGINX_PERL_PATH/suite/hello.js $::dict_hex;
 brotli_dcb_dict_trust_hashes on;"
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
"brotli_dcb_dict_trust_hashes on" was declared AFTER
--- no_error_log
[alert]



=== TEST 32: trust_hashes on does not excuse a malformed literal
# Trust changes what a well-formed literal means, not what a malformed
# one does: syntax is validated before the file is opened under either
# policy.
--- http_config
    brotli_dcb_dict_trust_hashes on;
--- config
    location /t {
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js zz11;
        default_type text/plain;
        return 200 "unreachable\n";
    }
--- must_die
--- error_log
invalid dcb dictionary hash
--- no_error_log
[alert]

=== TEST 33: a dictionary above the 10 MB limit is a config-load error
# Pins the off_t bound that now runs BEFORE the size_t narrowing (zstd
# siblings' round-4 R3-9 twin): on ILP32 the old order let a 4 GiB
# file load as its low 32 bits, sail under this limit, hash clean and
# serve. The wrap itself needs a 32-bit rig; this pins the bound and
# its message so the check cannot silently vanish.
--- http_config eval
do {
    my $big = "$::walkdir/oversize.dict";
    if (!-e $big) {
        open my $h, '>', $big or die "spew: $!";
        seek $h, 10 * 1024 * 1024, 0;
        print $h "x";
        close $h;
    }
    "brotli_dcb_dict_file $big;";
}
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
too large
--- no_error_log
[alert]
