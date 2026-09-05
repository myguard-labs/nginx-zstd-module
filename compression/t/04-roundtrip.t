use Test::Nginx::Socket;
use Test::More;
use Digest::SHA qw(sha256 sha256_hex);
use MIME::Base64 qw(encode_base64);
use File::Temp qw(tempdir);
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/lib';
use CompressionRoundtrip qw(spew slurp cli_decode assert_decoders);

assert_decoders('zstd', 'brotli');

# Decode roundtrips INSIDE the suite (review round 2, finding 3): every
# block's response body is fed back through the reference decoder named
# by its `--- decode_with` section and compared byte-exact against the
# original plaintext. The big fixture is deliberately INCOMPRESSIBLE
# (base64 of random bytes, ~200 KB) so brotli's 32 KB output chunks
# ship several buffers per response — the multi-buffer FINISH path the
# round-1 double-FINISH fix lives on. The one-byte blocks pin round
# 2's blocking find: brotli's content-derived out_size (7 bytes for a
# 1-byte body) is smaller than the 36-byte dcb prologue, and the
# chassis clamp is what makes them serve intact (pre-fix this was an
# ASan heap-buffer-overflow and a silently corrupt response).

my $tmp = tempdir(CLEANUP => 1);

our $dict = "const shared = 'roundtrip dictionary material';\n" x 40;
our $hex  = sha256_hex($dict);
our $b64  = encode_base64(sha256($dict), "");

# incompressible big body: forces multiple output-buffer ships
our $big = '';
{
    open my $ur, '<', '/dev/urandom' or die $!;
    my $raw; read $ur, $raw, 150_000; close $ur;
    $big = encode_base64($raw, "");
}

our %srcs = ( big => $big, one => "x",
              len29 => ("a" x 29), len30 => ("a" x 30) );

# spew/slurp/cli_decode come from t/lib/CompressionRoundtrip.pm

spew("$tmp/dict", $dict);


our %decoders = (
    zstd => sub { cli_decode("zstd -dq -c", $_[0]) },
    br   => sub { cli_decode("brotli -d -c", $_[0]) },
    # dcz's 40-byte skippable-frame prologue is skipped by the decoder
    # natively; the dictionary rides -D
    dcz  => sub { cli_decode("zstd -dq -D $tmp/dict -c", $_[0]) },
    # dcb's 36 raw bytes are NOT consumed by the decoder. ASSERT the
    # prologue before stripping it (CodeRabbit round 5): the regression
    # these blocks defend against is a corrupt prologue with a valid
    # stream behind it -- skip-36-and-decode is blind to exactly that.
    dcb  => sub {
        return undef
            if substr($_[0], 0, 36) ne "\xff" . "DCB" . sha256($dict);
        return cli_decode("brotli -d -D $tmp/dict -c", substr($_[0], 36));
    },
);

add_response_body_check(sub {
    my ($block, $body, $req_idx, $rep_idx, $dry) = @_;
    return if $dry;

    my $how = $block->decode_with or return;
    chomp $how;

    my $srckey = $block->expect_src // "big";
    chomp $srckey;
    # an unknown key must die HERE, not hash undef into a failure that
    # blames the C code (CodeRabbit round 5)
    die $block->name . ": unknown expect_src key '$srckey'"
        unless exists $srcs{$srckey};

    my $dec = $decoders{$how} ? $decoders{$how}->($body) : undef;

    Test::More::is(
        defined $dec ? sha256_hex($dec) : "(decode failed)",
        sha256_hex($srcs{$srckey}),
        $block->name . " - $how roundtrip decodes byte-exact"
    );
});

# RFC 9842 §8 secure-context gate (#158): dcz/dcb only elect on a secure
# context and Test::Nginx speaks cleartext, so the dict roundtrips here
# run behind an http-level compression_dict_assume_secure_transport (the
# TLS-terminating-proxy acknowledgement). This suite proves byte-exact
# decoding, not the gate itself — the gate's behaviour lives in
# 02-dict-negotiation.t.
add_block_preprocessor(sub {
    my $block = shift;

    my $hc = $block->http_config;
    $hc = defined($hc) ? $hc : '';
    $block->set_value('http_config',
                      "compression_dict_assume_secure_transport on;\n$hc");
});

no_long_string();
log_level 'warn';
repeat_each(1);
plan 'no_plan';
run_tests();

__DATA__


=== TEST 1: plain zstd roundtrip, multi-buffer body
--- user_files eval
[ [ "rt/big.txt" => $::big ] ]
--- config
    location /rt/ {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /rt/big.txt
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- decode_with: zstd
--- no_error_log
[error]



=== TEST 2: plain brotli roundtrip, multi-buffer body
# ~200 KB of incompressible output through 32 KB out chunks: several
# full-buffer ships ending in FINISH
--- user_files eval
[ [ "rt/big.txt" => $::big ] ]
--- config
    location /rt/ {
        compression on;
        compression_order br zstd;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /rt/big.txt
--- more_headers
Accept-Encoding: br
--- response_headers
Content-Encoding: br
--- decode_with: br
--- no_error_log
[error]



=== TEST 3: dcz roundtrip with the dictionary, multi-buffer body
--- user_files eval
[ [ "rt/big.txt" => $::big ], [ "rt.dict" => $::dict ] ]
--- http_config
    compression_dict_file html/rt.dict;
--- config
    location /rt/ {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        root html;
    }
--- request
GET /rt/big.txt
--- more_headers eval
qq{Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::b64:}
--- response_headers
Content-Encoding: dcz
--- decode_with: dcz
--- no_error_log
[error]



=== TEST 4: dcb roundtrip with the dictionary, multi-buffer body
--- user_files eval
[ [ "rt/big.txt" => $::big ], [ "rt.dict" => $::dict ] ]
--- http_config
    compression_dict_file html/rt.dict;
--- config
    location /rt/ {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        root html;
    }
--- request
GET /rt/big.txt
--- more_headers eval
qq{Accept-Encoding: br, dcb\nAvailable-Dictionary: :$::b64:}
--- response_headers
Content-Encoding: dcb
--- decode_with: dcb
--- no_error_log
[error]



=== TEST 5: ONE-BYTE dcb body serves intact (the overflow pin)
# brotli sizes the out buffer from the content length — 7 bytes for a
# 1-byte body — and the 36-byte prologue used to be memcpy'd straight
# past it (heap write; worker survived; response silently corrupt).
# The chassis clamp makes this the smallest possible healthy dcb
# response, decoded here to prove prologue AND stream both intact.
--- user_files eval
[ [ "rt.dict" => $::dict ] ]
--- http_config
    compression_dict_file html/rt.dict;
--- config
    location /one {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        return 200 "x";
    }
--- request
GET /one
--- more_headers eval
qq{Accept-Encoding: br, dcb\nAvailable-Dictionary: :$::b64:}
--- response_headers
Content-Encoding: dcb
--- decode_with: dcb
--- expect_src: one
--- no_error_log
[error]



=== TEST 6: ONE-BYTE dcz body serves intact
# zstd's out_size is fixed and large, so this side never overflowed —
# pinned anyway: the clamp's guarantee is chassis-wide, not
# backend-specific
--- user_files eval
[ [ "rt.dict" => $::dict ] ]
--- http_config
    compression_dict_file html/rt.dict;
--- config
    location /one {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        return 200 "x";
    }
--- request
GET /one
--- more_headers eval
qq{Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::b64:}
--- response_headers
Content-Encoding: dcz
--- decode_with: dcz
--- expect_src: one
--- no_error_log
[error]



=== TEST 7: 29-byte dcb body — the last pre-clamp-unsafe length
# BrotliEncoderMaxCompressedSize(29) = 35 < 36: without the clamp this
# was the largest body that still sized the buffer under the prologue
--- user_files eval
[ [ "rt.dict" => $::dict ] ]
--- http_config
    compression_dict_file html/rt.dict;
--- config
    location /one {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        return 200 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    }
--- request
GET /one
--- more_headers eval
qq{Accept-Encoding: br, dcb\nAvailable-Dictionary: :$::b64:}
--- response_headers
Content-Encoding: dcb
--- decode_with: dcb
--- expect_src: len29
--- no_error_log
[error]



=== TEST 8: 30-byte dcb body — buffer EXACTLY equals the prologue
# MaxCompressedSize(30) = 36: the clamp leaves out_size == prologue_len,
# so the prologue fills the first buffer completely, forcing an
# immediate full-buffer ship before the encoder writes a byte — the
# prologue-exactly-fills path no other block reaches
--- user_files eval
[ [ "rt.dict" => $::dict ] ]
--- http_config
    compression_dict_file html/rt.dict;
--- config
    location /one {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        return 200 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    }
--- request
GET /one
--- more_headers eval
qq{Accept-Encoding: br, dcb\nAvailable-Dictionary: :$::b64:}
--- response_headers
Content-Encoding: dcb
--- decode_with: dcb
--- expect_src: len30
--- no_error_log
[error]
