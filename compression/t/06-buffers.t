use Test::Nginx::Socket;
use Test::More;
use Digest::SHA qw(sha256_hex);
use MIME::Base64 qw(encode_base64);
use File::Temp qw(tempdir);

# Phase-3 output-buffer recycling. The deterministic witnesses are the
# get_buf debug lines: "buffer cap N reached, awaiting drain" proves
# the cap paused production, "reused output buf" proves a reclaimed
# buffer came back through the free list -- and with a cap far below
# the output's buffer count, FINISHING the response at all requires
# reuse, so the decode roundtrip doubles as the functional proof that
# pause/drain/resume preserved the stream byte-exact.

my $tmp = tempdir(CLEANUP => 1);

# incompressible ~200 KB: compressed output ~200 KB, far above any
# small cap x step size
our $big = '';
{
    open my $ur, '<', '/dev/urandom' or die $!;
    my $raw;
    # check the byte count (CodeRabbit round 5): a short read shrinks
    # $big, both sides hash the same shortened fixture, and the
    # MUST-pause assertions in TESTs 1/2/11/12 become the only witness
    my $got = read($ur, $raw, 150_000);
    die "urandom short read: got " . ($got // 'undef') . " of 150000"
        unless defined $got && $got == 150_000;
    close $ur;
    $big = encode_base64($raw, "");
}

sub spew { open my $h, '>', $_[0] or die "$_[0]: $!"; binmode $h; print $h $_[1]; close $h }
sub slurp { open my $h, '<', $_[0] or die "$_[0]: $!"; binmode $h; local $/; <$h> }

sub cli_decode {
    my ($cmd, $data) = @_;
    spew("$tmp/in", $data);
    system("$cmd < $tmp/in > $tmp/out 2>/dev/null") == 0 or return undef;
    return slurp("$tmp/out");
}

our %decoders = (
    zstd => sub { cli_decode("zstd -dq -c", $_[0]) },
    br   => sub { cli_decode("brotli -d -c", $_[0]) },
);

add_response_body_check(sub {
    my ($block, $body, $req_idx, $rep_idx, $dry) = @_;
    return if $dry;

    my $how = $block->decode_with or return;
    chomp $how;

    my $dec = $decoders{$how} ? $decoders{$how}->($body) : undef;

    Test::More::is(
        defined $dec ? sha256_hex($dec) : "(decode failed)",
        sha256_hex($big),
        $block->name . " - $how roundtrip decodes byte-exact"
    );
});

no_long_string();
log_level 'warn';
repeat_each(1);
plan 'no_plan';
run_tests();

__DATA__


=== TEST 1: a tight cap pauses, drains, reuses -- and the stream survives
# brotli's step bufs are 32 KB; ~200 KB of incompressible output needs
# 6+ of them, so cap 2 MUST pause at least once and MUST reuse
# reclaimed bufs to finish. The roundtrip proves the pause/resume
# seams did not corrupt the stream.
--- log_level: debug
--- timeout: 10
--- user_files eval
[ [ "b/big.txt" => $::big ] ]
--- config
    location /b/ {
        compression on;
        compression_order br;
        compression_buffers 2;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /b/big.txt
--- more_headers
Accept-Encoding: br
--- response_headers
Content-Encoding: br
--- decode_with
br
--- error_log eval
[qr/compression: buffer cap 2 reached, awaiting drain/,
 qr/compression: reused output buf/]


=== TEST 2: an operator size override feeds the same recycling machinery
# 8 KB bufs x cap 4 against ~200 KB of zstd output: dozens of pauses,
# reuse mandatory, stream still byte-exact
--- log_level: debug
--- timeout: 10
--- user_files eval
[ [ "b/big.txt" => $::big ] ]
--- config
    location /b/ {
        compression on;
        compression_buffers 4 8k;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /b/big.txt
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- decode_with
zstd
--- error_log eval
[qr/compression: buffer cap 4 reached, awaiting drain/,
 qr/compression: reused output buf/]


=== TEST 3: the default cap never pauses an ordinary response
# 32 bufs at the backend step size is far above what ~200 KB needs;
# the cap line must NOT appear (the recycling machinery stays dormant
# on the fast path)
--- log_level: debug
--- timeout: 10
--- user_files eval
[ [ "b/big.txt" => $::big ] ]
--- config
    location /b/ {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /b/big.txt
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- decode_with
zstd
--- no_error_log eval
[qr/buffer cap \d+ reached/]


=== TEST 4: a zero buffer count is a config error
--- config
    location / {
        compression_buffers 0;
    }
--- must_die
--- error_log
invalid number "0" in "compression_buffers"


=== TEST 5: a malformed size is a config error
--- config
    location / {
        compression_buffers 4 zap;
    }
--- must_die
--- error_log
invalid size "zap" in "compression_buffers"


=== TEST 6: duplicate compression_buffers is a config error
--- config
    location / {
        compression_buffers 4;
        compression_buffers 8;
    }
--- must_die
--- error_log
is duplicate


=== TEST 7: an overflowing compression_buffers product is a hard error (parent #167)
# each argument parses fine on its own; only their product overflows the
# address space. Refused unconditionally — no size means "meant it".
--- config
    location / {
        compression_buffers 1000000000 1000000000000;
    }
--- must_die
--- error_log
overflows the address space


=== TEST 8: a huge but representable product is refused above the hard cap
# 1024 x 1m = 1 GB of output-chain memory per response, past the 256 MB
# cap; the advisory/cap tier fires at merge time (the parse slot checks
# only overflow), so the merged value is what is refused.
--- config
    location / {
        compression_buffers 1024 1m;
    }
--- must_die
--- error_log
above the 256 MB hard cap


=== TEST 9: compression_buffers_unsafe on accepts a total above the hard cap
# the operator acknowledges the 1 GB total in words; it loads with a
# warning instead of failing.
--- config
    location /t {
        compression on;
        compression_buffers 1024 1m;
        compression_buffers_unsafe on;
        default_type text/html;
        return 200 "unsafe-acknowledged buffers fixture body to compress\n";
    }
--- request
GET /t
--- error_code: 200
--- error_log
acknowledges it


=== TEST 10: a total between the advisory and the hard cap warns and loads
# 32 x 1m = 32 MB per response: past the 8 MB advisory, under the 256 MB
# cap. Warns, does not fail.
--- config
    location /t {
        compression on;
        compression_buffers 32 1m;
        default_type text/html;
        return 200 "advisory-tier buffers fixture body long enough to compress\n";
    }
--- request
GET /t
--- error_code: 200
--- error_log
output-chain memory PER RESPONSE
--- no_error_log
[emerg]

=== TEST 11: a tight SIZE ships sub-postpone writes -- zstd completes intact
# The buffered-bit/recycled pair (review round 3): without recycled=1
# on fresh bufs, every 64-byte ship sat under postpone_output's hold,
# the busy chain never drained, and this exact config truncated the
# zstd response to the first caps' worth of bytes under a 200 -- the
# decode check is what catches a short-but-valid-looking body. And
# without the connection-level buffered bit (r->buffered is a four-bit
# field; 0x20 truncates to nothing), held encoder state was invisible
# to the writer. Incompressible input keeps every buffer full-width.
--- log_level: debug
--- timeout: 10
--- user_files eval
[ [ "b/big.txt" => $::big ] ]
--- config
    location /b/ {
        compression on;
        compression_buffers 2 64;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /b/big.txt
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- decode_with
zstd
--- no_error_log
[error]


=== TEST 12: a tight SIZE ships sub-postpone writes -- brotli completes intact
# Same config, brotli coding: pre-fix this one did not truncate, it
# never answered at all (the busy chain deadlock), so the block's
# timeout is the fail-first witness.
--- log_level: debug
--- timeout: 10
--- user_files eval
[ [ "b/big.txt" => $::big ] ]
--- config
    location /b/ {
        compression on;
        compression_order br;
        compression_buffers 2 64;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /b/big.txt
--- more_headers
Accept-Encoding: br
--- response_headers
Content-Encoding: br
--- decode_with
br
--- no_error_log
[error]
