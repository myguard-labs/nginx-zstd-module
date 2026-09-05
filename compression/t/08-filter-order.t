use Test::Nginx::Socket;
use Test::More;
use Digest::SHA qw(sha256_hex);
use File::Temp qw(tempdir);

# Filter-order composition: the parent's most-recurrent bug class
# (f4ba115, 2d2e641, cae80f9, 3f73e15, 8a6e370, 18c778d — SIX
# regressions), rediscovered here when the port shipped without the
# parent's ngx_module_order and compressed raw .shtml source before
# SSI could expand it. These blocks pin the property the order fix
# provides: the compression filter runs AFTER every
# content-transforming filter, so the TRANSFORMED body is what gets
# compressed. Each block decodes the response through the reference
# CLI and asserts the transformation is present in the decoded bytes
# -- CE assertions alone cannot see this class (the pre-fix build
# happily served CE: zstd of the wrong bytes).

my $tmp = tempdir(CLEANUP => 1);

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

# expected DECODED bodies, keyed by block
our %expect = (
    subbed   => ("line with REPLACED token\n" x 40),
    expanded => "before[" . ("included content line\n" x 40) . "]after\n",
    added    => "prefix part\n" . ("main body line\n" x 40),
);

add_response_body_check(sub {
    my ($block, $body, $req_idx, $rep_idx, $dry) = @_;
    return if $dry;

    my $how = $block->decode_with or return;
    chomp $how;
    my $key = $block->expect_key or return;
    chomp $key;

    my $dec = $decoders{$how} ? $decoders{$how}->($body) : undef;

    Test::More::is(
        defined $dec ? sha256_hex($dec) : "(decode failed)",
        sha256_hex($expect{$key}),
        $block->name . " - decoded output is the TRANSFORMED body"
    );
});

no_long_string();
log_level 'warn';
repeat_each(1);
plan 'no_plan';
run_tests();

__DATA__


=== TEST 1: sub_filter's replacement is present in the decoded output
# the parent's TEST 33 shape: compression must run AFTER sub_filter,
# or the substitution never happens in what the client decodes
--- user_files eval
[ [ "o/page.txt" => ("line with NEEDLE token\n" x 40) ] ]
--- config
    location /o/ {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        sub_filter 'NEEDLE' 'REPLACED';
        sub_filter_once off;
        sub_filter_types text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /o/page.txt
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- decode_with
zstd
--- expect_key
subbed
--- no_error_log
[error]


=== TEST 2: SSI expansion is present in the decoded output (brotli)
# same property through the other backend: the include must expand
# BEFORE compression, and the decoded body proves it did
--- user_files eval
[ [ "o/page.shtml" => qq{before[<!--#include virtual="/o/inc.html" -->]after\n} ],
  [ "o/inc.html" => ("included content line\n" x 40) ] ]
--- config
    location /o/ {
        compression on;
        compression_order br;
        compression_min_length 1;
        ssi on;
        default_type text/html;
        gzip_vary on;
        root html;
    }
--- request
GET /o/page.shtml
--- more_headers
Accept-Encoding: br
--- response_headers
Content-Encoding: br
--- decode_with
br
--- expect_key
expanded
--- no_error_log
[error]


=== TEST 3: addition's prefix subrequest is present in the decoded output
--- user_files eval
[ [ "o/main.txt" => ("main body line\n" x 40) ],
  [ "o/prefix.txt" => "prefix part\n" ] ]
--- config
    location /o/ {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        add_before_body /o/prefix.txt;
        addition_types text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /o/main.txt
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- decode_with
zstd
--- expect_key
added
--- no_error_log
[error]
