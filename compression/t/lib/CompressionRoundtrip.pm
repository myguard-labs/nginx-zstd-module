package CompressionRoundtrip;

# The one decode harness both roundtrip-asserting suites share
# (04-roundtrip and 05-tuning used to carry identical
# spew/slurp/cli_decode copies, and neither checked that the reference
# decoders exist -- a missing CLI turned every decode failure into a
# confusing hash mismatch blamed on the C code).

use strict;
use warnings;
use File::Temp qw(tempdir);
use Exporter 'import';

our @EXPORT_OK = qw(spew slurp cli_decode rt_tmpdir assert_decoders);

my $tmp = tempdir(CLEANUP => 1);

sub rt_tmpdir { return $tmp }

sub spew {
    my ($path, $data) = @_;
    open my $h, '>', $path or die "$path: $!";
    binmode $h;
    print $h $data;
    close $h or die "close $path: $!";
    return;
}

sub slurp {
    my ($path) = @_;
    open my $h, '<', $path or die "$path: $!";
    binmode $h;
    local $/;
    my $content = <$h>;
    close $h or die "close $path: $!";
    return $content;
}

sub cli_decode {
    my ($cmd, $data) = @_;
    spew("$tmp/in", $data);
    system("$cmd < $tmp/in > $tmp/out 2>/dev/null") == 0 or return;
    return slurp("$tmp/out");
}

# Die EARLY, with the true diagnosis, when a reference CLI is absent:
# every roundtrip oracle downstream depends on these tools, and their
# absence must not read as a compression bug.
sub assert_decoders {
    my @tools = @_;
    for my $tool (@tools) {
        system("$tool --version >/dev/null 2>&1") == 0
            or die "reference decoder '$tool' is not on PATH -- the "
                 . "roundtrip oracles cannot run without it";
    }
    return;
}

1;
