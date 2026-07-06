use Test::Nginx::Socket;
use File::Basename;
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

no_long_string();
log_level 'warn';
# Config-load warnings are emitted ONCE at startup; with repeat_each > 1
# the error.log is wiped between repeats and later iterations cannot
# re-observe them (why these blocks live outside t/00-filter.t).
repeat_each(1);
plan 'no_plan';
run_tests();

__DATA__


=== TEST 1: zstd_bypass_vary without zstd_bypass warns at config load
# zstd_bypass_vary names the header the zstd_bypass decision varies on;
# set alone it emits a Vary field no response varies on (silent cache
# hit-rate degradation). merge_loc_conf warns — assert the warning is
# actually emitted so the misconfig stays visible.
--- config
    location /warn {
        zstd on;
        zstd_bypass_vary X-No-Compression;
        default_type text/plain;
        return 200 "hello world padding padding padding\n";
    }
--- request
GET /warn
--- more_headers
Accept-Encoding: zstd
--- error_log
"zstd_bypass_vary" is set without a "zstd_bypass" predicate
--- no_error_log
[error]



=== TEST 2: zstd_bypass_vary WITH zstd_bypass does not warn
# The complementary half: a correctly paired configuration must load
# silently, so the warning cannot become noise on valid configs.
--- config
    location /paired {
        zstd on;
        zstd_bypass $http_x_no_compression;
        zstd_bypass_vary X-No-Compression;
        default_type text/plain;
        return 200 "hello world padding padding padding\n";
    }
--- request
GET /paired
--- more_headers
Accept-Encoding: zstd
--- no_error_log eval
[qr/zstd_bypass_vary.*without/, qr/\[error\]/]
