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



=== TEST 3: zstd_static rejects an invalid enum value cleanly
# Regression for the missing ngx_null_string sentinel in the
# ngx_http_zstd_static[] ngx_conf_enum_t array. ngx_conf_set_enum_slot()
# scans until name.len == 0; without the terminating { ngx_null_string, 0 }
# an unmatched value walked off the array end (OOB read, wild-pointer
# ngx_strcasecmp -> possible crash / ASAN abort). With the sentinel an
# unknown value is a clean "invalid value" config error. The ASAN CI job
# runs this binary, so a re-introduced OOB read aborts here.
--- config
    location /bad {
        zstd_static maybe;
        root html;
    }
--- must_die
--- error_log
invalid value "maybe"
--- no_error_log
[alert]



=== TEST 4: zstd_static accepts the last valid enum value ("always")
# Positive counterpart: the sentinel must not shorten the valid range.
# "always" is the final real entry, immediately before the sentinel — it
# still parses and loads.
--- config
    location /ok {
        zstd_static always;
        root html;
    }
--- request
GET /ok/nope
--- error_code: 404
--- no_error_log
invalid value



=== TEST 5: zstd_dict_file without zstd_dict_file_unsafe refuses to start
# RFC1 gate (init_main_conf): a dictionary-compressed body is emitted as a
# plain "Content-Encoding: zstd" that no generic client can decode and that
# RFC 9842 (dcz) does not negotiate. Starting without the explicit
# acknowledgement must be a hard config error, not a warning — otherwise the
# non-standard mode ships silently. Guards the operator-acknowledgement gate.
--- http_config
    zstd_dict_file $TEST_NGINX_SERVER_ROOT/html/zstd.dict;
--- user_files
>>> zstd.dict
the quick brown fox jumps over the lazy dog
--- config
    location /d {
        zstd on;
        default_type text/plain;
        return 200 "body";
    }
--- must_die
--- error_log
Set "zstd_dict_file_unsafe on;" to acknowledge you control both ends
--- no_error_log
[alert]



=== TEST 6: zstd_dict_file pointing at a missing file fails at config load
# The open() failure path in merge_loc_conf. A dictionary that vanished (bad
# path, un-deployed asset) must fail startup with the filename in the message,
# rather than starting and silently compressing without the dictionary.
--- http_config
    zstd_dict_file_unsafe on;
    zstd_dict_file $TEST_NGINX_SERVER_ROOT/html/does-not-exist.dict;
--- config
    location /d {
        zstd on;
        default_type text/plain;
        return 200 "body";
    }
--- must_die
--- error_log
does-not-exist.dict" failed
--- no_error_log
[alert]



=== TEST 7: zstd_comp_level above the library maximum is rejected
# ngx_http_zstd_comp_level bounds the level against ZSTD_minCLevel()/
# ZSTD_maxCLevel() at config load. Without the check libzstd would reject the
# value per-request, turning one typo into a 500 on every response for the
# location. Test above the upper bound rather than below the lower one:
# ZSTD_minCLevel() is -131072, so a "clearly too negative" literal would have
# to be enormous to stay invalid.
#
# The value is deliberately far above the bound rather than maxCLevel()+1: the
# module reads the maximum from libzstd at runtime, so a literal 23 would stop
# being invalid the day libzstd raises its ceiling, and this must_die block
# would silently start passing for the wrong reason.
--- config
    location /lvl {
        zstd on;
        zstd_comp_level 999999;
        default_type text/plain;
        return 200 "body";
    }
--- must_die
--- error_log
zstd compression level must be between
--- no_error_log
[alert]



=== TEST 8: zstd_window_log outside the library bounds is rejected
# C3 regression: zstd_window_log is validated against
# ZSTD_cParam_getBounds(ZSTD_c_windowLog) at config load, not hard-coded
# constants. 99 is above upperBound on every supported libzstd; catching it
# here turns a per-request 500 into a clear startup error.
--- config
    location /wl {
        zstd on;
        zstd_window_log 99;
        default_type text/plain;
        return 200 "body";
    }
--- must_die
--- error_log
"zstd_window_log" must be 0 (default) or between
--- no_error_log
[alert]



=== TEST 9: zstd_window_log accepts 0 (explicit "library default")
# Positive counterpart to TEST 8: the bounds check must special-case 0 rather
# than comparing it against lowerBound (which is > 0), or "keep zstd's
# level-derived default" would be unspellable.
--- config
    location /wl0 {
        zstd on;
        zstd_window_log 0;
        zstd_min_length 1;
        zstd_types text/plain;
        default_type text/plain;
        return 200 "compress me compress me compress me compress me";
    }
--- request
GET /wl0
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 10: a non-numeric zstd_window_log is rejected as an invalid number
# ngx_conf_zstd_set_num_slot_with_negatives' ngx_atoi failure path. The custom
# slot parser exists to accept negative levels, so its error handling is the
# module's own code rather than nginx's stock ngx_conf_set_num_slot.
--- config
    location /wlx {
        zstd on;
        zstd_window_log abc;
        default_type text/plain;
        return 200 "body";
    }
--- must_die
--- error_log
invalid number
--- no_error_log
[alert]



=== TEST 11: a duplicate zstd_comp_level in one location is rejected
# The "is duplicate" guard in ngx_conf_zstd_set_num_slot_with_negatives. The
# custom slot must reject a repeated directive exactly like nginx's stock
# num slot, or the second value would silently win.
--- config
    location /dup {
        zstd on;
        zstd_comp_level 3;
        zstd_comp_level 5;
        default_type text/plain;
        return 200 "body";
    }
--- must_die
--- error_log
"zstd_comp_level" directive is duplicate
--- no_error_log
[alert]



=== TEST 12: zstd on without gzip_vary warns at config load
# Whether the response is zstd or identity depends on Accept-Encoding;
# without Vary a shared cache can serve the compressed variant to a
# client that cannot decode it. The check has lived in merge_loc_conf
# since the Vary work but never had a test pinning it — the brotli
# sibling's TEST 12a predates this one.
--- config
    location /gv {
        zstd on;
        zstd_min_length 1;
        default_type text/plain;
        return 200 "gzip_vary warning fixture body, long enough\n";
    }
--- request
GET /gv
--- more_headers
Accept-Encoding: zstd
--- error_log
zstd is enabled but "gzip_vary" is off
--- no_error_log
[error]



=== TEST 13: zstd on WITH gzip_vary does not warn
# The complementary half: a correctly paired configuration must load
# silently, so the warning cannot become noise on valid configs.
--- config
    location /gv {
        zstd on;
        zstd_min_length 1;
        gzip_vary on;
        default_type text/plain;
        return 200 "gzip_vary warning fixture body, long enough\n";
    }
--- request
GET /gv
--- more_headers
Accept-Encoding: zstd
--- no_error_log eval
[qr/"gzip_vary" is off/, qr/\[error\]/]



=== TEST 14: zstd_static on without gzip_vary warns at config load
# Same hazard as TEST 12 through the static module's own merge-time
# check. No .zst fixture is needed: the warning is a config-load
# statement about the location, not about any request — the request
# below just keeps the block well-formed (identity fallback, no .zst).
--- config
    location /st/ {
        zstd_static on;
        root html;
    }
--- user_files
>>> st/plain.txt
static warn fixture
--- request
GET /st/plain.txt
--- error_log
zstd_static is enabled but "gzip_vary" is off
--- no_error_log
[error]



=== TEST 15: zstd_static always does not warn without gzip_vary
# "always" ignores Accept-Encoding, never sets r->gzip_vary, and the
# response carries no Vary — asking for gzip_vary would describe the
# response incorrectly, so the warning must stay quiet (see the C5
# comment at the check).
--- config
    location /st/ {
        zstd_static always;
        root html;
    }
--- user_files
>>> st/plain.txt
static warn fixture
--- request
GET /st/plain.txt
--- no_error_log eval
[qr/zstd_static is enabled but/, qr/\[error\]/]
