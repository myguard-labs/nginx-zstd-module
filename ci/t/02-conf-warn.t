use Test::Nginx::Socket;
use File::Basename;
use File::Spec;
use lib 'lib';

my $dirname = dirname(__FILE__);
# Absolute path to the committed fixture dir (ci/t/suite, holding test +
# test.zst). TEST 14 serves from here rather than "root ../suite": this
# suite's servroot is created under /tmp in CI (build-test.yml, confwarn
# step), so a relative climb out of the servroot escapes the workspace and
# open() fails. 01-static.t can use ../suite only because its own servroot
# is placed inside ci/t/.
our $suite_dir = File::Spec->rel2abs("$dirname/suite");
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



=== TEST 12: zstd on without gzip_vary still emits Vary: Accept-Encoding
# G5. Whether the response is zstd or identity depends on
# Accept-Encoding; without Vary a shared cache serves the compressed
# variant to a client that cannot decode it. This used to be a
# config-load WARNING telling the operator to set "gzip_vary on" —
# advice that was silently ignorable, and one missed warning poisoned a
# cache. The module now emits the field itself, so the header is what
# gets asserted, and the warning is gone: a warning about a directive
# that no longer changes the outcome would be misleading.
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
--- response_headers
Content-Encoding: zstd
Vary: Accept-Encoding
--- no_error_log eval
[qr/gzip_vary/, qr/\[error\]/]



=== TEST 13: zstd on WITH gzip_vary emits exactly one Vary line
# The duplicate-safety half. With "gzip_vary on" nginx emits the field
# from r->gzip_vary, so the module must NOT push a second identical
# line. Test::Nginx's response_headers compares the joined value of the
# field, so a doubled emission reads as "Accept-Encoding, Accept-Encoding"
# and fails here.
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
--- response_headers
Content-Encoding: zstd
Vary: Accept-Encoding
--- no_error_log eval
[qr/gzip_vary/, qr/\[error\]/]



=== TEST 14: zstd_static on without gzip_vary still emits Vary: Accept-Encoding
# G5, static handler, on the DECLINE arm. ci/t/suite holds test +
# test.zst, so this URI is Accept-Encoding-dependent; the client here
# does not accept zstd, so the handler emits the Vary field and then
# declines for the identity file to be served. That identity response
# is exactly the one a shared cache must not pin every later client to,
# and it must carry the field with no "gzip_vary on" configured — which
# is what the old warning could only ask for. TEST 25 in 01-static.t is
# the same arm WITH gzip_vary on.
#
# The fixture dir is addressed by ABSOLUTE path ($::suite_dir), not as
# "root ../suite": this suite's servroot is created under /tmp in CI
# (build-test.yml, the confwarn step), so a relative climb out of the
# servroot escapes the workspace entirely and open() fails with ENOENT.
# 01-static.t can use ../suite only because its own servroot is placed
# inside ci/t/ (build-test.yml:1307 vs :1290).
--- config eval
"    location /test {
        zstd_static on;
        root $::suite_dir;
    }"
--- request
GET /test
--- more_headers
Accept-Encoding: gzip
--- response_headers
!Content-Encoding
Vary: Accept-Encoding
--- no_error_log eval
[qr/gzip_vary/, qr/\[error\]/]



=== TEST 15: zstd_static always does not vary and does not mention gzip_vary
# "always" ignores Accept-Encoding: it is not a negotiated variant, so
# it must NOT claim to vary on Accept-Encoding (that would fragment
# every cache key for nothing). The G5 emission is deliberately scoped
# to "on" only. See C5.
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
--- response_headers
!Vary
--- no_error_log eval
[qr/gzip_vary/, qr/\[error\]/]



=== TEST 16: an empty zstd_dict_file is rejected at config load
# A 0-byte trained dictionary used to load as a silent no-op: the read is
# complete (0 == size) and ZSTD_createCDict(buf, 0, level) returns a VALID
# CDict, so nginx started and compressed with no dictionary at all -- after
# the operator had explicitly set zstd_dict_file_unsafe on. The dcz loader
# has always rejected an empty file; both loaders now agree.
--- http_config
    zstd_dict_file_unsafe on;
    zstd_dict_file $TEST_NGINX_SERVER_ROOT/html/empty.dict;
--- user_files
>>> empty.dict
--- config
    location /d {
        zstd on;
        default_type text/plain;
        return 200 "body";
    }
--- must_die
--- error_log
empty.dict" is empty
--- no_error_log
[alert]



=== TEST 17: a duplicate zstd_comp_level is rejected when the first value is -1
# Regression: NGX_CONF_UNSET is -1, and -1 is a valid documented level, so
# the "is duplicate" guard tested the same value a real directive could
# store. "zstd_comp_level -1; zstd_comp_level 5;" was therefore accepted
# silently and 5 won. TEST 11 cannot catch this -- neither of its values is
# the sentinel. The slot now tests NGX_HTTP_ZSTD_LEVEL_UNSET.
--- config
    location /dup {
        zstd on;
        zstd_comp_level -1;
        zstd_comp_level 5;
        default_type text/plain;
        return 200 "body";
    }
--- must_die
--- error_log
"zstd_comp_level" directive is duplicate
--- no_error_log
[alert]



=== TEST 18: both modules in one location emit exactly ONE Vary: Accept-Encoding
# The duplicate-emission cell the G5 matrix missed, and it was REAL:
# with "zstd_static on" + "zstd on" + gzip_vary off, a non-accepting
# client made the static handler emit Vary and DECLINE, after which the
# filter emitted it again on the identity response it also declined to
# encode -- two identical field lines, breaking the exactly-one contract
# ngx_http_zstd_vary_accept_encoding() exists to keep. Reproduced with
# curl before the guard (2 lines), 1 after.
#
# The response_headers check below asserts the VALUE, which Test::Nginx
# joins with ", " when a field repeats -- so a regression reads as
# "Accept-Encoding, Accept-Encoding" and fails here rather than passing
# a mere presence check. That is the whole point of this block.
--- config eval
"    location /test {
        zstd_static on;
        zstd on;
        zstd_types text/plain;
        root $::suite_dir;
    }"
--- request
GET /test
--- more_headers
Accept-Encoding: gzip
--- response_headers
!Content-Encoding
Vary: Accept-Encoding
--- no_error_log eval
[qr/gzip_vary/, qr/\[error\]/]



=== TEST 19: both modules, accepting client, still exactly ONE Vary
# The other half of TEST 18: the zstd client takes the static sidecar
# path, which emits Vary and then SERVES rather than declining. Same
# exactly-one contract on the arm that actually returns a body.
--- config eval
"    location /test {
        zstd_static on;
        zstd on;
        zstd_types text/plain;
        root $::suite_dir;
    }"
--- request
GET /test
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
Vary: Accept-Encoding
--- no_error_log eval
[qr/gzip_vary/, qr/\[error\]/]
