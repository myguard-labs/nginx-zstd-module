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
log_level 'debug';
repeat_each(3);
plan tests => repeat_each() * (blocks() * 3) + 150;
run_tests();


__DATA__


=== TEST 1: zstd off
--- config
	location /filter {
		zstd off;
		proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
	}
	location /test {
		root $TEST_NGINX_PERL_PATH/suite/;
	}
--- request
GET /filter
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]


=== TEST 2: zstd off (with accept-encoding header)
--- config
    location /filter {
        zstd off;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
Accept-Encoding: gzip,zstd
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 3: zstd on
--- config
    location /filter {
        zstd on;
		zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: gzip, zstd
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]



=== TEST 4: zstd on (without accept-encoding header)
--- config
    location /filter {
        zstd on;
		zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 5: zstd on (without zstd component in accept-encoding header)
--- config
    location /filter {
        zstd on;
		zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: gzip, br
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]

=== TEST 6: zstd zstd_min_length (greater than min_length)
--- config
    location /filter {
        zstd on;
		zstd_min_length 1024;
		zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd, br
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]

=== TEST 7: zstd zstd_min_length (less than length)
--- config
    location /filter {
        zstd on;
		zstd_types text/plain;
        zstd_min_length 60k;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd, br
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]

=== TEST 8 zstd & gzip
--- config
    location /filter {
        zstd on;
        zstd_min_length 1024;
        zstd_types text/plain;

		gzip on;
		gzip_min_length 1024;
		gzip_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd, gzip, br
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]

=== TEST 9 zstd & gzip (Accept-Encoding start with gzip)
--- config
    location /filter {
        zstd on;
        zstd_min_length 1024;
        zstd_types text/plain;

        gzip on;
        gzip_min_length 1024;
        gzip_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: gzip, zstd, br
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]

=== TEST 10 zstd & gzip (hit gzip)
--- config
    location /filter {
        zstd on;
        zstd_min_length 60k;
        zstd_types text/plain;

        gzip on;
        gzip_min_length 1024;
        gzip_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd, gzip, br
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: gzip
Content-type: text/plain
--- no_error_log
[error]

=== TEST 11 zstd on (file does not exist)
--- config
    location /filter {
        zstd on;
	zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test2;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: gzip, br
--- error_code: 404



=== TEST 12 zstd off (file does not exist)
--- config
    location /filter {
        zstd off;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test2;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: gzip, br
--- error_code: 404



=== TEST 13: RFC 7231 quality value - q=0 (explicitly reject)
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q=0, gzip;q=1
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 14: RFC 7231 quality value - q=0.0 (explicitly reject)
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q=0.0, gzip;q=1
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 15: RFC 7231 quality value - q=0.5 (accept with lower priority)
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q=0.5
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]



=== TEST 16: RFC 7231 quality value - q=1.0 (highest priority)
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q=1.0
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]



=== TEST 17: zstd with max_length (exceeds limit)
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        zstd_max_length 10k;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 18: zstd with max_length (within limit)
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        zstd_max_length 100k;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]



=== TEST 19: zstd compression level 3
--- config
    location /filter {
        zstd on;
        zstd_comp_level 3;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]



=== TEST 20: zstd compression level 10 (high)
--- config
    location /filter {
        zstd on;
        zstd_comp_level 10;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]



=== TEST 21: zstd with multiple content types
--- config
    location /filter {
        zstd on;
        zstd_types text/plain text/html application/json;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]



=== TEST 22: zstd - mixed quality values (prefer highest)
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        gzip on;
        gzip_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q=0.9, gzip;q=0.8
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]



=== TEST 23: zstd - gzip preferred via quality
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        gzip on;
        gzip_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q=0.5, gzip;q=0.9
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]



=== TEST 24: zstd filter preserves HEAD pass-through behaviour
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
HEAD /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
!Content-Length
--- no_error_log
[error]


=== TEST 25: zstd filter skips 204 responses
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        return 204;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- error_code: 204
--- response_headers
!Content-Encoding
--- no_error_log
[error]



=== TEST 26: zstd filter skips 205 responses
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        return 205;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- error_code: 205
--- response_headers
!Content-Encoding
--- no_error_log
[error]


=== TEST 27: zstd filter skips 304 responses
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        return 304;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- error_code: 304
--- response_headers
!Content-Encoding
--- no_error_log
[error]




=== TEST 28: zstd filter compresses 403 responses above min_length
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        default_type text/plain;
        return 403 "forbidden body\n";
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- error_code: 403
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-Type: text/plain
--- no_error_log
[error]


=== TEST 29: zstd filter compresses 404 responses above min_length
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        default_type text/plain;
        return 404 "not found body\n";
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- error_code: 404
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-Type: text/plain
--- no_error_log
[error]
