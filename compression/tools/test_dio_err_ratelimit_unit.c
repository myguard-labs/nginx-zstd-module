/*
 * Unit fixture for ngx_http_compression_static_dio_err_should_log()
 * (parent #320): the directio hard-error probe arm logs once per window
 * and folds the suppressed count into the next emitted line.
 *
 * The function is `static` inside ngx_http_compression_static.c, so
 * test_dio_err_ratelimit_unit.sh extracts it verbatim by signature and
 * compiles it here against a fake, test-controlled ngx_time() clock and
 * a minimal main-conf struct carrying the two fields it touches (the
 * counter is cycle-owned conf in the module, never a file static). No
 * nginx tree, no zstd, no filesystem.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

typedef unsigned long  ngx_uint_t;
typedef struct ngx_log_s  ngx_log_t;

typedef struct {
    time_t      dio_err_window_start;
    ngx_uint_t  dio_err_suppressed;
} ngx_http_compression_static_main_conf_t;

static time_t  fake_now;

#define ngx_time()  fake_now
#define NGX_LOG_DEBUG_HTTP  0
#define ngx_log_debug1(level, log, err, fmt, arg1)  ((void) (log))

#include "dio_err_ratelimit.inc"

#define NOT_LOGGED  ((ngx_uint_t) -1)

static int  failures;
static int  checks;

static void
check(const char *what, ngx_uint_t got, ngx_uint_t want)
{
    checks++;
    if (got != want) {
        failures++;
        printf("FAIL: %s: got %lu, want %lu\n", what, got, want);
    } else {
        printf("OK: %s\n", what);
    }
}

int
main(void)
{
    ngx_http_compression_static_main_conf_t  smcf = { 0, 0 };
    ngx_uint_t                               r;
    int                                      i;

    fake_now = 1000;
    r = ngx_http_compression_static_dio_err_should_log(&smcf, NULL);
    check("first hit logs immediately (nothing suppressed before it)", r, 0);

    for (i = 1; i <= 5; i++) {
        fake_now = 1000 + i * 10;
        r = ngx_http_compression_static_dio_err_should_log(&smcf, NULL);
        check("hit inside the window is suppressed", r, NOT_LOGGED);
    }

    fake_now = 1000 + NGX_HTTP_COMPRESSION_STATIC_DIO_ERR_WINDOW - 1;
    r = ngx_http_compression_static_dio_err_should_log(&smcf, NULL);
    check("last second before rollover is still suppressed", r, NOT_LOGGED);

    fake_now = 1000 + NGX_HTTP_COMPRESSION_STATIC_DIO_ERR_WINDOW;
    r = ngx_http_compression_static_dio_err_should_log(&smcf, NULL);
    check("rollover logs and reports the six folded hits", r, 6);

    fake_now += 1;
    r = ngx_http_compression_static_dio_err_should_log(&smcf, NULL);
    check("hit right after the rollover is suppressed", r, NOT_LOGGED);

    fake_now += NGX_HTTP_COMPRESSION_STATIC_DIO_ERR_WINDOW;
    r = ngx_http_compression_static_dio_err_should_log(&smcf, NULL);
    check("the count did not leak across the rollover", r, 1);

    fake_now -= 500;
    r = ngx_http_compression_static_dio_err_should_log(&smcf, NULL);
    check("a clock step backwards forces a rollover, not endless suppression", r, 0);

    check("the window start followed the clock backwards",
          (ngx_uint_t) smcf.dio_err_window_start, (ngx_uint_t) fake_now);

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
