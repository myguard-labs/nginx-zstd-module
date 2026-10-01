/*
 * Unit oracle for ngx_http_brotli_ratio_parts() -- the $brotli_ratio split
 * (the zstd siblings' #294 fixture shape). The previous form computed
 * `bytes_in * 100 / bytes_out` and a `bytes_in * 1000 / bytes_out`
 * rounding digit in one step each: for a bytes_in past UINT64_MAX / 1000
 * (a long-lived streamed response) the multiply wraps and corrupts the
 * digits reported to the log.
 *
 * The helper yields the integer part and THREE exact fractional digits;
 * the variable rounds those to the two decimals $brotli_ratio has always
 * printed. This file never re-implements the split: the function is
 * extracted verbatim by test_ratio_scaling_unit.sh, so a stale copy of
 * itself cannot quietly agree.
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>

typedef unsigned long  ngx_uint_t;

#include "generated_ratio_parts.inc"

static long long failures;

static void
check(const char *what, uint64_t bytes_in, uint64_t bytes_out,
    ngx_uint_t want_int, ngx_uint_t want_frac)
{
    ngx_uint_t  got_int, got_frac;

    ngx_http_brotli_ratio_parts(bytes_in, bytes_out, &got_int, &got_frac);

    if (got_int != want_int || got_frac != want_frac) {
        failures++;
        if (failures <= 20) {
            fprintf(stderr,
                    "FAIL %s: bytes_in=%" PRIu64 " bytes_out=%" PRIu64
                    " -> %lu.%03lu, want %lu.%03lu\n",
                    what, bytes_in, bytes_out, got_int, got_frac, want_int,
                    want_frac);
        }
    }
}

static void
check_oracle(const char *what, uint64_t bi, uint64_t bo)
{
    unsigned __int128  scaled;
    ngx_uint_t         gi, gf;

    scaled = ((unsigned __int128) bi * 1000) / (unsigned __int128) bo;

    ngx_http_brotli_ratio_parts(bi, bo, &gi, &gf);

    if (gi != (ngx_uint_t) (scaled / 1000)
        || gf != (ngx_uint_t) (scaled % 1000))
    {
        failures++;
        if (failures <= 20) {
            printf("FAIL %s: bytes_in=%llu bytes_out=%llu -> "
                   "%llu.%03llu, want %llu.%03llu\n",
                   what, (unsigned long long) bi, (unsigned long long) bo,
                   (unsigned long long) gi, (unsigned long long) gf,
                   (unsigned long long) (scaled / 1000),
                   (unsigned long long) (scaled % 1000));
        }
    }
}

int
main(void)
{
    /* 1. Ordinary threshold/boundary cases. */
    check("equal", 1000, 1000, 1, 0);
    check("2x-exact", 2000, 1000, 2, 0);
    check("half", 500, 1000, 0, 500);
    check("one-third", 1000, 3000, 0, 333);
    check("small-remainder", 1001, 1000, 1, 1);
    check("rounding-witness 2.125", 2125, 1000, 2, 125);
    check("large-ordinary", 987654321ULL, 123456789ULL, 8, 0);

    /* 2. bytes_in near UINT64_MAX, small divisor. */
    {
        uint64_t  bytes_in  = UINT64_MAX - 3;
        uint64_t  bytes_out = 7;
        uint64_t  want_int  = bytes_in / bytes_out;
        uint64_t  remainder = bytes_in % bytes_out;
        uint64_t  want_frac = remainder * 1000 / bytes_out;

        check("near-uint64-max-small-divisor", bytes_in, bytes_out,
              (ngx_uint_t) want_int, (ngx_uint_t) want_frac);
    }
    check("near-uint64-max-both", UINT64_MAX, UINT64_MAX - 1, 1, 0);

    /* 3. Expanding streams: the remainder is bytes_in itself. */
    check("large-expanding-stream", UINT64_MAX - 1, UINT64_MAX, 0, 999);
    check("expanding-near-max-third", UINT64_MAX / 3, UINT64_MAX, 0, 333);

    /* 4. Table sweep against the 128-bit oracle. */
    {
        static const uint64_t vals[] = {
            1, 2, 3, 7, 999, 1000, 1001, 65535,
            4294967295ULL, 4294967296ULL,
            987654321987654321ULL,
            UINT64_MAX / 3, UINT64_MAX / 2, UINT64_MAX - 1, UINT64_MAX
        };
        size_t  n = sizeof(vals) / sizeof(vals[0]);
        size_t  i, j;
        char    name[64];

        for (i = 0; i < n; i++) {
            for (j = 0; j < n; j++) {
                snprintf(name, sizeof(name), "oracle[%zu][%zu]", i, j);
                check_oracle(name, vals[i], vals[j]);
            }
        }
    }

    /* 5. Seeded random sweep, reproducible, mixed magnitudes. */
    {
        unsigned long long  state = 0x9E3779B97F4A7C15ULL;
        int                 iter;
        char                name[64];

        for (iter = 0; iter < 200000; iter++) {
            uint64_t  bi, bo;

            state = state * 6364136223846793005ULL + 1442695040888963407ULL;
            bi = state;
            state = state * 6364136223846793005ULL + 1442695040888963407ULL;
            bo = state;

            if (iter % 3 == 1) { bi >>= (iter % 63); }
            if (iter % 3 == 2) { bo >>= (iter % 63); }
            if (bo == 0) { bo = 1; }

            snprintf(name, sizeof(name), "random[%d]", iter);
            check_oracle(name, bi, bo);

            if (failures) {
                break;
            }
        }
    }

    if (failures) {
        printf("FAILED: %lld assertion(s)\n", failures);
        return 1;
    }

    printf("OK: ratio scaling (ordinary thresholds unchanged, "
           "near-UINT64_MAX and expanding streams exact)\n");
    return 0;
}
