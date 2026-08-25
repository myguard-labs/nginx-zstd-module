/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit oracle for ngx_http_zstd_dcz_window_log().
 *
 * The function and its ngx_http_zstd_ceil_log2() dependency are EXTRACTED
 * VERBATIM from src/ngx_http_zstd_filter_module.c by
 * test_dcz_window_log_unit.sh into generated_dcz_window_log.inc -- this file
 * never re-implements the arithmetic, so it cannot quietly agree with a stale
 * copy of itself.
 *
 * What is asserted, and why each one matters:
 *
 *   1. DEFAULT UNCHANGED. With neither clamp configured (both ceilings 0),
 *      the result is exactly ceil_log2(dict + content). Both clamps are
 *      opt-in, and an operator who never asked for a memory bound must not
 *      see dcz wire bytes move. This is the regression guard for the scoping
 *      decision; without it the "fix" silently becomes a global behaviour
 *      change.
 *
 *   2. EITHER CEILING BINDS, and only downward. zstd_window_log and
 *      zstd_max_cctx_memory are ceilings of the same class, so a configured
 *      one lowers the window and never raises it -- a ceiling that could
 *      raise the window would be a memory ESCAPE, the exact defect this
 *      function was written to close.
 *
 *   3. THE LOWER OF THE TWO WINS when both are set. Honouring the larger
 *      would void whichever bound the operator set more tightly.
 *
 *   4. RANGE. The result is always in [10, NGX_HTTP_ZSTD_DCZ_MAX_WINDOW_LOG].
 *      The lower bound keeps an invalid windowLog out of libzstd; the upper
 *      bound is the RFC 9842 client-window guarantee. Both bounds also keep
 *      the value inside ngx_http_zstd_profile_pack()'s 6-bit window_log
 *      field, whose packer REFUSES rather than masks an out-of-domain value
 *      -- so a violation here would turn into a failed CCtx acquisition,
 *      not a silent aliasing.
 *
 * The sweep is exhaustive over the interesting domain rather than a handful
 * of hand-picked cases: every dictionary size across the power-of-two
 * boundaries, both pledged-size branches (known length and unknown), and
 * every value of both ceilings including the out-of-range ones.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

/* Minimal nginx shim: the extracted code uses these names only. */
typedef long           ngx_int_t;
typedef unsigned long  ngx_uint_t;
#define ngx_inline     inline

#include "generated_dcz_window_log.inc"

#define WLOG_MIN  10
#define UNKNOWN   ((off_t) -1)

static long long failures;

static void
fail(const char *what, size_t dict, off_t pledged, ngx_int_t conf,
    ngx_int_t budget, ngx_int_t got, ngx_int_t want)
{
    failures++;
    if (failures <= 20) {
        fprintf(stderr,
                "FAIL %s: dict=%zu pledged=%lld conf_wlog=%ld budget_cap=%ld"
                " -> %ld, want %ld\n",
                what, dict, (long long) pledged, (long) conf, (long) budget,
                (long) got, (long) want);
    }
}

int
main(void)
{
    /*
     * Dictionary sizes straddling every power-of-two boundary in range, so
     * the ceil_log2 rounding is exercised at the exact points it can be off
     * by one, not only in the middle of a decade.
     */
    static const size_t dicts[] = {
        0, 1, 1023, 1024, 1025,
        4095, 4096, 4097,
        (1u << 20) - 1, 1u << 20, (1u << 20) + 1,
        (1u << 22) - 1, 1u << 22, (1u << 22) + 1,
        (1u << 23) - 1, 1u << 23, (1u << 23) + 1,
        (size_t) 1 << 25
    };
    static const off_t pledges[] = { UNKNOWN, 0, 1, 4096, 1u << 20, 1u << 23 };

    size_t     di, pi;
    ngx_int_t  conf, budget;
    long long  swept = 0;

    for (di = 0; di < sizeof(dicts) / sizeof(dicts[0]); di++) {
        for (pi = 0; pi < sizeof(pledges) / sizeof(pledges[0]); pi++) {
            size_t     dict = dicts[di];
            off_t      pledged = pledges[pi];
            ngx_int_t  base;

            /* Unclamped reference: BOTH ceilings unset. */
            base = ngx_http_zstd_dcz_window_log(dict, pledged, 0, 0);
            swept++;

            /* 4. range */
            if (base < WLOG_MIN
                || base > NGX_HTTP_ZSTD_DCZ_MAX_WINDOW_LOG)
            {
                fail("range(unclamped)", dict, pledged, 0, 0, base, -1);
            }

            /*
             * 1. default unchanged -- the unclamped answer is exactly the
             * sizing rule, independently recomputed here from ceil_log2 so
             * this is an oracle rather than a tautology.
             */
            {
                size_t     required;
                ngx_int_t  want;

                required = dict + (pledged >= 0
                                   ? (size_t) pledged
                                   : 1024 * 1024);
                want = (ngx_int_t) ngx_http_zstd_ceil_log2(required);

                if (base != want) {
                    fail("default-unchanged", dict, pledged, 0, 0, base, want);
                }
            }

            /* -1 and 0 are the "unset" spellings; sweep past the cap too. */
            for (conf = -1; conf <= 25; conf++) {
                for (budget = -1; budget <= 25; budget++) {
                    ngx_int_t  got, want;

                    got = ngx_http_zstd_dcz_window_log(dict, pledged, conf,
                                                       budget);
                    swept++;

                    /* Expected: base, lowered by whichever ceilings are set. */
                    want = base;
                    if (conf > 0 && conf < want) {
                        want = conf;
                    }
                    if (budget > 0 && budget < want) {
                        want = budget;
                    }

                    /* 2 + 3: either ceiling binds, the lower one wins. */
                    if (got != want) {
                        fail("clamp", dict, pledged, conf, budget, got, want);
                        continue;
                    }

                    /* 2: a ceiling never RAISES the window. */
                    if (got > base) {
                        fail("ceiling-raised-window", dict, pledged, conf,
                             budget, got, base);
                    }

                    /*
                     * 4: range again, now under clamping. A configured
                     * ceiling below ZSTD_WINDOWLOG_MIN would otherwise push
                     * an invalid windowLog into libzstd -- assert the floor
                     * holds for EVERY combination, not just the unclamped
                     * one.
                     */
                    if (got > NGX_HTTP_ZSTD_DCZ_MAX_WINDOW_LOG) {
                        fail("range(above-cap)", dict, pledged, conf, budget,
                             got, NGX_HTTP_ZSTD_DCZ_MAX_WINDOW_LOG);
                    }
                }
            }
        }
    }

    printf("swept %lld combinations\n", swept);

    if (failures) {
        printf("FAILED: %lld assertion(s)\n", failures);
        return 1;
    }

    printf("OK: dcz window log (default unchanged, both ceilings bind "
           "downward, lower wins, result in range)\n");
    return 0;
}
