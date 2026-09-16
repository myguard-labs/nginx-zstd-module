/*
 * Unit fixture for ngx_http_compression_max_length_exceeded() (parent
 * #227): the length-independent compression_max_length cap checked per
 * iteration of the streaming body filter.
 *
 * The predicate compares ctx->bytes_in (uint64_t) against the location's
 * max_length (ssize_t). The signed-cast form it replaced,
 * `(off_t) bytes_in > (off_t) max_length`, loses bits only when off_t is
 * narrower than the accumulator, i.e. a genuine 32-bit off_t build (plain
 * -m32, no _FILE_OFFSET_BITS override). A native 64-bit build and an
 * ILP32+LFS build both have an 8-byte off_t and cannot tell the two forms
 * apart, so test_max_length_cap_unit.sh runs this twice when it can: native,
 * and plain -m32, where assertion 4 is the one a regression to the cast
 * form fails.
 *
 * The function is extracted verbatim by test_max_length_cap_unit.sh, so
 * there is no hand-copied duplicate of the arithmetic here to drift.
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

typedef intptr_t  ngx_flag_t;

#define NGX_CONF_UNSET  -1

#include "generated_max_length_cap.inc"

static long long failures;

static void
fail(const char *what, uint64_t bytes_in, ssize_t max_length, int got,
    int want)
{
    failures++;
    if (failures <= 20) {
        fprintf(stderr,
                "FAIL %s: bytes_in=%" PRIu64 " max_length=%zd -> %d, want %d\n",
                what, bytes_in, max_length, got, want);
    }
}

int
main(void)
{
    /*
     * max_length values across the legal ssize_t range: unset, tiny,
     * astride INT32_MAX (where a narrowing cast disagrees), and one past
     * it where ssize_t is wide enough to hold it.
     */
    static const ssize_t max_lengths[] = {
        (ssize_t) NGX_CONF_UNSET,
        0,
        1,
        100,
        4999,
        5000,
        (ssize_t) INT32_MAX - 1,
        (ssize_t) INT32_MAX,
#if SSIZE_MAX > INT32_MAX
        (ssize_t) INT32_MAX + 1,
#endif
    };

    size_t     mi;
    long long  swept = 0;

    for (mi = 0; mi < sizeof(max_lengths) / sizeof(max_lengths[0]); mi++) {
        ssize_t  max_length = max_lengths[mi];

        /* 1. no cap configured never fires, whatever bytes_in is */
        if (max_length == NGX_CONF_UNSET) {
            static const uint64_t probes[] = {
                0, 1, 5000, (uint64_t) INT32_MAX, (uint64_t) INT32_MAX + 1,
                (uint64_t) UINT32_MAX + 1000,
            };
            size_t  pi;

            for (pi = 0; pi < sizeof(probes) / sizeof(probes[0]); pi++) {
                int  got = ngx_http_compression_max_length_exceeded(probes[pi],
                                                                    max_length);
                swept++;
                if (got) {
                    fail("unset-never-fires", probes[pi], max_length, got, 0);
                }
            }
            continue;
        }

        /* 2. at the cap: must not fire */
        {
            uint64_t  bytes_in = (uint64_t) max_length;
            int       got = ngx_http_compression_max_length_exceeded(
                                bytes_in, max_length);

            swept++;
            if (got) {
                fail("at-cap", bytes_in, max_length, got, 0);
            }
        }

        /* 3. one byte over: must fire (computed in uint64_t so the
         * SSIZE_MAX case cannot overflow before widening) */
        {
            uint64_t  bytes_in = (uint64_t) max_length + 1;
            int       got = ngx_http_compression_max_length_exceeded(
                                bytes_in, max_length);

            swept++;
            if (!got) {
                fail("one-over-cap", bytes_in, max_length, got, 1);
            }
        }

        /* 4. bytes_in far past INT32_MAX against a small cap must fire:
         * the 32-bit off_t regression case. Skipped when max_length is
         * itself at or above the probe, where the expected answer flips. */
        {
            uint64_t  bytes_in = (uint64_t) INT32_MAX + 1000000;

            if ((uint64_t) max_length < bytes_in) {
                int  got = ngx_http_compression_max_length_exceeded(
                               bytes_in, max_length);

                swept++;
                if (!got) {
                    fail("large-bytes-in-exceeds-small-cap", bytes_in,
                         max_length, got, 1);
                }
            }
        }
    }

    printf("swept %lld combinations\n", swept);

    if (failures) {
        printf("FAILED: %lld assertion(s)\n", failures);
        return 1;
    }

    printf("OK: max_length cap (unset never fires, at-cap allows, over-cap "
           "fires, large bytes_in vs small cap fires)\n");
    return 0;
}
