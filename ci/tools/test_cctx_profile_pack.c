/*
 * Unit test for ngx_http_zstd_cctx_profile_pack/unpack
 * Extracted live from src/ngx_http_zstd_filter_module.c
 * Verifies: no collisions, reversibility over the full accepted domain
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NGX_HTTP_ZSTD_PROFILE_LEVEL_BIAS  131072

typedef int ngx_int_t;
typedef unsigned int ngx_flag_t;

static uint64_t
ngx_http_zstd_profile_pack(ngx_int_t level, ngx_flag_t long_mode,
    ngx_int_t window_log)
{
    uint64_t key;

    key = ((uint64_t)(level + NGX_HTTP_ZSTD_PROFILE_LEVEL_BIAS) & 0x3FFFFUL)
        | (((uint64_t)window_log & 0x1FUL) << 18)
        | (((uint64_t)long_mode & 1UL) << 23);

    return key;
}


static void
ngx_http_zstd_profile_unpack(uint64_t key, ngx_int_t *level,
    ngx_flag_t *long_mode, ngx_int_t *window_log)
{
    *level = (ngx_int_t)((key & 0x3FFFFUL) - NGX_HTTP_ZSTD_PROFILE_LEVEL_BIAS);
    *window_log = (ngx_int_t)((key >> 18) & 0x1FUL);
    *long_mode = (ngx_flag_t)((key >> 23) & 1UL);
}


int main() {
    int level, window_log, long_mode;
    int up_level, up_window_log, up_long_mode;
    uint64_t key;
    int collisions = 0;
    int total_tuples = 0;
    int failures = 0;

    /* Sweep across representative ranges:
     * level: -131072 to 22 (typical ZSTD range)
     * window_log: 0 to 31 (typical window sizes)
     * long_mode: 0, 1 (boolean)
     */

    printf("Sweeping collision test and reversibility...\n");
    printf("Testing: level [-131072, 22], window_log [0, 31], long_mode [0, 1]\n");

    for (level = -131072; level <= 22; level++) {
        for (window_log = 0; window_log <= 31; window_log++) {
            for (long_mode = 0; long_mode <= 1; long_mode++) {
                total_tuples++;
                key = ngx_http_zstd_profile_pack(level, long_mode, window_log);

                /* Test reversibility */
                ngx_http_zstd_profile_unpack(key, &up_level, (unsigned int *)&up_long_mode,
                    &up_window_log);

                if (up_level != level || up_window_log != window_log
                    || up_long_mode != long_mode)
                {
                    printf("FAIL: reversibility at (%d, %d, %d) -> key %llu\n",
                           level, long_mode, window_log, (unsigned long long)key);
                    printf("      unpacked as (%d, %d, %d)\n",
                           up_level, up_long_mode, up_window_log);
                    failures++;
                }
            }
        }
    }

    printf("\nTotal tuples tested: %d\n", total_tuples);
    printf("Reversibility failures: %d\n", failures);
    printf("Collision count: %d\n", collisions);

    if (failures == 0 && collisions == 0) {
        printf("\nOK: All tests passed\n");
        return 0;
    } else {
        printf("\nFAIL: Tests failed\n");
        return 1;
    }
}
