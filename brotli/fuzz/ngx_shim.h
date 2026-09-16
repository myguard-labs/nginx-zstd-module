/*
 * Minimal nginx shim for fuzzing ngx_http_zstd_accept_encoding().
 *
 * The real ngx_http_zstd_common.h pulls in <ngx_config.h>/<ngx_core.h>/
 * <ngx_http.h> — the entire nginx tree. The Accept-Encoding parser only
 * touches a tiny, well-defined slice of that surface, so we reproduce just
 * that slice here with the EXACT upstream semantics. The fuzz target then
 * includes the real, shipped header unmodified, so we are fuzzing production
 * code — not a re-implementation.
 *
 * If nginx ever changes the semantics of ngx_strcasestrn / ngx_tolower this
 * shim must be updated to match; the comments below cite the upstream source
 * (src/core/ngx_string.{h,c}) these are copied from.
 */

#ifndef NGX_ZSTD_FUZZ_SHIM_H
#define NGX_ZSTD_FUZZ_SHIM_H

#include <stddef.h>
#include <stdint.h>

/* Guard against the real nginx headers being pulled in alongside the shim. */
#define NGX_HTTP_ZSTD_COMMON_H_SHIMMED 1

typedef intptr_t   ngx_int_t;
typedef uintptr_t  ngx_uint_t;
typedef unsigned char u_char;

#define NGX_OK        0
#define NGX_DECLINED -5

typedef struct {
    size_t  len;
    u_char *data;
} ngx_str_t;

/* src/core/ngx_string.h: ngx_tolower(c) — ASCII-only, no locale. */
#define ngx_tolower(c) (u_char) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)

/*
 * src/core/ngx_string.c: ngx_strncasecmp() — faithful upstream copy.
 * Compares up to n bytes case-insensitively; stops early on NUL in s1.
 */
static inline ngx_int_t
ngx_strncasecmp(u_char *s1, u_char *s2, size_t n)
{
    ngx_uint_t  c1, c2;

    while (n) {
        c1 = (ngx_uint_t) *s1++;
        c2 = (ngx_uint_t) *s2++;

        c1 = (c1 >= 'A' && c1 <= 'Z') ? (c1 | 0x20) : c1;
        c2 = (c2 >= 'A' && c2 <= 'Z') ? (c2 | 0x20) : c2;

        if (c1 == c2) {
            if (c1) {
                n--;
                continue;
            }
            return 0;
        }

        return c1 - c2;
    }

    return 0;
}

/*
 * src/core/ngx_string.c: ngx_strcasestrn().
 *
 * Case-insensitive search for a NUL-terminated needle inside a
 * NUL-terminated haystack. `n` is strlen(needle) - 1 (the function does
 * the +1 internally), exactly as the upstream contract — and exactly how
 * ngx_http_zstd_accept_encoding() calls it with sizeof("zstd") - 2.
 *
 * This is a faithful copy of the upstream implementation. It relies on
 * s1 (the haystack, == ae->data) being NUL-terminated, which is the
 * property the fuzz target deliberately stresses.
 */
static inline u_char *
ngx_strcasestrn(u_char *s1, char *s2, size_t n)
{
    ngx_uint_t  c1, c2;

    c2 = (ngx_uint_t) *s2++;
    c2 = (c2 >= 'A' && c2 <= 'Z') ? (c2 | 0x20) : c2;

    do {
        do {
            c1 = (ngx_uint_t) *s1++;

            if (c1 == 0) {
                return NULL;
            }

            c1 = (c1 >= 'A' && c1 <= 'Z') ? (c1 | 0x20) : c1;

        } while (c1 != c2);

    } while (ngx_strncasecmp(s1, (u_char *) s2, n) != 0);

    return --s1;
}

#endif /* NGX_ZSTD_FUZZ_SHIM_H */
