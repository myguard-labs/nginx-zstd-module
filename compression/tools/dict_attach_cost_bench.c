/*
 * Microbenchmark: what does attaching a dictionary cost per request, per
 * backend, as a function of dictionary size and level?
 *
 * A MEASUREMENT tool only -- it does not touch the module. It links
 * libzstd and libbrotlienc directly and times, for one request, exactly
 * the per-request sequence the two backends run
 * (create -> attach_dictionary -> process, see
 * ngx_http_compression_zstd.c and ngx_http_compression_brotli.c):
 *
 *   zstd:   ZSTD_createCCtx() + setParameter(level)
 *           + ZSTD_CCtx_refPrefix(dict) + ZSTD_compress2(body)
 *           + ZSTD_freeCCtx()
 *   brotli: BrotliEncoderCreateInstance() + QUALITY/LGWIN/SIZE_HINT
 *           + BrotliEncoderPrepareDictionary(RAW, dict, quality)
 *           + BrotliEncoderAttachPreparedDictionary()
 *           + BrotliEncoderCompressStream(FINISH)
 *           + destroy both
 *
 * and, per point, the same sequence WITHOUT the dictionary, so the
 * reported delta is the dictionary's own cost. The body is 1 KiB and is
 * a slice of the dictionary (the dcz/dcb shape: body << dictionary, body
 * content the dictionary describes). Sweep: dictionary size x {64 KiB,
 * 1 MiB, 8 MiB} x the backend's level axis.
 *
 * The number that matters is the minimum over the iterations: it is the
 * cost with the least scheduling noise in it, and the advisory keys on
 * the level at which that cost stops being flat in dictionary size.
 * Means are printed beside it so a bimodal run is visible.
 *
 * Build and run: compression/tools/dict_attach_cost_bench.sh
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include <zstd.h>
#include <brotli/encode.h>

#define BODY_LEN     1024
#define WARMUP       2

static const size_t  dict_sizes[] = { 64 * 1024, 1024 * 1024, 8 * 1024 * 1024 };
static const int     zstd_levels[] = { 1, 3, 6, 9, 12, 19 };
static const int     brotli_qualities[] = { 1, 4, 5, 6, 7, 9, 10, 11 };


static double
now_ms(void)
{
    struct timespec  ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double) ts.tv_sec * 1000.0 + (double) ts.tv_nsec / 1e6;
}


/* text-like pseudo-random content: matches exist but are not trivial */
static void
fill(unsigned char *p, size_t len, uint32_t seed)
{
    static const char  alphabet[] =
        "the quick brown fox jumps over the lazy dog 0123456789 ,.;:\n";
    size_t    i;
    uint32_t  x = seed;

    for (i = 0; i < len; i++) {
        x = x * 1664525u + 1013904223u;
        p[i] = (unsigned char) alphabet[(x >> 24) % (sizeof(alphabet) - 1)];
    }
}


static int
iters_for(size_t dict_len)
{
    if (dict_len <= 64 * 1024) {
        return 400;
    }
    if (dict_len <= 1024 * 1024) {
        return 60;
    }
    return 12;
}


/* one zstd request; returns 0 on success */
static int
zstd_request(int level, const unsigned char *dict, size_t dict_len,
    const unsigned char *body, unsigned char *out, size_t out_cap)
{
    ZSTD_CCtx  *cctx;
    size_t      rc;

    cctx = ZSTD_createCCtx();
    if (cctx == NULL) {
        return 1;
    }

    rc = ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, level);
    if (ZSTD_isError(rc)) {
        ZSTD_freeCCtx(cctx);
        return 1;
    }

    if (dict != NULL) {
        rc = ZSTD_CCtx_refPrefix(cctx, dict, dict_len);
        if (ZSTD_isError(rc)) {
            ZSTD_freeCCtx(cctx);
            return 1;
        }
    }

    rc = ZSTD_compress2(cctx, out, out_cap, body, BODY_LEN);
    ZSTD_freeCCtx(cctx);

    return ZSTD_isError(rc) ? 1 : 0;
}


/* one brotli request; returns 0 on success */
static int
brotli_request(int quality, const unsigned char *dict, size_t dict_len,
    const unsigned char *body, unsigned char *out, size_t out_cap)
{
    BrotliEncoderState               *enc;
    BrotliEncoderPreparedDictionary  *prepared = NULL;
    const uint8_t                    *in = body;
    uint8_t                          *o = out;
    size_t                            avail_in = BODY_LEN;
    size_t                            avail_out = out_cap;
    int                               ok = 1;

    enc = BrotliEncoderCreateInstance(NULL, NULL, NULL);
    if (enc == NULL) {
        return 1;
    }

    ok = ok && BrotliEncoderSetParameter(enc, BROTLI_PARAM_QUALITY,
                                         (uint32_t) quality);
    ok = ok && BrotliEncoderSetParameter(enc, BROTLI_PARAM_LGWIN, 19);
    ok = ok && BrotliEncoderSetParameter(enc, BROTLI_PARAM_SIZE_HINT,
                                         BODY_LEN);

    if (ok && dict != NULL) {
        prepared = BrotliEncoderPrepareDictionary(BROTLI_SHARED_DICTIONARY_RAW,
                                                  dict_len, dict, quality,
                                                  NULL, NULL, NULL);
        ok = (prepared != NULL)
             && BrotliEncoderAttachPreparedDictionary(enc, prepared);
    }

    while (ok && !BrotliEncoderIsFinished(enc)) {
        ok = BrotliEncoderCompressStream(enc, BROTLI_OPERATION_FINISH,
                                         &avail_in, &in, &avail_out, &o,
                                         NULL);
        if (avail_out == 0) {
            ok = 0;     /* out_cap is sized so this never happens */
        }
    }

    BrotliEncoderDestroyInstance(enc);
    if (prepared != NULL) {
        BrotliEncoderDestroyPreparedDictionary(prepared);
    }

    return ok ? 0 : 1;
}


typedef int (*request_fn)(int, const unsigned char *, size_t,
    const unsigned char *, unsigned char *, size_t);


/* time `iters` requests; fills min and mean in ms; returns 0 on success */
static int
measure(request_fn fn, int level, const unsigned char *dict, size_t dict_len,
    const unsigned char *body, unsigned char *out, size_t out_cap, int iters,
    double *min_ms, double *mean_ms)
{
    int     i;
    double  t0, t, total = 0.0, best = 1e300;

    for (i = 0; i < WARMUP; i++) {
        if (fn(level, dict, dict_len, body, out, out_cap) != 0) {
            return 1;
        }
    }

    for (i = 0; i < iters; i++) {
        t0 = now_ms();
        if (fn(level, dict, dict_len, body, out, out_cap) != 0) {
            return 1;
        }
        t = now_ms() - t0;
        total += t;
        if (t < best) {
            best = t;
        }
    }

    *min_ms = best;
    *mean_ms = total / iters;
    return 0;
}


static int
sweep(const char *name, request_fn fn, const int *levels, size_t nlevels,
    unsigned char *dict, unsigned char *out, size_t out_cap)
{
    size_t         di, li, dict_len;
    int            iters;
    double         nmin, nmean, dmin, dmean;
    unsigned char  body[BODY_LEN];

    printf("== %s: per-request cost, 1 KiB body (ms; min over iterations, mean beside it) ==\n",
           name);
    printf("%-8s %-8s %12s %12s %12s\n",
           "level", "dict", "no-dict", "with-dict", "delta");

    for (di = 0; di < sizeof(dict_sizes) / sizeof(dict_sizes[0]); di++) {
        dict_len = dict_sizes[di];
        iters = iters_for(dict_len);
        fill(dict, dict_len, 0x5eed0000u + (uint32_t) di);
        memcpy(body, dict + dict_len / 2, BODY_LEN);

        for (li = 0; li < nlevels; li++) {
            if (measure(fn, levels[li], NULL, 0, body, out, out_cap, iters,
                        &nmin, &nmean) != 0
                || measure(fn, levels[li], dict, dict_len, body, out, out_cap,
                           iters, &dmin, &dmean) != 0)
            {
                fprintf(stderr, "%s: request failed at level %d dict %zu\n",
                        name, levels[li], dict_len);
                return 1;
            }

            printf("%-8d %-8zuK %6.3f/%-6.3f %6.3f/%-6.3f %8.3f\n",
                   levels[li], dict_len / 1024, nmin, nmean, dmin, dmean,
                   dmin - nmin);
        }
    }

    printf("\n");
    return 0;
}


int
main(void)
{
    size_t          out_cap;
    unsigned char  *dict, *out;
    int             rc;

    dict = malloc(dict_sizes[2]);
    out_cap = 4 * BODY_LEN + 1024;
    out = malloc(out_cap);
    if (dict == NULL || out == NULL) {
        fprintf(stderr, "alloc failed\n");
        return 1;
    }

    printf("libzstd %s, libbrotli %u.%u.%u\n\n", ZSTD_versionString(),
           BrotliEncoderVersion() >> 24, (BrotliEncoderVersion() >> 12) & 0xfff,
           BrotliEncoderVersion() & 0xfff);

    rc = sweep("zstd (ZSTD_CCtx_refPrefix)", zstd_request, zstd_levels,
               sizeof(zstd_levels) / sizeof(zstd_levels[0]), dict, out,
               out_cap);
    if (rc == 0) {
        rc = sweep("brotli (BrotliEncoderPrepareDictionary)", brotli_request,
                   brotli_qualities,
                   sizeof(brotli_qualities) / sizeof(brotli_qualities[0]),
                   dict, out, out_cap);
    }

    free(dict);
    free(out);
    return rc;
}
