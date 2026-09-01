/*
 * Microbenchmark for A31b-F2: does ZSTD_CCtx_refPrefix() (the dcz raw-prefix
 * path, ngx_http_zstd_filter_module.c:~3870) pay a per-request dictionary
 * table build that ZSTD_CCtx_refCDict() (the trained zstd_dict_file path,
 * :~3911) amortises once at config load?
 *
 * This is a PROOF/MEASUREMENT tool only -- it does not touch the module. It
 * links libzstd directly (ZSTD_STATIC_LINKING_ONLY, for
 * ZSTD_createCDict_advanced(), exactly as the module itself gates it) and
 * times two code paths at the module's real parameters:
 *
 *   PREFIX path (dcz):   ZSTD_CCtx_reset(session_and_parameters)
 *                         + ZSTD_CCtx_setParameter(level, windowLog)
 *                         + ZSTD_CCtx_refPrefix(dict, dictLen)
 *                         + ZSTD_compress2(body)
 *     -- mirrors init_cctx()'s per-request sequence exactly: reset first
 *        (module :3694), then refPrefix (module :3870/:3874).
 *
 *   CDICT path (hypothetical fix direction): CDict built ONCE outside the
 *   timed loop with ZSTD_createCDict_advanced(..., ZSTD_dct_rawContent, ...)
 *   -- rawContent, not dct_auto, to preserve RFC 9842 raw-prefix wire
 *   semantics (dct_auto risks treating a dictionary-shaped buffer as a
 *   trained dictionary structure instead of raw content) -- then per
 *   request only ZSTD_CCtx_reset() + ZSTD_CCtx_refCDict() + compress2().
 *
 * Sweep: dictionary size x {64 KiB, 1 MiB, 4 MiB, 10 MiB (module's
 * NGX_HTTP_ZSTD_MAX_DICT_SIZE cap)} x body size x {4 KiB (normal dcz shape,
 * body << dict) , 256 KiB (body larger than dict)}.
 *
 * Level fixed at 3 (the module's compiled-in default, module :4143 /
 * NGX_HTTP_ZSTD_LEVEL_UNSET resolves to 3). windowLog is derived the same
 * way ngx_http_zstd_dcz_window_log() derives it for dcz: ceil_log2(dict +
 * body), clamped to [ZSTD_WINDOWLOG_MIN=10, 23] -- see module comment at
 * :270-303.
 *
 * NOISE FLOOR: before trusting any prefix-vs-cdict delta, this program
 * measures identical-vs-identical (prefix path timed against itself, two
 * disjoint sets of iterations) at the same sweep points and reports that
 * delta first. Only a prefix-vs-cdict gap that clearly exceeds the
 * identical-vs-identical noise floor is reported as a real effect.
 *
 * BYTE IDENTITY: for every sweep point the program also confirms the two
 * paths' compressed output is byte-for-byte identical (the "preserve: wire
 * semantics" condition from the queue row) and reports any mismatch loudly
 * -- a wire-format regression would invalidate the whole fix direction, so
 * this is checked unconditionally, not just under a flag.
 *
 * Runtime: bounded, single-process, a few seconds total. No server, no
 * soak, no fuzzing.
 *
 * Build: cc -Wall -Wextra -O2 -DZSTD_STATIC_LINKING_ONLY \
 *           dcz_refprefix_cost_bench.c -lzstd -o dcz_refprefix_cost_bench
 * Run:   ./dcz_refprefix_cost_bench
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

#define LEVEL            3
#define WLOG_MIN         10
#define WLOG_CAP         23
#define WARMUP_ITERS     10
#define TIMED_ITERS      120
#define NOISE_ITERS      120

static const size_t dict_sizes[] = {
    64 * 1024,
    1 * 1024 * 1024,
    4 * 1024 * 1024,
    10 * 1024 * 1024,   /* NGX_HTTP_ZSTD_MAX_DICT_SIZE */
};

static const size_t body_sizes[] = {
    4 * 1024,           /* normal dcz shape: body << dictionary */
    256 * 1024,         /* body larger than the smallest dictionaries */
};

static unsigned
ceil_log2_clamped(size_t v)
{
    unsigned log = 0;
    size_t   x = 1;

    while (x < v && log < 63) {
        x <<= 1;
        log++;
    }
    if (log < WLOG_MIN) {
        log = WLOG_MIN;
    }
    if (log > WLOG_CAP) {
        log = WLOG_CAP;
    }
    return log;
}

/* Deterministic pseudo-content: reproducible across runs, and NOT trivially
 * compressible to zero-length (a real dictionary/body has structure). */
static void
fill_buf(unsigned char *buf, size_t len, uint32_t seed)
{
    size_t   i;
    uint32_t state = seed;

    for (i = 0; i < len; i++) {
        state = state * 1103515245u + 12345u;
        /* bias toward repeats every 37 bytes so the buffer is compressible,
         * like real HTTP bodies/dictionaries, rather than incompressible
         * random noise that would mask table-build cost inside i/o-bound
         * entropy coding. */
        buf[i] = (unsigned char) ((i % 37 == 0) ? (state >> 24) : (state >> 16));
    }
}

static double
now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double) ts.tv_sec * 1000.0 + (double) ts.tv_nsec / 1e6;
}

/* Runs the dcz-style refPrefix path `iters` times; returns total ms and
 * (via *out_csize) the compressed size of the LAST iteration, for the
 * byte-identity check. *out_dst receives that last iteration's bytes
 * (caller-owned buffer, at least dstCap). */
static double
bench_prefix(ZSTD_CCtx *cctx, const unsigned char *dict, size_t dictLen,
    const unsigned char *body, size_t bodyLen, unsigned wlog, int iters,
    unsigned char *dst, size_t dstCap, size_t *out_csize)
{
    int      i;
    double   t0, t1;
    size_t   rc = 0;

    if (iters <= 0) {
        fprintf(stderr, "bench_prefix: iters must be positive\n");
        exit(1);
    }

    t0 = now_ms();
    for (i = 0; i < iters; i++) {
        ZSTD_CCtx_reset(cctx, ZSTD_reset_session_and_parameters);
        ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, LEVEL);
        ZSTD_CCtx_setParameter(cctx, ZSTD_c_windowLog, (int) wlog);
        rc = ZSTD_CCtx_refPrefix(cctx, dict, dictLen);
        if (ZSTD_isError(rc)) {
            fprintf(stderr, "refPrefix failed: %s\n", ZSTD_getErrorName(rc));
            exit(1);
        }
        rc = ZSTD_compress2(cctx, dst, dstCap, body, bodyLen);
        if (ZSTD_isError(rc)) {
            fprintf(stderr, "compress2(prefix) failed: %s\n",
                    ZSTD_getErrorName(rc));
            exit(1);
        }
    }
    t1 = now_ms();
    *out_csize = rc;
    return t1 - t0;
}

/* Runs the CDict path `iters` times against a CDict built ONCE by the
 * caller (outside this function, outside the timed region) -- that is the
 * entire point of the comparison. */
static double
bench_cdict(ZSTD_CCtx *cctx, ZSTD_CDict *cdict, const unsigned char *body,
    size_t bodyLen, int iters, unsigned char *dst, size_t dstCap,
    size_t *out_csize)
{
    int      i;
    double   t0, t1;
    size_t   rc = 0;

    if (iters <= 0) {
        fprintf(stderr, "bench_cdict: iters must be positive\n");
        exit(1);
    }

    t0 = now_ms();
    for (i = 0; i < iters; i++) {
        ZSTD_CCtx_reset(cctx, ZSTD_reset_session_and_parameters);
        rc = ZSTD_CCtx_refCDict(cctx, cdict);
        if (ZSTD_isError(rc)) {
            fprintf(stderr, "refCDict failed: %s\n", ZSTD_getErrorName(rc));
            exit(1);
        }
        rc = ZSTD_compress2(cctx, dst, dstCap, body, bodyLen);
        if (ZSTD_isError(rc)) {
            fprintf(stderr, "compress2(cdict) failed: %s\n",
                    ZSTD_getErrorName(rc));
            exit(1);
        }
    }
    t1 = now_ms();
    *out_csize = rc;
    return t1 - t0;
}

/* Noise floor: prefix path timed against itself, two disjoint iteration
 * sets. Establishes the threshold a real prefix-vs-cdict effect must clear
 * before it can be trusted. Returns 0 on success, 1 on allocation failure. */
static int
run_noise_floor(ZSTD_CCtx *cctx, unsigned char *scratch, size_t dstCap)
{
    size_t  di;

    printf("== noise floor (identical prefix path, two disjoint iter sets) ==\n");
    printf("%-10s %-10s %10s %10s %8s\n",
           "dict", "body", "run_a_ms", "run_b_ms", "delta%");

    for (di = 0; di < sizeof(dict_sizes) / sizeof(dict_sizes[0]); di++) {
        size_t          dictLen = dict_sizes[di];
        size_t          bodyLen = body_sizes[0];
        unsigned        wlog = ceil_log2_clamped(dictLen + bodyLen);
        double          ms_a, ms_b, delta_pct;
        size_t          csz;
        unsigned char  *dict, *body;
        int             w;

        dict = malloc(dictLen);
        body = malloc(bodyLen);
        if (dict == NULL || body == NULL) {
            fprintf(stderr, "alloc failed (dictLen=%zu bodyLen=%zu)\n",
                    dictLen, bodyLen);
            free(dict);
            free(body);
            return 1;
        }
        fill_buf(dict, dictLen, 0xD1C7);
        fill_buf(body, bodyLen, 0xB0D7);

        for (w = 0; w < WARMUP_ITERS; w++) {
            ZSTD_CCtx_reset(cctx, ZSTD_reset_session_and_parameters);
            ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, LEVEL);
            ZSTD_CCtx_setParameter(cctx, ZSTD_c_windowLog, (int) wlog);
            ZSTD_CCtx_refPrefix(cctx, dict, dictLen);
            ZSTD_compress2(cctx, scratch, dstCap, body, bodyLen);
        }

        ms_a = bench_prefix(cctx, dict, dictLen, body, bodyLen, wlog,
                             NOISE_ITERS, scratch, dstCap, &csz);
        ms_b = bench_prefix(cctx, dict, dictLen, body, bodyLen, wlog,
                             NOISE_ITERS, scratch, dstCap, &csz);
        delta_pct = 100.0 * (ms_b - ms_a) / ms_a;

        printf("%-10zu %-10zu %10.3f %10.3f %+7.1f%%\n",
               dictLen, bodyLen, ms_a, ms_b, delta_pct);

        free(dict);
        free(body);
    }

    return 0;
}

/* One sweep point: measure the prefix path and the cdict path at the same
 * (dictLen, bodyLen), and check the compressed bytes match. Returns 1 if
 * the two paths mismatched (byte-identity failure), 0 if they matched;
 * exits the process on allocation/library failure. */
static int
run_sweep_point(ZSTD_CCtx *cctx, size_t dictLen, size_t bodyLen,
    uint32_t seed_salt, unsigned char *dst_a, unsigned char *dst_b,
    size_t dstCap)
{
    unsigned                     wlog = ceil_log2_clamped(dictLen + bodyLen);
    double                       ms_prefix, ms_cdict, per_op_prefix,
                                 per_op_cdict;
    size_t                       csz_prefix, csz_cdict;
    unsigned char               *dict, *body;
    ZSTD_CDict                  *cdict;
    ZSTD_compressionParameters   cparams;
    int                          identical, w;

    dict = malloc(dictLen);
    body = malloc(bodyLen);
    if (dict == NULL || body == NULL) {
        fprintf(stderr, "alloc failed (dictLen=%zu bodyLen=%zu)\n",
                dictLen, bodyLen);
        exit(1);
    }
    fill_buf(dict, dictLen, 0xD1C7 + seed_salt);
    fill_buf(body, bodyLen, 0xB0D7 + seed_salt);

    for (w = 0; w < WARMUP_ITERS; w++) {
        ZSTD_CCtx_reset(cctx, ZSTD_reset_session_and_parameters);
        ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, LEVEL);
        ZSTD_CCtx_setParameter(cctx, ZSTD_c_windowLog, (int) wlog);
        ZSTD_CCtx_refPrefix(cctx, dict, dictLen);
        ZSTD_compress2(cctx, dst_a, dstCap, body, bodyLen);
    }

    ms_prefix = bench_prefix(cctx, dict, dictLen, body, bodyLen, wlog,
                              TIMED_ITERS, dst_a, dstCap, &csz_prefix);

    /* Build the CDict ONCE, outside the timed region -- this is the
     * amortisation the fix direction proposes. dct_rawContent preserves
     * RFC 9842 raw-prefix wire semantics (module comment near
     * ZSTD_CCtx_refPrefix's call site). */
    cparams = ZSTD_getCParams(LEVEL, (unsigned long long) bodyLen, dictLen);
    cparams.windowLog = wlog;
    cdict = ZSTD_createCDict_advanced(dict, dictLen, ZSTD_dlm_byRef,
                                       ZSTD_dct_rawContent, cparams,
                                       ZSTD_defaultCMem);
    if (cdict == NULL) {
        fprintf(stderr, "ZSTD_createCDict_advanced failed\n");
        exit(1);
    }

    for (w = 0; w < WARMUP_ITERS; w++) {
        ZSTD_CCtx_reset(cctx, ZSTD_reset_session_and_parameters);
        ZSTD_CCtx_refCDict(cctx, cdict);
        ZSTD_compress2(cctx, dst_b, dstCap, body, bodyLen);
    }

    ms_cdict = bench_cdict(cctx, cdict, body, bodyLen, TIMED_ITERS, dst_b,
                            dstCap, &csz_cdict);

    per_op_prefix = ms_prefix / TIMED_ITERS;
    per_op_cdict = ms_cdict / TIMED_ITERS;

    identical = (csz_prefix == csz_cdict)
                && (memcmp(dst_a, dst_b, csz_prefix) == 0);

    printf("%-10zu %-10zu %5u %12.4f %12.4f %10.4f %10s\n",
           dictLen, bodyLen, wlog, per_op_prefix, per_op_cdict,
           per_op_prefix - per_op_cdict, identical ? "yes" : "NO -- MISMATCH");

    ZSTD_freeCDict(cdict);
    free(dict);
    free(body);

    return identical ? 0 : 1;
}

int
main(void)
{
    size_t          di, bi;
    unsigned char  *dst_a, *dst_b, *dst_noise;
    size_t          dstCap;
    ZSTD_CCtx      *cctx;
    int             mismatches = 0;

    printf("A31b-F2 dcz refPrefix per-request cost -- microbenchmark\n");
    printf("libzstd %s, level %d, %d warmup + %d timed iters per point\n\n",
           ZSTD_versionString(), LEVEL, WARMUP_ITERS, TIMED_ITERS);

    cctx = ZSTD_createCCtx();
    if (cctx == NULL) {
        fprintf(stderr, "ZSTD_createCCtx failed\n");
        return 1;
    }

    dstCap = ZSTD_compressBound(10 * 1024 * 1024 + 256 * 1024);
    dst_a = malloc(dstCap);
    dst_b = malloc(dstCap);
    dst_noise = malloc(dstCap);
    if (dst_a == NULL || dst_b == NULL || dst_noise == NULL) {
        fprintf(stderr, "alloc failed\n");
        free(dst_a);
        free(dst_b);
        free(dst_noise);
        ZSTD_freeCCtx(cctx);
        return 1;
    }

    if (run_noise_floor(cctx, dst_noise, dstCap) != 0) {
        free(dst_a);
        free(dst_b);
        free(dst_noise);
        ZSTD_freeCCtx(cctx);
        return 1;
    }

    printf("\n== prefix vs cdict sweep (per-op ms; refPrefix/refCDict setup only,\n");
    printf("   CDict itself built ONCE outside the timed loop) ==\n");
    printf("%-10s %-10s %5s %12s %12s %10s %10s\n",
           "dict", "body", "wlog", "prefix_ms/op", "cdict_ms/op",
           "delta_ms/op", "identical");

    for (di = 0; di < sizeof(dict_sizes) / sizeof(dict_sizes[0]); di++) {
        for (bi = 0; bi < sizeof(body_sizes) / sizeof(body_sizes[0]); bi++) {
            mismatches += run_sweep_point(cctx, dict_sizes[di],
                                          body_sizes[bi], (uint32_t) (di * 8U + bi),
                                          dst_a, dst_b, dstCap);
        }
    }

    ZSTD_freeCCtx(cctx);
    free(dst_a);
    free(dst_b);
    free(dst_noise);

    printf("\n");
    if (mismatches > 0) {
        printf("BYTE IDENTITY: FAILED -- %d/%zu sweep points produced "
               "different compressed bytes between refPrefix and "
               "refCDict(dct_rawContent). This is a wire-format regression "
               "risk for the proposed fix direction.\n",
               mismatches,
               (sizeof(dict_sizes) / sizeof(dict_sizes[0]))
                   * (sizeof(body_sizes) / sizeof(body_sizes[0])));
        return 1;
    }

    printf("BYTE IDENTITY: PASS -- refPrefix and refCDict(dct_rawContent) "
           "produced identical compressed bytes at every sweep point.\n");
    return 0;
}
