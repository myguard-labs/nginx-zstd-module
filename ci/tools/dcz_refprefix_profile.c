/*
 * Level-3 steady-state profile for the dcz raw-prefix request path.
 *
 * This complements dcz_refprefix_cost_bench.c's broad size/level sweep with
 * the exact A31-dcz-profile workload: one realistic 8 MiB raw dictionary,
 * deterministic bodies both smaller (1 MiB) and larger (12 MiB) than it,
 * warmed contexts, interleaved A/B order, and repeated raw observations.
 *
 * Each batch reports both wall time (the single-thread latency proxy) and
 * process CPU time. CPU is also split at the public API boundary into:
 *
 *   prepare:   CCtx reset and level/window parameters
 *   attach:    ZSTD_CCtx_refPrefix() itself (zero for the no-prefix control)
 *   compress:  ZSTD_compress2()
 *
 * libzstd lazily constructs the prefix match state in ZSTD_compress2(), not
 * in ZSTD_CCtx_refPrefix(), so the compress column deliberately includes
 * that construction. The 1 KiB setup-proxy cell isolates it: subtracting the
 * no-prefix control leaves virtually no body work, while the 1 MiB and 12 MiB
 * cells show the whole response cost. An identical-prefix A/A pair at every
 * size is the noise floor; an A/B delta is repeatable only when its median is
 * larger than the observed A/A spread.
 *
 * Output is TSV so every trial remains machine-readable. Summary rows are
 * medians, never a cherry-picked fastest run. The corpus overlaps the raw
 * dictionary (a response dictionary that never matches its body is not a
 * realistic dcz workload).
 *
 * Reference runs, 2026-09-28, libzstd 1.5.7: under different host load, the
 * inferred table-build cost ranged from 0.751 to 1.601 ms CPU/request while
 * the matching identical-path noise floor ranged from 0.002 to 0.037 ms.
 * Total prefix-path CPU ranged from 2.17 to 3.54 ms for 1 MiB and 22.1 to
 * 63.3 ms for 12 MiB. Setup was therefore 34-45% of the smaller response and
 * 2.5-3.4% of the larger response. Wall and CPU medians tracked within
 * 0.012 ms. The absolute time is host-frequency-sensitive, but the paired
 * result remains far beyond its local noise floor: this confirms the Major
 * level-3 finding and retains A31-dcz-cdict for a separate product decision.
 * That follow-up cannot assume refCDict is byte-equivalent; the companion
 * identity sweep documents overlapping-content wire divergences.
 */

#include <stdint.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <zstd.h>

#define LEVEL        3
#define WINDOW_LOG   23
#define DICT_SIZE    (8U * 1024U * 1024U)
#define WARMUP_ITERS 4
#define TRIALS       9
#define SETUP_ITERS  80
#define SMALL_ITERS  12
#define LARGE_ITERS  3

typedef struct {
    double wall_ms;
    double cpu_ms;
    double prepare_ms;
    double attach_ms;
    double compress_ms;
    size_t compressed_size;
} measurement_t;

typedef struct {
    const char *name;
    size_t      body_size;
    int         iterations;
} workload_t;

static const workload_t workloads[] = {
    {"setup-1k", 1024, SETUP_ITERS},
    {"smaller-1m", 1U * 1024U * 1024U, SMALL_ITERS},
    {"larger-12m", 12U * 1024U * 1024U, LARGE_ITERS},
};

static uint64_t clock_ns(clockid_t id)
{
    struct timespec ts;

    if (clock_gettime(id, &ts) != 0) {
        perror("clock_gettime");
        exit(1);
    }

    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static double elapsed_ms(uint64_t begin, uint64_t end)
{
    return (double)(end - begin) / 1000000.0;
}

static void check_zstd(size_t rc, const char *operation)
{
    if (ZSTD_isError(rc)) {
        fprintf(stderr, "%s failed: %s\n", operation, ZSTD_getErrorName(rc));
        exit(1);
    }
}

static void fill_dictionary(unsigned char *buf, size_t len)
{
    size_t   i;
    uint32_t state = UINT32_C(0x6d2b79f5);

    for (i = 0; i < len; i++) {
        state = state * UINT32_C(1664525) + UINT32_C(1013904223);
        buf[i] = (unsigned char)((i % 53 == 0) ? state >> 24 : state >> 16);
    }
}

static void fill_overlapping_body(unsigned char *body, size_t body_len,
                                  const unsigned char *dict, size_t dict_len)
{
    size_t off = 0;
    size_t step = 0;

    while (off < body_len) {
        size_t chunk = 384 + (step % 1664);
        size_t src;

        step += 613;
        if (chunk > body_len - off) {
            chunk = body_len - off;
        }
        src = (off * 7919 + step * 104729) % (dict_len - chunk);
        memcpy(body + off, dict + src, chunk);
        off += chunk;
    }
}

static measurement_t measure_batch(ZSTD_CCtx *cctx, int with_prefix,
                                   const unsigned char *dict, size_t dict_len,
                                   const unsigned char *body, size_t body_len,
                                   int iterations, unsigned char *dst,
                                   size_t dst_cap)
{
    measurement_t m = {0};
    uint64_t      wall_begin, wall_end, cpu_begin, cpu_end;
    int           i;

    wall_begin = clock_ns(CLOCK_MONOTONIC);
    cpu_begin = clock_ns(CLOCK_PROCESS_CPUTIME_ID);

    for (i = 0; i < iterations; i++) {
        uint64_t begin, end;
        size_t   rc;

        begin = clock_ns(CLOCK_PROCESS_CPUTIME_ID);
        check_zstd(ZSTD_CCtx_reset(cctx, ZSTD_reset_session_and_parameters),
                   "ZSTD_CCtx_reset");
        check_zstd(ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, LEVEL),
                   "ZSTD_c_compressionLevel");
        check_zstd(ZSTD_CCtx_setParameter(cctx, ZSTD_c_windowLog, WINDOW_LOG),
                   "ZSTD_c_windowLog");
        end = clock_ns(CLOCK_PROCESS_CPUTIME_ID);
        m.prepare_ms += elapsed_ms(begin, end);

        if (with_prefix) {
            begin = clock_ns(CLOCK_PROCESS_CPUTIME_ID);
            check_zstd(ZSTD_CCtx_refPrefix(cctx, dict, dict_len),
                       "ZSTD_CCtx_refPrefix");
            end = clock_ns(CLOCK_PROCESS_CPUTIME_ID);
            m.attach_ms += elapsed_ms(begin, end);
        }

        begin = clock_ns(CLOCK_PROCESS_CPUTIME_ID);
        rc = ZSTD_compress2(cctx, dst, dst_cap, body, body_len);
        end = clock_ns(CLOCK_PROCESS_CPUTIME_ID);
        check_zstd(rc, "ZSTD_compress2");
        m.compress_ms += elapsed_ms(begin, end);
        m.compressed_size = rc;
    }

    cpu_end = clock_ns(CLOCK_PROCESS_CPUTIME_ID);
    wall_end = clock_ns(CLOCK_MONOTONIC);
    m.wall_ms = elapsed_ms(wall_begin, wall_end) / iterations;
    m.cpu_ms = elapsed_ms(cpu_begin, cpu_end) / iterations;
    m.prepare_ms /= iterations;
    m.attach_ms /= iterations;
    m.compress_ms /= iterations;

    return m;
}

static int compare_double(const void *a, const void *b)
{
    double aa = *(const double *)a;
    double bb = *(const double *)b;

    return (aa > bb) - (aa < bb);
}

static double median(const double *values)
{
    double copy[TRIALS];

    memcpy(copy, values, TRIALS * sizeof(double));
    qsort(copy, TRIALS, sizeof(copy[0]), compare_double);
    return copy[TRIALS / 2];
}

static void print_measurement(const char *workload, int trial, const char *arm,
                              const measurement_t *m)
{
    printf("raw\t%s\t%d\t%s\t%.6f\t%.6f\t%.6f\t%.6f\t%.6f\t%zu\n", workload,
           trial, arm, m->wall_ms, m->cpu_ms, m->prepare_ms, m->attach_ms,
           m->compress_ms, m->compressed_size);
}

static void warm(ZSTD_CCtx *cctx, const unsigned char *dict, size_t dict_len,
                 const unsigned char *body, size_t body_len, unsigned char *dst,
                 size_t dst_cap)
{
    int i;

    for (i = 0; i < WARMUP_ITERS; i++) {
        (void)measure_batch(cctx, 1, dict, dict_len, body, body_len, 1, dst,
                            dst_cap);
        (void)measure_batch(cctx, 0, dict, dict_len, body, body_len, 1, dst,
                            dst_cap);
    }
}

int main(void)
{
    unsigned char *dict;
    unsigned char *body;
    unsigned char *dst;
    size_t         max_body =
        workloads[sizeof(workloads) / sizeof(workloads[0]) - 1].body_size;
    size_t     dst_cap = ZSTD_compressBound(max_body);
    ZSTD_CCtx *cctx;
    size_t     wi;
    double     inferred_setup_cpu = 0.0;

    dict = malloc(DICT_SIZE);
    body = malloc(max_body);
    dst = malloc(dst_cap);
    cctx = ZSTD_createCCtx();
    if (dict == NULL || body == NULL || dst == NULL || cctx == NULL) {
        fprintf(stderr, "allocation failed\n");
        free(dict);
        free(body);
        free(dst);
        ZSTD_freeCCtx(cctx);
        return 1;
    }

    fill_dictionary(dict, DICT_SIZE);
    printf("meta\tlibzstd=%s\tlevel=%d\tdict=%u\twarmup=%d\ttrials=%d\n",
           ZSTD_versionString(), LEVEL, DICT_SIZE, WARMUP_ITERS, TRIALS);
    printf("kind\tworkload\ttrial\tarm\twall_ms/op\tcpu_ms/op\t"
           "prepare_cpu_ms/op\tattach_cpu_ms/op\tcompress_cpu_ms/op\t"
           "compressed_bytes\n");

    for (wi = 0; wi < sizeof(workloads) / sizeof(workloads[0]); wi++) {
        const workload_t *w = &workloads[wi];
        double            ab_cpu[TRIALS];
        double            aa_cpu[TRIALS];
        double            prefix_cpu[TRIALS];
        double            prefix_wall[TRIALS];
        double            prefix_prepare[TRIALS];
        double            prefix_attach[TRIALS];
        double            prefix_compress[TRIALS];
        int               trial;

        fill_overlapping_body(body, w->body_size, dict, DICT_SIZE);
        warm(cctx, dict, DICT_SIZE, body, w->body_size, dst, dst_cap);

        for (trial = 0; trial < TRIALS; trial++) {
            measurement_t prefix_a, prefix_b, control;

            /* Alternate A/B order to cancel monotonic machine drift. */
            if ((trial & 1) == 0) {
                prefix_a =
                    measure_batch(cctx, 1, dict, DICT_SIZE, body, w->body_size,
                                  w->iterations, dst, dst_cap);
                control =
                    measure_batch(cctx, 0, dict, DICT_SIZE, body, w->body_size,
                                  w->iterations, dst, dst_cap);
            } else {
                control =
                    measure_batch(cctx, 0, dict, DICT_SIZE, body, w->body_size,
                                  w->iterations, dst, dst_cap);
                prefix_a =
                    measure_batch(cctx, 1, dict, DICT_SIZE, body, w->body_size,
                                  w->iterations, dst, dst_cap);
            }
            prefix_b = measure_batch(cctx, 1, dict, DICT_SIZE, body,
                                     w->body_size, w->iterations, dst, dst_cap);

            print_measurement(w->name, trial + 1, "prefix-a", &prefix_a);
            print_measurement(w->name, trial + 1, "no-prefix", &control);
            print_measurement(w->name, trial + 1, "prefix-b", &prefix_b);

            prefix_cpu[trial] = prefix_a.cpu_ms;
            prefix_wall[trial] = prefix_a.wall_ms;
            prefix_prepare[trial] = prefix_a.prepare_ms;
            prefix_attach[trial] = prefix_a.attach_ms;
            prefix_compress[trial] = prefix_a.compress_ms;
            ab_cpu[trial] = prefix_a.cpu_ms - control.cpu_ms;
            aa_cpu[trial] = fabs(prefix_b.cpu_ms - prefix_a.cpu_ms);
        }

        printf("summary\t%s\tmedian\tprefix\t%.6f\t%.6f\t%.6f\t"
               "%.6f\t%.6f\t-\n",
               w->name, median(prefix_wall), median(prefix_cpu),
               median(prefix_prepare), median(prefix_attach),
               median(prefix_compress));
        printf("summary\t%s\tmedian\tprefix-minus-control-cpu\t-\t"
               "%.6f\t-\t-\t-\t-\n",
               w->name, median(ab_cpu));
        printf("summary\t%s\tmedian\tabs-identical-prefix-spread-cpu\t-\t"
               "%.6f\t-\t-\t-\t-\n",
               w->name, median(aa_cpu));

        if (wi == 0) {
            inferred_setup_cpu = median(ab_cpu);
        }
        printf("attribution\t%s\tmedian\tinferred-table-build-cpu\t-\t"
               "%.6f\t-\t-\t-\t-\n",
               w->name, inferred_setup_cpu);
        printf("attribution\t%s\tmedian\tbody-compression-remainder-cpu\t"
               "-\t%.6f\t-\t-\t-\t-\n",
               w->name, median(prefix_cpu) - inferred_setup_cpu);
        printf("attribution\t%s\tmedian\ttable-build-share-pct\t-\t"
               "%.3f\t-\t-\t-\t-\n",
               w->name, 100.0 * inferred_setup_cpu / median(prefix_cpu));
    }

    ZSTD_freeCCtx(cctx);
    free(dict);
    free(body);
    free(dst);
    return 0;
}
