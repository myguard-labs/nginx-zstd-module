/*
 * nginx-compression — phase 2: unified static sidecar serving.
 *
 * One content-phase handler probes for precompressed sidecars
 * (file.zst / file.br / file.gz) in compression_static_order and
 * serves the first hit with the right Content-Encoding. NO compression
 * library is ever called — this is file serving, which is also why
 * gzip is FIRST-CLASS here (serving a premade .gz needs no zlib; the
 * unified static subsumes gzip_static for free, gzip-less builds
 * included), unlike the filter side's defer/veto.
 *
 * The #76 latch-bug class is structurally inexpressible here: one
 * handler probing codings in order falls through to the next coding —
 * or declines entirely, letting the identity original (and the
 * dynamic filter) take over — without any cross-module latch that
 * could strand a fallback.
 *
 * The zstd probe (magic + declared-window cap, RFC 8878) is the
 * parent zstd_static module's reviewed implementation ported intact,
 * directio geometry included; see that history (#101) for why every
 * branch is shaped the way it is.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_compression.h"
#include "ngx_http_compression_ae.h"

/*
 * THE frame probe (parent #270/#278): verdicts, the RFC 8878 window
 * cap, the bounded skippable-walk limit, probe_frame() and
 * probe_reuse() all come from the parent's authoritative header --
 * this module used to carry a synchronized copy of every one of
 * them. The header self-defines the RFC-frozen format constants, so
 * this module still links no compression library.
 */
#include "../src/ngx_http_zstd_frame_probe.h"


/*
 * ITS OWN MODULE since the split (Mark's packaging call, gzip_static /
 * parent-pair precedent): static serving must ship as a
 * dependency-free .so — this TU calls no compression library, so a
 * static-only deployment (CDN edge, internal artifact host) loads a
 * module whose ldd shows nothing but libc. The filter module is not
 * required to be present, loaded, or even built.
 */

#define NGX_HTTP_COMPRESSION_STATIC_OFF     0
#define NGX_HTTP_COMPRESSION_STATIC_ON      1
#define NGX_HTTP_COMPRESSION_STATIC_ALWAYS  2


typedef struct {
    ngx_uint_t     enable;
    ngx_array_t   *order;   /* the enable set AND the probe order */
    ngx_flag_t     dict_bypass;
} ngx_http_compression_static_conf_t;


#define NGX_HTTP_COMPRESSION_STATIC_BAD_SLOTS  64

/* a memo slot's verdict (parent #325: positive verdicts join the ring) */
#define NGX_HTTP_COMPRESSION_STATIC_VERDICT_NONE  0
#define NGX_HTTP_COMPRESSION_STATIC_VERDICT_BAD   1
#define NGX_HTTP_COMPRESSION_STATIC_VERDICT_GOOD  2

typedef struct {
    ngx_file_uniq_t  uniq;
    time_t           mtime;
    off_t            size;
    time_t           checked;  /* when a GOOD verdict was probed */
    size_t           len;
    ngx_uint_t       valid;    /* NGX_HTTP_COMPRESSION_STATIC_VERDICT_* */
    u_char           path[NGX_MAX_PATH];
} ngx_http_compression_static_bad_t;


typedef struct {
    /*
     * "Could this cycle ever serve a sidecar" latch (parent #182), set at
     * directive PARSE time whenever "compression_static on|always" is
     * parsed anywhere. compression_static does NOT take NGX_HTTP_LIF_CONF,
     * so there is no "if"-block conf to reason about — but parse-time
     * latching stays symmetric with the filter module and avoids walking
     * the merge tree. When it stays clear, postconfiguration skips
     * registering the content-phase handler entirely.
     */
    ngx_flag_t     any_enabled;

    /*
     * Worker-lifetime directio scratch (parent #210). Cycle-owned ON
     * PURPOSE: the buffer is allocated from the cycle pool, and keeping
     * its bookkeeping in file-scope statics would let an in-process
     * cycle replacement ("master_process off" + SIGHUP) destroy that
     * pool while statics retained valid-looking capacity — the next
     * probe would then write into freed memory. In conf, metadata and
     * buffer share one lifetime: a new cycle starts from a pcalloc'd
     * conf and allocates afresh (the #103-era rule — module state lives
     * in cycle-owned conf, never process statics).
     */
    u_char        *dio_scratch;
    size_t         dio_scratch_cap;
    size_t         dio_scratch_align;
    ngx_uint_t     dio_scratch_busy;

    /*
     * Bounded worker-local memo of MALFORMED sidecar verdicts (parent
     * #287): a broken generated asset otherwise pays the same probe
     * read and the same NGX_LOG_ERR on every request. Exact path plus
     * file identity, size and mtime form the key, so a replaced or
     * edited file is probed afresh; round-robin eviction lets a
     * later re-probe through. Only deterministic verdicts (format,
     * geometry, window) are remembered -- a read error is transient
     * and must be retried. Cycle-owned like the scratch above: a new
     * cycle starts from a pcalloc'd conf, nothing to reset.
     *
     * GOOD verdicts share the ring (parent #325): under directio the
     * probe is an O_DIRECT read that bypasses the page cache, a real
     * device read on every request that reaches it, and the probe's
     * whole output is its verdict (window and skippable-chain findings
     * become DECLINED plus a log line inside it), so a cached NGX_OK
     * carries everything a fresh one would. A GOOD entry is remembered
     * only when open_file_cache is configured and lives exactly
     * open_file_cache_valid seconds -- the same freshness contract the
     * fd itself is served under -- so a file edited in place inside
     * one mtime tick is re-probed no later than the cache re-opens it.
     */
    ngx_http_compression_static_bad_t
                   bad[NGX_HTTP_COMPRESSION_STATIC_BAD_SLOTS];
    ngx_uint_t     bad_next;

    /*
     * Log rate limit for the directio hard-error probe arm (parent
     * #320). NOT memoized in the ring above: that ring is keyed on
     * file identity, and this failure is a configuration mismatch
     * (directio_alignment against the device), not a property of the
     * file -- caching it there would keep suppressing after the
     * operator fixed the alignment, with no config-tied invalidation.
     * A per-worker window instead: the first hit logs, later hits
     * inside the window are counted, and the next emitted line
     * reports the count. Cycle-owned like everything else here (the
     * #103 rule): a reload's workers start at zero and log the first
     * hit again, so a new misalignment can never hide behind a stale
     * window.
     */
    time_t         dio_err_window_start;
    ngx_uint_t     dio_err_suppressed;
    ngx_uint_t     bad_count;   /* slots ever populated, capped at SLOTS
                                 * (parent #321 P7): the common never-
                                 * populated worker skips the scan, and a
                                 * partly filled ring scans only what it
                                 * holds; saturation and wrap unchanged */
} ngx_http_compression_static_main_conf_t;


static char *ngx_http_compression_static_order(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static void *ngx_http_compression_static_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_compression_static_set_enable_slot(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_compression_static_default_order(ngx_conf_t *cf,
    ngx_http_compression_static_conf_t *conf);
static ngx_int_t ngx_http_compression_static_handler(ngx_http_request_t *r);
static void *ngx_http_compression_static_create_conf(ngx_conf_t *cf);
static char *ngx_http_compression_static_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_compression_static_init(ngx_conf_t *cf);


static ngx_conf_enum_t  ngx_http_compression_static_enum[] = {
    { ngx_string("off"), NGX_HTTP_COMPRESSION_STATIC_OFF },
    { ngx_string("on"), NGX_HTTP_COMPRESSION_STATIC_ON },
    { ngx_string("always"), NGX_HTTP_COMPRESSION_STATIC_ALWAYS },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_compression_static_commands[] = {

    { ngx_string("compression_static"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_compression_static_set_enable_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_compression_static_conf_t, enable),
      &ngx_http_compression_static_enum },

    { ngx_string("compression_static_order"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_compression_static_order,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("compression_static_dict_bypass"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_compression_static_conf_t, dict_bypass),
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_compression_static_module_ctx = {
    NULL,                                    /* preconfiguration */
    ngx_http_compression_static_init,        /* postconfiguration */

    ngx_http_compression_static_create_main_conf, /* create main config */
    NULL,                                    /* init main configuration */

    NULL,                                    /* create server configuration */
    NULL,                                    /* merge server configuration */

    ngx_http_compression_static_create_conf, /* create location config */
    ngx_http_compression_static_merge_conf   /* merge location config */
};


ngx_module_t  ngx_http_compression_static_module = {
    NGX_MODULE_V1,
    &ngx_http_compression_static_module_ctx, /* module context */
    ngx_http_compression_static_commands,    /* module directives */
    NGX_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    NULL,                                    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};


/* directio probe floor: one logical block, raised to the operator's
 * directio_alignment when larger */
#define NGX_HTTP_COMPRESSION_STATIC_DIO_PROBE   4096

/*
 * CEILING for the probe alignment (parent #208). The probe reads a
 * frame HEADER (<= 18 bytes); it is not the body copy, and it does not
 * need the operator's bulk-I/O buffer size. "directio_alignment" has no
 * upper bound in core and governs the copy filter's body buffer, where
 * a large value is a throughput choice; O_DIRECT LEGALITY is a property
 * of the device's logical block size (512 or 4096 in practice). 64 KB
 * is a multiple of every logical block size a Linux/BSD block device
 * reports, so the capped value stays O_DIRECT-legal, and the cap stops
 * an unbounded directive from turning an 18-byte header check into a
 * multi-megabyte aligned allocation and read on every probed request.
 */
#define NGX_HTTP_COMPRESSION_STATIC_DIO_PROBE_MAX  (64 * 1024)

/*
 * Largest byte count the directio probe can ever ask for: PROBE_MAX
 * doubled to the two-block read. Fixed now that the alignment is
 * capped, so a worker-lifetime scratch buffer can be sized against a
 * known ceiling (parent #210).
 */
#define NGX_HTTP_COMPRESSION_STATIC_DIO_SCRATCH_MAX  \
    (NGX_HTTP_COMPRESSION_STATIC_DIO_PROBE_MAX * 2)

/*
 * The frame probe runs on Win32 too (parent #162) and on any POSIX
 * build with pread(2); a POSIX build without pread skips it (a
 * build-time tripwire — every modern target has pread). Gated so the
 * verdict logic below is shared byte-for-byte across platforms and
 * cannot drift, which is exactly how Win32 came to serve .zst files
 * with no validation at all.
 */
#if (NGX_WIN32)
#define NGX_HTTP_COMPRESSION_STATIC_HAVE_PROBE  1
#define NGX_HTTP_COMPRESSION_STATIC_PREAD_NAME  "ReadFile"
#elif (NGX_HAVE_PREAD)
#define NGX_HTTP_COMPRESSION_STATIC_HAVE_PROBE  1
#define NGX_HTTP_COMPRESSION_STATIC_PREAD_NAME  "pread"
#else
#define NGX_HTTP_COMPRESSION_STATIC_HAVE_PROBE  0
#endif


static ngx_int_t ngx_http_compression_static_check_zstd(
    ngx_http_request_t *r, ngx_open_file_info_t *of,
    ngx_http_core_loc_conf_t *clcf, ngx_str_t *path);


/*
 * The static coding table: order token, sidecar extension (no dot),
 * Content-Encoding value == token, and an optional serve-time
 * validator. PHASE2 note: productization derives this from the
 * backend registry (a sidecar_ext field) so a new coding lands in
 * static serving automatically; the prototype keeps it literal
 * because gzip has no backend to hang an ext on either way.
 */
typedef struct {
    ngx_str_t    coding;
    ngx_str_t    ext;
    ngx_int_t  (*check)(ngx_http_request_t *r, ngx_open_file_info_t *of,
                        ngx_http_core_loc_conf_t *clcf, ngx_str_t *path);
} ngx_http_compression_static_coding_t;


/*
 * RFC 9842 dictionary-coding tokens, for the dict-bypass check. Spec
 * constants like the format magics above — NOT registry lookups: this
 * module links nothing, the filter's registry included (the split's
 * whole point).
 */
static ngx_str_t  ngx_http_compression_static_dcz = ngx_string("dcz");
static ngx_str_t  ngx_http_compression_static_dcb = ngx_string("dcb");


static ngx_http_compression_static_coding_t
    ngx_http_compression_static_codings[] =
{
    { ngx_string("zstd"), ngx_string("zst"),
      ngx_http_compression_static_check_zstd },
    { ngx_string("br"),   ngx_string("br"),   NULL },
    { ngx_string("gzip"), ngx_string("gz"),   NULL },
    { ngx_null_string,    ngx_null_string,    NULL }
};


static char *
ngx_http_compression_static_order(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_compression_static_conf_t *ccf = conf;

    ngx_str_t                              *value;
    ngx_uint_t                              i, j, k;
    ngx_http_compression_static_coding_t   *c, **cp, **list;

    (void) cmd;

    if (ccf->order != NULL && ccf->order->nelts > 0) {
        return "is duplicate";
    }

    ccf->order = ngx_array_create(cf->pool, cf->args->nelts - 1,
                        sizeof(ngx_http_compression_static_coding_t *));
    if (ccf->order == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        c = NULL;
        for (k = 0; ngx_http_compression_static_codings[k].coding.len; k++) {
            if (value[i].len
                    == ngx_http_compression_static_codings[k].coding.len
                && ngx_strncmp(value[i].data,
                       ngx_http_compression_static_codings[k].coding.data,
                       value[i].len) == 0)
            {
                c = &ngx_http_compression_static_codings[k];
                break;
            }
        }

        if (c == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "unknown coding \"%V\" in "
                               "\"compression_static_order\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        /* the order list IS the enable set: once each */
        list = ccf->order->elts;
        for (j = 0; j < ccf->order->nelts; j++) {
            if (list[j] == c) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "duplicate coding \"%V\" in "
                                   "\"compression_static_order\"",
                                   &value[i]);
                return NGX_CONF_ERROR;
            }
        }

        cp = ngx_array_push(ccf->order);
        if (cp == NULL) {
            return NGX_CONF_ERROR;
        }
        *cp = c;
    }

    return NGX_CONF_OK;
}


/* shipped default: br zstd gzip — static prefers br because its CPU
 * was spent at build time (the deliberate filter/static asymmetry) */
static ngx_int_t
ngx_http_compression_static_default_order(ngx_conf_t *cf,
    ngx_http_compression_static_conf_t *conf)
{
    ngx_uint_t                              i;
    static ngx_uint_t                       def[3] = { 1, 0, 2 };
    ngx_http_compression_static_coding_t  **cp;

    conf->order = ngx_array_create(cf->pool, 3,
                         sizeof(ngx_http_compression_static_coding_t *));
    if (conf->order == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < 3; i++) {
        cp = ngx_array_push(conf->order);
        if (cp == NULL) {
            return NGX_ERROR;
        }
        *cp = &ngx_http_compression_static_codings[def[i]];
    }

    return NGX_OK;
}


#if (NGX_HTTP_COMPRESSION_STATIC_HAVE_PROBE)


/*
 * The probe's only platform-dependent step (parent #162): fetch up to
 * `size` bytes from `offset` WITHOUT moving the descriptor's file
 * position — pread(2) on POSIX, ngx_read_file() (offset-explicit
 * ReadFile via OVERLAPPED) on Win32. Everything else is shared, so the
 * two platforms cannot drift. Returns the byte count, or -1 on error,
 * matching pread(2) so the caller's short-read handling is unchanged.
 */
static ssize_t
ngx_http_compression_static_pread(ngx_fd_t fd, u_char *buf, size_t size,
    off_t offset, ngx_log_t *log, ngx_str_t *name)
{
#if (NGX_WIN32)
    ssize_t     n;
    ngx_file_t  file;

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.fd = fd;
    file.log = log;
    file.name = *name;

    n = ngx_read_file(&file, buf, size, offset);

    if (n == NGX_ERROR) {
        return -1;
    }

    return n;
#else
    (void) log;
    (void) name;

    return pread(fd, buf, size, offset);
#endif
}

#endif /* NGX_HTTP_COMPRESSION_STATIC_HAVE_PROBE */


#if (NGX_HTTP_COMPRESSION_STATIC_HAVE_PROBE)

/*
 * Worker-lifetime scratch buffer for the directio probe (parent #210):
 * the aligned read exists only to inspect a frame header and every byte
 * is discarded when the probe returns, so one lazily-grown buffer
 * serves every directio probe this worker ever runs instead of an
 * aligned r->pool allocation per hit. Reuse is safe because the probe
 * is synchronous inside one content-phase handler invocation (direct
 * pread/ReadFile, never a thread pool), and `busy` still guards that
 * invariant explicitly: an overlapping caller falls back to its own
 * pool-scoped allocation rather than corrupting the shared buffer.
 * File-scope static = per OS process; reloads fork fresh workers, and
 * the cycle-pool allocation dies with the process.
 */
static u_char *
ngx_http_compression_static_dio_buf(
    ngx_http_compression_static_main_conf_t *smcf, ngx_pool_t *pool,
    size_t want, size_t align)
{
    u_char  *p;

    /*
     * SCRATCH_MAX is the sizing contract the capped alignment
     * guarantees (want = align * 2, align <= PROBE_MAX); enforce it so
     * a future geometry change cannot silently grow the cached
     * worker-lifetime buffer — an oversized ask falls through to the
     * request pool and caches nothing.
     */
    if (smcf->dio_scratch_busy
        || want > NGX_HTTP_COMPRESSION_STATIC_DIO_SCRATCH_MAX)
    {
        return ngx_pmemalign(pool, want, align);
    }

    if (smcf->dio_scratch_cap < want || smcf->dio_scratch_align < align) {
        p = ngx_pmemalign((ngx_pool_t *) ngx_cycle->pool, want, align);
        if (p == NULL) {
            return ngx_pmemalign(pool, want, align);
        }

        smcf->dio_scratch = p;
        smcf->dio_scratch_cap = want;
        smcf->dio_scratch_align = align;
    }

    smcf->dio_scratch_busy = 1;

    return smcf->dio_scratch;
}


static void
ngx_http_compression_static_dio_buf_release(
    ngx_http_compression_static_main_conf_t *smcf)
{
    smcf->dio_scratch_busy = 0;
}


#define NGX_HTTP_COMPRESSION_STATIC_DIO_ERR_WINDOW  60

/*
 * Returns the number of hits suppressed before this one (0 for the
 * first in a window, or when a window just rolled over), or
 * (ngx_uint_t) -1 when this hit is itself suppressed. ngx_time() is
 * nginx's per-iteration cached clock; a step backwards (`now < start`,
 * an administrative or NTP jump) forces a rollover rather than
 * extending suppression indefinitely through a negative difference.
 */
static ngx_uint_t
ngx_http_compression_static_dio_err_should_log(
    ngx_http_compression_static_main_conf_t *smcf, ngx_log_t *log)
{
    time_t      now;
    ngx_uint_t  suppressed;

    now = ngx_time();

    if (smcf->dio_err_window_start == 0
        || now < smcf->dio_err_window_start
        || now - smcf->dio_err_window_start
           >= NGX_HTTP_COMPRESSION_STATIC_DIO_ERR_WINDOW)
    {
        suppressed = smcf->dio_err_suppressed;
        smcf->dio_err_window_start = now;
        smcf->dio_err_suppressed = 0;
        return suppressed;
    }

    smcf->dio_err_suppressed++;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "compression static: directio probe error suppressed "
                   "(%ui so far this window)", smcf->dio_err_suppressed);

    return (ngx_uint_t) -1;
}


/*
 * The memoized verdict for this file identity, or VERDICT_NONE. A GOOD
 * entry older than good_valid seconds (or any GOOD entry when good_valid
 * is 0) is retired here rather than skipped: the caller records the
 * fresh verdict at the ring cursor, and a stale twin left live would
 * shadow that newer entry on every lookup until the cursor evicted it.
 */
static ngx_uint_t
ngx_http_compression_static_cached_verdict(
    ngx_http_compression_static_main_conf_t *smcf, ngx_str_t *path,
    ngx_open_file_info_t *of, time_t now, time_t good_valid)
{
    ngx_uint_t                          i;
    ngx_http_compression_static_bad_t  *e;

    if (path->len >= NGX_MAX_PATH || smcf->bad_count == 0) {
        return NGX_HTTP_COMPRESSION_STATIC_VERDICT_NONE;
    }

    for (i = 0; i < smcf->bad_count; i++) {
        e = &smcf->bad[i];

        if (e->valid != NGX_HTTP_COMPRESSION_STATIC_VERDICT_NONE
            && e->uniq == of->uniq && e->mtime == of->mtime
            && e->size == of->size && e->len == path->len
            && ngx_memcmp(e->path, path->data, path->len) == 0)
        {
            if (e->valid == NGX_HTTP_COMPRESSION_STATIC_VERDICT_GOOD
                && (good_valid == 0 || now < e->checked
                    || now - e->checked >= good_valid))
            {
                e->valid = NGX_HTTP_COMPRESSION_STATIC_VERDICT_NONE;
                continue;
            }

            return e->valid;
        }
    }

    return NGX_HTTP_COMPRESSION_STATIC_VERDICT_NONE;
}


static void
ngx_http_compression_static_remember(
    ngx_http_compression_static_main_conf_t *smcf, ngx_str_t *path,
    ngx_open_file_info_t *of, ngx_uint_t verdict, time_t now,
    time_t good_valid)
{
    ngx_http_compression_static_bad_t  *e;

    if (path->len >= NGX_MAX_PATH
        || (verdict == NGX_HTTP_COMPRESSION_STATIC_VERDICT_GOOD
            && good_valid == 0))
    {
        return;
    }

    e = &smcf->bad[smcf->bad_next];
    e->uniq = of->uniq;
    e->mtime = of->mtime;
    e->size = of->size;
    e->checked = now;
    e->len = path->len;
    ngx_memcpy(e->path, path->data, path->len);

    if (e->valid == NGX_HTTP_COMPRESSION_STATIC_VERDICT_NONE
        && smcf->bad_count < NGX_HTTP_COMPRESSION_STATIC_BAD_SLOTS)
    {
        smcf->bad_count++;
    }

    e->valid = verdict;

    smcf->bad_next++;
    if (smcf->bad_next == NGX_HTTP_COMPRESSION_STATIC_BAD_SLOTS) {
        smcf->bad_next = 0;
    }
}


#endif /* NGX_HTTP_COMPRESSION_STATIC_HAVE_PROBE */


/*
 * The parent zstd_static probe (ported): magic sanity (a truncated /
 * half-downloaded / mistakenly-renamed file must not be served as zstd)
 * plus the declared-window cap on the leading REGULAR frame — reached
 * by walking a bounded chain of leading skippable frames so the guard
 * cannot be dodged by prepending one (parent #159). Reads are
 * offset-explicit (parent #162: pread(2)/ngx_read_file()) so they never
 * corrupt the open_file_cache's shared fd position. Under directio the
 * read is block-aligned at max(4096, directio_alignment) into an
 * equally aligned buffer, and a failed aligned read DECLINES — for a
 * validation read, falling back beats certifying a file we could not
 * inspect. Runs on Win32 too now (parent #162).
 */
static ngx_int_t
ngx_http_compression_static_check_zstd(ngx_http_request_t *r,
    ngx_open_file_info_t *of, ngx_http_core_loc_conf_t *clcf,
    ngx_str_t *path)
{
#if (NGX_HTTP_COMPRESSION_STATIC_HAVE_PROBE)
    /*
     * 58 bytes buffered (parent #261): a canonical 40-byte dcz
     * skippable prefix plus the largest possible 18-byte frame header,
     * so the common two-frame shape reuses ONE read. Short files return
     * fewer bytes; each parse path checks it got what its layout needs.
     */
    u_char      hdrbuf[58];
    u_char     *hdr, *frame;
    size_t      want, align, frame_off, avail, need;
    ssize_t     n;
    uint64_t    window, skip;
    ngx_int_t   probe_rc;
    ngx_uint_t  frames, scratch, have_block, reuse, malformed;
    ngx_uint_t  dio_suppressed, verdict;
    time_t      now, good_valid;
    off_t       pos, base, have_base;
    ngx_log_t  *log;

    ngx_http_compression_static_main_conf_t  *smcf;

    smcf = ngx_http_get_module_main_conf(r,
                                         ngx_http_compression_static_module);

    log = r->connection->log;

    scratch = 0;
    have_block = 0;
    have_base = 0;
    malformed = 0;
    n = 0;

    now = ngx_time();
    good_valid = clcf->open_file_cache == NULL
                     ? 0 : clcf->open_file_cache_valid;

    verdict = ngx_http_compression_static_cached_verdict(smcf, path, of,
                                                         now, good_valid);

    if (verdict == NGX_HTTP_COMPRESSION_STATIC_VERDICT_BAD) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "compression static: cached malformed verdict for "
                       "\"%V\"", path);
        return NGX_DECLINED;
    }

    if (verdict == NGX_HTTP_COMPRESSION_STATIC_VERDICT_GOOD) {
        /*
         * Debug witness that the probe was elided: serving correctly
         * proves only that the verdict was right, not where it came
         * from. Returning here skips the scratch buffer entirely, so
         * its busy guard is never taken on this path.
         */
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "compression static: cached good frame verdict for "
                       "\"%V\"", path);
        return NGX_OK;
    }

    if (of->size < 4) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "compression static: \"%V\" too small to be a zstd "
                      "frame (%O bytes)", path, of->size);
        malformed = 1;
        probe_rc = NGX_DECLINED;
        goto probe_done;
    }

    if (of->is_directio) {
        align = NGX_HTTP_COMPRESSION_STATIC_DIO_PROBE;
        if ((size_t) clcf->directio_alignment > align) {
            align = (size_t) clcf->directio_alignment;
        }

        /* the #208 ceiling: see NGX_HTTP_COMPRESSION_STATIC_DIO_PROBE_MAX */
        if (align > NGX_HTTP_COMPRESSION_STATIC_DIO_PROBE_MAX) {
            align = NGX_HTTP_COMPRESSION_STATIC_DIO_PROBE_MAX;
        }

        /*
         * TWO blocks, not one (parent #197). The probe offset is rounded
         * down to `align` — an O_DIRECT descriptor rejects an unaligned
         * file offset with EINVAL — so a frame header can start as late
         * as align-1 bytes into the first block and would then straddle
         * the boundary; parsing only one block would misreport that
         * legitimate frame as truncated. A second block guarantees at
         * least `align` (>= 4096) bytes behind any in-block start, far
         * more than the 18 a frame header needs. Both the length and the
         * buffer stay `align`-aligned, which is what O_DIRECT requires.
         */
        want = align * 2;

        /* worker-lifetime scratch, pool fallback under overlap (#210);
         * `scratch` remembers whether THIS call took the shared buffer
         * so only that call clears the guard at probe_done */
        hdr = ngx_http_compression_static_dio_buf(smcf, r->pool, want,
                                                  align);
        if (hdr == NULL) {
            return NGX_ERROR;
        }
        scratch = (hdr == smcf->dio_scratch);

    } else {
        align = 0;
        hdr = hdrbuf;
        want = sizeof(hdrbuf);
    }

    pos = 0;

    /*
     * Walk a bounded chain of leading skippable frames to reach the
     * first regular frame. Each iteration reads at the current offset.
     * Under directio the O_DIRECT descriptor rejects an unaligned file
     * offset with EINVAL, and `pos` after a leading skippable frame is
     * whatever that frame's length made it (40 for the canonical dcz
     * SHA-256 prefix) — almost never a block multiple. So the read
     * offset is rounded DOWN to `align` and the frame is parsed at its
     * offset inside the block: `base` is the aligned read offset,
     * `frame_off` the distance from there to `pos`, and `avail` the
     * bytes of the read that lie at or after `pos`. Off the directio
     * path `base == pos`, `frame_off == 0`, `avail == n` — byte-for-byte
     * the previous behaviour (parent #197).
     */
    for (frames = 0; ; frames++) {

        /*
         * `>` not `>=` (parent #273): `frames` counts ITERATIONS, and
         * iteration N probes the frame after N prior skips — so the
         * bound must permit iteration MAX (the frame after exactly MAX
         * skips, the documented boundary) and decline only when a
         * MAX+1th skippable frame actually appeared. The old `>=`
         * declined a valid file with exactly four leading skippable
         * frames one probe early.
         */
        if (frames > NGX_HTTP_ZSTD_STATIC_MAX_SKIP_FRAMES) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "compression static: \"%V\" has more than %ui "
                          "leading skippable frames — declining rather "
                          "than searching further for the first regular "
                          "frame", path,
                          (ngx_uint_t)
                              NGX_HTTP_ZSTD_STATIC_MAX_SKIP_FRAMES);
            malformed = 1;
            probe_rc = NGX_DECLINED;
            goto probe_done;
        }

        if (of->is_directio) {
            frame_off = (size_t) ((uint64_t) pos % (uint64_t) align);
            base = pos - (off_t) frame_off;

        } else {
            frame_off = 0;
            base = pos;
        }

        /*
         * Reuse the bytes already in `hdr` when they cover everything
         * this iteration can parse (parent #233/#261): the whole
         * possible 18-byte header, or all bytes remaining in a shorter
         * file, floored at the 4-byte magic. Under directio this
         * collapses the skip-frame walk's repeated same-block reads;
         * buffered, the 58-byte first read covers the canonical
         * dcz-prefix-then-frame shape, dropping its second read.
         */
        need = (size_t) ngx_min((off_t) 18,
                                ngx_max((off_t) 4, of->size - pos));

        reuse = have_block
                && ngx_http_zstd_static_probe_reuse(pos, have_base,
                                                           n, need,
                                                           &frame_off,
                                                           &base);

        if (!reuse) {
            n = ngx_http_compression_static_pread(of->fd, hdr, want, base,
                                                  log, path);

            if (n > 0) {
                have_block = 1;
                have_base = base;
            }
        }

        /*
         * Bytes of the block that lie at or after `pos`. A short read
         * that stopped inside the prefix leaves nothing for the frame,
         * the same "too few bytes" condition as a short read at offset 0
         * and taking the same branch.
         */
        avail = ((size_t) (n > 0 ? n : 0) > frame_off)
                    ? (size_t) n - frame_off : 0;

        frame = hdr + frame_off;

        if (n < 0 || avail < 4) {
            if (of->is_directio) {
                /*
                 * Once per window, with the suppressed count folded
                 * into the next emitted line (parent #320): this fires
                 * on every request to a misaligned sidecar, 1:1 with
                 * traffic, and the operator needs the first line, not
                 * the ten-thousandth.
                 */
                dio_suppressed =
                    ngx_http_compression_static_dio_err_should_log(smcf, log);

                if (dio_suppressed == 0) {
                    ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                                  "compression static: %uz-byte aligned "
                                  "probe on directio file \"%V\" returned "
                                  "%z — declining; check directio_alignment "
                                  "against the device geometry",
                                  align, path, n);

                } else if (dio_suppressed != (ngx_uint_t) -1) {
                    ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                                  "compression static: %uz-byte aligned "
                                  "probe on directio file \"%V\" returned "
                                  "%z — declining; check directio_alignment "
                                  "against the device geometry (%ui more "
                                  "such probes in the last %d seconds)",
                                  align, path, n, dio_suppressed,
                                  NGX_HTTP_COMPRESSION_STATIC_DIO_ERR_WINDOW);
                }

                probe_rc = NGX_DECLINED;
                goto probe_done;
            }

            /*
             * n >= 0 is a read that succeeded and returned too few
             * bytes (a sidecar of nothing but skippable frames: n == 0
             * at offset == size): errno is stale then, so it is logged
             * at ERR with errno 0 and memoized as a malformed verdict
             * like any other deterministic shape (parent #314). A
             * genuine read failure keeps CRIT and the real ngx_errno,
             * and stays transient.
             */
            if (n >= 0) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "compression static: "
                              NGX_HTTP_COMPRESSION_STATIC_PREAD_NAME
                              "(\"%V\", frame header) returned %z",
                              path, n);
                malformed = 1;

            } else {
                ngx_log_error(NGX_LOG_CRIT, log, ngx_errno,
                              "compression static: "
                              NGX_HTTP_COMPRESSION_STATIC_PREAD_NAME
                              "(\"%V\", frame header) returned %z",
                              path, n);
            }

            probe_rc = NGX_DECLINED;
            goto probe_done;
        }

        if (of->is_directio) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                           "compression static: %uz-byte aligned probe on "
                           "directio file \"%V\"", align, path);
        }

        switch (ngx_http_zstd_static_probe_frame(frame, avail,
                                                        &window))
        {

        case NGX_HTTP_ZSTD_STATIC_FRAME_NOT_ZSTD:
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "compression static: \"%V\" is not a zstd frame "
                          "(leading bytes 0x%02xd%02xd%02xd%02xd)", path,
                          (unsigned) frame[0], (unsigned) frame[1],
                          (unsigned) frame[2], (unsigned) frame[3]);
            malformed = 1;
            probe_rc = NGX_DECLINED;
            goto probe_done;

        case NGX_HTTP_ZSTD_STATIC_FRAME_TRUNCATED:
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "compression static: \"%V\" frame header "
                          "truncated", path);
            malformed = 1;
            probe_rc = NGX_DECLINED;
            goto probe_done;

        case NGX_HTTP_ZSTD_STATIC_FRAME_WINDOW_BIG:
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "compression static: \"%V\" declares a %uL-byte "
                          "decompression window, above the 8 MB limit "
                          "browsers enforce for Content-Encoding: zstd "
                          "(RFC 8878) — declining so a fallback coding is "
                          "used; recompress with a window log <= 23", path,
                          window);
            malformed = 1;
            probe_rc = NGX_DECLINED;
            goto probe_done;

        case NGX_HTTP_ZSTD_STATIC_FRAME_RESERVED:
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "compression static: \"%V\" frame header sets "
                          "reserved Frame_Header_Descriptor bit 0x08 "
                          "(RFC 8878) — declining so a fallback coding is "
                          "used", path);
            malformed = 1;
            probe_rc = NGX_DECLINED;
            goto probe_done;

        case NGX_HTTP_ZSTD_STATIC_FRAME_SKIP:

            /*
             * `window` carries the declared skip length here. Prove the
             * 8-byte skippable header AND the full declared skip both
             * fit within of->size before trusting the jump — checked
             * arithmetic throughout, since `skip` is attacker-controlled
             * and wide enough to overflow a 32-bit add on its own.
             */
            skip = window;

            if ((uint64_t) pos > (uint64_t) of->size
                || (uint64_t) of->size - (uint64_t) pos < 8)
            {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "compression static: \"%V\" skippable frame "
                              "header runs past end of file", path);
                malformed = 1;
                probe_rc = NGX_DECLINED;
                goto probe_done;
            }

            if (skip > (uint64_t) of->size - (uint64_t) pos - 8) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "compression static: \"%V\" skippable frame "
                              "declares a %uL-byte skip past end of file",
                              path, skip);
                malformed = 1;
                probe_rc = NGX_DECLINED;
                goto probe_done;
            }

            pos += (off_t) 8 + (off_t) skip;

            continue;

        default:
            break;
        }

        break;
    }

    probe_rc = NGX_OK;

probe_done:

    /*
     * Single release point for every exit above (parent #210): clears
     * the scratch reuse guard only when THIS call set it -- a pool-
     * fallback call never touched it and must not clear it out from
     * under a genuinely concurrent caller.
     */
    if (scratch) {
        ngx_http_compression_static_dio_buf_release(smcf);
    }

    if (probe_rc == NGX_DECLINED && malformed) {
        ngx_http_compression_static_remember(smcf, path, of,
                                        NGX_HTTP_COMPRESSION_STATIC_VERDICT_BAD,
                                        now, good_valid);

    } else if (probe_rc == NGX_OK) {
        ngx_http_compression_static_remember(smcf, path, of,
                                       NGX_HTTP_COMPRESSION_STATIC_VERDICT_GOOD,
                                       now, good_valid);
    }

    return probe_rc;

#else
    (void) r; (void) of; (void) clcf; (void) path;
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_compression_static_handler(ngx_http_request_t *r)
{
    u_char                                 *p;
    size_t                                  root;
    ngx_int_t                               rc, w;
    ngx_str_t                               path;
    ngx_buf_t                              *b;
    ngx_log_t                              *log;
    ngx_uint_t                              i, level, vary_emitted;
    ngx_chain_t                             out;
    ngx_list_part_t                        *part;
    ngx_table_elt_t                        *h, *ae;
    ngx_open_file_info_t                    of;
    ngx_http_core_loc_conf_t               *clcf;
    ngx_http_compression_static_conf_t     *conf;
    ngx_http_compression_static_coding_t   *c, **order;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_DECLINED;
    }

    if (r->uri.len == 0 || r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

    conf = ngx_http_get_module_loc_conf(r,
                                        ngx_http_compression_static_module);

    if (conf->enable == NGX_HTTP_COMPRESSION_STATIC_OFF) {
        return NGX_DECLINED;
    }

    /*
     * PHASE3 (found in the production soak): a request that both
     * HOLDS a dictionary (Available-Dictionary) and explicitly
     * accepts a dictionary coding can be served dramatically smaller
     * by the FILTER module's dcz/dcb delta path than by any
     * precompressed sidecar — but this handler runs first in the
     * content phase and would serve the sidecar before negotiation
     * ever happens. compression_static_dict_bypass makes this
     * handler stand aside for exactly those requests, in BOTH on and
     * always modes. Opt-in per location (deploy tooling emits it
     * beside compression_dict_file), default off so a static-only
     * deployment never serves identity to dict-capable clients. The
     * check runs BEFORE the Vary delegation below on purpose: a
     * declined request must not carry a delegated AE line beside the
     * filter's combined one (the split-Vary cache hazard). Documented
     * tradeoff: an Available-Dictionary that misses the filter's
     * store pays runtime compression instead of the sidecar — rare
     * by construction, since clients only advertise dictionaries
     * whose match pattern covers the URL.
     *
     * Main requests only (parent #222's gate, which this port
     * originally lacked): a subrequest inherits the main request's
     * headers_in, but the filter never negotiates a dictionary
     * coding for subrequests — standing aside would hand the
     * subrequest to a filter that cannot dcz/dcb it, losing the
     * sidecar with zero upside.
     *
     * NO secure-context precheck, deliberately: the honest check is
     * "ssl || assume_secure" and the ack lives in the filter's conf,
     * unreadable across the module split — while a bare-ssl shortcut
     * would misfire in exactly the TLS-terminating-proxy topology the
     * ack exists for. The cost of not checking lands only on
     * hand-built clients: browsers gate dictionary advertisement on
     * secure contexts CLIENT-side, so over genuine cleartext no
     * browser sends Available-Dictionary and the bypass never fires.
     */
    if (conf->dict_bypass && r == r->main) {

        part = &r->headers_in.headers.part;
        h = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    h = NULL;
                    break;
                }
                part = part->next;
                h = part->elts;
                i = 0;
            }

            if (h[i].key.len == sizeof("Available-Dictionary") - 1
                && ngx_strncasecmp(h[i].key.data,
                                   (u_char *) "Available-Dictionary",
                                   sizeof("Available-Dictionary") - 1) == 0)
            {
                h = &h[i];
                break;
            }
        }

        if (h != NULL) {
            ae = ngx_http_compression_ae_header(r);

            if (ae != NULL
                && (ngx_http_compression_request_coding_weight(r,
                        &ngx_http_compression_static_dcz, 0) > 0
                    || ngx_http_compression_request_coding_weight(r,
                        &ngx_http_compression_static_dcb, 0) > 0))
            {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "compression static: standing aside for "
                               "dictionary negotiation");
                return NGX_DECLINED;
            }
        }
    }

    ae = NULL;
    vary_emitted = 0;

    /*
     * Negotiated-mode Vary moved INTO the probe loop (parent #202,
     * eilandert's port ruling on round 4): the header is emitted on
     * the first sidecar that proves USABLE — after is_dir/is_file and
     * the frame probe — not before any existence check. A URI whose
     * every sidecar is missing, a directory, truncated or
     * window-oversized is not a negotiated variant, and stamping Vary
     * on its identity response fragmented shared caches for nothing.
     * The flip side is the condition the ruling attached: the probe
     * must run INDEPENDENTLY of the client's weights, or a
     * non-accepting client would never open a sidecar, never learn
     * one is usable, and its identity response would enter shared
     * caches with no Vary at all — the poisoning case. So: probe
     * first, Vary on the first pass, and the weight decides
     * serve-vs-decline rather than probe-vs-skip. "always" still
     * never varies (it ignores Accept-Encoding; gzip_static parity).
     */
    if (conf->enable == NGX_HTTP_COMPRESSION_STATIC_ON) {
        ae = ngx_http_compression_ae_header(r);
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    log = r->connection->log;

    order = conf->order->elts;

    for (i = 0; i < conf->order->nelts; i++) {

        c = order[i];

        p = ngx_http_map_uri_to_path(r, &path, &root, c->ext.len + 2);
        if (p == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        *p++ = '.';
        p = ngx_cpymem(p, c->ext.data, c->ext.len);
        *p = '\0';
        path.len = p - path.data;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "compression static probe: \"%s\"", path.data);

        ngx_memzero(&of, sizeof(ngx_open_file_info_t));

        of.read_ahead = clcf->read_ahead;
        of.directio = clcf->directio;
        of.valid = clcf->open_file_cache_valid;
        of.min_uses = clcf->open_file_cache_min_uses;
        of.errors = clcf->open_file_cache_errors;
        of.events = clcf->open_file_cache_events;

        if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
            != NGX_OK)
        {
            switch (of.err) {

            case 0:
                return NGX_HTTP_INTERNAL_SERVER_ERROR;

            case NGX_ENOENT:
            case NGX_ENOTDIR:
            case NGX_ENAMETOOLONG:
                continue;       /* next coding in the order */

            case NGX_EACCES:
#if (NGX_HAVE_OPENAT)
            case NGX_EMLINK:
            case NGX_ELOOP:
#endif
                level = NGX_LOG_ERR;
                break;

            default:
                level = NGX_LOG_CRIT;
                break;
            }

            ngx_log_error(level, log, of.err,
                          "%s \"%s\" failed", of.failed, path.data);
            continue;           /* decline-and-log, keep probing */
        }

        if (of.is_dir) {
            continue;
        }

#if !(NGX_WIN32)
        if (!of.is_file) {
            ngx_log_error(NGX_LOG_CRIT, log, 0,
                          "\"%s\" is not a regular file", path.data);
            continue;
        }
#endif

        if (c->check != NULL
            && c->check(r, &of, clcf, &path) != NGX_OK)
        {
            /* already logged; fall through to the next coding — the
             * unified probe loop is what makes decline-and-log land on
             * a BETTER answer than identity when one exists */
            continue;
        }

        /*
         * A USABLE sidecar exists: this URI genuinely varies on
         * Accept-Encoding, so the header goes out now (#202 contract)
         * — on the serve path AND on every decline below it, the
         * non-accepting client included.
         */
        if (conf->enable == NGX_HTTP_COMPRESSION_STATIC_ON) {

            if (!vary_emitted) {
                if (ngx_http_compression_vary(r) != NGX_OK) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                vary_emitted = 1;
            }

            if (ae == NULL) {
                /*
                 * No Accept-Encoding at all: no coding can serve. An
                 * empty FIRST line no longer short-circuits (parent
                 * #215/#275) — the whole-field weight below reads
                 * every line, and all-empty lines decline naturally.
                 * The Vary
                 * this usable sidecar earned is already out — further
                 * probes could only confirm what one usable file
                 * already proved. Identity, correctly partitioned.
                 */
                return NGX_DECLINED;
            }

            /* base codings accept the "*" wildcard, same as the
             * filter election; a usable-but-unaccepted sidecar keeps
             * probing — the next coding may be both */
            w = ngx_http_compression_request_coding_weight(r,
                                                           &c->coding, 1);
            if (w <= 0) {
                continue;
            }
        }

        /* ── serve this sidecar ─────────────────────────────────── */

        r->root_tested = !r->error_page;

        rc = ngx_http_discard_request_body(r);
        if (rc != NGX_OK) {
            return rc;
        }

        log->action = (char *) "sending response to client";

        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = of.size;
        r->headers_out.last_modified_time = of.mtime;

        if (ngx_http_set_etag(r) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /* content type derives from the ORIGINAL uri's extension */
        if (ngx_http_set_content_type(r) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        h = ngx_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        h->hash = 1;
        h->next = NULL;
        ngx_str_set(&h->key, "Content-Encoding");
        h->value = c->coding;
        r->headers_out.content_encoding = h;

        /* gzip_static parity: on the static side the representation IS
         * the sidecar's bytes and the validator is strong, so byte
         * ranges are coherent — and they only work by opting in (the
         * range filter bails unless r->allow_ranges is set; a content
         * handler serving a local file never gets it otherwise).
         * "Ranges are meaningless on a compressed body" is a FILTER
         * truth: there the encoded stream is generated on the fly. */
        r->allow_ranges = 1;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "compression static: serving \"%s\"", path.data);

        /*
         * HEAD fast path (parent #179): the response headers already
         * carry everything a HEAD needs — Content-Encoding above and the
         * Vary line emitted earlier in the negotiated path — so send them
         * and skip the body buffer + ngx_file_t allocations below. Strict
         * r->method == NGX_HTTP_HEAD, NOT r->header_only: the latter also
         * covers 304/204, whose existing header_only return past the
         * body-buffer setup stays correct.
         */
        if (r->method == NGX_HTTP_HEAD) {
            return ngx_http_send_header(r);
        }

        /*
         * One ngx_pcalloc() for the ngx_buf_t and its ngx_file_t
         * (parent #210): the two objects share this response's
         * lifetime and ownership, so the split allocation bought
         * nothing. Zero-init, alignment and failure behavior are
         * unchanged — either both members exist, zeroed, or neither.
         */
        {
            struct {
                ngx_buf_t   buf;
                ngx_file_t  file;
            } *wrap;

            wrap = ngx_pcalloc(r->pool, sizeof(*wrap));
            if (wrap == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            b = &wrap->buf;
            b->file = &wrap->file;
        }

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }

        b->file_pos = 0;
        b->file_last = of.size;

        b->in_file = b->file_last ? 1 : 0;
        b->last_buf = (r == r->main) ? 1 : 0;
        b->last_in_chain = 1;

        /* an empty sidecar in a subrequest leaves in_file and last_buf
         * both 0 — sync marks the flagless zero-size buf deliberate so
         * the output chain doesn't alert (gzip_static parity) */
        b->sync = (b->last_buf || b->in_file) ? 0 : 1;

        b->file->fd = of.fd;
        b->file->name = path;
        b->file->log = log;
        b->file->directio = of.is_directio;

        out.buf = b;
        out.next = NULL;

        return ngx_http_output_filter(r, &out);
    }

    /* nothing served: the identity original (and possibly the dynamic
     * filter) takes over — no latches touched, by design */
    return NGX_DECLINED;
}

static void *
ngx_http_compression_static_create_main_conf(ngx_conf_t *cf)
{
    /* pcalloc zeroes any_enabled — cycle-owned, no reset hook needed */
    return ngx_pcalloc(cf->pool,
                       sizeof(ngx_http_compression_static_main_conf_t));
}


/*
 * "compression_static off|on|always" (parent #182): the standard enum
 * slot plus a parse-time latch of the cycle-global any_enabled bit, so
 * postconfiguration can skip the content-phase handler when static
 * serving is off in every location. Latched for "on"/"always", not "off".
 */
static char *
ngx_http_compression_static_set_enable_slot(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_str_t                                *value;
    char                                     *rc;
    ngx_http_compression_static_main_conf_t  *smcf;

    rc = ngx_conf_set_enum_slot(cf, cmd, conf);
    if (rc != NGX_CONF_OK) {
        return rc;
    }

    /* value[1] is "off", "on", or "always" — the enum already rejected
     * anything else above. */
    value = cf->args->elts;
    if (value[1].len == 3 && ngx_strncmp(value[1].data, "off", 3) == 0) {
        return NGX_CONF_OK;
    }

    smcf = ngx_http_conf_get_module_main_conf(cf,
                                        ngx_http_compression_static_module);
    smcf->any_enabled = 1;

    return NGX_CONF_OK;
}


static void *
ngx_http_compression_static_create_conf(ngx_conf_t *cf)
{
    ngx_http_compression_static_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_compression_static_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET_UINT;
    conf->order = NULL;     /* NULL = inherit / shipped default */
    conf->dict_bypass = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_compression_static_merge_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_http_compression_static_conf_t *prev = parent;
    ngx_http_compression_static_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->enable, prev->enable,
                              NGX_HTTP_COMPRESSION_STATIC_OFF);
    ngx_conf_merge_value(conf->dict_bypass, prev->dict_bypass, 0);

    if (conf->order == NULL) {
        conf->order = prev->order;
    }

    if (conf->order == NULL) {
        if (ngx_http_compression_static_default_order(cf, conf) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    /*
     * No "gzip_vary off" warning any more (parent #163): the handler's
     * negotiated path calls ngx_http_compression_vary(), which now
     * emits Vary: Accept-Encoding by construction regardless of the
     * gzip_vary directive. "always" mode ignores Accept-Encoding and
     * deliberately does not call it, so it still carries no Vary — the
     * correct behaviour for a non-negotiated response.
     */

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_compression_static_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt                      *h;
    ngx_http_core_main_conf_t                *cmcf;
    ngx_http_compression_static_main_conf_t  *smcf;

    /*
     * Skip registering the content-phase handler when "compression_static"
     * is off in every location (parent #182). any_enabled is latched at
     * directive parse time, so a build that carries the static module but
     * never enables it pays no per-request always-declining handler.
     */
    smcf = ngx_http_conf_get_module_main_conf(cf,
                                        ngx_http_compression_static_module);
    if (smcf == NULL || !smcf->any_enabled) {
        return NGX_OK;
    }

    /* the content phase, exactly like gzip_static and the parent
     * *_static modules */
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_compression_static_handler;

    return NGX_OK;
}
