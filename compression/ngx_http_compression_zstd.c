/*
 * zstd backend for nginx-compression (phase-0 prototype).
 * The reference implementation the vtable was shaped against; see
 * ngx_http_compression.h for the contract each hook satisfies.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_compression.h"

#if (NGX_HTTP_COMPRESSION_HAVE_ZSTD)

/*
 * ZSTD_getCParams (the level->parameters table read the browser
 * window cap needs) sits behind the static-linking-only gate, and it
 * is this module's ONE static-API import — accepted deliberately,
 * with the parent's #237 caveat stated rather than hidden:
 * ZSTDLIB_STATIC_API symbols carry no dynamic-ABI guarantee upstream,
 * so a future libzstd.so is nominally free to remove or reshape them.
 * In practice ZSTD_getCParams is exported by every distribution
 * libzstd and has been shape-stable since 1.4. The define lives HERE,
 * in the only TU that needs it, not on CFLAGS (see auto/detect) —
 * every other libzstd call in this file is stable public API, and if
 * a stable replacement for the cparams table ever lands, this import
 * and this comment both go.
 */
#ifndef ZSTD_STATIC_LINKING_ONLY
#define ZSTD_STATIC_LINKING_ONLY  1
#endif

#include <zstd.h>

/* the parent's runtime version policy, shared verbatim (parent #284) */
#include "../src/ngx_http_zstd_version.h"


/*
 * Declared level bounds (parent zstd_comp_level parity). The
 * initializer needs compile-time constants, so the runtime
 * ZSTD_minCLevel()/ZSTD_maxCLevel() values are pinned as literals:
 * -(1 << 17) and 22, stable across every 1.4+ release. 0 is inside
 * the range on purpose — it selects ZSTD_CLEVEL_DEFAULT. Pre-1.4
 * libraries have no negative levels, matching the parent's clamp.
 */
#if ZSTD_VERSION_NUMBER >= 10400
#define NGX_HTTP_COMPRESSION_ZSTD_LEVEL_MIN  (-131072)
#else
#define NGX_HTTP_COMPRESSION_ZSTD_LEVEL_MIN  0
#endif
#define NGX_HTTP_COMPRESSION_ZSTD_LEVEL_MAX  22

/* the 8 MB window browsers enforce for Content-Encoding: zstd
 * (RFC 8878 §3.1.1.1.2) — same limit the static probe serves by */
#define NGX_HTTP_COMPRESSION_ZSTD_BROWSER_WLOG  23


typedef struct {
    ZSTD_CCtx           *cctx;
    ngx_http_request_t  *r;      /* for error logging with context */
} ngx_http_compression_zstd_ctx_t;


static void
ngx_http_compression_zstd_cleanup(void *data)
{
    ngx_http_compression_zstd_ctx_t  *z = data;

    if (z->cctx != NULL) {
        ZSTD_freeCCtx(z->cctx);
        z->cctx = NULL;
    }
}


static ngx_int_t
ngx_http_compression_zstd_create(ngx_http_request_t *r,
    const ngx_http_compression_tuning_t *tuning, void **bctx)
{
    ngx_pool_cleanup_t               *cln;
    ngx_http_compression_zstd_ctx_t  *z;

    cln = ngx_pool_cleanup_add(r->pool,
                               sizeof(ngx_http_compression_zstd_ctx_t));
    if (cln == NULL) {
        return NGX_ERROR;
    }

    z = cln->data;
    z->r = r;
    z->cctx = ZSTD_createCCtx();
    if (z->cctx == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_http_compression_zstd_cleanup;

    if (ZSTD_isError(ZSTD_CCtx_setParameter(z->cctx,
                                            ZSTD_c_compressionLevel,
                                            (int) tuning->level)))
    {
        return NGX_ERROR;
    }

    /*
     * The window is a per-request memory CEILING (parent
     * zstd_window_log semantics) when the operator set it. When they
     * did NOT, the effective window is capped at the browser limit —
     * an INTENTIONAL DEVIATION from the parent (Mark's call, 2026-08-19):
     * on an UNPLEDGED stream (chunked proxying, SSI — no
     * Content-Length) the frame header declares the parameter's
     * window, and every browser rejects anything above 8 MB (RFC 8878
     * §3.1.1.1.2) before decoding a byte. Levels 20+ default past the
     * limit, and long-distance matching would default to 128 MB at
     * ANY level — the dynamic twin of the vite/128MB static incident.
     * The cap is min(level default, 23): a ceiling, never a floor, so
     * low levels keep their smaller windows and memory profile.
     * Pledged responses are unaffected either way (their headers
     * declare the content size), and an explicit compression_window
     * still wins verbatim for operators serving non-browser clients.
     *
     * PHASE3 note: the parent's dcz path additionally sizes the
     * window UP to dictionary + expected content so the far end of a
     * large dictionary keeps matching — that computation joins
     * attach_dictionary when the prepared-dictionary work lands; an
     * explicit operator ceiling must still win there, as here.
     */
    if (tuning->window_bits > 0) {
        if (ZSTD_isError(ZSTD_CCtx_setParameter(z->cctx, ZSTD_c_windowLog,
                                                (int) tuning->window_bits)))
        {
            return NGX_ERROR;
        }

    } else {
        ZSTD_compressionParameters  cp;

        cp = ZSTD_getCParams((int) tuning->level, 0, 0);

        if (cp.windowLog > NGX_HTTP_COMPRESSION_ZSTD_BROWSER_WLOG) {
            if (ZSTD_isError(ZSTD_CCtx_setParameter(z->cctx,
                                 ZSTD_c_windowLog,
                                 NGX_HTTP_COMPRESSION_ZSTD_BROWSER_WLOG)))
            {
                return NGX_ERROR;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "compression: zstd window capped to browser "
                           "limit (level default %ui exceeds it)",
                           (ngx_uint_t) cp.windowLog);
        }
    }

    *bctx = z;
    return NGX_OK;
}


static ngx_int_t
ngx_http_compression_zstd_hint_input_size(void *bctx, off_t bytes)
{
    ngx_http_compression_zstd_ctx_t  *z = bctx;

    /*
     * Negative sizes never reach the wire as a pledge (CodeRabbit,
     * round 5): the unsigned cast would turn them into a huge value —
     * exactly -1 happens to alias ZSTD_CONTENTSIZE_UNKNOWN, but any
     * other negative becomes a real pledge the stream cannot honour,
     * and ZSTD_compressStream2 then fails at ZSTD_e_end ("Src size is
     * incorrect") after the response is already on the wire. Declining
     * the hint keeps the frame unpledged, which is the no-hint default.
     */
    if (bytes < 0) {
        return NGX_OK;
    }

    if (ZSTD_isError(ZSTD_CCtx_setPledgedSrcSize(z->cctx,
                                                 (unsigned long long) bytes)))
    {
        return NGX_ERROR;
    }
    return NGX_OK;
}


static ngx_int_t
ngx_http_compression_zstd_attach_dictionary(void *bctx, ngx_str_t *raw)
{
    ngx_http_compression_zstd_ctx_t  *z = bctx;

    /*
     * Content checksum on dictionary-compressed frames (parent repo
     * #102, defence in depth): a client decoding against the WRONG
     * dictionary bytes can otherwise succeed silently with corrupt
     * output — the checksum converts that into a visible decode
     * error for ~4 bytes per response. Set here rather than at
     * create() so plain-zstd responses keep the parent module's
     * bare-frame behavior — and set BEFORE refPrefix (CodeRabbit,
     * round 5): prefix attachment snapshots the active parameters, so
     * every parameter write belongs ahead of it rather than leaning on
     * current libzstd tolerance.
     */
    if (ZSTD_isError(ZSTD_CCtx_setParameter(z->cctx, ZSTD_c_checksumFlag,
                                            1)))
    {
        return NGX_ERROR;
    }

    /*
     * Zero-copy: the CCtx references the raw bytes in place for the
     * whole stream — the reason the interface contract makes the
     * caller keep `raw` alive for the request.
     */
    if (ZSTD_isError(ZSTD_CCtx_refPrefix(z->cctx, raw->data, raw->len))) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ssize_t
ngx_http_compression_zstd_wire_prologue(void *bctx,
    const u_char *dict_sha256, u_char *out, size_t out_len)
{
    (void) bctx;

    /*
     * RFC 9842 §2.2: dcz opens with a 40-byte zstd SKIPPABLE frame —
     * magic 0x184D2A5E and the 32-byte content size, both little-
     * endian, then the dictionary's SHA-256. A zstd decoder skips it
     * natively (which is why the phase-0 contract text got away with
     * calling dcz "a plain frame" for as long as it did); libzstd
     * will not emit it.
     */
    if (out_len < 40) {
        return NGX_ERROR;
    }

    out[0] = 0x5e; out[1] = 0x2a; out[2] = 0x4d; out[3] = 0x18;
    out[4] = 0x20; out[5] = 0x00; out[6] = 0x00; out[7] = 0x00;
    ngx_memcpy(out + 8, dict_sha256, 32);

    return 40;
}


static ngx_int_t
ngx_http_compression_zstd_process(void *bctx, ngx_http_compression_io_t *io,
    ngx_http_compression_op_e op)
{
    size_t                            rem;
    ZSTD_inBuffer                     zin;
    ZSTD_outBuffer                    zout;
    ZSTD_EndDirective                 ed;
    ngx_http_compression_zstd_ctx_t  *z = bctx;

    zin.src = io->in;
    zin.size = io->in_len;
    zin.pos = 0;

    zout.dst = io->out;
    zout.size = io->out_len;
    zout.pos = 0;

    switch (op) {
    case NGX_HTTP_COMPRESSION_OP_FINISH: ed = ZSTD_e_end;      break;
    case NGX_HTTP_COMPRESSION_OP_FLUSH:  ed = ZSTD_e_flush;    break;
    default:                             ed = ZSTD_e_continue; break;
    }

    rem = ZSTD_compressStream2(z->cctx, &zout, &zin, ed);

    if (ZSTD_isError(rem)) {
        ngx_log_error(NGX_LOG_ERR, z->r->connection->log, 0,
                      "compression: ZSTD_compressStream2() failed: %s",
                      ZSTD_getErrorName(rem));
        return NGX_ERROR;
    }

    io->in_consumed = zin.pos;
    io->out_produced = zout.pos;

    if (ed == ZSTD_e_continue) {
        /* PROCESS: zstd buffers internally; consumed == done */
        io->done = (zin.pos == zin.size);
    } else {
        /* FLUSH / FINISH: rem is the bytes still to be flushed */
        io->done = (rem == 0);
    }

    return NGX_OK;
}


static size_t
ngx_http_compression_zstd_out_size(off_t content_length)
{
    (void) content_length;
    return ZSTD_CStreamOutSize();
}


static ngx_http_compression_backend_t  ngx_http_compression_zstd_backend = {
    ngx_string("zstd"),
    ngx_string("dcz"),
    NGX_HTTP_COMPRESSION_ZSTD_LEVEL_MIN,
    NGX_HTTP_COMPRESSION_ZSTD_LEVEL_MAX,
    3,      /* parent zstd_comp_level merge default */
    10,     /* ZSTD_WINDOWLOG_MIN */
    27,     /* ZSTD_WINDOWLOG_LIMIT_DEFAULT: past this, decoders demand
             * explicit opt-in — a serving ceiling has no business
             * beyond it */
    0,      /* unset: the level's own window default */
    ngx_http_compression_zstd_create,
    ngx_http_compression_zstd_hint_input_size,
    ngx_http_compression_zstd_attach_dictionary,
    ngx_http_compression_zstd_wire_prologue,
    ngx_http_compression_zstd_process,
    ngx_http_compression_zstd_out_size,
};

ngx_http_compression_backend_t  *ngx_http_compression_backend_zstd =
    &ngx_http_compression_zstd_backend;


/*
 * Runtime libzstd feature-floor check (parent #284; policy function
 * shared verbatim from ../src/ngx_http_zstd_version.h). This module
 * has no target-cblock-size directive, so that refusal arm is
 * structurally absent — the arguments say so explicitly.
 */
ngx_int_t
ngx_http_compression_zstd_verify_runtime(ngx_cycle_t *cycle,
    ngx_flag_t any_negative_level)
{
    unsigned                         runtime;
    ngx_http_zstd_version_result_t   policy;

    runtime = ZSTD_versionNumber();

    policy = ngx_http_zstd_version_policy(ZSTD_VERSION_NUMBER, runtime,
                                          0 /* no target-cblock knob */,
                                          any_negative_level != 0);
    if (policy == NGX_HTTP_ZSTD_VERSION_OK) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                  "compression module was built with libzstd %ui but "
                  "loaded libzstd %ui at runtime",
                  (ngx_uint_t) ZSTD_VERSION_NUMBER, (ngx_uint_t) runtime);

    if (policy == NGX_HTTP_ZSTD_VERSION_REFUSE_NEGATIVE_LEVEL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "a configured negative zstd \"compression_level\" "
                      "requires runtime libzstd 1.4.0 or newer "
                      "(loaded %ui)", (ngx_uint_t) runtime);
        return NGX_ERROR;
    }

    return NGX_OK;
}

#endif /* NGX_HTTP_COMPRESSION_HAVE_ZSTD */
