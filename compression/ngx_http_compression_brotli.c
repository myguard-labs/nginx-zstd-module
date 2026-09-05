/*
 * brotli backend for nginx-compression (phase-0 prototype).
 * The second implementation — the one that stress-tested the vtable.
 * Every divergence from zstd's shape is noted at the hook that absorbs
 * it; the interface survived without brotli-specific slots.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_compression.h"

#if (NGX_HTTP_COMPRESSION_HAVE_BROTLI)

#include <brotli/encode.h>

/* Guarded like the brotli fork's twin: __has_include predates nothing
 * on gcc/clang but only exists on MSVC from VS2017 15.3 -- an older
 * compiler must select DICT 0, not fail at preprocessing. */
#if defined(__has_include)
#if __has_include(<brotli/shared_dictionary.h>)
#include <brotli/shared_dictionary.h>
#define NGX_HTTP_COMPRESSION_BROTLI_DICT  1
#endif
#endif
#ifndef NGX_HTTP_COMPRESSION_BROTLI_DICT
#define NGX_HTTP_COMPRESSION_BROTLI_DICT  0
#endif


typedef struct {
    BrotliEncoderState            *enc;
#if (NGX_HTTP_COMPRESSION_BROTLI_DICT)
    BrotliEncoderPreparedDictionary  *prepared;
#endif
    ngx_http_request_t            *r;
    ngx_int_t                      level;   /* kept for attach: prepared
                                             * dictionaries bake in the
                                             * quality (interface
                                             * ordering invariant) */
} ngx_http_compression_brotli_ctx_t;


static void
ngx_http_compression_brotli_cleanup(void *data)
{
    ngx_http_compression_brotli_ctx_t  *b = data;

    if (b->enc != NULL) {
        BrotliEncoderDestroyInstance(b->enc);
        b->enc = NULL;
    }
#if (NGX_HTTP_COMPRESSION_BROTLI_DICT)
    if (b->prepared != NULL) {
        BrotliEncoderDestroyPreparedDictionary(b->prepared);
        b->prepared = NULL;
    }
#endif
}


static ngx_int_t
ngx_http_compression_brotli_create(ngx_http_request_t *r,
    const ngx_http_compression_tuning_t *tuning, void **bctx)
{
    ngx_pool_cleanup_t                 *cln;
    ngx_http_compression_brotli_ctx_t  *b;

    cln = ngx_pool_cleanup_add(r->pool,
                               sizeof(ngx_http_compression_brotli_ctx_t));
    if (cln == NULL) {
        return NGX_ERROR;
    }

    b = cln->data;
    ngx_memzero(b, sizeof(*b));
    b->r = r;
    b->level = tuning->level;

    b->enc = BrotliEncoderCreateInstance(NULL, NULL, NULL);
    if (b->enc == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_http_compression_brotli_cleanup;

    if (!BrotliEncoderSetParameter(b->enc, BROTLI_PARAM_QUALITY,
                                   (uint32_t) tuning->level))
    {
        return NGX_ERROR;
    }

    /* lg_win is always concrete here (declared default 19 = 512k,
     * ngx_brotli's brotli_window default) */
    if (!BrotliEncoderSetParameter(b->enc, BROTLI_PARAM_LGWIN,
                                   (uint32_t) tuning->window_bits))
    {
        return NGX_ERROR;
    }

    *bctx = b;
    return NGX_OK;
}


static ngx_int_t
ngx_http_compression_brotli_hint_input_size(void *bctx, off_t bytes)
{
    ngx_http_compression_brotli_ctx_t  *b = bctx;

    /*
     * The hook exists because of THIS call: SIZE_HINT measurably
     * improves brotli's ratio and is only meaningful before the first
     * byte. (And its absence is what stamps oversized windows in other
     * encoders — the vite/128MB-window incident class.)
     */
    /* same negative-size decline as the zstd backend: a negative off_t
     * must not become a bogus uint32_t hint */
    if (bytes < 0) {
        return NGX_OK;
    }

    if (!BrotliEncoderSetParameter(b->enc, BROTLI_PARAM_SIZE_HINT,
                                   (uint32_t) ngx_min(bytes, 0xffffffff)))
    {
        return NGX_ERROR;
    }
    return NGX_OK;
}


static ngx_int_t
ngx_http_compression_brotli_attach_dictionary(void *bctx, ngx_str_t *raw)
{
#if (NGX_HTTP_COMPRESSION_BROTLI_DICT)
    ngx_http_compression_brotli_ctx_t  *b = bctx;

    /*
     * Unlike zstd's zero-copy refPrefix, brotli builds a PREPARED form
     * whose contents depend on the quality set at create() — the
     * interface's create→attach ordering invariant exists for this
     * line. Per-request preparation is the phase-0/1 model (the shared
     * store holds raw bytes only); a prepared-dictionary cache keyed
     * on (dict, quality) is a later optimization the interface leaves
     * room for without changing this hook's signature.
     */
    b->prepared = BrotliEncoderPrepareDictionary(
        BROTLI_SHARED_DICTIONARY_RAW, raw->len, raw->data,
        (int) b->level, NULL, NULL, NULL);
    if (b->prepared == NULL) {
        return NGX_ERROR;
    }

    if (!BrotliEncoderAttachPreparedDictionary(b->enc, b->prepared)) {
        return NGX_ERROR;
    }
    return NGX_OK;
#else
    (void) bctx;
    (void) raw;
    return NGX_ERROR;   /* libbrotli < 1.1: dcb unavailable */
#endif
}


#if (NGX_HTTP_COMPRESSION_BROTLI_DICT)
static ssize_t
ngx_http_compression_brotli_wire_prologue(void *bctx,
    const u_char *dict_sha256, u_char *out, size_t out_len)
{
    (void) bctx;

    /*
     * RFC 9842 §2.1: dcb opens with 36 raw bytes — the magic
     * 0xFF 'D' 'C' 'B' and the dictionary's SHA-256 — that the brotli
     * DECODER does not consume: a client must strip them before
     * feeding the stream to the decoder, unlike dcz's natively-skipped
     * frame. Same asymmetry the interface documents at dict_coding.
     */
    if (out_len < 36) {
        return NGX_ERROR;
    }

    out[0] = 0xff; out[1] = 0x44; out[2] = 0x43; out[3] = 0x42;
    ngx_memcpy(out + 4, dict_sha256, 32);

    return 36;
}
#endif


static ngx_int_t
ngx_http_compression_brotli_process(void *bctx,
    ngx_http_compression_io_t *io, ngx_http_compression_op_e op)
{
    size_t                              avail_in, avail_out;
    const uint8_t                      *next_in;
    uint8_t                            *next_out;
    BrotliEncoderOperation              bop;
    ngx_http_compression_brotli_ctx_t  *b = bctx;

    next_in = io->in;
    avail_in = io->in_len;
    next_out = io->out;
    avail_out = io->out_len;

    switch (op) {
    case NGX_HTTP_COMPRESSION_OP_FINISH: bop = BROTLI_OPERATION_FINISH; break;
    case NGX_HTTP_COMPRESSION_OP_FLUSH:  bop = BROTLI_OPERATION_FLUSH;  break;
    default:                             bop = BROTLI_OPERATION_PROCESS; break;
    }

    if (!BrotliEncoderCompressStream(b->enc, bop,
                                     &avail_in, &next_in,
                                     &avail_out, &next_out, NULL))
    {
        ngx_log_error(NGX_LOG_ERR, b->r->connection->log, 0,
                      "compression: BrotliEncoderCompressStream() failed");
        return NGX_ERROR;
    }

    io->in_consumed = io->in_len - avail_in;
    io->out_produced = io->out_len - avail_out;

    /*
     * Completion probes differ per op — the wrinkle that shaped the
     * io->done contract (see the header). brotli can sit on ready
     * output after PROCESS, which zstd never surfaces; folding
     * HasMoreOutput into done keeps the caller loop backend-agnostic.
     */
    switch (op) {
    case NGX_HTTP_COMPRESSION_OP_FINISH:
        /*
         * IsFinished() alone is correct against current libbrotli but
         * rests on the undocumented invariant that a finished encoder
         * never holds output; the HasMoreOutput() conjunct costs
         * nothing and makes all three branches read the same
         * (round-4 review).
         */
        io->done = (BrotliEncoderIsFinished(b->enc)
                    && !BrotliEncoderHasMoreOutput(b->enc)) ? 1 : 0;
        break;
    case NGX_HTTP_COMPRESSION_OP_FLUSH:
        io->done = (avail_in == 0
                    && !BrotliEncoderHasMoreOutput(b->enc)) ? 1 : 0;
        break;
    default:
        io->done = (avail_in == 0
                    && !BrotliEncoderHasMoreOutput(b->enc)) ? 1 : 0;
        break;
    }

    return NGX_OK;
}


static size_t
ngx_http_compression_brotli_out_size(off_t content_length)
{
    /*
     * brotli's only sizing API is a whole-input bound needing a length
     * we may not have (chunked upstreams); the contract asks only for
     * a progress-making step size, so cap the bound at a sane chunk.
     */
    if (content_length > 0 && content_length < 32768) {
        size_t  bound = BrotliEncoderMaxCompressedSize(
                                                (size_t) content_length);
        if (bound > 0) {
            return bound;
        }
    }
    return 32768;
}


static ngx_http_compression_backend_t  ngx_http_compression_brotli_backend = {
    ngx_string("br"),
    ngx_string("dcb"),
    BROTLI_MIN_QUALITY,
    BROTLI_MAX_QUALITY,
    6,      /* ngx_brotli's brotli_comp_level merge default — the
             * phase-0 shim said 5, a drift from the parent this
             * declaration corrects */
    BROTLI_MIN_WINDOW_BITS,
    BROTLI_MAX_WINDOW_BITS,
    19,     /* 512k, ngx_brotli's brotli_window default */
    ngx_http_compression_brotli_create,
    ngx_http_compression_brotli_hint_input_size,
    ngx_http_compression_brotli_attach_dictionary,
#if (NGX_HTTP_COMPRESSION_BROTLI_DICT)
    ngx_http_compression_brotli_wire_prologue,
#else
    NULL,   /* libbrotli < 1.1: no shared-dictionary encoder API, so
             * "dcb" stays unelectable — the readiness gate doing its
             * job for a capability hole rather than a missing emitter */
#endif
    ngx_http_compression_brotli_process,
    ngx_http_compression_brotli_out_size,
};

ngx_http_compression_backend_t  *ngx_http_compression_backend_brotli =
    &ngx_http_compression_brotli_backend;

#endif /* NGX_HTTP_COMPRESSION_HAVE_BROTLI */
