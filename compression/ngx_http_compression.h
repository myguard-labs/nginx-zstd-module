/*
 * nginx-compression — the unified compression module family
 * (RFC: nginx-zstd-module #109).
 *
 * THE BACKEND INTERFACE. Two backends (zstd, brotli) sit behind it
 * today; a new coding implements it in one translation unit and gets
 * the filter module's election, negotiation and buffer handling
 * without touching them. Every place the two libraries refused to be
 * shaped the same way is documented at the member that absorbs the
 * difference — those notes are the "wrinkles found", also collected
 * in WRINKLES.md.
 *
 * Deliberately NOT here: gzip. Per the RFC's "defer or veto, never
 * implement", gzip is an election TOKEN, not a backend — the election
 * either stands aside for the core gzip filter (defer: decline without
 * touching the r->gzip_tested latch) or shuts it off (veto: latch).
 * The interface proves itself partly by gzip never needing a slot.
 */

#ifndef NGX_HTTP_COMPRESSION_H
#define NGX_HTTP_COMPRESSION_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

/*
 * Requires nginx >= 1.23.0 (May 2022): the list-linked header change
 * (ngx_table_elt_t.next) this module relies on when pushing
 * Content-Encoding and Vary.
 */
#if (nginx_version < 1023000)
#error "nginx-compression requires nginx >= 1.23.0 (ngx_table_elt_t.next)"
#endif


/*
 * One streaming step. The caller owns both buffers; the backend
 * reports how much of each it used. A step never fails "partially":
 * on NGX_ERROR the stream is dead and the caller unhooks.
 */
typedef struct {
    const u_char  *in;            /* remaining input (may be NULL/0)   */
    size_t         in_len;
    u_char        *out;           /* output space for this step        */
    size_t         out_len;

    size_t         in_consumed;   /* OUT: bytes of `in` eaten          */
    size_t         out_produced;  /* OUT: bytes written to `out`       */

    /*
     * OUT: "this operation needs no further steps." The meaning is
     * op-relative, and pinning it down was the first real wrinkle —
     * the two libraries report completion through different channels
     * and the interface must define done per-op, not globally:
     *
     *   PROCESS: all input consumed AND the encoder is not sitting on
     *            ready output (brotli can hold output while zstd
     *            buffers input silently; both map, via different
     *            probes: zstd "input consumed", brotli additionally
     *            BrotliEncoderHasMoreOutput()).
     *   FLUSH:   everything buffered so far is in `out` bytes the
     *            caller has seen (zstd: compressStream2 returned 0;
     *            brotli: !HasMoreOutput && input drained).
     *   FINISH:  the stream's final byte is emitted (zstd: returned 0;
     *            brotli: BrotliEncoderIsFinished()).
     *
     * done == 0 after a step means: give me a fresh `out` and call
     * again with the SAME op and the unconsumed remainder.
     */
    unsigned       done:1;
} ngx_http_compression_io_t;


typedef enum {
    NGX_HTTP_COMPRESSION_OP_PROCESS = 0,  /* more input will follow    */
    NGX_HTTP_COMPRESSION_OP_FLUSH,        /* make output decodable now */
    NGX_HTTP_COMPRESSION_OP_FINISH        /* end of stream             */
} ngx_http_compression_op_e;


/*
 * Backend availability. The config script (or -D on the compiler
 * line) sets these to 0 when a library is absent; unset means
 * present, so the current always-both build glue keeps working
 * unchanged. Each backend translation unit compiles to nothing under
 * its 0 — the
 * registry stays DENSE (no holes), which is what lets everything
 * downstream index by registry position.
 *
 * The zero-backend build is deliberately legal: static sidecar
 * serving is file serving and needs no compression library for ANY
 * coding (the .zst window probe reads format constants, not the
 * libzstd API), so a lib-less build still subsumes gzip_static and
 * serves .zst/.br sidecars byte-exact. Only the dynamic filter needs
 * the libraries.
 */
#ifndef NGX_HTTP_COMPRESSION_HAVE_ZSTD
#define NGX_HTTP_COMPRESSION_HAVE_ZSTD    1
#endif

#ifndef NGX_HTTP_COMPRESSION_HAVE_BROTLI
#define NGX_HTTP_COMPRESSION_HAVE_BROTLI  1
#endif

/*
 * Compile-time backend count — derived, never hand-set. The registry
 * is a fixed array (plus the NULL terminator) and the conf's
 * per-coding tuning slots are sized by it; a new backend adds its
 * HAVE term here along with its registry entry.
 */
#define NGX_HTTP_COMPRESSION_NBACKENDS                                       \
    (NGX_HTTP_COMPRESSION_HAVE_ZSTD + NGX_HTTP_COMPRESSION_HAVE_BROTLI)

/* zero-length arrays are not C; the zero-backend build keeps one
 * (never-indexed) conf slot */
#if (NGX_HTTP_COMPRESSION_NBACKENDS > 0)
#define NGX_HTTP_COMPRESSION_CONF_SLOTS  NGX_HTTP_COMPRESSION_NBACKENDS
#else
#define NGX_HTTP_COMPRESSION_CONF_SLOTS  1
#endif

/* the longest wire prologue any backend emits (dcz: 40 bytes, dcb: 36) */
#define NGX_HTTP_COMPRESSION_PROLOGUE_MAX  40


/*
 * Resolved per-request tuning, passed to create(). The values
 * are always concrete by the time a backend sees them — conf merge
 * fills unset slots from the backend's declared defaults — so a
 * backend never re-implements defaulting. window_bits is log2 of the
 * window size; 0 means "leave the library's own default untouched"
 * (only zstd uses that meaning: its window is a per-request memory
 * ceiling the operator may simply not set).
 */
typedef struct {
    ngx_int_t  level;
    ngx_int_t  window_bits;
} ngx_http_compression_tuning_t;


typedef struct ngx_http_compression_backend_s  ngx_http_compression_backend_t;

struct ngx_http_compression_backend_s {

    /*
     * The content-coding: election-order token, Accept-Encoding token
     * and Content-Encoding value, all one string ("zstd", "br").
     */
    ngx_str_t    coding;

    /*
     * RFC 9842 dictionary variant of the coding ("dcz", "dcb"), or
     * empty when the backend has none. Negotiation
     * (Available-Dictionary) happens in the filter module against the
     * shared store; the backend only ever sees raw bytes.
     *
     * BOTH dictionary codings carry a wire prologue the compression
     * library does not emit, which the backend supplies through the
     * wire_prologue hook below:
     *
     *   dcz: a 40-byte zstd SKIPPABLE frame (magic 0x184D2A5E, size
     *        0x20, then the dictionary's SHA-256) which a zstd decoder
     *        skips natively;
     *   dcb: 36 raw bytes (0xFF 'D' 'C' 'B' + SHA-256) the brotli
     *        decoder does NOT consume.
     *
     * Same shape — magic plus hash — but different framing and
     * different consumer obligations, which is why the prologue is a
     * per-backend hook rather than filter-module code.
     */
    ngx_str_t    dict_coding;

    /*
     * Declared tuning contract. Each backend owns its level
     * SCALE (zstd -131072..22 where 0 = library default, brotli
     * quality 0..11) — the scales share no axis, which is why there
     * is no single unified level VALUE. The keyed directives
     * (`compression_level <coding> <n>`, `compression_window <coding>
     * <size>`) keep per-coding values behind one name and validate
     * against these bounds at config load, so a new backend gets its
     * directives for free with its registry entry. The dict variant
     * shares the base coding's tuning (a prepared brotli dictionary
     * bakes in the quality — one more reason there is no separate
     * dcz/dcb knob).
     */
    ngx_int_t    level_min;
    ngx_int_t    level_max;
    ngx_int_t    level_default;
    ngx_int_t    window_bits_min;       /* log2 bounds for the window */
    ngx_int_t    window_bits_max;
    ngx_int_t    window_bits_default;   /* 0 = library default */

    /*
     * Level at or above which attaching a dictionary costs enough per
     * request to be named at configuration load (0 = never). Both
     * backends rebuild their match tables from the raw bytes on every
     * dictionary response, at a cost set by dictionary size and level
     * and independent of the body; below this level that cost is flat
     * in dictionary size, from it upward it climbs steeply. The
     * backend declares the level with the measurement behind it
     * (tools/dict_attach_cost_bench.sh), and the merge warns when a
     * location configures dictionaries at or above it.
     */
    ngx_int_t    dict_advisory_level;

    /*
     * Per-request lifecycle. INVARIANT (wrinkle #2, both libraries
     * force it): create → hint_input_size → attach_dictionary →
     * process. zstd's ZSTD_CCtx_refPrefix must precede the first
     * compress call and its parameters must already be final; brotli's
     * BrotliEncoderPrepareDictionary bakes in the QUALITY, so the
     * level cannot change after attach either. The filter module
     * enforces the order; backends may assume it.
     *
     * create() allocates the backend ctx from r->pool and registers
     * its own pool cleanup for the library handle — the filter module
     * never sees a raw encoder pointer and there is no destroy() slot
     * to forget to call on error paths.
     */
    ngx_int_t  (*create)(ngx_http_request_t *r,
                         const ngx_http_compression_tuning_t *tuning,
                         void **bctx);

    /*
     * Optional (NULL = skip): declared input size, when known, before
     * the first byte. Exists because brotli's SIZE_HINT measurably
     * improves ratio and must be set up front; zstd has
     * ZSTD_CCtx_setPledgedSrcSize with the same up-front constraint.
     * A backend without the concept just omits the hook (wrinkle #3:
     * the hook must be optional, not a required no-op, or every future
     * backend inherits dead code).
     */
    ngx_int_t  (*hint_input_size)(void *bctx, off_t bytes);

    /*
     * Attach one RAW (unstructured) dictionary. `raw` must outlive
     * the request —
     * zstd references the bytes in place (refPrefix, zero copy);
     * brotli builds a prepared form and could drop them, but the
     * contract is written for the cheapest backend to keep the store's
     * "raw bytes live in the cycle pool" ownership model load-bearing.
     */
    ngx_int_t  (*attach_dictionary)(void *bctx, ngx_str_t *raw);

    /*
     * Wire prologue BEFORE the first encoder byte, from the elected
     * dictionary's SHA-256 (see dict_coding above for both shapes).
     * Emission stays per-backend: dcz's prologue is a VALID ZSTD
     * SKIPPABLE FRAME whose layout is zstd format knowledge, dcb's is
     * raw out-of-band bytes the decoder never sees; a filter-module
     * emitter would need per-backend format descriptors, which is
     * this hook wearing a struct costume.
     *
     * The prologue is mandatory on the wire, so NULL means the
     * dictionary coding is NOT SERVABLE: the election gates dict
     * codings on `wire_prologue != NULL`, never on `dict_coding.len`
     * alone.
     *
     * A pure function of the hash: the filter module calls it ONCE per
     * dictionary and backend at configuration load, with bctx NULL,
     * and stores the bytes on the dictionary entry; the election then
     * copies them instead of calling the hook per request. Emits at
     * most NGX_HTTP_COMPRESSION_PROLOGUE_MAX bytes.
     *
     * Returns the number of bytes written into `out` (bounded by
     * out_len), or NGX_ERROR.
     */
    ssize_t    (*wire_prologue)(void *bctx, const u_char *dict_sha256,
                                u_char *out, size_t out_len);

    /*
     * The streaming step. See ngx_http_compression_io_t for the
     * per-op `done` contract.
     */
    ngx_int_t  (*process)(void *bctx, ngx_http_compression_io_t *io,
                          ngx_http_compression_op_e op);

    /*
     * Recommended output-buffer size for one step. The two libraries
     * answer a different question here (wrinkle #4): zstd has a fixed
     * stream-chunk recommendation (ZSTD_CStreamOutSize()), brotli
     * only offers a whole-input bound (BrotliEncoderMaxCompressedSize)
     * that needs a length we may not have. So the contract is the
     * modest one both can honour: "a size at which repeated steps make
     * progress without pathological ping-ponging"; content_length may
     * be -1.
     */
    size_t     (*out_size)(off_t content_length);
};


/*
 * Registry: compiled-in backends, NULL-terminated. The extensibility
 * contract from the RFC in its smallest form — a new coding is one
 * translation unit exporting one of these, a registry entry, an
 * NGX_HTTP_COMPRESSION_HAVE_* availability macro, and that macro's
 * term in NGX_HTTP_COMPRESSION_NBACKENDS (which also sizes the conf's
 * tuning slots).
 */
extern ngx_http_compression_backend_t
    *ngx_http_compression_backends[NGX_HTTP_COMPRESSION_NBACKENDS + 1];

#if (NGX_HTTP_COMPRESSION_HAVE_ZSTD)
/*
 * Runtime libzstd feature-floor check (parent #284), called from the
 * filter's init_module hook. Lives in the zstd backend so the filter
 * module stays library-clean: warns on build-vs-runtime version skew,
 * returns NGX_ERROR only when a configured negative level needs an API
 * floor the loaded library predates. The policy is the parent's
 * ../src/ngx_http_zstd_version.h verbatim.
 */
ngx_int_t ngx_http_compression_zstd_verify_runtime(ngx_cycle_t *cycle,
    ngx_flag_t any_negative_level);
#endif


/*
 * One election-order entry. backend == NULL is the gzip token: on the
 * FILTER side gzip is never implemented (defer/veto); on the STATIC
 * side gzip is fully first-class — serving a precompressed .gz is file
 * serving and needs no zlib library (how the unified static subsumes
 * gzip_static for free, gzip-less builds included).
 */
typedef struct {
    ngx_http_compression_backend_t  *backend;
} ngx_http_compression_token_t;


/*
 * The FILTER module's location configuration. The static module is
 * its own ngx_module_t with its own private conf in
 * ngx_http_compression_static.c (the static .so must stay
 * dependency-free, and the pair replaces modules that ship split).
 */
typedef struct {
    ngx_flag_t     enable;
    ssize_t        min_length;
    ssize_t        max_length;    /* NGX_CONF_UNSET = no ceiling */
    ngx_uint_t     http_version;  /* minimum protocol version, default
                                   * 1.1 (gzip_http_version parity):
                                   * HTTP/1.0 requests DEFER to core
                                   * gzip — RFC 1945-era clients are
                                   * gzip-at-best, and 1.0 often means
                                   * an ancient intermediary */
    ngx_hash_t     types;
    ngx_array_t   *types_keys;
    ngx_array_t   *order;          /* of ngx_http_compression_token_t */

    /*
     * Per-coding tuning, indexed by registry position. Merged
     * against the backend's declared defaults, so by election time
     * every slot is concrete (see ngx_http_compression_tuning_t).
     */
    ngx_int_t      levels[NGX_HTTP_COMPRESSION_CONF_SLOTS];
    ngx_int_t      window_bits[NGX_HTTP_COMPRESSION_CONF_SLOTS];

    /*
     * This level's active dictionaries — pointers into the
     * cycle-global store (see ngx_http_compression_dict.h).
     * NULL = inherit.
     */
    ngx_array_t   *dicts;          /* of ngx_http_compression_dict_t * */

    /*
     * RFC 9842 §8 secure-context escape hatch (parent #158), applied to
     * every dictionary coding: a dictionary-compressed
     * response is only offered on a secure context, because over
     * cleartext it hands a network attacker a length oracle over content
     * the dictionary already describes. The context is secure when this
     * nginx terminates TLS (r->connection->ssl != NULL); off by default.
     * `compression_dict_assume_secure_transport on` asserts that a
     * TLS-terminating proxy in front made the hop the client actually
     * spoke secure — an operator acknowledgement, NEVER inferred from
     * X-Forwarded-Proto or any sibling, which a client can set on a
     * directly reachable listener to re-enable the coding over cleartext.
     */
    ngx_flag_t     dict_assume_secure;

    /*
     * Per-request bypass predicates (compression_bypass; the parents'
     * zstd_bypass / brotli_bypass semantics): any predicate variable
     * resolving non-empty and not "0" serves identity. bypass_vary is
     * the operator-named extra Vary field for header/cookie-driven
     * predicates, emitted on BOTH the bypassed identity response and
     * the compressed one; responses that leave the header filter
     * earlier (module off, subrequests, already-encoded, no-transform)
     * never carry it. One unified-module delta from the parents: a
     * bypass VETOES the gzip token too (latches core gzip off) — here
     * gzip is part of the stack, and a bypass that silently fell
     * through to core gzip would defeat the operator's intent.
     */
    ngx_array_t   *bypass;         /* of ngx_http_complex_value_t */
    ngx_str_t      bypass_vary;

    /*
     * Output-buffer pool geometry. num caps how many output
     * bufs a request may hold in flight (the recycling backstop
     * against a slow client + fast upstream); size 0 means "the
     * backend's recommended step size" — an explicit size overrides
     * the recommendation, and the dict-prologue clamp applies to
     * either source.
     */
    ngx_bufs_t     bufs;

    /*
     * Acknowledgement (parent #167) for an aggregate compression_buffers
     * number*size above the hard cap. Mirrors the RFC's "say it in words"
     * posture: an output-chain pool this large per response is refused at
     * config load unless the operator writes
     * compression_buffers_unsafe on. Only consulted when an EXPLICIT size
     * makes the product knowable — size 0 (backend-recommended) resolves
     * small at runtime and is never bounded here.
     */
    ngx_flag_t     bufs_unsafe;
} ngx_http_compression_conf_t;


extern ngx_module_t  ngx_http_compression_filter_module;

/* the vary/ae_header helpers live in ngx_http_compression_ae.h as
 * header-statics: each module of the split pair carries its own copy,
 * so neither .so links symbols from the other */


#endif /* NGX_HTTP_COMPRESSION_H */
