
/*
 * Copyright (C) Alex Zhang
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <zstd.h>

#include <limits.h>  /* INT_MAX — config-load bound on (int)-narrowed sizes */

#include "ngx_http_zstd_common.h"
#include "ngx_http_zstd_sha256.h"


/*
 * The ONLY sanctioned way to hash a dcz dictionary at config load: the
 * $zstd_dcz_dicts_hashed accounting is inseparable from the operation.
 * An increment sitting beside a call site counts that line running, not
 * a dictionary being hashed — a restored unconditional bare call in
 * front of the supplied-hash branch slid past the counter tests
 * untouched (review of #103, demonstrated on a planted build). The bare
 * identifier is poisoned below, so reintroducing a direct call is a
 * compile error rather than a silent under-count.
 */
static ngx_inline void
ngx_http_zstd_dcz_dict_hash(const u_char *data, size_t len,
    u_char digest[NGX_HTTP_ZSTD_SHA256_DIGEST_LEN], ngx_uint_t *hashed)
{
    ngx_http_zstd_sha256(data, len, digest);
    (*hashed)++;
}

#if defined(__GNUC__)
#pragma GCC poison ngx_http_zstd_sha256
#endif


#define NGX_HTTP_ZSTD_MAX_DICT_SIZE  (10 * 1024 * 1024)  /* 10 MB limit */

/*
 * RFC 9842 §2.2 dcz framing: an 8-byte zstd skippable-frame header
 * (magic 0x184D2A5E and frame-size 32, both little-endian on the wire)
 * followed by the 32-byte SHA-256 of the dictionary, prepended to an
 * ordinary zstd frame. Existing zstd decoders skip it by design, so
 * `zstd -d -D <dict>` decodes a dcz body as-is.
 */
#define NGX_HTTP_ZSTD_DCZ_HEADER_LEN  (8 + NGX_HTTP_ZSTD_SHA256_DIGEST_LEN)

/*
 * ngx_http_zstd_dcz_decode_digest()'s scratch/output buffer size. Must
 * stay >= 48: an Available-Dictionary byte-sequence up to the 44-char
 * length ceiling can carry unpadded base64 that decodes to 33 bytes
 * (one past NGX_HTTP_ZSTD_SHA256_DIGEST_LEN) before the post-decode
 * length check runs, so the destination buffer must have that headroom.
 */
#define NGX_HTTP_ZSTD_DCZ_DECODE_BUF_LEN  48

/*
 * RFC 9842 §2.2.2: a dcz client guarantees a decode window of at least
 * max(8 MB, 1.25 x dictionary size). Never exceeding 2^23 (8 MB) keeps
 * every emitted frame inside the guarantee for any dictionary size, so
 * the module does not need to reason about the 1.25x branch.
 */
#define NGX_HTTP_ZSTD_DCZ_MAX_WINDOW_LOG  23


typedef struct {
    ngx_str_t                    dict_file;
    /* explicit opt-in for the non-RFC-9842 dict mode; S1/RFC1 */
    ngx_flag_t                   dict_unsafe;

    /*
     * Load-time SHA-256 computations over dcz dictionaries in THIS
     * configuration ($zstd_dcz_dicts_hashed). Cycle-owned on purpose:
     * a process-global static is reset and incremented while parsing a
     * CANDIDATE config, so a rejected reload would leave the refused
     * config's count behind for respawned workers to report (review of
     * #103, reproduced live). Here a rejected cycle takes its count
     * down with its pool, and the variable handler reads the request's
     * active cycle's conf. pcalloc zeroes it — no reset hook needed.
     */
    ngx_uint_t                   dcz_dicts_hashed;

    /*
     * Locations where the gzip_vary-off warning was withheld because a
     * compression_vary module is loaded (see merge_loc_conf). Counted
     * per cycle for the same reason as above, and reported as one
     * summary warning from postconfiguration instead of per location.
     */
    ngx_uint_t                   vary_warn_suppressed;
} ngx_http_zstd_main_conf_t;


/*
 * One RFC 9842 dictionary, loaded at config parse. `bytes` is the raw
 * file content in cf->pool (worker-lifetime; old workers keep their
 * forked copy across a reload until they drain), referenced per request
 * via ZSTD_CCtx_refPrefix() — RFC 9842 type=raw semantics exactly. The
 * SHA-256 is the negotiation key: it is what a client's
 * Available-Dictionary header carries and what the dcz frame header
 * must embed.
 */
typedef struct {
    ngx_str_t                    file;    /* resolved path, for logs */
    ngx_str_t                    bytes;   /* raw dictionary contents */
    u_char                       hash[NGX_HTTP_ZSTD_SHA256_DIGEST_LEN];
} ngx_http_zstd_dcz_dict_t;


typedef struct {
    ngx_flag_t                   enable;
    ngx_int_t                    level;
    ssize_t                      min_length;
    ssize_t                      max_length;
    /* Issue #38: ZSTD_c_targetCBlockSize */
    ssize_t                      target_cblock_size;
    /* ZSTD_c_windowLog: bounds per-request memory */
    ngx_int_t                    window_log;
    /* ZSTD_c_enableLongDistanceMatching */
    ngx_flag_t                   long_mode;
    /* config-load assert: per-request CCtx memory budget */
    ssize_t                      max_cctx_memory;

    /* ngx_http_complex_value_t: per-request bypass */
    ngx_array_t                 *bypass;
    /* extra Vary field for header/cookie-driven bypass; see S1 */
    ngx_str_t                    bypass_vary;

    ngx_hash_t                   types;

    ngx_bufs_t                   bufs;

    ngx_array_t                 *types_keys;

    ZSTD_CDict                  *dict;

    ngx_array_t                 *dcz_dicts;  /* ngx_http_zstd_dcz_dict_t */
} ngx_http_zstd_loc_conf_t;


/* PR #49: Action state machine for compression lifecycle */
typedef enum {
    NGX_HTTP_ZSTD_FILTER_COMPRESS = 0,
    NGX_HTTP_ZSTD_FILTER_FLUSH    = 1,
    NGX_HTTP_ZSTD_FILTER_END      = 2,
} ngx_http_zstd_action_t;


typedef struct {
    ngx_chain_t                 *in;
    ngx_chain_t                 *free;
    ngx_chain_t                 *busy;
    ngx_chain_t                 *out;
    ngx_chain_t                **last_out;

    ngx_buf_t                   *in_buf;
    ngx_buf_t                   *out_buf;
    ngx_int_t                    bufs;

    ZSTD_inBuffer                buffer_in;
    ZSTD_outBuffer               buffer_out;

    ngx_http_request_t          *request;
    ZSTD_CCtx                   *cctx;

    /* dictionary negotiated for this response via Available-Dictionary;
     * NULL means plain zstd. Points into the loc conf's dcz_dicts array
     * (config-pool lifetime, outlives the request). */
    ngx_http_zstd_dcz_dict_t    *dcz_dict;

    size_t                       bytes_in;
    size_t                       bytes_out;

    /*
     * Original response body length captured in the header filter BEFORE
     * ngx_http_clear_content_length() wipes r->headers_out.content_length_n.
     * -1 when unknown (chunked/streaming). Used to pledge the source size to
     * libzstd in init_cctx for a more compact frame header; see P1.
     */
    off_t                        pledged_size;

    unsigned                     last:1;
    unsigned                     redo:1;
    unsigned                     flush:1;
    unsigned                     done:1;
    unsigned                     nomem:1;

    /* the 40-byte dcz frame header has been queued on the out chain.
     * Kept even though cctx_ready below now makes init single-shot: the
     * prefix must never be duplicated regardless of init bookkeeping. */
    unsigned                     dcz_header_sent:1;

    /*
     * First-body-data latch for init_cctx. This used to be inferred from
     * `ctx->buffer_in.src == NULL`, but buffer_in.src is data state, not
     * lifecycle state: add_data reloads it from every incoming buffer, and
     * a data-less carrier buffer (ngx_buf_special() — e.g. the sync bufs
     * the sub filter emits while a match candidate spans input buffers)
     * has pos == NULL, which re-armed the check. The next invocation then
     * re-ran ZSTD_CCtx_reset() mid-stream, silently discarding everything
     * libzstd had buffered but not yet flushed: the response still ended
     * in ONE well-formed frame (200 + valid zstd), just with the reset-
     * window content missing. Observed in production as truncated HTML on
     * sub_filter-rewritten pages fed by a small-buffer upstream (the
     * dcz_header_sent guard above was an earlier symptom of the same
     * re-run, without the data-loss diagnosis).
     */
    unsigned                     cctx_ready:1;

    /* PR #49: Action state machine (COMPRESS, FLUSH, or END) */
    ngx_http_zstd_action_t       action;
} ngx_http_zstd_ctx_t;


/*
 * zstd_comp_level cannot use NGX_CONF_UNSET as its "not configured"
 * marker: NGX_CONF_UNSET is -1, and -1 is itself a valid, documented
 * compression level (ZSTD_minCLevel()..-1, see README). With the shared
 * sentinel, "zstd_comp_level -1;" was indistinguishable from an absent
 * directive, so the merge below silently replaced it with the inherited
 * value or the default 3 -- and the duplicate-directive guard in
 * ngx_conf_zstd_set_num_slot_with_negatives() could never fire for it.
 * The value is out of band for every libzstd: ZSTD_minCLevel() is
 * -131072 at its most extreme, far above the type minimum. nginx defines
 * NGX_MAX_INT_T_VALUE but no signed minimum, so derive it.
 */
#define NGX_HTTP_ZSTD_LEVEL_UNSET  (-NGX_MAX_INT_T_VALUE - 1)


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt  ngx_http_next_body_filter;

static ngx_str_t  ngx_http_zstd_ratio = ngx_string("zstd_ratio");

/*
 * $zstd_dcz_dicts_hashed serves two audiences: operators checking that
 * supplied hashes actually took effect (the value is 0 when every
 * dictionary carried one), and the regression suite, which asserts
 * exactly that — the supplied-hash fast path is otherwise unobservable
 * from outside, since the branch fills dict->hash either way. The count
 * itself lives in ngx_http_zstd_main_conf_t (see there for why), fed by
 * ngx_http_zstd_dcz_dict_hash() (see there for why).
 */
static ngx_str_t  ngx_http_zstd_dcz_dicts_hashed_name =
    ngx_string("zstd_dcz_dicts_hashed");
static ngx_str_t  ngx_http_zstd_bytes_in = ngx_string("zstd_bytes_in");
static ngx_str_t  ngx_http_zstd_bytes_out = ngx_string("zstd_bytes_out");

/*
 * Sensible web-content defaults when zstd_types is omitted. Keep the
 * directive parser's post value as ngx_http_html_default_types below: an
 * explicitly configured zstd_types list retains nginx's long-standing
 * "text/html plus the configured types" behaviour.
 */
static ngx_str_t  ngx_http_zstd_default_types[] = {
    ngx_string("text/html"),
    ngx_string("text/plain"),
    ngx_string("text/css"),
    ngx_string("text/csv"),
    ngx_string("application/json"),
    ngx_string("application/x-ndjson"),
    ngx_string("application/json-seq"),
    ngx_string("application/javascript"),
    ngx_string("text/xml"),
    ngx_string("application/xml"),
    ngx_string("application/xml+rss"),
    ngx_string("text/javascript"),
    ngx_string("image/svg+xml"),
    ngx_string("application/atom+xml"),
    ngx_string("application/ld+json"),
    ngx_string("application/manifest+json"),
    ngx_string("application/problem+json"),
    ngx_string("application/rss+xml"),
    ngx_string("application/vnd.api+json"),
    ngx_string("application/xhtml+xml"),
    ngx_string("application/wasm"),
    ngx_string("text/wgsl"),
    ngx_null_string
};


static ngx_int_t ngx_http_zstd_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_zstd_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_zstd_filter_add_data(ngx_http_request_t *r,
    ngx_http_zstd_ctx_t *ctx);
static ngx_int_t ngx_http_zstd_filter_get_buf(ngx_http_request_t *r,
    ngx_http_zstd_ctx_t *ctx);
static ngx_int_t ngx_http_zstd_set_param(ngx_http_request_t *r,
    ZSTD_CCtx *cctx, ZSTD_cParameter param, int value, const char *name);
static ngx_int_t ngx_http_zstd_filter_init_cctx(ngx_http_request_t *r,
    ngx_http_zstd_ctx_t *ctx);
static ngx_int_t ngx_http_zstd_filter_compress(ngx_http_request_t *r,
    ngx_http_zstd_ctx_t *ctx);
static ngx_int_t ngx_http_zstd_filter_init(ngx_conf_t *cf);
static void * ngx_http_zstd_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_zstd_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_zstd_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_zstd_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_zstd_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_zstd_dcz_dicts_hashed_variable(
    ngx_http_request_t *r, ngx_http_variable_value_t *vv, uintptr_t data);
static ngx_int_t ngx_http_zstd_ratio_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *vv, uintptr_t data);
static ngx_int_t ngx_http_zstd_bytes_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *vv, uintptr_t data);
static char *ngx_http_zstd_comp_level(ngx_conf_t *cf, void *post, void *data);
static char *ngx_http_zstd_check_size_int_max(ngx_conf_t *cf, void *post,
    void *data);
static char *ngx_http_zstd_check_num_int_max(ngx_conf_t *cf, void *post,
    void *data);
static char *ngx_conf_zstd_set_num_slot_with_negatives(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static void ngx_http_zstd_cleanup_dict(void *data);
static void ngx_http_zstd_cleanup_cctx(void *data);
static void ngx_http_zstd_release_cctx(void *data);
static ngx_int_t ngx_http_zstd_acquire_cctx(ngx_http_request_t *r,
    ngx_http_zstd_ctx_t *ctx, ngx_http_zstd_loc_conf_t *zlcf);
static void ngx_http_zstd_exit_process(ngx_cycle_t *cycle);
static char *ngx_http_zstd_dcz_dict_file(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_table_elt_t *ngx_http_zstd_find_request_header(
    ngx_http_request_t *r, const char *name, size_t len, ngx_uint_t *count);
static ngx_http_zstd_dcz_dict_t *ngx_http_zstd_dcz_negotiate(
    ngx_http_request_t *r, ngx_http_zstd_loc_conf_t *zlcf);
static ngx_int_t ngx_http_zstd_filter_emit_dcz_header(ngx_http_request_t *r,
    ngx_http_zstd_ctx_t *ctx);


/*
 * Worker-lifetime CCtx cache.
 *
 * ZSTD_createCCtx() plus the first-use workspace allocation is 34-75% of the
 * per-response libzstd CPU on typical body sizes (measured, libzstd 1.5.7:
 * ~1.6us of 3.1us at level 6 / 8 KB; ~10.8us of 15.0us at level 6 / 64 KB).
 * Since ngx_http_zstd_filter_init_cctx() already does a full
 * ZSTD_reset_session_and_parameters() and re-applies every parameter on each
 * request, a context carried across requests is byte-for-byte equivalent on
 * the wire to a freshly created one -- the creation is pure overhead.
 *
 * Why this does NOT reintroduce the shared-context bug 774b4a5 fixed: that
 * commit's defect was a context shared between CONCURRENT requests (interleaved
 * compression state). Here the cache lends the context to exactly one
 * request at a time -- `busy` is set on loan and cleared by the request
 * pool's cleanup handler -- so any second concurrent claimant (a subrequest
 * compressing while the main request is mid-stream) transparently gets its
 * own per-request context instead. The per-request ownership model is
 * preserved; only the allocation is amortised.
 *
 * Why there is no runtime memory cap: ZSTD_sizeof_CCtx() does not shrink on
 * reset, so an unbounded cache would pin each worker's RSS at its
 * largest-ever footprint. The cache is therefore keyed on the COMPLETE set
 * of parameters that drive that workspace, and every one of them is fixed at
 * config load: zstd_comp_level, zstd_long and zstd_window_log.
 *
 * An earlier revision keyed on the level alone, on a measurement that said
 * windowLog did not move ZSTD_sizeof_CCtx() at a fixed level. That
 * measurement was taken with a known pledged source size, which clamps the
 * window to the input; it does not hold on this module's path, where the
 * body length is generally unknown to libzstd. Re-measured on libzstd 1.5.7
 * with a streaming, unknown-size compression at level 6:
 *
 *     zstd_long  zstd_window_log   ZSTD_sizeof_CCtx()
 *     off        (unset)                    5 498 401
 *     off        20                         4 449 825
 *     off        27                       137 618 977
 *     on         (unset)                  154 551 841
 *     on         20                         4 606 497
 *     on         27                       154 551 841
 *
 * So both zstd_long and zstd_window_log move the retained workspace by more
 * than thirty times at one level, and the growth is permanent: walking a
 * context through the 154 MB profile and back to the 4 MB one leaves
 * ZSTD_sizeof_CCtx() at 154 MB. Lending one worker context across locations
 * with differing profiles would raise the worker's floor to the largest
 * profile ever served and silently defeat a lower location's
 * zstd_max_cctx_memory budget, which is computed from exactly these three
 * values at config load.
 *
 * Keying on all three keeps the cached context's high-water mark equal to
 * the figure config load already vetted for that profile. A location whose
 * profile differs in any of the three does not reuse the cache; it takes the
 * per-request path, which is the pre-existing safe behaviour.
 */
static ZSTD_CCtx  *ngx_http_zstd_worker_cctx;
static ngx_int_t   ngx_http_zstd_worker_cctx_level;
static ngx_flag_t  ngx_http_zstd_worker_cctx_long_mode;
static ngx_int_t   ngx_http_zstd_worker_cctx_window_log;
static ngx_uint_t  ngx_http_zstd_worker_cctx_busy;


static ngx_conf_post_t  ngx_http_zstd_comp_level_bounds = {
    ngx_http_zstd_comp_level
};


/*
 * Config-load bound for the two directives whose parsed value is later
 * narrowed with an (int) cast before being handed to libzstd
 * (zstd_target_cblock_size -> ssize_t, zstd_window_log -> ngx_int_t).
 * On a 64-bit platform a configured value above INT_MAX would silently
 * truncate (and possibly wrap negative) in that cast, bypassing zstd's
 * own range check with a meaningless value. Reject it at config load
 * with a clear error instead of a confusing runtime failure. Separate
 * handlers because set_size_slot stores ssize_t and set_num_slot
 * stores ngx_int_t; both defer to the same INT_MAX comparison.
 */
static ngx_conf_post_t  ngx_http_zstd_check_size_int_max_post = {
    ngx_http_zstd_check_size_int_max
};

static ngx_conf_post_t  ngx_http_zstd_check_num_int_max_post = {
    ngx_http_zstd_check_num_int_max
};


static ngx_command_t  ngx_http_zstd_filter_commands[] = {

    { ngx_string("zstd"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
      |NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, enable),
      NULL },

    { ngx_string("zstd_comp_level"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_zstd_set_num_slot_with_negatives,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, level),
      &ngx_http_zstd_comp_level_bounds },

    { ngx_string("zstd_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, types_keys),
      &ngx_http_html_default_types[0] },

    { ngx_string("zstd_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, bufs),
      NULL },

    { ngx_string("zstd_min_length"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, min_length),
      NULL },

    { ngx_string("zstd_max_length"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, max_length),
      NULL },

    { ngx_string("zstd_target_cblock_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, target_cblock_size),
      &ngx_http_zstd_check_size_int_max_post },

    { ngx_string("zstd_window_log"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, window_log),
      &ngx_http_zstd_check_num_int_max_post },

    { ngx_string("zstd_long"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, long_mode),
      NULL },

    { ngx_string("zstd_max_cctx_memory"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, max_cctx_memory),
      NULL },

    { ngx_string("zstd_bypass"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_set_predicate_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, bypass),
      NULL },

    { ngx_string("zstd_bypass_vary"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, bypass_vary),
      NULL },

    { ngx_string("zstd_dict_file"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_zstd_main_conf_t, dict_file),
      NULL },

    { ngx_string("zstd_dict_file_unsafe"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_zstd_main_conf_t, dict_unsafe),
      NULL },

    { ngx_string("zstd_dcz_dict_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_zstd_dcz_dict_file,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_zstd_filter_module_ctx = {
    ngx_http_zstd_add_variables,            /* preconfiguration */
    ngx_http_zstd_filter_init,              /* postconfiguration */

    ngx_http_zstd_create_main_conf,         /* create main configuration */
    ngx_http_zstd_init_main_conf,           /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_zstd_create_loc_conf,          /* create location configuration */
    ngx_http_zstd_merge_loc_conf,           /* merge location configuration */
};


ngx_module_t  ngx_http_zstd_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_zstd_filter_module_ctx,       /* module context */
    ngx_http_zstd_filter_commands,          /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    ngx_http_zstd_exit_process,             /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_zstd_header_filter(ngx_http_request_t *r)
{
    ngx_table_elt_t           *h;
    ngx_http_zstd_loc_conf_t  *zlcf;
    ngx_http_zstd_ctx_t       *ctx;
    ngx_http_zstd_dcz_dict_t  *dcz;

    zlcf = ngx_http_get_module_loc_conf(r, ngx_http_zstd_filter_module);

    /*
     * Eligibility gate. This is the original single 9-term disjunction
     * split into one early return per reason: behaviour is identical
     * (|| short-circuits and every term led to the same next-filter
     * return), but each rejection cause is now individually visible and
     * greppable. Order is preserved so short-circuit semantics — e.g.
     * not dereferencing content_encoding before the cheaper checks — are
     * unchanged.
     */

    /* zstd disabled for this location */
    if (!zlcf->enable) {
        return ngx_http_next_header_filter(r);
    }

    /* status not eligible: < 200, bodyless 204/205, 206 Partial Content,
     * or any > 299 except 403/404 (which carry compressible error bodies).
     *
     * 206 is excluded (matching nginx's gzip filter): an upstream 206 has a
     * Content-Range computed against its selected representation. Applying a
     * new content coding here would invalidate that Content-Range (RFC 9110
     * §14.1.2 requires ranges for an encoded representation to be computed
     * against the encoded byte sequence), and the filter only clears
     * Accept-Ranges, not Content-Range. See RFC4. */
    if (r->headers_out.status < NGX_HTTP_OK
        || r->headers_out.status == NGX_HTTP_NO_CONTENT
        || r->headers_out.status == 205   /* 205 Reset Content: no core macro */
        || r->headers_out.status == NGX_HTTP_PARTIAL_CONTENT
        || (r->headers_out.status > 299
            && r->headers_out.status != NGX_HTTP_FORBIDDEN
            && r->headers_out.status != NGX_HTTP_NOT_FOUND))
    {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd: skip, status %ui not eligible",
                       r->headers_out.status);
        return ngx_http_next_header_filter(r);
    }

    /* already encoded (e.g. upstream gzip/br) — do not double-compress */
    if (r->headers_out.content_encoding
        && r->headers_out.content_encoding->value.len)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd: skip, already encoded as \"%V\"",
                       &r->headers_out.content_encoding->value);
        return ngx_http_next_header_filter(r);
    }

    /* known body smaller than zstd_min_length — not worth a frame */
    if (r->headers_out.content_length_n != -1
        && r->headers_out.content_length_n < zlcf->min_length)
    {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd: skip, body %O < zstd_min_length %z",
                       r->headers_out.content_length_n, zlcf->min_length);
        return ngx_http_next_header_filter(r);
    }

    /* known body larger than zstd_max_length cap */
    if (zlcf->max_length != NGX_CONF_UNSET
        && r->headers_out.content_length_n != -1
        && r->headers_out.content_length_n > zlcf->max_length)
    {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd: skip, body %O > zstd_max_length %O",
                       r->headers_out.content_length_n,
                       (off_t) zlcf->max_length);
        return ngx_http_next_header_filter(r);
    }

    /* content type not in zstd_types */
    if (ngx_http_test_content_type(r, &zlcf->types) == NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd: skip, content type \"%V\" not in zstd_types",
                       &r->headers_out.content_type);
        return ngx_http_next_header_filter(r);
    }

    /* header-only response: no body to compress */
    if (r->header_only) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd: skip, header-only response");
        return ngx_http_next_header_filter(r);
    }

    /*
     * Cache-correctness for request-header / cookie-driven bypass. When the
     * decision to compress varies on a request header (e.g.
     * "zstd_bypass $http_x_no_compression"), a shared cache must key on that
     * header or it will serve a stored identity response to a normal client
     * (or a compressed one to a bypass client). The module cannot infer which
     * header drove the predicate, so the operator names it via
     * zstd_bypass_vary; we append it to Vary on BOTH the bypassed identity
     * response and the compressed one (this runs before the bypass return
     * below). A second Vary header line is fine — caches union all Vary
     * fields. See S1.
     */
    if (zlcf->bypass_vary.len) {
        ngx_table_elt_t  *v;

        v = ngx_list_push(&r->headers_out.headers);
        if (v == NULL) {
            return NGX_ERROR;
        }

        v->hash = 1;
#if (nginx_version >= 1023000)
        v->next = NULL;
#endif
        ngx_str_set(&v->key, "Vary");
        v->value = zlcf->bypass_vary;
    }

    /*
     * Per-request bypass. If any zstd_bypass predicate variable resolves
     * to a non-empty value other than "0", skip compression for this
     * request. This is the operator lever for serving identity on
     * endpoints that must not be compressed — e.g. responses that mix a
     * secret (CSRF token, session data) with attacker-influenced
     * reflected input (a BREACH-style exposure), or already-compressed
     * dynamic payloads — without splitting the location.
     */
    if (zlcf->bypass != NULL
        && ngx_http_test_predicates(r, zlcf->bypass) != NGX_OK)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd: bypassed by zstd_bypass predicate");
        return ngx_http_next_header_filter(r);
    }

    r->gzip_vary = 1;

    /*
     * With dictionaries configured, WHICH encoding this location serves
     * depends on the request's Available-Dictionary header — the dcz
     * variant obviously, the plain zstd variant a dictionary-less client
     * receives, and equally the identity fallback: a client sending
     * "Accept-Encoding: dcz" (no zstd) with a hash we do not hold gets
     * identity NOW, but the same client holding a dictionary we DO hold
     * would get dcz — so a shared cache must key that identity variant
     * on Available-Dictionary too, or it can keep serving it after the
     * client acquires the dictionary (a silent compression loss). That
     * is why this push sits ABOVE the acceptance gate below rather than
     * next to the Content-Encoding push: every return before this point
     * declines for reasons invariant in Available-Dictionary; the two
     * paths after it are not invariant. Accept-Encoding itself is
     * already covered by gzip_vary above; caches union all Vary lines.
     */
    if (zlcf->dcz_dicts != NULL && zlcf->dcz_dicts->nelts > 0) {
        ngx_table_elt_t  *v;

        v = ngx_list_push(&r->headers_out.headers);
        if (v == NULL) {
            return NGX_ERROR;
        }

        v->hash = 1;
#if (nginx_version >= 1023000)
        v->next = NULL;
#endif
        ngx_str_set(&v->key, "Vary");
        ngx_str_set(&v->value, "Available-Dictionary");
    }

    /*
     * RFC 9842 dcz negotiation first: a client that advertises a
     * dictionary we hold (Available-Dictionary hash match) and accepts
     * the dcz coding gets dictionary compression; everything else falls
     * through to the plain zstd path unchanged.
     */
    dcz = ngx_http_zstd_dcz_negotiate(r, zlcf);

    if (dcz != NULL) {
        /*
         * Latch gzip off exactly as ngx_http_zstd_ok() does on the plain
         * path: the commitment to encode is made immediately below, so a
         * later gzip filter must not double-compress.
         */
        r->gzip_tested = 1;
        r->gzip_ok = 0;

    } else if (ngx_http_zstd_ok(r) != NGX_OK) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd: skip, client did not accept zstd encoding");
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_zstd_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_zstd_filter_module);

    ctx->request = r;
    ctx->last_out = &ctx->out;
    ctx->dcz_dict = dcz;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
#if (nginx_version >= 1023000)
    h->next = NULL;
#endif
    ngx_str_set(&h->key, "Content-Encoding");
    if (dcz != NULL) {
        ngx_str_set(&h->value, "dcz");
    } else {
        ngx_str_set(&h->value, "zstd");
    }
    r->headers_out.content_encoding = h;

    r->main_filter_need_in_memory = 1;

    /*
     * Capture the known body length before clearing it. ngx_http_clear_
     * content_length() sets content_length_n to -1, so the init_cctx pledge
     * (which runs after the first body data) would otherwise always see -1
     * and never call ZSTD_CCtx_setPledgedSrcSize(). -1 here means unknown.
     */
    ctx->pledged_size = r->headers_out.content_length_n;

    ngx_http_clear_content_length(r);
    ngx_http_clear_accept_ranges(r);
    ngx_http_weak_etag(r);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "zstd: compressing response (content-length %O)",
                   r->headers_out.content_length_n);

    return ngx_http_next_header_filter(r);
}


/*
 * Case-insensitive lookup of a request header nginx keeps no dedicated
 * headers_in slot for (Available-Dictionary, Sec-Fetch-Site). Plain list
 * walk — both headers appear at most once and only on dictionary-aware
 * requests, so a hashed lookup buys nothing here.
 */
/*
 * Find a request header by name. Neither header this is used for
 * (Available-Dictionary, Sec-Fetch-Site) appears in nginx's
 * ngx_http_headers_in table, so neither gets ngx_http_process_unique_
 * header_line's duplicate rejection: a request may legitimately reach a
 * module carrying two of them, and a plain first-match lookup would let
 * whichever line sorts first decide the outcome. Both are single-valued
 * by their specifications and a browser never sends either twice, so
 * `*count` reports how many occurrences exist and the dcz caller fails
 * closed on more than one -- for Sec-Fetch-Site that check is the RFC
 * 9842 SS8.3 cross-origin partitioning gate, and a proxy that merges or
 * forwards a client-supplied duplicate, or a request-smuggling desync,
 * must not be able to turn it off by prepending an agreeable value.
 */
static ngx_table_elt_t *
ngx_http_zstd_find_request_header(ngx_http_request_t *r, const char *name,
    size_t len, ngx_uint_t *count)
{
    ngx_uint_t              i;
    const ngx_list_part_t  *part;
    ngx_table_elt_t        *h, *found;

    part = &r->headers_in.headers.part;
    h = part->elts;
    found = NULL;
    *count = 0;

    for (i = 0; ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].key.len == len
            && ngx_strncasecmp(h[i].key.data, (u_char *) name, len) == 0)
        {
            (*count)++;

            if (found == NULL) {
                found = &h[i];
            }
        }
    }

    return found;
}


/*
 * RFC 9842 dcz negotiation. Returns the configured dictionary this
 * response must be compressed against, or NULL for the plain zstd path.
 * Every requirement is a hard gate — on any miss the response falls back
 * to ordinary content negotiation, never to a broken dcz:
 *
 *   - the location has zstd_dcz_dict_file dictionaries;
 *   - the request carries Available-Dictionary, a structured-field byte
 *     sequence (":base64:") decoding to exactly 32 bytes (the SHA-256 of
 *     the client's cached dictionary), and it matches one of ours;
 *   - Accept-Encoding lists dcz explicitly with q>0. The "*" wildcard
 *     deliberately does NOT match: only a client that actually holds the
 *     dictionary can decode dcz, so a blanket wildcard must not turn it
 *     on (see ngx_http_zstd_coding_weight);
 *   - Sec-Fetch-Site, when present, is "same-origin" or "none" (§8.3:
 *     dictionaries are same-origin-partitioned secrets; a cross-site
 *     response compressed against one leaks it). Browsers always send
 *     the header; its absence means a non-browser client, where the
 *     cross-origin read model does not apply.
 *
 * Dictionary-ID is intentionally not parsed: it only matters when the
 * operator sets id= in Use-As-Dictionary, and the hash alone is a
 * complete, collision-resistant key for the lookup below. (SHA-256 is
 * collision-RESISTANT, not collision-free -- the distinction does not
 * weaken the lookup, which indexes public dictionary identities, but the
 * stronger claim is not one SHA-256 makes.)
 */
/*
 * Decode an RFC 8941 byte-sequence Available-Dictionary header value
 * (":base64:") into a fixed-size digest buffer.
 *
 * Pulled out of ngx_http_zstd_dcz_negotiate() below as a pure function of
 * its inputs: no ngx_http_request_t, no connection log, no config
 * structures. That is deliberate -- it is the exact slice of the
 * negotiation logic that parses attacker-controlled bytes (the base64
 * length/prefix gate plus ngx_decode_base64() itself), and the
 * request/config entanglement in the caller is what previously made it
 * impossible to fuzz in isolation.
 *
 * `raw` is the full header value including the wrapping colons, exactly
 * as ngx_http_zstd_dcz_negotiate() receives it in h->value. `out` must
 * point at a buffer of at least NGX_HTTP_ZSTD_DCZ_DECODE_BUF_LEN (48)
 * bytes -- NOT just NGX_HTTP_ZSTD_SHA256_DIGEST_LEN (32) -- and receives
 * the decoded digest on success. The larger size is load-bearing: the
 * length gate below only bounds the base64 *text* to 44 characters, and
 * an unpadded 44-character input (no trailing "=") decodes to 33 bytes,
 * one past a tight 32-byte buffer, before the post-decode length check
 * ever runs. A caller-supplied buffer smaller than
 * NGX_HTTP_ZSTD_DCZ_DECODE_BUF_LEN reintroduces that overflow.
 *
 * Returns NGX_OK when raw is a well-formed byte-sequence decoding to
 * exactly NGX_HTTP_ZSTD_SHA256_DIGEST_LEN bytes (written to *out*),
 * NGX_DECLINED otherwise (malformed byte-sequence framing, or a decoded
 * length other than 32 bytes) -- *out* is left untouched on NGX_DECLINED.
 */
static ngx_int_t
ngx_http_zstd_dcz_decode_digest(ngx_str_t raw,
    u_char out[NGX_HTTP_ZSTD_DCZ_DECODE_BUF_LEN])
{
    ngx_str_t   b64, decoded;

    /*
     * RFC 8941 byte sequence: colon-delimited standard base64. 32 bytes
     * encode to 44 characters with padding (43 without); anything longer
     * cannot be a SHA-256 and is rejected before decoding.
     */
    if (raw.len < 2
        || raw.data[0] != ':'
        || raw.data[raw.len - 1] != ':'
        || raw.len - 2 > 44)
    {
        return NGX_DECLINED;
    }

    b64.data = raw.data + 1;
    b64.len = raw.len - 2;

    decoded.data = out;

    if (ngx_decode_base64(&decoded, &b64) != NGX_OK
        || decoded.len != NGX_HTTP_ZSTD_SHA256_DIGEST_LEN)
    {
        return NGX_DECLINED;
    }

    return NGX_OK;
}


static ngx_http_zstd_dcz_dict_t *
ngx_http_zstd_dcz_negotiate(ngx_http_request_t *r,
    ngx_http_zstd_loc_conf_t *zlcf)
{
    u_char                     buf[NGX_HTTP_ZSTD_DCZ_DECODE_BUF_LEN];
    ngx_uint_t                 i, nheaders;
    ngx_table_elt_t           *h, *ae;
    ngx_http_zstd_dcz_dict_t  *dicts;

    if (zlcf->dcz_dicts == NULL || zlcf->dcz_dicts->nelts == 0) {
        return NULL;
    }

    if (r != r->main) {
        return NULL;
    }

    /*
     * Accept-Encoding is in nginx's headers_in table, so duplicate lines
     * are chained on ae->next rather than rejected. Only the first line's
     * value is evaluated here -- byte-for-byte what nginx's own gzip
     * filter does, so this is upstream parity rather than a gap: a client
     * splitting its codings across two header lines has the second line
     * ignored and falls back to plain zstd, which is the safe direction.
     */
    ae = r->headers_in.accept_encoding;
    if (ae == NULL) {
        return NULL;
    }

    h = ngx_http_zstd_find_request_header(r, "available-dictionary",
                                          sizeof("available-dictionary") - 1,
                                          &nheaders);
    if (h == NULL) {
        return NULL;
    }

    if (nheaders > 1) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd dcz: skip, %ui Available-Dictionary headers",
                       nheaders);
        return NULL;
    }

    /*
     * RFC 8941 byte sequence: colon-delimited standard base64. 32 bytes
     * encode to 44 characters with padding (43 without); anything longer
     * cannot be a SHA-256 and is rejected before decoding. The framing
     * check and ngx_decode_base64() call live in
     * ngx_http_zstd_dcz_decode_digest() so that attacker-controlled-byte
     * slice can be fuzzed independently of ngx_http_request_t.
     */
    if (h->value.len < 2
        || h->value.data[0] != ':'
        || h->value.data[h->value.len - 1] != ':'
        || h->value.len - 2 > 44)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd dcz: malformed Available-Dictionary \"%V\"",
                       &h->value);
        return NULL;
    }

    if (ngx_http_zstd_dcz_decode_digest(h->value, buf) != NGX_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd dcz: Available-Dictionary \"%V\" is not a "
                       "base64 SHA-256", &h->value);
        return NULL;
    }

    h = ngx_http_zstd_find_request_header(r, "sec-fetch-site",
                                          sizeof("sec-fetch-site") - 1,
                                          &nheaders);

    /*
     * More than one Sec-Fetch-Site is never a browser and cannot be
     * evaluated: fail closed rather than trust the first line.
     */
    if (nheaders > 1) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd dcz: skip, %ui Sec-Fetch-Site headers",
                       nheaders);
        return NULL;
    }

    if (h != NULL
        && !(h->value.len == sizeof("same-origin") - 1
             && ngx_strncasecmp(h->value.data, (u_char *) "same-origin",
                                sizeof("same-origin") - 1) == 0)
        && !(h->value.len == sizeof("none") - 1
             && ngx_strncasecmp(h->value.data, (u_char *) "none",
                                sizeof("none") - 1) == 0))
    {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd dcz: skip, Sec-Fetch-Site \"%V\"", &h->value);
        return NULL;
    }

    if (ngx_http_zstd_coding_weight(&ae->value, "dcz",
                                    sizeof("dcz") - 1, 0) <= 0)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd dcz: skip, no explicit dcz in Accept-Encoding");
        return NULL;
    }

    dicts = zlcf->dcz_dicts->elts;

    for (i = 0; i < zlcf->dcz_dicts->nelts; i++) {
        if (ngx_memcmp(dicts[i].hash, buf,
                       NGX_HTTP_ZSTD_SHA256_DIGEST_LEN) == 0)
        {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "zstd dcz: dictionary \"%V\" negotiated",
                           &dicts[i].file);
            return &dicts[i];
        }
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "zstd dcz: skip, no configured dictionary matches "
                   "Available-Dictionary");
    return NULL;
}


static ngx_int_t
ngx_http_zstd_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                  flush, rc;
    ngx_chain_t               *cl;
    ngx_http_zstd_ctx_t       *ctx;
    ngx_http_zstd_loc_conf_t  *zlcf;


    ctx = ngx_http_get_module_ctx(r, ngx_http_zstd_filter_module);

    if (ctx == NULL || ctx->done || r->header_only) {
        return ngx_http_next_body_filter(r, in);
    }

    /*
     * Fetch the location conf once. It cannot change for the lifetime of
     * a request, so resolving it per inner-loop iteration (as the
     * zstd_max_length check below previously did) only adds module-index
     * indirection to the hottest path.
     */
    zlcf = ngx_http_get_module_loc_conf(r, ngx_http_zstd_filter_module);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http zstd filter");

    if (!ctx->cctx_ready) {
        /*
         * First call: configure the CCtx for this request. Latched by an
         * explicit flag — do NOT infer this from buffer_in.src == NULL;
         * see the cctx_ready comment in ngx_http_zstd_ctx_t.
         */
        if (ngx_http_zstd_filter_init_cctx(r, ctx) != NGX_OK) {
            goto failed;
        }

        /*
         * dcz responses start with the fixed 40-byte frame header (RFC
         * 9842 §2.2). Queue it ahead of any compressed output. The
         * dcz_header_sent guard predates cctx_ready (this block used to
         * re-run when a data-less buffer cleared buffer_in.src); it stays
         * as an independent invariant on the wire prefix.
         */
        if (ctx->dcz_dict != NULL && !ctx->dcz_header_sent) {
            if (ngx_http_zstd_filter_emit_dcz_header(r, ctx) != NGX_OK) {
                goto failed;
            }
        }

        ctx->cctx_ready = 1;
    }

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
            goto failed;
        }

        r->connection->buffered |= NGX_HTTP_GZIP_BUFFERED;
    }

    if (ctx->nomem) {

        /* flush busy buffers */

        if (ngx_http_next_body_filter(r, NULL) == NGX_ERROR) {
            goto failed;
        }

        cl = NULL;

        ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &cl,
                                (ngx_buf_tag_t) &ngx_http_zstd_filter_module);

        /*
         * Same reason as the invalidation after the other
         * ngx_chain_update_chains() below: the buffer ctx->out_buf points
         * at may have just been recycled onto the free chain. Reaching
         * here with a stale non-NULL out_buf is currently unreachable --
         * it would need get_buf's top guard to fail, which requires a
         * memzero'd buffer_out -- but that argument spans three functions
         * and a future edit should not have to re-derive it to stay safe.
         */
        ctx->out_buf = NULL;

        flush = 0;
        ctx->nomem = 0;

    } else {
        flush = ctx->busy ? 1 : 0;
    }

    for ( ;; ) {

        /* cycle while we can write to a client */

        for ( ;; ) {

            rc = ngx_http_zstd_filter_add_data(r, ctx);

            if (rc == NGX_DECLINED) {
                break;
            }

            if (rc == NGX_AGAIN) {
                continue;
            }

            /*
             * Length-independent input cap. The header filter rejects
             * responses whose advertised Content-Length exceeds
             * zstd_max_length, but that gate only sees the *declared* length:
             * a chunked/streaming response carries none, and a misbehaving
             * known-length upstream can stream more bytes than it declared.
             * Either way an abusive or runaway upstream could feed the
             * compressor unbounded input (worker CPU/memory exhaustion).
             * Enforce the limit against the running input total here,
             * regardless of whether a Content-Length was advertised.
             * Compression has already started and the client is receiving a
             * Content-Encoding: zstd stream, so the only safe action is to
             * fail the request — protecting the worker is preferred over
             * completing one runaway response.
             */
            if (zlcf->max_length != NGX_CONF_UNSET
                && (off_t) ctx->bytes_in > (off_t) zlcf->max_length)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "zstd: input exceeded zstd_max_length (%O) on a "
                              "response with no Content-Length; aborting to "
                              "protect the worker", (off_t) zlcf->max_length);
                goto failed;
            }

            rc = ngx_http_zstd_filter_get_buf(r, ctx);

            if (rc == NGX_ERROR) {
                goto failed;
            }

            if (rc == NGX_DECLINED) {
                break;
            }

            rc = ngx_http_zstd_filter_compress(r, ctx);

            if (rc == NGX_ERROR) {
                goto failed;
            }

            if (rc == NGX_OK) {
                break;
            }

            /* rc == NGX_AGAIN */
        }

        if (ctx->out == NULL && !flush) {
            return ctx->busy ? NGX_AGAIN : NGX_OK;
        }

        rc = ngx_http_next_body_filter(r, ctx->out);

        if (rc == NGX_ERROR) {
            goto failed;
        }

        ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &ctx->out,
                                (ngx_buf_tag_t) &ngx_http_zstd_filter_module);

        /* After chain update, buffers may have been recycled or reassigned.
         * Invalidate ctx->out_buf to force fresh buffer allocation/validation
         * on next compression iteration to prevent
         * use-after-free of recycled buffers. */
        ctx->out_buf = NULL;

        ctx->last_out = &ctx->out;
        ctx->nomem = 0;
        flush = 0;

        if (ctx->done) {
            return rc;
        }
    }

failed:

    ctx->done = 1;

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_zstd_filter_compress(ngx_http_request_t *r, ngx_http_zstd_ctx_t *ctx)
{
    size_t            zrc, pos_in, pos_out;  /* zrc: ZSTD_compressStream2
                                              * bytes-remaining hint, not an
                                              * NGX_* code */
    ngx_uint_t        last;
    ZSTD_EndDirective directive;
    ngx_chain_t      *cl;
    ngx_buf_t        *b;
    ZSTD_CCtx        *cctx;

    ngx_log_debug6(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "zstd compress in: src:%p pos:%uz size:%uz "
                   "dst:%p pos:%uz size:%uz",
                   ctx->buffer_in.src,  ctx->buffer_in.pos,
                   ctx->buffer_in.size,
                   ctx->buffer_out.dst, ctx->buffer_out.pos,
                   ctx->buffer_out.size);

    pos_in  = ctx->buffer_in.pos;
    pos_out = ctx->buffer_out.pos;

    /*
     * Determine the compression directive.
     *
     * END always wins (terminal frame). Otherwise a pending flush
     * (ctx->flush) must map to ZSTD_e_flush even while the action state
     * machine is still COMPRESS: that machine only transitions
     * COMPRESS->FLUSH *after* a call that returned rc > 0 (zstd already
     * had output to drain). Under `proxy_buffering off` the upstream
     * forces a flush around a chunk that zstd consumes/buffers
     * internally with rc == 0; if the directive stayed ZSTD_e_continue
     * there, libzstd is never told to flush and holds those bytes
     * indefinitely. Mapping ctx->flush -> ZSTD_e_flush forces libzstd
     * to disgorge whatever it has buffered, exactly as the stock nginx
     * gzip/brotli body filters issue a sync flush on a pending flush.
     */
    if (ctx->action == NGX_HTTP_ZSTD_FILTER_END) {
        directive = ZSTD_e_end;
    } else if (ctx->action == NGX_HTTP_ZSTD_FILTER_FLUSH || ctx->flush) {
        directive = ZSTD_e_flush;
    } else {
        directive = ZSTD_e_continue;
    }

    cctx = ctx->cctx;
    if (cctx == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "zstd: request CCtx not initialized");
        return NGX_ERROR;
    }

    zrc = ZSTD_compressStream2(cctx, &ctx->buffer_out, &ctx->buffer_in,
                               directive);

    if (ZSTD_isError(zrc)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "zstd: ZSTD_compressStream2() failed: %s",
                      ZSTD_getErrorName(zrc));
        return NGX_ERROR;
    }

    ngx_log_debug6(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "zstd compress out: src:%p pos:%uz size:%uz "
                   "dst:%p pos:%uz size:%uz",
                   ctx->buffer_in.src,  ctx->buffer_in.pos,
                   ctx->buffer_in.size,
                   ctx->buffer_out.dst, ctx->buffer_out.pos,
                   ctx->buffer_out.size);

    /*
     * Guard the zero-delta case instead of unconditionally adding: when the
     * dequeued link is a data-less carrier (last_buf/flush, pos == NULL —
     * see add_data), buffer_in still describes the previous, fully-drained
     * buffer, so the delta is provably 0 — but `NULL + 0` is still undefined
     * pointer arithmetic. gcc's UBSan lets it pass; clang's aborts with
     * "applying zero offset to null pointer".
     */
    if (ctx->buffer_in.pos != pos_in) {
        ctx->in_buf->pos += ctx->buffer_in.pos - pos_in;
    }

    ctx->out_buf->last += ctx->buffer_out.pos - pos_out;
    ctx->redo = 0;

    /* PR #49: State machine logic for action transitions */
    if (zrc > 0) {
        /*
         * rc > 0: zstd has buffered data. For COMPRESS, transition to FLUSH
         * to drain libzstd's internal buffers. For FLUSH/END, keep the action.
         */
        if (ctx->action == NGX_HTTP_ZSTD_FILTER_COMPRESS) {
            ctx->action = NGX_HTTP_ZSTD_FILTER_FLUSH;
        }
        ctx->redo = 1;

    } else if (ctx->last && ctx->action != NGX_HTTP_ZSTD_FILTER_END
               && ctx->buffer_in.pos >= ctx->buffer_in.size
               && ctx->in == NULL)
    {
        /*
         * PR #49: All input consumed; transition to END only when:
         * - last flag is set (we know this is the final chunk)
         * - input buffer fully drained (no more bytes to feed libzstd)
         * - no more chain links queued (all input streams exhausted)
         * This prevents premature END transitions that cause 131072-byte
         * truncation.
         */
        ctx->action = NGX_HTTP_ZSTD_FILTER_END;
        ctx->redo   = 1;

        /*
         * We have only just switched to END; the call above ran with
         * ZSTD_e_continue/flush and has NOT yet written the zstd end-of-frame
         * marker. If it produced no output, force another iteration so
         * ZSTD_e_end runs. If it did produce output, fall through to emit
         * those (valid, non-terminal) bytes — but `last` must stay false this
         * iteration so we do not set last_buf before the end marker exists.
         */
        if (ngx_buf_size(ctx->out_buf) == 0) {
            return NGX_AGAIN;
        }

    } else if (ctx->action != NGX_HTTP_ZSTD_FILTER_END) {
        /* Restore to COMPRESS after FLUSH drains (unless transitioning
         * to END) */
        ctx->action = NGX_HTTP_ZSTD_FILTER_COMPRESS;
    }

    /*
     * Terminal frame: the call that just ran used ZSTD_e_end (so `directive`
     * — captured before any action transition above — is ZSTD_e_end) and
     * libzstd reports the frame is fully flushed (rc == 0). Keyed on
     * `directive`, not `ctx->action`, because the COMPRESS→END transition
     * above mutates ctx->action *after* the compress call; using ctx->action
     * here would declare the stream terminal one iteration too early and
     * truncate it (no end-of-frame marker written yet).
     *
     * Evaluated before the empty-buffer early return below: a terminal
     * ZSTD_e_end that produces zero output bytes (everything drained on a
     * prior iteration) must still emit a zero-length last_buf, otherwise the
     * request loops forever with NGX_HTTP_GZIP_BUFFERED set and hangs until
     * timeout.
     */
    last = zrc == 0 && ctx->last && directive == ZSTD_e_end;

    /*
     * Structured emit-decision trace. Permanent: compiled out of
     * release builds via NGX_DEBUG (zero runtime cost when off),
     * visible with `error_log ... debug`. This is the single most
     * useful probe for the module's recurring truncation /
     * zero-size-buffer / terminal-frame bug class — it records exactly
     * what the emit guard saw (output size, libzstd return, terminal
     * and flush state, action) so future diagnosis is one
     * `error_log debug` away instead of a patch/rebuild cycle. Behaviour
     * is unchanged; this only observes.
     */
    ngx_log_debug6(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "zstd emit?: outsz:%uz rc0:%d last:%d ctx_last:%d "
                   "ctx_flush:%d action:%d",
                   (size_t) ngx_buf_size(ctx->out_buf), zrc == 0, last,
                   ctx->last, ctx->flush, (ngx_uint_t) ctx->action);

    /*
     * Empty, non-terminal output buffer handling.
     *
     * Two distinct empty-buffer cases reach here:
     *
     *  1. A content-less *completed flush*: ctx->flush is set and the
     *     ZSTD_e_flush call returned rc == 0 with zero bytes produced.
     *     Per the libzstd contract rc == 0 from a flush means the
     *     encoder is fully drained — there is genuinely nothing to
     *     send. The OLD code's `!(rc == 0 && ctx->flush)` exception
     *     forwarded a zero-size buffer here, which nginx's
     *     ngx_http_write_filter rejects ("zero size buf in writer")
     *     and aborts the request — bug B, under `proxy_buffering off`
     *     where the upstream forces such flushes.
     *
     *     The flush is COMPLETE, so satisfy and clear it here: drop the
     *     NGX_HTTP_GZIP_BUFFERED bit and ctx->flush, emit nothing, and
     *     return NGX_AGAIN. Clearing ctx->flush is what makes the body
     *     filter's inner loop terminate: ngx_http_zstd_filter_add_data()
     *     keeps the loop alive while ctx->flush is set (expecting this
     *     function to consume it); a naive "suppress the empty buffer
     *     but leave ctx->flush set" change spins the worker at 100% CPU
     *     (a NGX_AGAIN livelock — observed). Clearing it lets the next
     *     add_data() fall through to NGX_DECLINED (input drained) and
     *     break the loop cleanly.
     *
     *  2. Any other empty, non-terminal buffer (no pending flush):
     *     nothing to send and nothing to satisfy — just suppress and
     *     return NGX_AGAIN as before.
     *
     * The genuine terminal empty buffer (last) is never suppressed; it
     * falls through to be emitted with last_buf set below.
     */
    if (ngx_buf_size(ctx->out_buf) == 0 && !last) {
        if (zrc == 0 && ctx->flush) {
            r->connection->buffered &= ~NGX_HTTP_GZIP_BUFFERED;
            ctx->flush = 0;
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "zstd emit: content-less flush completed, "
                           "cleared (no empty buffer forwarded)");
        } else {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "zstd emit: suppressed empty non-terminal "
                           "buffer");
        }
        return NGX_AGAIN;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    b = ctx->out_buf;

    if (zrc == 0 && (ctx->flush || last)) {
        r->connection->buffered &= ~NGX_HTTP_GZIP_BUFFERED;

        b->flush = ctx->flush && !ctx->last;
        b->last_buf = last;

        ctx->done  = b->last_buf;
        ctx->flush = 0;
    }

    ctx->bytes_out += ngx_buf_size(b);

    cl->next = NULL;
    cl->buf  = b;

    *ctx->last_out = cl;
    ctx->last_out  = &cl->next;

    ngx_memzero(&ctx->buffer_out, sizeof(ZSTD_outBuffer));

    return last ? NGX_OK : NGX_AGAIN;
}


static ngx_int_t
ngx_http_zstd_filter_add_data(ngx_http_request_t *r, ngx_http_zstd_ctx_t *ctx)
{
    ngx_chain_t  *cl;

    if (ctx->buffer_in.pos < ctx->buffer_in.size
        || ctx->flush
        || ctx->last
        || ctx->redo)
    {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "zstd in: %p", ctx->in);

    if (ctx->in == NULL) {
        return NGX_DECLINED;
    }

    /*
     * ngx_chain_add_copy() above allocated a fresh chain link per incoming
     * link. Once we have taken its buffer, return the consumed link to the
     * pool's free list with ngx_free_chain(); otherwise the copied links
     * accumulate in the request pool for the whole request, so a long-lived
     * chunked/SSE response grows worker memory linearly with chunk count
     * even though the output buffers are recycled. The buffer itself stays
     * valid — only the link wrapper is freed.
     */
    cl = ctx->in;
    ctx->in_buf = cl->buf;
    ctx->in = cl->next;
    ngx_free_chain(r->pool, cl);

    /*
     * Test last_buf FIRST, then flush — matching the order used by the
     * nginx gzip and brotli body filters
     * (ngx_http_gzip_filter_module.c / brotli filter). An upstream
     * terminal chain link can legitimately carry BOTH last_buf=1 and
     * flush=1 (e.g. proxy_buffering off + the upstream finalising its
     * stream): with the reverse order ctx->flush wins, ctx->last is
     * never set, the END-action transition below never fires, and the
     * stream is sent without its terminal zstd frame — the connection
     * hangs or the decoder sees a truncated frame. End-of-stream
     * implies a flush at the writer layer, so prioritising last_buf
     * loses nothing.
     */
    if (ctx->in_buf->last_buf) {
        ctx->last = 1;

    } else if (ctx->in_buf->flush) {
        ctx->flush = 1;
    }

    if (ngx_buf_size(ctx->in_buf) == 0) {
        /*
         * Data-less buffer (flush/sync/last carrier, or an empty data
         * buf). Its signal flags were captured above; never load it into
         * buffer_in. These bufs can carry pos == NULL (ngx_buf_special()),
         * and installing that as buffer_in.src both hands libzstd a NULL
         * src and clobbers the pointer other code may treat as state (the
         * old init_cctx first-call check did — see cctx_ready). If last or
         * flush was just set, return OK so the compress step runs the
         * end/flush immediately; otherwise skip to the next link.
         */
        return (ctx->last || ctx->flush) ? NGX_OK : NGX_AGAIN;
    }

    ctx->buffer_in.src = ctx->in_buf->pos;
    ctx->buffer_in.pos = 0;
    ctx->buffer_in.size = ngx_buf_size(ctx->in_buf);

    ctx->bytes_in += ngx_buf_size(ctx->in_buf);

    return NGX_OK;
}


static ngx_int_t
ngx_http_zstd_filter_get_buf(ngx_http_request_t *r, ngx_http_zstd_ctx_t *ctx)
{
    ngx_chain_t               *cl;
    ngx_http_zstd_loc_conf_t  *zlcf;

    /*
     * Keep using the current output buffer only if it still exists AND has
     * room. The body filter deliberately sets ctx->out_buf = NULL after
     * ngx_chain_update_chains() (to avoid touching a buffer that was just
     * recycled onto the free/busy chains). On a response large enough to
     * need more than one ZSTD_CStreamOutSize output buffer (chunked /
     * no-Content-Length is the common trigger), the inner compress loop can
     * re-enter get_buf with ctx->out_buf == NULL while ctx->buffer_out still
     * looks non-full. Without the NULL check this returned NGX_OK and the
     * very next ngx_http_zstd_filter_compress() dereferenced the NULL
     * ctx->out_buf ("ctx->out_buf->last += ...") — a worker SIGSEGV that
     * only manifests past the first ~128 KB of output. Require a live
     * out_buf here so an invalidated one always forces a fresh acquire.
     */
    if (ctx->out_buf != NULL && ctx->buffer_out.pos < ctx->buffer_out.size) {
        return NGX_OK;
    }

    zlcf = ngx_http_get_module_loc_conf(r, ngx_http_zstd_filter_module);

    if (ctx->free) {
        cl = ctx->free;
        ctx->free = ctx->free->next;
        ctx->out_buf = cl->buf;
        ngx_free_chain(r->pool, cl);

        /*
         * ngx_chain_update_chains() resets pos/last on a recycled buffer but
         * NOT the control flags. This buffer may previously have carried
         * flush / last_buf / last_in_chain (set in the compress step before
         * it went downstream). Clear them here so a later ordinary data
         * buffer cannot trigger a spurious downstream flush or a false
         * end-of-stream marker. See P2.
         */
        ctx->out_buf->flush = 0;
        ctx->out_buf->sync = 0;
        ctx->out_buf->last_buf = 0;
        ctx->out_buf->last_in_chain = 0;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd get_buf: reused free buffer %p", ctx->out_buf);

    } else if (ctx->bufs < zlcf->bufs.num) {
        ctx->out_buf = ngx_create_temp_buf(r->pool, zlcf->bufs.size);
        if (ctx->out_buf == NULL) {
            return NGX_ERROR;
        }

        ctx->out_buf->tag = (ngx_buf_tag_t) &ngx_http_zstd_filter_module;
        ctx->out_buf->recycled = 1;
        ctx->bufs++;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd get_buf: allocated buffer %p (%i in use)",
                       ctx->out_buf, ctx->bufs);

    } else {
        ctx->nomem = 1;
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd get_buf: no free buffer, nomem set");
        return NGX_DECLINED;
    }

    if (ctx->out_buf == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "zstd: out_buf is NULL after buffer allocation");
        return NGX_ERROR;
    }

    ctx->buffer_out.dst = ctx->out_buf->pos;
    ctx->buffer_out.pos = 0;

    /* Validate buffer pointers to detect corruption before using in ZSTD */
    if (ctx->out_buf->end < ctx->out_buf->start) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "corrupted output buffer: end (%p) < start (%p)",
                      ctx->out_buf->end, ctx->out_buf->start);
        return NGX_ERROR;
    }

    ctx->buffer_out.size = ctx->out_buf->end - ctx->out_buf->start;

    return NGX_OK;
}


/*
 * Queue the 40-byte dcz frame header (RFC 9842 §2.2) as the first link
 * on the out chain: the zstd skippable-frame magic 0x184D2A5E with a
 * declared 32-byte content, then the dictionary's SHA-256. Emitted from
 * its own pool buffer rather than through the compressor's recycled
 * buffers so it can never be reordered behind compressed output. A
 * plain zstd decoder skips the frame; a dcz client checks the hash
 * against the dictionary it advertised.
 */
static ngx_int_t
ngx_http_zstd_filter_emit_dcz_header(ngx_http_request_t *r,
    ngx_http_zstd_ctx_t *ctx)
{
    static const u_char  magic[8] = {
        0x5e, 0x2a, 0x4d, 0x18,     /* 0x184D2A5E, little-endian */
        0x20, 0x00, 0x00, 0x00      /* frame content size: 32 */
    };

    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    b = ngx_create_temp_buf(r->pool, NGX_HTTP_ZSTD_DCZ_HEADER_LEN);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->last = ngx_cpymem(b->last, magic, sizeof(magic));
    b->last = ngx_cpymem(b->last, ctx->dcz_dict->hash,
                         NGX_HTTP_ZSTD_SHA256_DIGEST_LEN);

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    *ctx->last_out = cl;
    ctx->last_out = &cl->next;

    ctx->bytes_out += NGX_HTTP_ZSTD_DCZ_HEADER_LEN;
    ctx->dcz_header_sent = 1;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "zstd dcz: 40-byte frame header queued (dict \"%V\")",
                   &ctx->dcz_dict->file);

    return NGX_OK;
}


/*
 * Set one ZSTD_CCtx parameter, logging a uniform NGX_LOG_ALERT and
 * returning NGX_ERROR on failure. Collapses the five structurally
 * identical setParameter+isError+log blocks in init_cctx into one
 * call site each, and gives every parameter the same error-message
 * format (they previously diverged slightly per call). `name` is the
 * human-readable parameter label for the log line.
 */
static ngx_int_t
ngx_http_zstd_set_param(ngx_http_request_t *r, ZSTD_CCtx *cctx,
    ZSTD_cParameter param, int value, const char *name)
{
    size_t  rc;

    rc = ZSTD_CCtx_setParameter(cctx, param, value);
    if (ZSTD_isError(rc)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "zstd: ZSTD_CCtx_setParameter(%s=%d) failed: %s",
                      name, value, ZSTD_getErrorName(rc));
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * Give this request a CCtx: either the worker's cached one on loan, or a
 * fresh per-request context.
 *
 * Extracted from ngx_http_zstd_filter_init_cctx() so the loan bookkeeping --
 * which cleanup handler owns the context, and when `busy` may be set -- reads
 * as one unit instead of as five branches inside the parameter-setting code.
 *
 * On success ctx->cctx is non-NULL and a pool cleanup owns it: either
 * ngx_http_zstd_release_cctx (returns the loan) or ngx_http_zstd_cleanup_cctx
 * (frees an unshared context).
 */
static ngx_int_t
ngx_http_zstd_acquire_cctx(ngx_http_request_t *r, ngx_http_zstd_ctx_t *ctx,
    ngx_http_zstd_loc_conf_t *zlcf)
{
    ngx_uint_t           borrowed;
    ngx_pool_cleanup_t  *cln;

    /*
     * The cleanup slot is registered BEFORE the context is claimed, so a
     * borrowed context can never be stranded with busy set: an allocation
     * failure here happens while the cache is still untouched.
     */
    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    borrowed = 0;

    /*
     * Borrow the worker context when it is free and was built for this
     * location's complete memory-affecting profile: compression level, long
     * mode and window log. A mismatch in any of the three takes the
     * per-request path rather than re-parameterising the cache: the retained
     * workspace is driven by all three and never shrinks, so honouring a
     * higher-memory location here would raise the worker's floor for every
     * subsequent request of every other location.
     */
    if (!ngx_http_zstd_worker_cctx_busy
        && ngx_http_zstd_worker_cctx != NULL
        && ngx_http_zstd_worker_cctx_level == zlcf->level
        && ngx_http_zstd_worker_cctx_long_mode == zlcf->long_mode
        && ngx_http_zstd_worker_cctx_window_log == zlcf->window_log)
    {
        ctx->cctx = ngx_http_zstd_worker_cctx;
        borrowed = 1;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd: reusing worker cctx %p", ctx->cctx);

    } else {
        ctx->cctx = ZSTD_createCCtx();
        if (ctx->cctx == NULL) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "zstd: ZSTD_createCCtx() failed");
            return NGX_ERROR;
        }

        /*
         * Seed an empty cache so subsequent requests amortise. Only an empty
         * cache is populated -- a live cached context is never evicted
         * mid-flight, and one already on loan is left alone.
         */
        if (ngx_http_zstd_worker_cctx == NULL) {
            ngx_http_zstd_worker_cctx = ctx->cctx;
            ngx_http_zstd_worker_cctx_level = zlcf->level;
            ngx_http_zstd_worker_cctx_long_mode = zlcf->long_mode;
            ngx_http_zstd_worker_cctx_window_log = zlcf->window_log;
            borrowed = 1;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd: created cctx %p (cached:%ui)",
                       ctx->cctx, borrowed);
    }

    if (borrowed) {
        ngx_http_zstd_worker_cctx_busy = 1;
        cln->handler = ngx_http_zstd_release_cctx;

    } else {
        cln->handler = ngx_http_zstd_cleanup_cctx;
    }

    cln->data = ctx->cctx;

    return NGX_OK;
}


/*
 * Configure this request's CCtx on first body data.
 *
 * The context comes from ngx_http_zstd_acquire_cctx() -- either the worker's
 * cached one on loan or a fresh per-request one -- and is attached to the
 * request cleanup chain either way, so overlapping requests in one worker
 * never share libzstd streaming state. Every parameter is (re-)applied here
 * after a full reset, which is what makes a carried-over context equivalent
 * to a freshly created one.
 */
static ngx_int_t
ngx_http_zstd_filter_init_cctx(ngx_http_request_t *r,
    ngx_http_zstd_ctx_t *ctx)
{
    size_t                      rc;
    ZSTD_CCtx                  *cctx;
    ngx_http_zstd_loc_conf_t   *zlcf;

    zlcf = ngx_http_get_module_loc_conf(r, ngx_http_zstd_filter_module);

    if (ctx->cctx == NULL
        && ngx_http_zstd_acquire_cctx(r, ctx, zlcf) != NGX_OK)
    {
        return NGX_ERROR;
    }

    cctx = ctx->cctx;

    /* Full reset: session state + all parameters. */
    rc = ZSTD_CCtx_reset(cctx, ZSTD_reset_session_and_parameters);
    if (ZSTD_isError(rc)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "zstd: ZSTD_CCtx_reset() failed: %s",
                      ZSTD_getErrorName(rc));
        return NGX_ERROR;
    }

    if (ngx_http_zstd_set_param(r, cctx, ZSTD_c_compressionLevel,
                                (int) zlcf->level, "level")
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /*
     * Issue #38: Apply target compressed block size if configured.
     *
     * Gate on the library version, NOT #ifdef ZSTD_c_targetCBlockSize:
     * ZSTD_c_targetCBlockSize is an enum member, not a preprocessor macro,
     * so #ifdef is always false and silently compiled this whole block out
     * even on libzstd >= 1.5.6 where the parameter is fully supported. The
     * directive was therefore a permanent no-op. See C1.
     */
#if ZSTD_VERSION_NUMBER >= 10506
    if (zlcf->target_cblock_size > 0) {
        if (ngx_http_zstd_set_param(r, cctx, ZSTD_c_targetCBlockSize,
                                    (int) zlcf->target_cblock_size,
                                    "targetCBlockSize")
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }
#endif

    /*
     * Long-distance matching. zstd keeps a secondary long-range hash
     * table that finds repeats far beyond the regular match window —
     * a meaningful ratio win on large, internally repetitive bodies
     * (concatenated JSON, HTML with repeated boilerplate, logs) at a
     * modest, bounded extra memory cost. Off by default; the win only
     * materialises on inputs large enough to exceed the window, and
     * small responses should not pay the table allocation. Set before
     * zstd_window_log below so an explicit window cap still takes
     * precedence over the LDM-derived default.
     */
    if (zlcf->long_mode) {
        if (ngx_http_zstd_set_param(r, cctx,
                                    ZSTD_c_enableLongDistanceMatching, 1,
                                    "enableLongDistanceMatching")
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    /*
     * Cap the compression window. zstd's per-context working memory is
     * dominated by the window size (~2^windowLog bytes plus match-table
     * overhead). Without a cap, a high level on large bodies lets each
     * concurrent request inflate worker RSS unpredictably. Bounding
     * windowLog gives operators a hard, predictable per-request memory
     * ceiling at a small ratio cost on inputs larger than the window.
     * Unset (0) keeps zstd's level-derived default.
     */
    if (zlcf->window_log > 0) {
        if (ngx_http_zstd_set_param(r, cctx, ZSTD_c_windowLog,
                                    (int) zlcf->window_log, "windowLog")
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    if (ctx->dcz_dict != NULL) {
        size_t     required;
        ngx_int_t  wlog;

        /*
         * RFC 9842 window bound. The client guarantees a decode window of
         * max(8 MB, 1.25 x dict size); staying at or under 2^23 keeps every
         * frame inside that guarantee unconditionally. Within the cap, the
         * window must reach back across the whole prefix from the end of
         * the content or the far end of the dictionary stops matching —
         * so size it to dictionary + expected content (1 MB guess when the
         * length is unknown), rounded up to a power of two. An operator
         * zstd_window_log below the computed value still wins: it is a
         * memory ceiling, and a dictionary must not silently void it
         * (that was audit C2/R1's lesson with the CDict path).
         */
        required = ctx->dcz_dict->bytes.len
                   + (ctx->pledged_size >= 0
                      ? (size_t) ctx->pledged_size
                      : 1024 * 1024);

        /* 10 = ZSTD_WINDOWLOG_MIN (static-API constant; literal so the
         * plain-API build compiles) */
        for (wlog = 10;
             wlog < NGX_HTTP_ZSTD_DCZ_MAX_WINDOW_LOG
             && ((size_t) 1 << wlog) < required;
             wlog++) { /* void */ }

        if (zlcf->window_log > 0 && zlcf->window_log < wlog) {
            wlog = zlcf->window_log;
        }

        if (ngx_http_zstd_set_param(r, cctx, ZSTD_c_windowLog, (int) wlog,
                                    "windowLog(dcz)")
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        /*
         * Reference the raw dictionary bytes as a prefix — RFC 9842
         * type=raw semantics exactly (ZSTD_CCtx_refPrefix interprets the
         * buffer as raw content, not a trained-dictionary structure).
         * Per-request table build over the prefix is the deliberate MVP
         * trade against caching a CDict per (dict, level, window) tuple;
         * the buffer itself is config-pool memory that outlives the
         * request. Mutually exclusive with the trained zstd_dict_file
         * CDict below: a dcz response's frame must reference ONLY the
         * negotiated dictionary or the client cannot decode it.
         */
        rc = ZSTD_CCtx_refPrefix(cctx, ctx->dcz_dict->bytes.data,
                                 ctx->dcz_dict->bytes.len);
        if (ZSTD_isError(rc)) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "zstd: ZSTD_CCtx_refPrefix() failed: %s",
                          ZSTD_getErrorName(rc));
            return NGX_ERROR;
        }

        /*
         * Content checksum on dcz frames — defence in depth against a
         * mismatched dictionary. Decoding against a wrong same-size
         * dictionary structurally SUCCEEDS: raw-prefix back-references
         * stay in range and nothing else ties the output to the
         * content, so the client gets wrong bytes with a success code
         * (demonstrated in review of the supplied-hash argument, where
         * a stale declared hash is the realistic way to get there).
         * The checksum (XXH64-low32 of the uncompressed content,
         * verified by libzstd-based clients — i.e. browsers — by
         * default) turns that into a visible decode error. Four bytes
         * per response plus an XXH64 pass; negligible next to the
         * compression itself. Plain responses are unchanged: a
         * zstd_dict_file CDict already embeds a dictionary ID that the
         * decoder checks (a wrong trained dictionary fails as
         * "Dictionary mismatch"), and a dictionary-less response has
         * nothing to mismatch. Only the RFC 9842 raw prefix carries no
         * such binding, which is why it needs the checksum.
         */
        if (ngx_http_zstd_set_param(r, cctx, ZSTD_c_checksumFlag, 1,
                                    "checksumFlag(dcz)")
            != NGX_OK)
        {
            return NGX_ERROR;
        }

    } else if (zlcf->dict) {
        rc = ZSTD_CCtx_refCDict(cctx, zlcf->dict);
        if (ZSTD_isError(rc)) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "zstd: ZSTD_CCtx_refCDict() failed: %s",
                          ZSTD_getErrorName(rc));
            return NGX_ERROR;
        }
    }

    /*
     * When the response body length is known exactly (a declared
     * Content-Length, i.e. the common proxied / static case), tell zstd
     * up front. With the pledged size the encoder can size its internals
     * to the input and write a more compact frame header (an exact
     * content-size field instead of the streaming-unknown encoding),
     * improving both speed and ratio slightly at no cost.
     *
     * This stays strictly per-request: it is set on this request's own
     * CCtx after the reset above and before the first compress call,
     * exactly as ZSTD_CCtx_setPledgedSrcSize() requires. It does NOT
     * reintroduce a shared/worker-lifetime context — the per-request
     * context model from 774b4a5 is a deliberate correctness guarantee
     * and is preserved.
     *
     * ctx->pledged_size is the body length captured in the header filter
     * before ngx_http_clear_content_length() wiped it (the header filter
     * runs the eligibility gate and clear; the live content_length_n is -1
     * by now). For a non-chunked response that is exactly what is fed to the
     * compressor. The pledge is only an optimisation hint, so a failure to
     * set it is logged and ignored rather than failing the request; a genuine
     * size mismatch would still be caught by ZSTD_compressStream2() and
     * handled on the existing failed: path.
     */
    if (ctx->pledged_size >= 0) {
        rc = ZSTD_CCtx_setPledgedSrcSize(
                 cctx, (unsigned long long) ctx->pledged_size);
        if (ZSTD_isError(rc)) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "zstd: ZSTD_CCtx_setPledgedSrcSize(%O) ignored: %s",
                           ctx->pledged_size, ZSTD_getErrorName(rc));
        }
    }

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "zstd cctx ready: level:%i long:%i window_log:%i "
                   "dict:%p dcz:%p",
                   zlcf->level, zlcf->long_mode, zlcf->window_log,
                   zlcf->dict, ctx->dcz_dict);

    return NGX_OK;
}


static void *
ngx_http_zstd_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_zstd_main_conf_t  *zmcf;

    zmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_zstd_main_conf_t));
    if (zmcf == NULL) {
        return NULL;
    }

    /* NGX_CONF_UNSET so ngx_conf_set_flag_slot does not mistake the
     * pcalloc'd 0 for an already-set value ("is duplicate"). */
    zmcf->dict_unsafe = NGX_CONF_UNSET;

    return zmcf;
}


static char *
ngx_http_zstd_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_zstd_main_conf_t *zmcf = conf;

    if (zmcf->dict_file.len == 0) {
        return NGX_CONF_OK;
    }

    /*
     * RFC1: zstd_dict_file emits Content-Encoding: zstd while compressing with
     * an external dictionary. That is not HTTP dictionary negotiation: RFC 9842
     * (Sept 2025) defines the "dcz" content coding and Available-Dictionary for
     * that. A generic client that only advertises "zstd" cannot decode this
     * response, and a shared cache keys it as an ordinary zstd variant. Until
     * dcz is implemented, refuse to start unless the operator explicitly
     * acknowledges the non-standard, control-both-ends-only mode.
     */
    if (zmcf->dict_unsafe != 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"zstd_dict_file\" produces a non-standard "
                           "\"Content-Encoding: zstd\" response that only "
                           "clients sharing the dictionary can decode and that "
                           "is not negotiated per RFC 9842 (dcz). Set "
                           "\"zstd_dict_file_unsafe on;\" to acknowledge you "
                           "control both ends (and key any shared cache "
                           "accordingly), or remove \"zstd_dict_file\"");
        return NGX_CONF_ERROR;
    }

    if (ngx_conf_full_name(cf->cycle, &zmcf->dict_file, 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_zstd_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_zstd_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_zstd_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *    conf->bufs.num = 0;
     *    conf->types = { NULL };
     *    conf->types_keys = NULL;
     *    conf->dict = NULL;
     */

    conf->enable = NGX_CONF_UNSET;
    conf->level = NGX_HTTP_ZSTD_LEVEL_UNSET;
    conf->min_length = NGX_CONF_UNSET;
    conf->max_length = NGX_CONF_UNSET;
    conf->target_cblock_size = NGX_CONF_UNSET;
    conf->window_log = NGX_CONF_UNSET;
    conf->long_mode = NGX_CONF_UNSET;
    conf->max_cctx_memory = NGX_CONF_UNSET;
    conf->bypass = NGX_CONF_UNSET_PTR;
    conf->dcz_dicts = NGX_CONF_UNSET_PTR;

    return conf;
}


static char *
ngx_http_zstd_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_zstd_loc_conf_t *prev = parent;
    ngx_http_zstd_loc_conf_t *conf = child;

    ngx_fd_t                    fd;
    off_t                       fsize;
    size_t                      size;
    ssize_t                     n;
    char                       *rc;
    u_char                     *buf;
    ngx_file_info_t             info;
    ngx_http_zstd_main_conf_t  *zmcf;

    rc = NGX_CONF_OK;
    buf = NULL;
    fd = NGX_INVALID_FILE;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    /*
     * Hand-rolled rather than ngx_conf_merge_value(): that macro tests
     * against NGX_CONF_UNSET, which is a legal level here. See
     * NGX_HTTP_ZSTD_LEVEL_UNSET above.
     */
    if (conf->level == NGX_HTTP_ZSTD_LEVEL_UNSET) {
        conf->level = (prev->level == NGX_HTTP_ZSTD_LEVEL_UNSET)
                      ? 3 : prev->level;
    }

    ngx_conf_merge_value(conf->min_length, prev->min_length, 1024);
    ngx_conf_merge_value(conf->max_length, prev->max_length, NGX_CONF_UNSET);
    ngx_conf_merge_value(conf->target_cblock_size, prev->target_cblock_size, 0);
    ngx_conf_merge_value(conf->window_log, prev->window_log, 0);
    ngx_conf_merge_value(conf->long_mode, prev->long_mode, 0);
    ngx_conf_merge_value(conf->max_cctx_memory, prev->max_cctx_memory, 0);
    ngx_conf_merge_ptr_value(conf->bypass, prev->bypass, NULL);
    ngx_conf_merge_str_value(conf->bypass_vary, prev->bypass_vary, "");

    /* a location that declares its own zstd_dcz_dict_file list replaces the
     * inherited one wholesale (standard nginx array-directive semantics) */
    ngx_conf_merge_ptr_value(conf->dcz_dicts, prev->dcz_dicts, NULL);

    /*
     * zstd_bypass_vary only makes sense alongside a zstd_bypass predicate: it
     * names the request header the bypass decision varies on so shared caches
     * key correctly. Set on its own it just emits a Vary field no response
     * actually varies on (harmless over-varying). Warn so the misconfig is
     * visible rather than silently degrading cache hit rate.
     */
    if (conf->bypass_vary.len && conf->bypass == NULL) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "\"zstd_bypass_vary\" is set without a "
                           "\"zstd_bypass\" predicate; it adds a \"Vary: %V\" "
                           "field no response varies on. Add a "
                           "\"zstd_bypass\" directive or remove "
                           "\"zstd_bypass_vary\"", &conf->bypass_vary);
    }

    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             ngx_http_zstd_default_types))
    {
        return NGX_CONF_ERROR;
    }

    /*
     * NOTE: do NOT ngx_conf_merge_ptr_value(conf->dict, prev->dict, NULL)
     * here. That copied the parent pointer before the level/window
     * comparison below, leaving conf->dict non-NULL so the "build a fresh
     * child CDict" branch could never run — a child that changed
     * zstd_comp_level silently inherited the parent-level CDict. The dict is
     * resolved explicitly in the block below instead. See C2.
     */

    /*
     * Default the output buffer size to ZSTD_CStreamOutSize() — the
     * encoder's own recommended output granularity (~128 KB). It is the
     * documented minimum at which ZSTD_compressStream2() can flush a full
     * internal block in a single call; with any smaller buffer zstd is
     * forced to fragment a block across calls, costing extra
     * compress round-trips and ngx_alloc_chain_link() churn per response.
     * The previous 4 x 32 KB heuristic approximated this; using the API's
     * value is the principled form and tracks libzstd if it ever changes.
     *
     * Two such buffers: one being filled by the compressor while the
     * other is in flight down the output chain. This raises the
     * per-request filter-memory floor to ~2 x ZSTD_CStreamOutSize()
     * (~256 KB) from the prior ~128 KB — the deliberate cost of never
     * forcing zstd to mid-block flush. Operators who set zstd_buffers
     * explicitly are unaffected (the merge keeps their value), and can
     * tune it down if the memory trade is wrong for their workload.
     *
     * ZSTD_CStreamOutSize() is a constant-returning libzstd call (no
     * allocation, no per-call cost); it is evaluated once here at config
     * merge, not per request.
     */
    ngx_conf_merge_bufs_value(conf->bufs, prev->bufs,
                              2, ZSTD_CStreamOutSize());

    zmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_zstd_filter_module);

    if (conf->enable && zmcf->dict_file.len > 0) {

        if (prev->dict != NULL
            && conf->level == prev->level
            && conf->window_log == prev->window_log)
        {
            /*
             * Parent already loaded a CDict and every CDict-affecting
             * parameter matches: reuse it to avoid redundant loading.
             * window_log is part of the key because a CDict bakes in
             * compression parameters; a child that changes it must not
             * silently share the parent's.
             */
            conf->dict = prev->dict;

        } else {
            /*
             * No usable parent CDict, or this location changed a
             * CDict-affecting parameter: load the dict fresh for this
             * location's own parameters. (conf->dict is NULL here — the
             * premature merge that used to pre-populate it was removed.)
             */

            fd = ngx_open_file(zmcf->dict_file.data, NGX_FILE_RDONLY,
                               NGX_FILE_OPEN, 0);

            if (fd == NGX_INVALID_FILE) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                                   ngx_open_file_n " \"%V\" failed",
                                   &zmcf->dict_file);

                return NGX_CONF_ERROR;
            }

            if (ngx_fd_info(fd, &info) == NGX_FILE_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                                   ngx_fd_info_n " \"%V\" failed",
                                   &zmcf->dict_file);

                rc = NGX_CONF_ERROR;
                goto close;
            }

            /*
             * Compare as off_t BEFORE narrowing to size_t: on an ILP32
             * build with large-file support a >4 GiB dictionary wraps to
             * a small size_t, slipping past the cap below and loading a
             * truncated dictionary.
             */
            fsize = ngx_file_size(&info);

            /* Validate dictionary file size to prevent DoS
             * via memory exhaustion */
            if (fsize > (off_t) NGX_HTTP_ZSTD_MAX_DICT_SIZE) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "dictionary file too large: %O bytes "
                                   "(limit: %d bytes)",
                                   fsize, NGX_HTTP_ZSTD_MAX_DICT_SIZE);

                rc = NGX_CONF_ERROR;
                goto close;
            }

            /*
             * Reject an empty file rather than loading a do-nothing
             * dictionary. ZSTD_createCDict(buf, 0, level) returns a
             * VALID CDict, and ngx_read_fd(..., 0) returns 0 == size, so
             * every completeness check downstream passes and the operator
             * -- who had to set zstd_dict_file_unsafe on to get here --
             * silently gets no dictionary at all. The dcz loader below
             * has always rejected this; the two now agree.
             */
            if (fsize == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "dictionary file \"%V\" is empty",
                                   &zmcf->dict_file);

                rc = NGX_CONF_ERROR;
                goto close;
            }

            size = (size_t) fsize;

            buf = ngx_palloc(cf->pool, size);
            if (buf == NULL) {
                rc = NGX_CONF_ERROR;
                goto close;
            }

            n = ngx_read_fd(fd, (void *) buf, size);
            if (n < 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                                   ngx_read_fd_n " %V\" failed",
                                   &zmcf->dict_file);

                rc = NGX_CONF_ERROR;
                goto close;

            } else if ((size_t) n != size) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   ngx_read_fd_n " \"%V\" incomplete read",
                                   &zmcf->dict_file);

                rc = NGX_CONF_ERROR;
                goto close;
            }

            /*
             * Bake the location's effective compression parameters into the
             * CDict. ZSTD_CCtx_refCDict() lets a CDict's compression
             * parameters supersede the CCtx's, so a CDict built with the
             * simple ZSTD_createCDict() (level only) would silently override
             * the windowLog that init_cctx sets — making zstd_window_log a
             * non-cap whenever a dictionary is loaded (former audit C2 / R1).
             * Build the CDict with ZSTD_createCDict_advanced() seeding
             * windowLog from zstd_window_log so the baked params and the CCtx
             * params agree and the window cap (and the zstd_max_cctx_memory
             * estimate, computed from the same windowLog below) hold even with
             * a dictionary. The advanced builder lives in libzstd's static
             * API; on a non-static build fall back to the level-only CDict
             * (window cap not honored with a dict — documented in README).
             *
             * Long-distance matching is a separate CCtx frame parameter, not
             * part of ZSTD_compressionParameters, so refCDict does not override
             * it; zstd_long keeps applying via the CCtx in init_cctx.
             */
#if defined(ZSTD_STATIC_LINKING_ONLY) && ZSTD_VERSION_NUMBER >= 10400
            {
                ZSTD_compressionParameters  cparams;

                cparams = ZSTD_getCParams((int) conf->level, 0, size);

                if (conf->window_log > 0) {
                    cparams.windowLog = (unsigned) conf->window_log;
                }

                conf->dict = ZSTD_createCDict_advanced(buf, size,
                                 ZSTD_dlm_byCopy, ZSTD_dct_auto, cparams,
                                 ZSTD_defaultCMem);
            }
#else
            conf->dict = ZSTD_createCDict(buf, size, conf->level);
#endif
            if (conf->dict == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "ZSTD_createCDict() failed");
                rc = NGX_CONF_ERROR;
                goto close;
            }

            /* Register cleanup handler to free dictionary when
             * config is destroyed.
             * Note: Using ZSTD_createCDict() (copy mode) instead
             * of _byReference() to avoid use-after-free during
             * config reloads. Dictionary buffer is copied into
             * ZSTD's internal memory so config pool cleanup can
             * safely free the original buf without affecting
             * in-flight compressions. */
            {
                ngx_pool_cleanup_t  *cln;

                cln = ngx_pool_cleanup_add(cf->pool, 0);
                if (cln == NULL) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "ngx_pool_cleanup_add() failed");
                    /*
                     * The CDict is allocated outside the config pool and is
                     * only reclaimed by the cleanup handler we failed to
                     * register. Free it here (and drop the dangling pointer)
                     * so a failed reload does not leak the external libzstd
                     * allocation while the master keeps running.
                     */
                    ZSTD_freeCDict(conf->dict);
                    conf->dict = NULL;
                    rc = NGX_CONF_ERROR;
                    goto close;
                }

                cln->handler = ngx_http_zstd_cleanup_dict;
                cln->data = conf->dict;
            }
        }
    }

close:

    if (fd != NGX_INVALID_FILE && ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_close_file_n " \"%V\" failed",
                           &zmcf->dict_file);

        rc = NGX_CONF_ERROR;
    }

    /*
     * Per-request CCtx memory budget (config-load assertion).
     *
     * zstd's streaming compressor working set is dominated by the
     * compression-level *strategy* tables (chain/hash/search), not by
     * the window alone — see the README. Lowering windowLog therefore
     * does NOT meaningfully bound memory for high levels (level 22 at
     * windowLog 20 still allocates ~640 MB). The honest, precise lever
     * is to validate the configured parameters against the operator's
     * budget at config load using libzstd's own estimator, and refuse
     * to start if they exceed it. The directive does not silently tune
     * anything — a too-tight budget is a hard error so operators see
     * the misconfiguration up front instead of discovering it as a
     * worker-RSS surprise under concurrency.
     *
     * The estimator API lives in libzstd's experimental section
     * (ZSTDLIB_STATIC_API), so the check is compiled in only when the
     * module is built with -DZSTD_STATIC_LINKING_ONLY against
     * libzstd >= 1.4.0 (the project's production and CI builds enable
     * this). Without it, the directive is unsupported and rejected with
     * an actionable error rather than silently no-op'd.
     */
    if (rc == NGX_CONF_OK && conf->enable
        && conf->max_cctx_memory != NGX_CONF_UNSET
        && conf->max_cctx_memory > 0)
    {
#if defined(ZSTD_STATIC_LINKING_ONLY) && ZSTD_VERSION_NUMBER >= 10400
        ZSTD_CCtx_params  *cp;
        size_t             est;
        size_t             srv;

        cp = ZSTD_createCCtxParams();
        if (cp == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "ZSTD_createCCtxParams() failed");
            return NGX_CONF_ERROR;
        }

        srv = ZSTD_CCtxParams_init(cp, (int) conf->level);
        if (ZSTD_isError(srv)) {
            ZSTD_freeCCtxParams(cp);
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "ZSTD_CCtxParams_init(level=%i) failed: %s",
                               conf->level, ZSTD_getErrorName(srv));
            return NGX_CONF_ERROR;
        }

        if (conf->window_log > 0) {
            srv = ZSTD_CCtxParams_setParameter(cp, ZSTD_c_windowLog,
                                               (int) conf->window_log);
            if (ZSTD_isError(srv)) {
                ZSTD_freeCCtxParams(cp);
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "ZSTD_CCtxParams_setParameter("
                                   "windowLog=%i) failed: %s",
                                   conf->window_log,
                                   ZSTD_getErrorName(srv));
                return NGX_CONF_ERROR;
            }
        }

        if (conf->long_mode) {
            srv = ZSTD_CCtxParams_setParameter(
                      cp, ZSTD_c_enableLongDistanceMatching, 1);
            if (ZSTD_isError(srv)) {
                ZSTD_freeCCtxParams(cp);
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "ZSTD_CCtxParams_setParameter("
                                   "enableLongDistanceMatching) failed: %s",
                                   ZSTD_getErrorName(srv));
                return NGX_CONF_ERROR;
            }
        }

#if ZSTD_VERSION_NUMBER >= 10506
        if (conf->target_cblock_size > 0) {
            srv = ZSTD_CCtxParams_setParameter(
                      cp, ZSTD_c_targetCBlockSize,
                      (int) conf->target_cblock_size);
            if (ZSTD_isError(srv)) {
                ZSTD_freeCCtxParams(cp);
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "ZSTD_CCtxParams_setParameter("
                                   "targetCBlockSize=%z) failed: %s",
                                   conf->target_cblock_size,
                                   ZSTD_getErrorName(srv));
                return NGX_CONF_ERROR;
            }
        }
#endif

        est = ZSTD_estimateCStreamSize_usingCCtxParams(cp);
        ZSTD_freeCCtxParams(cp);

        if (ZSTD_isError(est)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "ZSTD_estimateCStreamSize_usingCCtxParams() "
                               "failed: %s", ZSTD_getErrorName(est));
            return NGX_CONF_ERROR;
        }

        if (est > (size_t) conf->max_cctx_memory) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the configured zstd parameters need ~%uz "
                               "bytes of per-request compressor memory, "
                               "which exceeds \"zstd_max_cctx_memory\" %z; "
                               "lower \"zstd_comp_level\" (currently %i), "
                               "lower \"zstd_window_log\", disable "
                               "\"zstd_long\", or raise the budget",
                               est, conf->max_cctx_memory, conf->level);
            return NGX_CONF_ERROR;
        }
#else
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"zstd_max_cctx_memory\" requires the module "
                           "to be built with -DZSTD_STATIC_LINKING_ONLY "
                           "against libzstd >= 1.4.0 (memory-estimation "
                           "API); rebuild accordingly, or use "
                           "\"zstd_window_log\" for a coarse window-based "
                           "bound");
        return NGX_CONF_ERROR;
#endif
    }

    if (rc == NGX_CONF_OK && conf->enable) {
        const ngx_http_core_loc_conf_t  *clcf;

        /*
         * The advice below is wrong when the compression_vary filter
         * module is loaded — it emits Vary: Accept-Encoding from
         * r->gzip_vary without needing "gzip_vary on" — but its
         * presence alone cannot prove it is ENABLED for this location
         * (see ngx_http_zstd_vary_handled_externally()). So withhold
         * the per-location warning and count it; postconfiguration
         * reports one summary warning instead of N noisy ones.
         */
        clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
        if (clcf != NULL && !clcf->gzip_vary) {

            if (ngx_http_zstd_vary_handled_externally(cf)) {
                zmcf = ngx_http_conf_get_module_main_conf(cf,
                                               ngx_http_zstd_filter_module);
                if (zmcf != NULL) {
                    zmcf->vary_warn_suppressed++;
                }

            } else {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "zstd is enabled but \"gzip_vary\" is "
                                   "off; add \"gzip_vary on\" to emit "
                                   "\"Vary: Accept-Encoding\" so proxies "
                                   "and CDNs cache compressed and "
                                   "uncompressed responses separately");
            }
        }
    }

    return rc;
}


static ngx_int_t
ngx_http_zstd_filter_init(ngx_conf_t *cf)
{
    ngx_http_zstd_main_conf_t  *zmcf;

    /*
     * The per-location gzip_vary-off warnings withheld in
     * merge_loc_conf, folded into one line. Still a warning rather
     * than silence: "compression_vary" defaults to off in that module,
     * so its presence does not prove the Vary header is actually
     * emitted for these locations — and one module cannot read
     * another's merged configuration to check (private conf struct,
     * and merge order between unrelated modules is unspecified).
     * Postconfiguration runs after every merge, so the count is final.
     */
    zmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_zstd_filter_module);
    if (zmcf != NULL && zmcf->vary_warn_suppressed) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "zstd is enabled with \"gzip_vary\" off in %ui "
                           "location(s); the per-location warnings are "
                           "suppressed because "
                           "ngx_http_compression_vary_filter_module is "
                           "loaded, but its \"compression_vary\" directive "
                           "defaults to off; verify \"compression_vary "
                           "on\" covers those locations so "
                           "\"Vary: Accept-Encoding\" is emitted",
                           zmcf->vary_warn_suppressed);
    }

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_zstd_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_zstd_body_filter;

    return NGX_OK;
}


static ngx_int_t
ngx_http_zstd_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *v;

    v = ngx_http_add_variable(cf, &ngx_http_zstd_ratio,
                              NGX_HTTP_VAR_NOCACHEABLE);
    if (v == NULL) {
        return NGX_ERROR;
    }

    v->get_handler = ngx_http_zstd_ratio_variable;

    v = ngx_http_add_variable(cf, &ngx_http_zstd_bytes_in,
                              NGX_HTTP_VAR_NOCACHEABLE);
    if (v == NULL) {
        return NGX_ERROR;
    }

    v->get_handler = ngx_http_zstd_bytes_variable;
    v->data = offsetof(ngx_http_zstd_ctx_t, bytes_in);

    v = ngx_http_add_variable(cf, &ngx_http_zstd_bytes_out,
                              NGX_HTTP_VAR_NOCACHEABLE);
    if (v == NULL) {
        return NGX_ERROR;
    }

    v->get_handler = ngx_http_zstd_bytes_variable;
    v->data = offsetof(ngx_http_zstd_ctx_t, bytes_out);

    v = ngx_http_add_variable(cf, &ngx_http_zstd_dcz_dicts_hashed_name, 0);
    if (v == NULL) {
        return NGX_ERROR;
    }

    v->get_handler = ngx_http_zstd_dcz_dicts_hashed_variable;

    return NGX_OK;
}


/*
 * $zstd_dcz_dicts_hashed — how many dcz dictionaries were SHA-256'd at
 * config load in the request's ACTIVE configuration. 0 means every
 * registered dictionary carried a supplied hash (the fast path); the
 * dictionary count itself when none did. Constant for the lifetime of
 * the configuration; reads the cycle-owned main conf, so a rejected
 * reload cannot leak a refused config's count into this value.
 */
static ngx_int_t
ngx_http_zstd_dcz_dicts_hashed_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *vv, uintptr_t data)
{
    ngx_http_zstd_main_conf_t  *zmcf;

    (void) data;

    zmcf = ngx_http_get_module_main_conf(r, ngx_http_zstd_filter_module);

    /*
     * Consistency with merge_loc_conf(), filter_init() and both static-module
     * sites, which all guard this. The main conf is present whenever the
     * module is loaded, so this cannot fire today -- but a reader should not
     * have to prove that from four other call sites to know it is safe.
     */
    if (zmcf == NULL) {
        vv->not_found = 1;
        return NGX_OK;
    }

    vv->data = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (vv->data == NULL) {
        return NGX_ERROR;
    }

    vv->len = ngx_sprintf(vv->data, "%ui", zmcf->dcz_dicts_hashed)
              - vv->data;

    vv->valid = 1;
    vv->no_cacheable = 0;
    vv->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_zstd_ratio_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *vv, uintptr_t data)
{
    ngx_uint_t                  ratio_int, ratio_frac;
    const ngx_http_zstd_ctx_t  *ctx;

    (void) data;

    ctx = ngx_http_get_module_ctx(r, ngx_http_zstd_filter_module);
    if (ctx == NULL || !ctx->done || ctx->bytes_out == 0) {
        vv->not_found = 1;
        return NGX_OK;
    }

    /* Two ngx_uint_t values (up to NGX_INT_T_LEN digits each) + '.' + '\0' */
    vv->data = ngx_pnalloc(r->pool, NGX_INT_T_LEN * 2 + 2);
    if (vv->data == NULL) {
        return NGX_ERROR;
    }

    /*
     * Compute the scaled ratio once and derive both the integer and the
     * three-decimal fractional part from it, instead of dividing
     * bytes_in by bytes_out twice. uint64_t scaling is required anyway to
     * avoid overflow in the *1000 step, so the single division carries no
     * extra precondition over the previous two.
     */
    {
        uint64_t  scaled = (uint64_t) ctx->bytes_in * 1000 / ctx->bytes_out;

        ratio_int  = (ngx_uint_t) (scaled / 1000);
        ratio_frac = (ngx_uint_t) (scaled % 1000);
    }

    vv->len = ngx_sprintf(vv->data, "%ui.%03ui", ratio_int, ratio_frac)
              - vv->data;

    vv->valid = 1;
    vv->no_cacheable = 1;

    return NGX_OK;
}


/*
 * $zstd_bytes_in / $zstd_bytes_out — absolute byte counts for the
 * compressed response, complementing $zstd_ratio (which only gives the
 * ratio). `data` is the offsetof() of the ctx field to report, so one
 * handler serves both. Only set once the filter has finished compressing
 * this response (log phase), like $zstd_ratio.
 */
static ngx_int_t
ngx_http_zstd_bytes_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *vv, uintptr_t data)
{
    size_t                value;
    ngx_http_zstd_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_zstd_filter_module);
    if (ctx == NULL || !ctx->done) {
        vv->not_found = 1;
        return NGX_OK;
    }

    value = *(size_t *) ((char *) ctx + data);

    vv->data = ngx_pnalloc(r->pool, NGX_SIZE_T_LEN);
    if (vv->data == NULL) {
        return NGX_ERROR;
    }

    vv->len = ngx_sprintf(vv->data, "%uz", value) - vv->data;
    vv->valid = 1;
    vv->no_cacheable = 1;

    return NGX_OK;
}


static void
ngx_http_zstd_cleanup_cctx(void *data)
{
    ZSTD_CCtx *cctx = data;

    if (cctx != NULL) {
        ZSTD_freeCCtx(cctx);
    }
}


/*
 * Return a borrowed worker context to the cache at request end.
 *
 * Runs from the request pool's cleanup list, so it fires on every exit path --
 * normal completion, client abort, upstream error, worker shutdown of a live
 * request -- which is what makes `busy` a reliable loan flag rather than a leak
 * waiting for the one path that forgot to clear it.
 *
 * The session is reset HERE, not only on the next acquire: a request may be
 * abandoned mid-stream (client reset on a partially compressed response), and
 * leaving that half-finished frame state resident means the cached context
 * holds the previous response's compression state until something else
 * claims it.
 * init_cctx does reset before reuse, so this is defence in depth against a
 * future caller that forgets -- and it releases the session's internal buffers
 * promptly rather than pinning them until the next request arrives.
 */
static void
ngx_http_zstd_release_cctx(void *data)
{
    ZSTD_CCtx *cctx = data;

    if (cctx == NULL) {
        return;
    }

    if (cctx == ngx_http_zstd_worker_cctx) {
        (void) ZSTD_CCtx_reset(cctx, ZSTD_reset_session_only);
        ngx_http_zstd_worker_cctx_busy = 0;
        return;
    }

    /*
     * Not the cached context: the cache was replaced while this request held
     * its loan (only reachable if a future edit adds eviction). Own it.
     */
    ZSTD_freeCCtx(cctx);
}


/*
 * Free the worker's cached context at process exit.
 *
 * Without this the cache is a live allocation at shutdown, which LeakSanitizer
 * and Valgrind both report -- this tree gates on both, so a "harmless" one-off
 * worker-lifetime leak would be a red CI job, not a footnote. Any request still
 * holding a loan has already had its pool destroyed by the time module exit
 * handlers run, so the context is unowned here.
 */
static void
ngx_http_zstd_exit_process(ngx_cycle_t *cycle)
{
    if (ngx_http_zstd_worker_cctx != NULL) {
        ZSTD_freeCCtx(ngx_http_zstd_worker_cctx);
        ngx_http_zstd_worker_cctx = NULL;
    }

    ngx_http_zstd_worker_cctx_busy = 0;
}


static void
ngx_http_zstd_cleanup_dict(void *data)
{
    ZSTD_CDict  *dict = data;

    if (dict != NULL) {
        ZSTD_freeCDict(dict);
    }
}


/*
 * zstd_dcz_dict_file <path> — load one RFC 9842 dictionary. The file is
 * read and hashed here at config parse (nginx -t validates it), into
 * cf->pool so the raw bytes live exactly as long as the configuration
 * that references them. No CDict is built: the request path references
 * the bytes with ZSTD_CCtx_refPrefix(), which honors whatever
 * per-location parameters that request's CCtx carries — repeating the
 * trained-dict path's CDict-per-(level,window) merge matrix here would
 * buy latency only, and is deferred until profiling demands it.
 */
static char *
ngx_http_zstd_dcz_dict_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_zstd_loc_conf_t *zlcf = conf;

    off_t                      fsize;
    size_t                     size;
    ssize_t                    n;
    ngx_fd_t                   fd;
    ngx_str_t                 *value, path, bytes;
    ngx_uint_t                 i, have_hash;
    u_char                     c, hi, lo;
    u_char                     hash[NGX_HTTP_ZSTD_SHA256_DIGEST_LEN];
    ngx_file_info_t            info;
    ngx_http_zstd_dcz_dict_t  *dict, *dicts;
    ngx_http_zstd_main_conf_t *zmcf;

    (void) cmd;

    value = cf->args->elts;
    path = value[1];

    if (ngx_conf_full_name(cf->cycle, &path, 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    /*
     * Optional second argument: the dictionary's SHA-256 as 64 hex
     * characters, trusted VERBATIM in place of hashing the file here —
     * the win is skipping a full read-and-hash pass per dictionary at
     * every config parse (nginx -t, every reload), which dominates
     * parse time at hundreds of registered dictionaries. The deploy
     * tooling that generates the directive list has typically just
     * computed these hashes anyway (deduplication). The trade, and why
     * the argument is opt-in: with a self-computed hash a file that
     * changes on disk after clients stored it simply stops matching
     * (safe fallback to plain zstd); a stale supplied hash instead
     * keeps matching and the client decodes against the wrong
     * dictionary. The frame's content checksum (see checksumFlag in
     * init_cctx) makes that a visible decode error rather than silent
     * wrong bytes — visible is still broken, so the generator owns
     * hash correctness; content-hashed immutable assets are the
     * intended use.
     *
     * Validated before the file is opened so a malformed literal is
     * reported as such, not shadowed by file errors.
     */
    have_hash = (cf->args->nelts == 3);

    if (have_hash) {

        if (value[2].len != 2 * NGX_HTTP_ZSTD_SHA256_DIGEST_LEN) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid dcz dictionary hash \"%V\": want %d "
                               "hex characters (the file's SHA-256)",
                               &value[2],
                               2 * NGX_HTTP_ZSTD_SHA256_DIGEST_LEN);
            return NGX_CONF_ERROR;
        }

        for (i = 0; i < NGX_HTTP_ZSTD_SHA256_DIGEST_LEN; i++) {

            c = value[2].data[2 * i];
            hi = (c >= '0' && c <= '9') ? (u_char) (c - '0')
                 : (c >= 'a' && c <= 'f') ? (u_char) (c - 'a' + 10)
                 : (c >= 'A' && c <= 'F') ? (u_char) (c - 'A' + 10)
                 : 0xff;

            c = value[2].data[2 * i + 1];
            lo = (c >= '0' && c <= '9') ? (u_char) (c - '0')
                 : (c >= 'a' && c <= 'f') ? (u_char) (c - 'a' + 10)
                 : (c >= 'A' && c <= 'F') ? (u_char) (c - 'A' + 10)
                 : 0xff;

            if (hi == 0xff || lo == 0xff) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid dcz dictionary hash \"%V\": "
                                   "non-hex character", &value[2]);
                return NGX_CONF_ERROR;
            }

            hash[i] = (u_char) ((hi << 4) | lo);
        }
    }

    if (zlcf->dcz_dicts == NGX_CONF_UNSET_PTR) {
        zlcf->dcz_dicts = ngx_array_create(cf->pool, 2,
                                           sizeof(ngx_http_zstd_dcz_dict_t));
        if (zlcf->dcz_dicts == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    fd = ngx_open_file(path.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_open_file_n " \"%V\" failed", &path);
        return NGX_CONF_ERROR;
    }

    if (ngx_fd_info(fd, &info) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_fd_info_n " \"%V\" failed", &path);
        goto failed;
    }

    /*
     * off_t comparison before the size_t narrowing: see the matching
     * note in ngx_http_zstd_merge_loc_conf(). A >4 GiB file on ILP32
     * would otherwise wrap under the cap.
     */
    fsize = ngx_file_size(&info);

    if (fsize == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "dcz dictionary \"%V\" is empty", &path);
        goto failed;
    }

    if (fsize > (off_t) NGX_HTTP_ZSTD_MAX_DICT_SIZE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "dcz dictionary \"%V\" too large: %O bytes "
                           "(limit: %d bytes)",
                           &path, fsize, NGX_HTTP_ZSTD_MAX_DICT_SIZE);
        goto failed;
    }

    size = (size_t) fsize;

    /*
     * Between the window cap (2^23) and the hard limit above the frame
     * stays well-formed — the RFC's client guarantee is a floor of
     * max(8 MB, 1.25 x dict), so an 8 MB window is inside it for any
     * dictionary size — but bytes beyond the window are out of the
     * matcher's reach and the far end of the dictionary silently stops
     * contributing. That is a ratio cliff, not an error: warn at config
     * load instead of letting the operator discover it in telemetry.
     */
    if (size > ((size_t) 1 << NGX_HTTP_ZSTD_DCZ_MAX_WINDOW_LOG)) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "dcz dictionary \"%V\" is %uz bytes, larger than "
                           "the 8 MB dcz compression window; bytes beyond "
                           "the window cannot be referenced during "
                           "compression and only shrink the ratio benefit",
                           &path, size);
    }

    /*
     * Build the entry in locals and push it only once the file has been
     * read in full. Pushing first left a half-initialised element (NULL
     * bytes.data, uninitialised hash) in zlcf->dcz_dicts on every error
     * path below -- unreachable today because NGX_CONF_ERROR aborts the
     * load before anything walks the array, but that is a non-local
     * safety argument and the next reader should not have to rebuild it.
     */
    bytes.len = size;
    bytes.data = ngx_palloc(cf->pool, size);
    if (bytes.data == NULL) {
        goto failed;
    }

    n = ngx_read_fd(fd, (void *) bytes.data, size);
    if (n < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_read_fd_n " \"%V\" failed", &path);
        goto failed;

    } else if ((size_t) n != size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           ngx_read_fd_n " \"%V\" incomplete read", &path);
        goto failed;
    }

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_close_file_n " \"%V\" failed", &path);
        return NGX_CONF_ERROR;
    }

    if (!have_hash) {
        zmcf = ngx_http_conf_get_module_main_conf(cf,
                                                  ngx_http_zstd_filter_module);
        ngx_http_zstd_dcz_dict_hash(bytes.data, size, hash,
                                    &zmcf->dcz_dicts_hashed);
    }

    /*
     * Two entries with the same hash make the negotiation lookup
     * ambiguous (for computed hashes that means identical content under
     * two paths — almost certainly a config mistake, e.g. a copy that
     * was meant to be a new version; supplied hashes are compared as
     * declared). Fail loudly at load rather than silently matching the
     * first.
     */
    dicts = zlcf->dcz_dicts->elts;

    for (i = 0; i < zlcf->dcz_dicts->nelts; i++) {
        if (ngx_memcmp(dicts[i].hash, hash,
                       NGX_HTTP_ZSTD_SHA256_DIGEST_LEN) == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "dcz dictionary \"%V\" has the same hash "
                               "as \"%V\"", &path, &dicts[i].file);
            return NGX_CONF_ERROR;
        }
    }

    dict = ngx_array_push(zlcf->dcz_dicts);
    if (dict == NULL) {
        return NGX_CONF_ERROR;
    }

    dict->file = path;
    dict->bytes = bytes;
    ngx_memcpy(dict->hash, hash, NGX_HTTP_ZSTD_SHA256_DIGEST_LEN);

    return NGX_CONF_OK;

failed:

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_close_file_n " \"%V\" failed", &path);
    }

    return NGX_CONF_ERROR;
}


static char *
ngx_http_zstd_comp_level(ngx_conf_t *cf, void *post, void *data)
{
    const ngx_int_t  *np = data;

    (void)post;

    /*
     * Validate compression level range.
     * ZSTD supports both positive (1-22) and negative (-131072 to -1) levels.
     * - Positive levels: higher number = more compression
     * - Negative levels: faster speed, less compression
     * - 0: Use ZSTD default compression level (ZSTD_CLEVEL_DEFAULT)
     *
     * ZSTD_minCLevel() was introduced in zstd 1.4.0. On older libraries
     * (zstd < 1.4.0) negative levels are not supported; clamp to 1.
     */
#if ZSTD_VERSION_NUMBER >= 10400
    if (*np < (ngx_int_t) ZSTD_minCLevel() || *np > ZSTD_maxCLevel()) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "zstd compression level must be between %i and %i "
                           "(0 = default, negative = faster, positive = "
                           "slower/better)",
                           (ngx_int_t) ZSTD_minCLevel(), ZSTD_maxCLevel());
        return NGX_CONF_ERROR;
    }
#else
    if (*np < 1 || *np > ZSTD_maxCLevel()) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "zstd compression level must be between 1 and %i "
                           "(zstd < 1.4.0: negative levels not supported)",
                           ZSTD_maxCLevel());
        return NGX_CONF_ERROR;
    }
#endif

    return NGX_CONF_OK;
}


/*
 * Shared INT_MAX bound check for the size/num post-handlers below. The
 * value is rejected if negative (these directives have no meaningful
 * negative setting) or above INT_MAX, since both are later passed to
 * libzstd through an (int) cast. `name` is the directive label for the
 * error message.
 */
static char *
ngx_http_zstd_int_max_bound(ngx_conf_t *cf, ngx_int_t value,
    const char *name)
{
    if (value < 0 || value > INT_MAX) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%s\" must be between 0 and %d",
                           name, INT_MAX);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_zstd_check_size_int_max(ngx_conf_t *cf, void *post, void *data)
{
    ssize_t  *sp = data;
    char     *rc;

    (void) post;

    rc = ngx_http_zstd_int_max_bound(cf, (ngx_int_t) *sp,
                                     "zstd_target_cblock_size");
    if (rc != NGX_CONF_OK) {
        return rc;
    }

    /*
     * ZSTD_c_targetCBlockSize first works in libzstd 1.5.6. On older
     * versions the apply-site at ngx_http_zstd_filter_init_cctx() is
     * version-gated out — meaning the directive is silently ignored at
     * runtime with no feedback to the operator. Warn loudly at config load
     * so the config is recognisable as a no-op rather than appearing to
     * "work" while having no effect. The directive is still accepted (a
     * hard reject would break configs that intentionally target newer
     * libzstd at runtime via library upgrades without rebuilding nginx).
     * Suppress the warning when the value is 0 (the unset default).
     *
     * Gate on ZSTD_VERSION_NUMBER, not #ifndef ZSTD_c_targetCBlockSize:
     * the symbol is an enum member, so #ifndef was always true and this
     * warning fired even on libzstd >= 1.5.6 where the directive does work.
     */
#if ZSTD_VERSION_NUMBER < 10506
    if (*sp > 0) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "\"zstd_target_cblock_size\" is set but the "
                           "module was built against libzstd without "
                           "ZSTD_c_targetCBlockSize support (requires "
                           "libzstd >= 1.5.6); the directive will have "
                           "no effect at runtime");
    }
#else
    /*
     * On a library that supports the parameter, validate the configured
     * value against libzstd's own accepted range now, at config load. Once
     * C1 made the runtime apply path live, an out-of-range value would
     * otherwise pass nginx -t and then fail ZSTD_CCtx_setParameter() for
     * every request in the location (a 500 storm). 0 stays "unset". See C3.
     */
    if (*sp > 0) {
        ZSTD_bounds  b = ZSTD_cParam_getBounds(ZSTD_c_targetCBlockSize);

        if (ZSTD_isError(b.error)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "ZSTD_cParam_getBounds(targetCBlockSize) "
                               "failed: %s", ZSTD_getErrorName(b.error));
            return NGX_CONF_ERROR;
        }

        if ((ngx_int_t) *sp < b.lowerBound || (ngx_int_t) *sp > b.upperBound) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"zstd_target_cblock_size\" must be 0 "
                               "(default) or between %d and %d",
                               b.lowerBound, b.upperBound);
            return NGX_CONF_ERROR;
        }
    }
#endif

    return NGX_CONF_OK;
}


static char *
ngx_http_zstd_check_num_int_max(ngx_conf_t *cf, void *post, void *data)
{
    ngx_int_t  *np = data;
    char       *rc;

    (void) post;

    rc = ngx_http_zstd_int_max_bound(cf, *np, "zstd_window_log");
    if (rc != NGX_CONF_OK) {
        return rc;
    }

    /*
     * 0 means "unset" (keep zstd's level-derived default). Any other value
     * is passed straight to ZSTD_c_windowLog. Ask the linked library for the
     * actual accepted range with ZSTD_cParam_getBounds() — a stable-API call
     * (no ZSTD_STATIC_LINKING_ONLY needed) — instead of inlining hard-coded
     * constants that can drift from the library. libzstd would otherwise
     * reject an out-of-range value per-request (a 500 on every response for
     * this location); catching it at config load turns that into a clear
     * startup error instead. See C3.
     */
    if (*np != 0) {
        ZSTD_bounds  b = ZSTD_cParam_getBounds(ZSTD_c_windowLog);

        if (ZSTD_isError(b.error)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "ZSTD_cParam_getBounds(windowLog) failed: %s",
                               ZSTD_getErrorName(b.error));
            return NGX_CONF_ERROR;
        }

        if (*np < b.lowerBound || *np > b.upperBound) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"zstd_window_log\" must be 0 (default) or "
                               "between %d and %d", b.lowerBound, b.upperBound);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_conf_zstd_set_num_slot_with_negatives(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_int_t        *np;
    ngx_str_t        *value;


    np = (ngx_int_t *) (p + cmd->offset);

    /*
     * NGX_HTTP_ZSTD_LEVEL_UNSET, not NGX_CONF_UNSET: this slot serves
     * only zstd_comp_level, whose unset marker is out of band precisely
     * because NGX_CONF_UNSET (-1) is a valid level. Testing the shared
     * sentinel here let "zstd_comp_level -1; zstd_comp_level 5;" through
     * as if the first line had never been parsed.
     */
    if (*np != NGX_HTTP_ZSTD_LEVEL_UNSET) {
        return (char *) "is duplicate";
    }

    value = cf->args->elts;

    if (*(value[1].data) == '-') {
        /* Parse ignoring the leading '-' character */
        *np = ngx_atoi(value[1].data + 1, value[1].len - 1);

        /* NGX_ERROR is -1 so we need to check for that before making the
         * parsed result negative */
        if (*np == NGX_ERROR) {
            return (char *) "invalid number";
        }

        *np = -*np;
    } else {
        *np = ngx_atoi(value[1].data, value[1].len);

        if (*np == NGX_ERROR) {
            return (char *) "invalid number";
        }
    }

    if (cmd->post) {
        ngx_conf_post_t  *post = cmd->post;

        return post->post_handler(cf, post, np);
    }

    return NGX_CONF_OK;
}
