/*
 * nginx-compression — phase-0 prototype core (RFC: nginx-zstd-module
 * #109). One filter module, N backends, election by compression_order,
 * gzip by defer/veto. Throwaway by charter: the deliverable is the
 * backend interface and the seams, not production polish — the known
 * shortcuts are marked "PHASE0:" and collected in WRINKLES.md.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_compression.h"
#include "ngx_http_compression_ae.h"
#include "ngx_http_compression_dict.h"

/*
 * The parent's authoritative copies (#270 series): the Cache-Control
 * no-transform detection and the $ratio split. This module used to
 * carry a synchronized transplant of each; #251/#274 and then #294
 * were each hand-mirrored into it within days of merging upstream.
 */
#include "../src/ngx_http_zstd_cache_control.h"
#include "../src/ngx_http_zstd_ratio.h"


#if (NGX_HTTP_COMPRESSION_HAVE_ZSTD)
extern ngx_http_compression_backend_t  *ngx_http_compression_backend_zstd;
#endif
#if (NGX_HTTP_COMPRESSION_HAVE_BROTLI)
extern ngx_http_compression_backend_t  *ngx_http_compression_backend_brotli;
#endif

/* filled densely in preconfiguration (add_backends); static storage
 * zero-fills the NULL terminator for every NBACKENDS value */
ngx_http_compression_backend_t
    *ngx_http_compression_backends[NGX_HTTP_COMPRESSION_NBACKENDS + 1];


/* conf struct + token type moved to ngx_http_compression.h in phase 2:
 * the static handler TU shares them */


typedef struct {
    ngx_http_compression_backend_t  *backend;
    void                            *bctx;
    ngx_chain_t                     *in;
    /*
     * Tail of ctx->in (points at the last link's &->next, or at &ctx->in
     * when empty) so the body filter appends each callback's input in
     * O(1) instead of ngx_chain_add_copy() re-walking the whole retained
     * backlog every time — the backlog grows under downstream
     * backpressure, making the naive append O(n^2) (parent #157/#176).
     * Re-pointed at &ctx->in whenever the last retained link drains,
     * because ngx_free_chain() immediately overwrites that link's ->next.
     */
    ngx_chain_t                    **last_in;
    ngx_buf_t                       *ob;        /* current output buf */
    size_t                           out_size;

    /*
     * PHASE3: output-buffer recycling (the gzip filter's busy/free
     * pattern). Shipped bufs sit on `busy` until downstream drains
     * them; ngx_chain_update_chains reclaims drained ones onto
     * `free`, and get_buf prefers a reclaimed buf over a fresh
     * allocation. `allocated` counts live temp bufs against the
     * compression_buffers cap; at the cap with nothing reclaimable,
     * `nomem` stops production until a later invocation flushes the
     * busy chain — the backstop that keeps a slow client from pinning
     * unbounded output memory.
     */
    ngx_chain_t                     *free;
    ngx_chain_t                     *busy;
    ngx_uint_t                       allocated;
    ngx_uint_t                       bufs_num;

    /*
     * PHASE3 parity: $compression_ratio / _bytes_in / _bytes_out feed
     * from these, and max_length enforces the parents' running input
     * cap — the declared-length gate in the header filter only sees
     * the ADVERTISED length; a chunked or lying upstream can stream
     * unbounded input past it (worker CPU/memory exhaustion).
     */
    /*
     * uint64_t, not size_t (parent #200 row m7): on ILP32 a size_t
     * wraps at 4 GiB, silently corrupting $compression_bytes_* and
     * $compression_ratio for larger streamed responses.
     */
    uint64_t                         bytes_in;
    uint64_t                         bytes_out;
    ssize_t                          max_length;

    /*
     * The upstream-declared body length at election time, -1 when
     * none (parent #283). Captured here because the header filter
     * clears headers_out.content_length before the body streams, so
     * the running-cap abort below could no longer tell a misdeclaring
     * upstream ("declared 4 KB, streamed 40 MB") from a chunked one --
     * and logged "no Content-Length" for both.
     */
    off_t                            pledged_size;

    /*
     * PHASE1b: the elected dictionary variant's wire prologue,
     * prepared at election time and emitted ahead of the first
     * encoder byte (40 bytes dcz, 36 dcb; 0 = base coding).
     */
    u_char                           prologue[40];
    size_t                           prologue_len;

    unsigned                         done:1;
    unsigned                         started:1; /* encoder has consumed
                                                 * input: it (and maybe
                                                 * ctx->ob) holds bytes
                                                 * until FINISH drains —
                                                 * drives r->buffered */
    unsigned                         prologue_sent:1;
    unsigned                         nomem:1;
} ngx_http_compression_ctx_t;


static ngx_int_t ngx_http_compression_add_backends(ngx_conf_t *cf);
static void *ngx_http_compression_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_compression_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_compression_create_conf(ngx_conf_t *cf);
static char *ngx_http_compression_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_compression_order(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_compression_level_cmd(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_compression_window_cmd(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_compression_buffers_cmd(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_compression_check_bufs_product(ngx_conf_t *cf,
    ngx_bufs_t *bufs, ngx_flag_t unsafe, const char *ctx, ngx_flag_t advise);
static char *ngx_http_compression_set_enable_slot(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_compression_set_bypass_vary(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_compression_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_compression_ratio_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *vv, uintptr_t data);
static ngx_int_t ngx_http_compression_bytes_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *vv, uintptr_t data);
static ngx_int_t ngx_http_compression_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_compression_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_compression_retain_input(ngx_http_request_t *r,
    ngx_http_compression_ctx_t *ctx, ngx_chain_t *in);
static ngx_buf_t *ngx_http_compression_next_in_buf(
    ngx_http_compression_ctx_t *ctx, ngx_chain_t *in, ngx_uint_t *retained);
static void ngx_http_compression_consume_in_link(ngx_http_request_t *r,
    ngx_http_compression_ctx_t *ctx, ngx_chain_t **in, ngx_uint_t retained);


static ngx_conf_enum_t  ngx_http_compression_http_version_enum[] = {
    { ngx_string("1.0"), NGX_HTTP_VERSION_10 },
    { ngx_string("1.1"), NGX_HTTP_VERSION_11 },
    { ngx_null_string, 0 }
};


/*
 * The levels[] slots cannot use NGX_CONF_UNSET as their "not
 * configured" marker: NGX_CONF_UNSET is -1, and -1 is itself a valid
 * level for the zstd backend (its vtable declares negative fast
 * levels). With the shared sentinel, "compression_level zstd -1;" was
 * indistinguishable from an absent directive: the merge silently
 * replaced it with the inherited or default level, and the duplicate
 * guard in the level parser could never fire for it. Same trap the
 * parent closed for zstd_comp_level; the value is out of band for
 * every backend's declared range.
 */
#define NGX_HTTP_COMPRESSION_LEVEL_UNSET  (-NGX_MAX_INT_T_VALUE - 1)


static ngx_command_t  ngx_http_compression_commands[] = {

    { ngx_string("compression"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
                        |NGX_HTTP_LIF_CONF|NGX_CONF_FLAG,
      ngx_http_compression_set_enable_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_compression_conf_t, enable),
      NULL },

    { ngx_string("compression_order"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_compression_order,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("compression_level"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_compression_level_cmd,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("compression_window"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_compression_window_cmd,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("compression_bypass"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_set_predicate_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_compression_conf_t, bypass),
      NULL },

    { ngx_string("compression_bypass_vary"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_compression_set_bypass_vary,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_compression_conf_t, bypass_vary),
      NULL },

    { ngx_string("compression_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_compression_buffers_cmd,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("compression_buffers_unsafe"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_compression_conf_t, bufs_unsafe),
      NULL },

    { ngx_string("compression_http_version"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_compression_conf_t, http_version),
      &ngx_http_compression_http_version_enum },

    { ngx_string("compression_max_length"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_compression_conf_t, max_length),
      NULL },

    { ngx_string("compression_min_length"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_compression_conf_t, min_length),
      NULL },

    { ngx_string("compression_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_compression_conf_t, types_keys),
      &ngx_http_html_default_types[0] },

    { ngx_string("compression_dict_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
      ngx_http_compression_dict_file,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_compression_conf_t, dicts),
      NULL },

    { ngx_string("compression_dict_strict_path"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_compression_main_conf_t, dict_strict_path),
      NULL },

    /*
     * MAIN_CONF like strict_path, same reason: what a supplied hash
     * literal MEANS is a property of the whole load's trust model,
     * not of one location. Must precede every compression_dict_file
     * carrying a literal (enforced in init_main_conf).
     */
    { ngx_string("compression_dict_trust_hashes"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_compression_main_conf_t, dict_trust_hashes),
      NULL },

    { ngx_string("compression_dict_assume_secure_transport"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_compression_conf_t, dict_assume_secure),
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_compression_filter_module_ctx = {
    ngx_http_compression_add_backends,     /* preconfiguration */
    ngx_http_compression_init,             /* postconfiguration */

    ngx_http_compression_create_main_conf, /* create main configuration */
    ngx_http_compression_init_main_conf,   /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_compression_create_conf,      /* create location configuration */
    ngx_http_compression_merge_conf,       /* merge location configuration */
};


static ngx_int_t ngx_http_compression_init_module(ngx_cycle_t *cycle);

ngx_module_t  ngx_http_compression_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_compression_filter_module_ctx,      /* module context */
    ngx_http_compression_commands,         /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_http_compression_init_module,      /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


/*
 * Runtime feature-floor gate (parent #284). Only the zstd backend has
 * version-gated API territory (negative levels, libzstd >= 1.4.0);
 * the check lives in its TU and runs only when that backend is
 * compiled in. A cycle with no http block has no main conf and
 * nothing configured — that is a pass, not an error.
 */
static ngx_int_t
ngx_http_compression_init_module(ngx_cycle_t *cycle)
{
#if (NGX_HTTP_COMPRESSION_HAVE_ZSTD)
    ngx_http_compression_main_conf_t  *cmcf;

    cmcf = ngx_http_cycle_get_module_main_conf(
               cycle, ngx_http_compression_filter_module);
    if (cmcf == NULL) {
        return NGX_OK;
    }

    return ngx_http_compression_zstd_verify_runtime(
               cycle, cmcf->any_negative_zstd_level);
#else
    (void) cycle;
    return NGX_OK;
#endif
}


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


/*
 * Default compression_types, mirrored from the parent zstd filter
 * (parent parity for migrators — the phase-0 html-only default was a
 * silent regression against it, caught reading GetPageSpeed's fork
 * via issue #123; the wasm/wgsl entries ride along, text-like formats
 * under non-text media types). The DIRECTIVE parser's post value
 * stays ngx_http_html_default_types: an explicitly configured list
 * keeps nginx's long-standing "text/html plus the configured types"
 * behaviour.
 */
static ngx_str_t  ngx_http_compression_default_types[] = {
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

static ngx_str_t  ngx_http_compression_gzip_token = ngx_string("gzip");


/* the vary/ae_header helpers moved to ngx_http_compression_ae.h as
 * header-statics with the filter/static module split: each module
 * carries its own copy, so neither .so links the other's symbols */


/*
 * PHASE1b: RFC 9842 negotiation. The client names the dictionary it
 * holds via Available-Dictionary — an RFC 8941 Byte Sequence, i.e.
 * `:<base64 of the raw SHA-256>:` — and it matches (or doesn't)
 * against this location's list of store entries. First match wins;
 * the lists are short by construction (a handful of dictionaries per
 * location), so a linear scan is the right tool.
 */
/*
 * Dictionary lookup by digest (parent #322). Up to the threshold a
 * linear memcmp over the pointer array is the cheaper scan; above it
 * the array is sorted by digest at config load (ngx_http_compression_
 * dicts_sort() from merge_loc_conf) and searched binarily. Equal
 * digests never coexist -- the store refuses a duplicate hash at
 * declaration -- so the order is unambiguous and the search exact.
 * The threshold is the parent's, from its dcz lookup measurement
 * (ci/tools/dcz_refprefix_cost_bench.sh); a deployment with hundreds
 * of dictionaries paid the full scan on every negotiated request.
 */
#define NGX_HTTP_COMPRESSION_DICT_BSEARCH_THRESHOLD  16

static int ngx_libc_cdecl
ngx_http_compression_dict_cmp(const void *one, const void *two)
{
    const ngx_http_compression_dict_t *const  *a = one;
    const ngx_http_compression_dict_t *const  *b = two;

    return ngx_memcmp((*a)->sha256, (*b)->sha256,
                      NGX_HTTP_COMPRESSION_SHA256_LEN);
}


static void
ngx_http_compression_dicts_sort(ngx_array_t *dicts)
{
    if (dicts != NULL && dicts->nelts > 1) {
        ngx_qsort(dicts->elts, (size_t) dicts->nelts,
                  sizeof(ngx_http_compression_dict_t *),
                  ngx_http_compression_dict_cmp);
    }
}


static ngx_http_compression_dict_t *
ngx_http_compression_dict_lookup(ngx_array_t *dicts,
    const u_char raw[NGX_HTTP_COMPRESSION_SHA256_LEN])
{
    ngx_int_t                       lo, hi, mid, c;
    ngx_uint_t                      i;
    ngx_http_compression_dict_t   **list;

    list = dicts->elts;

    if (dicts->nelts > NGX_HTTP_COMPRESSION_DICT_BSEARCH_THRESHOLD) {
        lo = 0;
        hi = (ngx_int_t) dicts->nelts - 1;

        while (lo <= hi) {
            mid = lo + (hi - lo) / 2;
            c = ngx_memcmp(list[mid]->sha256, raw,
                           NGX_HTTP_COMPRESSION_SHA256_LEN);

            if (c == 0) {
                return list[mid];
            }

            if (c < 0) {
                lo = mid + 1;

            } else {
                hi = mid - 1;
            }
        }

        return NULL;
    }

    for (i = 0; i < dicts->nelts; i++) {
        if (ngx_memcmp(list[i]->sha256, raw,
                       NGX_HTTP_COMPRESSION_SHA256_LEN) == 0)
        {
            return list[i];
        }
    }

    return NULL;
}


static ngx_http_compression_dict_t *
ngx_http_compression_match_dict(ngx_http_request_t *r,
    ngx_http_compression_conf_t *conf)
{
    /*
     * Decode target: sized by ngx_base64_decoded_length(44) = 33, NOT
     * by the hash length — the macro is an upper bound that ignores
     * padding, and a pad-less 44-char value legitimately decodes to
     * 33 bytes. Sizing this at 32 was a one-byte overflow waiting for
     * a malicious header; the dst.len == 32 check below rejects that
     * input AFTER it decoded safely.
     */
    u_char                         raw[36];
    u_char                        *p, *last;
    ngx_str_t                      b64, dst;
    ngx_uint_t                     i, ad_n, sfs_n;
    ngx_list_part_t               *part;
    ngx_table_elt_t               *h, *ad, *sfs;

    if (conf->dicts == NULL || conf->dicts->nelts == 0) {
        return NULL;
    }

    /*
     * RFC 9842 §8 secure-context gate (parent #158), fail-closed and
     * ahead of every other test: no dictionary coding — dcz or dcb — is
     * elected over a non-secure connection, because a dictionary-
     * compressed response over cleartext is a length oracle over content
     * the dictionary already describes. The context is secure when this
     * nginx terminates TLS. The guard mirrors ngx_connection_t's own
     * condition for the ssl member (#if (NGX_SSL || NGX_COMPAT)), not
     * NGX_SSL alone: this module ships --with-compat, where the field
     * exists (always NULL) without an SSL-capable nginx. HTTP/2 and
     * HTTP/3 both carry a non-NULL connection->ssl, so neither is
     * excluded. A TLS-terminating proxy makes ssl NULL here; that
     * deployment opts back in with compression_dict_assume_secure_transport
     * — an operator acknowledgement, never inferred from a client-settable
     * X-Forwarded-Proto or sibling.
     */
    if (!conf->dict_assume_secure) {
        ngx_flag_t  secure;

#if (NGX_SSL || NGX_COMPAT)
        secure = (r->connection->ssl != NULL);
#else
        secure = 0;
#endif

        if (!secure) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "compression: dict skip, not a secure context "
                           "(RFC 9842 §8); set "
                           "\"compression_dict_assume_secure_transport on\" "
                           "if TLS terminates upstream");
            return NULL;
        }
    }

    /* no built-in fields for Available-Dictionary or Sec-Fetch-Site:
     * one generic list walk collects both */
    ad = NULL;
    sfs = NULL;
    ad_n = 0;
    sfs_n = 0;
    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
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
            ad = &h[i];
            ad_n++;

        } else if (h[i].key.len == sizeof("Sec-Fetch-Site") - 1
                   && ngx_strncasecmp(h[i].key.data,
                                      (u_char *) "Sec-Fetch-Site",
                                      sizeof("Sec-Fetch-Site") - 1) == 0)
        {
            sfs = &h[i];
            sfs_n++;
        }
    }

    /*
     * Fail closed on duplicates (parent's #140, ported): neither header
     * is in nginx's ngx_http_headers_in table, so neither gets
     * ngx_http_process_unique_header_line's duplicate rejection — a
     * request can reach this walk carrying two of either, and the walk
     * above keeps the LAST occurrence. For Sec-Fetch-Site that is the
     * RFC 9842 §8.3 cross-origin partitioning gate: a proxy that merges
     * a client-supplied duplicate, or a request-smuggling desync, must
     * not be able to switch the gate off by APPENDING an agreeable
     * value (the mirror image of the parent's first-match hazard).
     * Both headers are single-valued by their specifications and a
     * browser never sends either twice, so refusing the dictionary
     * coding costs nothing — the response degrades to the base coding.
     */
    if (ad_n > 1 || sfs_n > 1) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "compression: duplicate negotiation header "
                       "(Available-Dictionary x%ui, Sec-Fetch-Site x%ui), "
                       "dictionary coding refused", ad_n, sfs_n);
        return NULL;
    }

    if (ad == NULL || ad->value.len == 0) {
        return NULL;
    }

    /*
     * Sec-Fetch-Site gate (parent parity, RFC 9842 §8.3 territory,
     * caught by the parent-suite audit): dictionaries are
     * same-origin-partitioned secrets — a cross-site response
     * compressed against one leaks it. When the header is present it
     * must say "same-origin" or "none"; browsers always send it, so
     * absence means a non-browser client where the cross-origin read
     * model does not apply.
     */
    if (sfs != NULL
        && !(sfs->value.len == sizeof("same-origin") - 1
             && ngx_strncasecmp(sfs->value.data, (u_char *) "same-origin",
                                sizeof("same-origin") - 1) == 0)
        && !(sfs->value.len == sizeof("none") - 1
             && ngx_strncasecmp(sfs->value.data, (u_char *) "none",
                                sizeof("none") - 1) == 0))
    {
        /*
         * Log the LENGTH, not the raw value (parent #168 row 7): the
         * header is client-controlled and could carry terminal control
         * bytes (obs-text, ESC, DEL) that would corrupt or inject into
         * the error log. The reason ("not same-origin/none") is already
         * implicit in reaching this branch; the length is enough to
         * correlate with the request. Debug-gated, so exposure is low —
         * but bounding it costs nothing.
         */
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "compression: dict skip, Sec-Fetch-Site not "
                       "same-origin/none (%uz bytes)", sfs->value.len);
        return NULL;
    }

    /* strict RFC 8941 byte-sequence shape: OWS ":" base64 ":" OWS */
    p = ad->value.data;
    last = ad->value.data + ad->value.len;

    while (p < last && (*p == ' ' || *p == '\t')) { p++; }
    while (last > p && (last[-1] == ' ' || last[-1] == '\t')) { last--; }

    if (last - p < 2 || *p != ':' || last[-1] != ':') {
        return NULL;    /* malformed: negotiate nothing, serve base */
    }

    b64.data = p + 1;
    b64.len = (last - 1) - (p + 1);

    /*
     * base64 of exactly 32 bytes is exactly 44 characters. Checked by
     * ENCODED length, not ngx_base64_decoded_length() — that macro is
     * an upper bound that ignores '=' padding (44 chars → 33), and
     * comparing it against 32 rejected every valid header this
     * negotiation exists to read (caught by the fallback matrix: all
     * dict elections silently degraded to base codings).
     */
    if (b64.len != 44) {
        return NULL;
    }

    dst.data = raw;
    if (ngx_decode_base64(&dst, &b64) != NGX_OK
        || dst.len != NGX_HTTP_COMPRESSION_SHA256_LEN)
    {
        return NULL;
    }

    return ngx_http_compression_dict_lookup(conf->dicts, raw);
}


/* the gzip-less Accept-Encoding walk moved into
 * ngx_http_compression_ae_header() above (phase 2: the static handler
 * needs it too) */


static ngx_int_t
ngx_http_compression_add_backends(ngx_conf_t *cf)
{
    ngx_uint_t  n;

    (void) cf;

    /*
     * Filled here rather than by static initializer only because the
     * backends live in separate TUs exporting pointers. Fill is DENSE
     * under the HAVE guards — a library-less build compacts the
     * registry instead of leaving a hole, so registry position stays
     * a valid conf-slot index everywhere.
     */
    n = 0;

#if (NGX_HTTP_COMPRESSION_HAVE_ZSTD)
    ngx_http_compression_backends[n++] = ngx_http_compression_backend_zstd;
#endif

#if (NGX_HTTP_COMPRESSION_HAVE_BROTLI)
    ngx_http_compression_backends[n++] = ngx_http_compression_backend_brotli;
#endif

    ngx_http_compression_backends[n] = NULL;

    /*
     * $compression_ratio / $compression_bytes_in / $compression_bytes_out
     * (parent $zstd_* parity): log-phase variables fed by the ctx
     * counters; not_found until the response finished compressing.
     *
     * No blanket NGX_HTTP_VAR_NOCACHEABLE (parent #184): each handler
     * sets vv->no_cacheable per call instead — 1 while compression has
     * not finished (ctx missing / !done, a retryable not_found), 0 once
     * it reports the final value. nginx's flushed-variable cache retries
     * an early no_cacheable lookup but reuses a cacheable one, so a
     * request that references one of these more than once (e.g. a
     * rewrite-phase set and the access log) formats the final value once
     * and reuses it — versus reformatting, and redoing $compression_ratio's
     * 64-bit scaled division, on every lookup under the blanket flag.
     */
    {
        ngx_http_variable_t  *var;

        static ngx_str_t  ratio_name = ngx_string("compression_ratio");
        static ngx_str_t  in_name = ngx_string("compression_bytes_in");
        static ngx_str_t  out_name = ngx_string("compression_bytes_out");

        var = ngx_http_add_variable(cf, &ratio_name, 0);
        if (var == NULL) {
            return NGX_ERROR;
        }
        var->get_handler = ngx_http_compression_ratio_variable;

        var = ngx_http_add_variable(cf, &in_name, 0);
        if (var == NULL) {
            return NGX_ERROR;
        }
        var->get_handler = ngx_http_compression_bytes_variable;
        var->data = offsetof(ngx_http_compression_ctx_t, bytes_in);

        var = ngx_http_add_variable(cf, &out_name, 0);
        if (var == NULL) {
            return NGX_ERROR;
        }
        var->get_handler = ngx_http_compression_bytes_variable;
        var->data = offsetof(ngx_http_compression_ctx_t, bytes_out);
    }

    return ngx_http_compression_dict_add_variables(cf);
}


static void *
ngx_http_compression_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_compression_main_conf_t  *cmcf;

    cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_compression_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&cmcf->store, cf->pool, 4,
                       sizeof(ngx_http_compression_dict_t *))
        != NGX_OK)
    {
        return NULL;
    }

    /* pcalloc zeroes dicts_hashed and the ordering records —
     * cycle-owned, no reset hook */

    cmcf->dict_strict_path = NGX_CONF_UNSET;
    cmcf->dict_trust_hashes = NGX_CONF_UNSET;

    return cmcf;
}


static char *
ngx_http_compression_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_compression_main_conf_t  *cmcf = conf;

    ngx_conf_init_value(cmcf->dict_strict_path, 0);   /* off by default */
    ngx_conf_init_value(cmcf->dict_trust_hashes, 0);  /* verify default */

    /*
     * Same ordering rejection as strict_path below, with the opposite
     * polarity: a literal that loaded before a later
     * "compression_dict_trust_hashes on;" was VERIFIED — correct
     * bytes, but the hashing pass the directive exists to skip was
     * silently paid, which at hundreds of dictionaries is the entire
     * cost. Reject rather than be quietly position-dependent.
     */
    if (cmcf->dict_trust_hashes == 1
        && cmcf->dict_verified_before_trust_on)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"compression_dict_trust_hashes on\" was "
                           "declared AFTER \"compression_dict_file %V\", "
                           "whose hash literal had already been verified "
                           "(hashed) by that point. nginx directives are "
                           "order-independent by convention, but this one "
                           "is not: move \"compression_dict_trust_hashes "
                           "on;\" before every \"compression_dict_file\" "
                           "directive it must apply to",
                           &cmcf->dict_verified_before_trust_on_file);
        return NGX_CONF_ERROR;
    }

    /*
     * Reject the ordering rather than silently accept an unchecked
     * load: ngx_http_compression_dict_file() records the first time
     * it loads a dictionary while dict_strict_path did not yet read
     * as the explicit "on". If the flag's FINAL value is "on", every
     * such recorded load ran without the O_NOFOLLOW / writable-target
     * checks this directive exists to apply — fail the config rather
     * than start with a dictionary the operator asked to have vetted
     * but that never was. nginx directives are conventionally
     * order-independent, so this is a real operator trap, not
     * pedantry. (Parent's init_main_conf carries the same check.)
     */
    if (cmcf->dict_strict_path == 1
        && cmcf->dict_loaded_before_strict_on)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"compression_dict_strict_path on\" was "
                           "declared AFTER \"compression_dict_file %V\", "
                           "which had already loaded unchecked by that "
                           "point. nginx directives are order-independent "
                           "by convention, but this one is not: move "
                           "\"compression_dict_strict_path on;\" before "
                           "every \"compression_dict_file\" directive it "
                           "must apply to",
                           &cmcf->dict_loaded_before_strict_on_file);
        return NGX_CONF_ERROR;
    }

    /*
     * Preformat $compression_dicts_hashed once (parent #154): every
     * compression_dict_file has been parsed and hashed by now — all
     * increments live in that directive handler, which runs before
     * init_main_conf — so the count is final and constant for the
     * worker's life. The variable handler then just points at these
     * bytes instead of ngx_sprintf'ing per lookup.
     */
    cmcf->dicts_hashed_str.data = ngx_pnalloc(cf->pool, NGX_INT_T_LEN);
    if (cmcf->dicts_hashed_str.data == NULL) {
        return NGX_CONF_ERROR;
    }
    cmcf->dicts_hashed_str.len =
        ngx_sprintf(cmcf->dicts_hashed_str.data, "%ui", cmcf->dicts_hashed)
        - cmcf->dicts_hashed_str.data;

    return NGX_CONF_OK;
}


/*
 * PHASE3 tuning directives. Phase 0 rejected one unified level VALUE
 * (zstd 3 and brotli 6 are both "the sane default" yet share no axis
 * — wrinkle #8); what survives is one unified level NAME, keyed by
 * coding: `compression_level zstd 9` / `compression_level br 11`.
 * The backend declares its scale's bounds and default in the vtable,
 * so a new coding gets both directives for free with its registry
 * entry — and the tokens that are NOT backends (gzip, dcz/dcb) get
 * educational rejections instead of silently doing nothing.
 */

/*
 * Coding names whose backend is compiled OUT of this build, for
 * error text: "unknown coding" would be wrong advice when the fix is
 * the build line, not the config. Returns NULL when the token is not
 * a compiled-out coding.
 */
static const char *
ngx_http_compression_absent_coding(ngx_str_t *token)
{
#if !(NGX_HTTP_COMPRESSION_HAVE_ZSTD)
    if ((token->len == 4 && ngx_strncmp(token->data, "zstd", 4) == 0)
        || (token->len == 3 && ngx_strncmp(token->data, "dcz", 3) == 0))
    {
        return "zstd";
    }
#endif

#if !(NGX_HTTP_COMPRESSION_HAVE_BROTLI)
    if ((token->len == 2 && ngx_strncmp(token->data, "br", 2) == 0)
        || (token->len == 3 && ngx_strncmp(token->data, "dcb", 3) == 0))
    {
        return "brotli";
    }
#endif

    (void) token;
    return NULL;
}


/*
 * Resolve a directive's coding token to a registry index. Returns
 * NGX_ERROR after logging when the token is known but not tunable
 * here (gzip, dict codings) or unknown entirely; `what` names the
 * directive for the message.
 */
static ngx_int_t
ngx_http_compression_tuning_index(ngx_conf_t *cf, ngx_str_t *token,
    const char *what)
{
    ngx_int_t                        i;
    ngx_http_compression_backend_t  *b;

    /* terminator-walked, not count-walked: compiles warning-free at
     * every NBACKENDS including zero */
    for (i = 0; ngx_http_compression_backends[i] != NULL; i++) {
        b = ngx_http_compression_backends[i];

        if (token->len == b->coding.len
            && ngx_strncmp(token->data, b->coding.data, token->len) == 0)
        {
            return i;
        }

        if (b->dict_coding.len != 0
            && token->len == b->dict_coding.len
            && ngx_strncmp(token->data, b->dict_coding.data,
                           token->len) == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%V\" is tuned through its base coding: "
                               "use \"%s %V ...\" (a dictionary variant "
                               "shares the base coding's parameters)",
                               token, what, &b->coding);
            return NGX_ERROR;
        }
    }

    if (token->len == 4 && ngx_strncmp(token->data, "gzip", 4) == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "gzip is compressed by the core gzip filter "
                           "(defer/veto): tune it with the core "
                           "\"gzip_comp_level\" directive, not \"%s\"",
                           what);
        return NGX_ERROR;
    }

    {
        const char  *absent = ngx_http_compression_absent_coding(token);

        if (absent != NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "coding \"%V\" in \"%s\" is not available: "
                               "this nginx was built without %s support",
                               token, what, absent);
            return NGX_ERROR;
        }
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "unknown coding \"%V\" in \"%s\"", token, what);
    return NGX_ERROR;
}


static char *
ngx_http_compression_level_cmd(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_compression_conf_t *ccf = conf;

    u_char                            *p;
    size_t                             len;
    ngx_int_t                          i, n;
    ngx_str_t                         *value;
    ngx_uint_t                         neg;
    ngx_http_compression_backend_t    *b;
    ngx_http_compression_main_conf_t  *cmcf;

    (void) cmd;

    value = cf->args->elts;

    i = ngx_http_compression_tuning_index(cf, &value[1],
                                          "compression_level");
    if (i == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    b = ngx_http_compression_backends[i];

    /* ngx_atoi has no sign handling; zstd's fast levels are negative */
    p = value[2].data;
    len = value[2].len;
    neg = 0;

    if (len > 0 && p[0] == '-') {
        neg = 1;
        p++;
        len--;
    }

    n = ngx_atoi(p, len);
    if (n == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid level \"%V\" in \"compression_level\"",
                           &value[2]);
        return NGX_CONF_ERROR;
    }

    if (neg) {
        n = -n;
    }

    if (n < b->level_min || n > b->level_max) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "compression level for \"%V\" must be between "
                           "%i and %i", &b->coding, b->level_min,
                           b->level_max);
        return NGX_CONF_ERROR;
    }

    if (n < 0) {
        /* only the zstd scale admits negatives (see the vtable
         * bounds); latch for init_module's runtime floor check */
        cmcf = ngx_http_conf_get_module_main_conf(
                   cf, ngx_http_compression_filter_module);
        cmcf->any_negative_zstd_level = 1;
    }

    if (ccf->levels[i] != NGX_HTTP_COMPRESSION_LEVEL_UNSET) {
        return "is duplicate";
    }

    ccf->levels[i] = n;

    return NGX_CONF_OK;
}


/*
 * compression_buffers <num> [size] — TAKE12 rather than the stock
 * bufs slot's TAKE2 because size is genuinely optional here: the
 * backend already recommends a step size (out_size), so most
 * operators only ever want the COUNT cap. An explicit size overrides
 * the recommendation; the dict-prologue clamp applies to either.
 */
static char *
ngx_http_compression_buffers_cmd(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_compression_conf_t *ccf = conf;

    ssize_t     size;
    ngx_int_t   n;
    ngx_str_t  *value;

    (void) cmd;

    if (ccf->bufs.num != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    n = ngx_atoi(value[1].data, value[1].len);
    if (n == NGX_ERROR || n < 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid number \"%V\" in \"compression_buffers\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    size = 0;   /* backend-recommended */

    if (cf->args->nelts == 3) {
        size = ngx_parse_size(&value[2]);
        if (size == NGX_ERROR || size == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid size \"%V\" in "
                               "\"compression_buffers\"", &value[2]);
            return NGX_CONF_ERROR;
        }
    }

    ccf->bufs.num = n;
    ccf->bufs.size = (size_t) size;

    /*
     * Overflow-only check on an EXPLICIT value at the earliest point
     * (#167). advise=0: the advisory/hard-cap tiers are owned by the
     * post-merge check alone — it is the only site that also covers an
     * inherited or defaulted value, and the only one where the merged
     * bufs_unsafe flag is final (the flag may appear before or after
     * this directive, or at an outer level). A size of 0
     * (backend-recommended) is unbounded here and the helper returns OK.
     */
    return ngx_http_compression_check_bufs_product(cf, &ccf->bufs, 0,
                                                   "explicit directive", 0);
}


/*
 * Aggregate memory bound for compression_buffers number*size (#167).
 *
 * The parse handler above range-checks each argument independently but
 * never their product, and neither an inherited value nor the module's
 * own default (32 bufs, backend-recommended size) re-validates the pair.
 * A typo ("compression_buffers 100000 100000;" for "100 100k;") or a
 * value inherited from an outer block could request an overflowing or
 * merely enormous per-response OUTPUT-chain pool that nginx commits for
 * every concurrent response.
 *
 * Three tiers on the representable (non-overflowing) product:
 *   <= 8 MB   silent (the ordinary range; the 32-buf default lands far
 *             under it);
 *   >  8 MB, <= 256 MB   warn — large, but a config that loads today
 *             keeps loading;
 *   >  256 MB  emerg, refused UNLESS compression_buffers_unsafe on:
 *             number and size are two integers the operator wrote
 *             literally, so at this magnitude a refusal-by-default is the
 *             safe reading of "probably a mistake", with an explicit
 *             opt-out for the deployment that means it.
 * Overflow is refused unconditionally — no size means "the operator
 * meant this", so no acknowledgement spelling exists for it.
 *
 * A size of 0 means "backend-recommended", resolved small at runtime and
 * not knowable here, so the product is not bounded in that case.
 */
#ifndef NGX_HTTP_COMPRESSION_BUFS_ADVISORY_BYTES
#define NGX_HTTP_COMPRESSION_BUFS_ADVISORY_BYTES  (8 * 1024 * 1024)
#endif

#ifndef NGX_HTTP_COMPRESSION_BUFS_HARD_CAP_BYTES
#define NGX_HTTP_COMPRESSION_BUFS_HARD_CAP_BYTES  (256 * 1024 * 1024)
#endif

static char *
ngx_http_compression_check_bufs_product(ngx_conf_t *cf, ngx_bufs_t *bufs,
    ngx_flag_t unsafe, const char *ctx, ngx_flag_t advise)
{
    size_t  total;

    if (bufs->num <= 0 || bufs->size == 0) {
        /* size 0 = backend-recommended (unbounded here); num<1 is already
         * rejected at parse — defend anyway rather than assume */
        return NGX_CONF_OK;
    }

    /*
     * Division-based pre-check, not "num * size < num": bufs->num is a
     * signed ngx_int_t, so comparing the already-wrapped product would
     * itself be operating on signed overflow (undefined behaviour).
     * Comparing against NGX_MAX_SIZE_T_VALUE / size never multiplies past
     * the type's range at all.
     */
    if ((size_t) bufs->num > NGX_MAX_SIZE_T_VALUE / bufs->size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"compression_buffers\" (%s) requests "
                           "%i x %uz bytes, which overflows the address "
                           "space", ctx, bufs->num, bufs->size);
        return NGX_CONF_ERROR;
    }

    if (!advise) {
        return NGX_CONF_OK;
    }

    total = (size_t) bufs->num * bufs->size;

    if (total > NGX_HTTP_COMPRESSION_BUFS_HARD_CAP_BYTES) {

        if (unsafe) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "\"compression_buffers\" (%s) requests "
                               "%i x %uz bytes = ~%uz bytes of output-chain "
                               "memory PER RESPONSE, above the %d MB hard "
                               "cap; accepted because "
                               "\"compression_buffers_unsafe on;\" "
                               "acknowledges it. That total is multiplied "
                               "by concurrent responses under load",
                               ctx, bufs->num, bufs->size, total,
                               (int) (NGX_HTTP_COMPRESSION_BUFS_HARD_CAP_BYTES
                                      / (1024 * 1024)));
            return NGX_CONF_OK;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"compression_buffers\" (%s) requests "
                           "%i x %uz bytes = ~%uz bytes of output-chain "
                           "memory PER RESPONSE, above the %d MB hard cap "
                           "— that is multiplied by concurrent responses "
                           "under load. Lower \"compression_buffers\", or "
                           "set \"compression_buffers_unsafe on;\" to "
                           "acknowledge this total is intentional",
                           ctx, bufs->num, bufs->size, total,
                           (int) (NGX_HTTP_COMPRESSION_BUFS_HARD_CAP_BYTES
                                  / (1024 * 1024)));
        return NGX_CONF_ERROR;
    }

    if (total > NGX_HTTP_COMPRESSION_BUFS_ADVISORY_BYTES) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "\"compression_buffers\" (%s) requests "
                           "%i x %uz bytes = ~%uz bytes of output-chain "
                           "memory PER RESPONSE, multiplied by concurrent "
                           "responses under load",
                           ctx, bufs->num, bufs->size, total);
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_compression_window_cmd(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_compression_conf_t *ccf = conf;

    ssize_t                          size;
    ngx_int_t                        i, bits;
    ngx_str_t                       *value;
    ngx_http_compression_backend_t  *b;

    (void) cmd;

    value = cf->args->elts;

    i = ngx_http_compression_tuning_index(cf, &value[1],
                                          "compression_window");
    if (i == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    b = ngx_http_compression_backends[i];

    size = ngx_parse_size(&value[2]);
    if (size == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid size \"%V\" in \"compression_window\"",
                           &value[2]);
        return NGX_CONF_ERROR;
    }

    /* the window is a power of two by both formats' definition; the
     * directive takes the human SIZE (512k, 8m) and stores its log2 */
    for (bits = b->window_bits_min; bits <= b->window_bits_max; bits++) {
        if (size == (ssize_t) 1 << bits) {
            break;
        }
    }

    if (bits > b->window_bits_max) {
        u_char     list[192], *p;
        ngx_int_t  i;
        ngx_str_t  vals;

        /*
         * The valid set is small and finite, so enumerate it in the
         * config's own notation (google's brotli_window error does
         * the same) — strictly more actionable than raw byte counts
         * for a message a human reads exactly once at config load.
         */
        p = list;

        for (i = b->window_bits_min; i <= b->window_bits_max; i++) {
            if (i > b->window_bits_min) {
                p = ngx_cpymem(p, ", ", 2);
            }
            if (i >= 20) {
                p = ngx_snprintf(p, list + sizeof(list) - p, "%uim",
                                 (ngx_uint_t) 1 << (i - 20));
            } else {
                p = ngx_snprintf(p, list + sizeof(list) - p, "%uik",
                                 (ngx_uint_t) 1 << (i - 10));
            }
        }

        vals.data = list;
        vals.len = p - list;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "compression window \"%V\" for \"%V\" must be a "
                           "power-of-two size (one of: %V)",
                           &value[2], &b->coding, &vals);
        return NGX_CONF_ERROR;
    }

    if (ccf->window_bits[i] != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    ccf->window_bits[i] = bits;

    return NGX_CONF_OK;
}



/*
 * $compression_ratio: bytes_in/bytes_out with three decimals through the
 * parent's shared overflow-safe split (../src/ngx_http_zstd_ratio.h).
 * Meaningful only after FINISH — a log-phase variable.
 */
static ngx_int_t
ngx_http_compression_ratio_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *vv, uintptr_t data)
{
    ngx_uint_t                   ratio_int, ratio_frac;
    ngx_http_compression_ctx_t  *ctx;

    (void) data;

    ctx = ngx_http_get_module_ctx(r, ngx_http_compression_filter_module);

    if (ctx == NULL || !ctx->done || ctx->bytes_out == 0) {
        /* retryable: a later lookup (once compression finished) recomputes */
        vv->no_cacheable = 1;
        vv->not_found = 1;
        return NGX_OK;
    }

    vv->data = ngx_pnalloc(r->pool, NGX_INT_T_LEN * 2 + 2);
    if (vv->data == NULL) {
        return NGX_ERROR;
    }

    ngx_http_zstd_ratio_parts(ctx->bytes_in, ctx->bytes_out,
                                     &ratio_int, &ratio_frac);

    vv->len = ngx_sprintf(vv->data, "%ui.%03ui", ratio_int, ratio_frac)
              - vv->data;

    vv->valid = 1;
    vv->no_cacheable = 0;   /* final value: cache and reuse within request */
    vv->not_found = 0;

    return NGX_OK;
}


/* $compression_bytes_in / _bytes_out — data is the ctx offsetof() */
static ngx_int_t
ngx_http_compression_bytes_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *vv, uintptr_t data)
{
    uint64_t                     val;
    ngx_http_compression_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_compression_filter_module);

    if (ctx == NULL || !ctx->done || ctx->bytes_out == 0) {
        /* retryable: a later lookup (once compression finished) recomputes */
        vv->no_cacheable = 1;
        vv->not_found = 1;
        return NGX_OK;
    }

    val = *(uint64_t *) ((char *) ctx + data);

    vv->data = ngx_pnalloc(r->pool, NGX_INT64_LEN);
    if (vv->data == NULL) {
        return NGX_ERROR;
    }

    vv->len = ngx_sprintf(vv->data, "%uL", val) - vv->data;
    vv->valid = 1;
    vv->no_cacheable = 0;   /* final value: cache and reuse within request */
    vv->not_found = 0;

    return NGX_OK;
}


static void *
ngx_http_compression_create_conf(ngx_conf_t *cf)
{
    ngx_uint_t                    i;
    ngx_http_compression_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_compression_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->min_length = NGX_CONF_UNSET;
    conf->order = NULL;     /* NULL = inherit / shipped default */
    conf->bufs.num = NGX_CONF_UNSET;
    conf->bypass = NGX_CONF_UNSET_PTR;
    conf->max_length = NGX_CONF_UNSET;
    conf->http_version = NGX_CONF_UNSET_UINT;
    conf->dict_assume_secure = NGX_CONF_UNSET;
    conf->bufs_unsafe = NGX_CONF_UNSET;

    for (i = 0; i < NGX_HTTP_COMPRESSION_CONF_SLOTS; i++) {
        conf->levels[i] = NGX_HTTP_COMPRESSION_LEVEL_UNSET;
        conf->window_bits[i] = NGX_CONF_UNSET;
    }

    return conf;
}


/*
 * Detects a DIRECT "$http_*" or "$cookie_*" reference in one
 * compression_bypass predicate's source text (#185).
 * ngx_http_complex_value_t.value keeps the raw argument as written, even
 * for a script with embedded variables (ngx_http_compile_complex_value()
 * copies the source into ccv->complex_value->value).
 *
 * Deliberately narrow: only the literal "$http_" / "$cookie_" spellings
 * count. A map or any other indirection (e.g. a map result variable
 * derived from a header) is a documented operator responsibility and
 * stays silent — a false warning on a map is worse than missing the
 * direct case.
 */
static ngx_uint_t
ngx_http_compression_predicate_is_direct_header_or_cookie(ngx_str_t *v)
{
    u_char  *p, *last;

    p = v->data;
    last = v->data + v->len;

    while (p < last) {
        p = ngx_strlchr(p, last, '$');
        if (p == NULL) {
            return 0;
        }

        p++;

        if (p < last && *p == '{') {
            p++;
        }

        if ((size_t) (last - p) >= sizeof("http_") - 1
            && ngx_strncmp(p, "http_", sizeof("http_") - 1) == 0)
        {
            return 1;
        }

        if ((size_t) (last - p) >= sizeof("cookie_") - 1
            && ngx_strncmp(p, "cookie_", sizeof("cookie_") - 1) == 0)
        {
            return 1;
        }
    }

    return 0;
}


/*
 * "compression on|off" (parent #182): the standard flag slot plus a
 * parse-time latch of the cycle-global any_enabled bit, so
 * postconfiguration can skip installing the filter hooks when the module
 * is off in every location. Latched for anything the flag slot accepts
 * that is not an explicit "off".
 */
static char *
ngx_http_compression_set_enable_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_str_t                         *value;
    char                              *rc;
    ngx_http_compression_main_conf_t  *cmcf;

    rc = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rc != NGX_CONF_OK) {
        return rc;
    }

    /* value[1] is "on" or "off" — the only two ngx_conf_set_flag_slot
     * accepts (anything else already returned an error above). */
    value = cf->args->elts;
    if (value[1].len == 3 && ngx_strncmp(value[1].data, "off", 3) == 0) {
        return NGX_CONF_OK;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf,
                                        ngx_http_compression_filter_module);
    cmcf->any_enabled = 1;

    return NGX_CONF_OK;
}


/*
 * "compression_bypass_vary <field-name>" (parent #168 row 6). The value
 * becomes a literal Vary field on bypassed and compressed responses alike,
 * so it must be exactly ONE RFC 9110 field-name token — a comma, a
 * semicolon, a quoted string, or a bare "*" would emit a malformed or
 * cache-defeating Vary. ngx_conf_set_str_slot would store any of them
 * verbatim; validate first, then store the same way.
 */
static char *
ngx_http_compression_set_bypass_vary(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_compression_conf_t  *ccf = conf;
    ngx_str_t                    *value;
    u_char                       *p, *end;

    (void) cmd;

    /* .data stays NULL from create_conf's pcalloc until set here, so a
     * non-NULL value means the directive appeared twice in one block
     * (inheritance runs later, via ngx_conf_merge_str_value). */
    if (ccf->bypass_vary.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;
    value = &value[1];      /* the single argument */

    if (value->len == 0) {
        return "empty value";
    }

    /* A bare wildcard disables shared caching and names no header — never
     * what the operator meant. ('*' inside a longer token is fine.) */
    if (value->len == 1 && value->data[0] == '*') {
        return "invalid value: bare wildcard \"*\" disables shared caching";
    }

    /*
     * RFC 9110 §5.1 token: tchar = DIGIT / ALPHA / one of
     * ! # $ % & ' * + - . ^ _ ` | ~ . Commas and semicolons (list /
     * parameter separators) and DQUOTE are rejected explicitly for a
     * clearer message; every other non-tchar falls through to the generic
     * arm.
     */
    for (p = value->data, end = value->data + value->len; p < end; p++) {
        u_char  c = *p;

        if (c == ',' || c == ';') {
            return "invalid value: comma or semicolon (not a token)";
        }

        if (c == '"') {
            return "invalid value: quoted string (not a token)";
        }

        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
              || (c >= '0' && c <= '9')
              || c == '!' || c == '#' || c == '$' || c == '%'
              || c == '&' || c == '\'' || c == '*' || c == '+'
              || c == '-' || c == '.' || c == '^' || c == '_'
              || c == '`' || c == '|' || c == '~'))
        {
            return "invalid value: not a valid field-name token (RFC 9110)";
        }
    }

    ccf->bypass_vary.len = value->len;
    ccf->bypass_vary.data = ngx_pstrdup(cf->pool, value);
    if (ccf->bypass_vary.data == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
 * The two halves of the bypass cache-vary contract, checked after the
 * merge (parent #283's extraction; behaviour unchanged):
 *
 * compression_bypass_vary only makes sense beside a bypass predicate: it
 * names the request header the bypass decision varies on so shared
 * caches key correctly. Alone it just emits a Vary field no response
 * varies on — harmless over-varying, but warn so the misconfig is
 * visible rather than silently degrading hit rate.
 *
 * Inverse (#185): a compression_bypass predicate that reads a request
 * header or cookie DIRECTLY (e.g. "compression_bypass
 * $http_x_no_compression;") without a matching compression_bypass_vary
 * lets a shared cache mix an identity response with a compressed one
 * under the same key — a cache-poisoning / wrong-variant-served hazard.
 * Only the literal "$http_*" / "$cookie_*" spellings are checked; a map
 * or other indirection stays a documented operator responsibility (see
 * ngx_http_compression_predicate_is_direct_header_or_cookie()).
 */
static void
ngx_http_compression_validate_bypass_vary(ngx_conf_t *cf,
    ngx_http_compression_conf_t *conf)
{
    ngx_uint_t                 i;
    ngx_http_complex_value_t  *cv;

    if (conf->bypass_vary.len && conf->bypass == NULL) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "\"compression_bypass_vary\" is set without a "
                           "\"compression_bypass\" predicate; it adds a "
                           "\"Vary: %V\" field no response actually varies "
                           "on", &conf->bypass_vary);
    }

    if (conf->bypass == NULL || conf->bypass_vary.len != 0) {
        return;
    }

    cv = conf->bypass->elts;

    for (i = 0; i < conf->bypass->nelts; i++) {
        if (ngx_http_compression_predicate_is_direct_header_or_cookie(
                &cv[i].value))
        {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "\"compression_bypass\" predicate \"%V\" "
                               "reads a request header or cookie directly "
                               "without a \"compression_bypass_vary\"; a "
                               "shared cache may mix identity and "
                               "compressed responses under the same key. "
                               "Add a \"compression_bypass_vary\" directive "
                               "naming the header this varies on",
                               &cv[i].value);
            return;
        }
    }
}


static char *
ngx_http_compression_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_compression_conf_t *prev = parent;
    ngx_http_compression_conf_t *conf = child;

    ngx_uint_t                     i;
    ngx_http_compression_token_t  *t;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->min_length, prev->min_length, 20);
    ngx_conf_merge_value(conf->max_length, prev->max_length, NGX_CONF_UNSET);
    ngx_conf_merge_uint_value(conf->http_version, prev->http_version,
                              NGX_HTTP_VERSION_11);

    ngx_conf_merge_ptr_value(conf->bypass, prev->bypass, NULL);
    ngx_conf_merge_str_value(conf->bypass_vary, prev->bypass_vary, "");
    ngx_conf_merge_value(conf->dict_assume_secure, prev->dict_assume_secure, 0);

    ngx_http_compression_validate_bypass_vary(cf, conf);

    /* default cap 32 in-flight bufs (core gzip's number), size 0 =
     * backend-recommended */
    if (conf->bufs.num == NGX_CONF_UNSET) {
        if (prev->bufs.num != NGX_CONF_UNSET) {
            conf->bufs = prev->bufs;

        } else {
            conf->bufs.num = 32;
            conf->bufs.size = 0;
        }
    }

    ngx_conf_merge_value(conf->bufs_unsafe, prev->bufs_unsafe, 0);

    /*
     * The parse-time slot only sees an EXPLICIT compression_buffers
     * written at this exact location. A value inherited from an outer
     * block (the conf->bufs = prev->bufs branch above) or the module's
     * own default never passes through it, so re-run the product bound
     * here — with the advisory/hard-cap tiers (advise=1) and the now-final
     * bufs_unsafe flag — so every value conf->bufs can hold at request
     * time is validated exactly once (#167). A defaulted size of 0 is a
     * no-op in the helper.
     */
    if (ngx_http_compression_check_bufs_product(cf, &conf->bufs,
                                                conf->bufs_unsafe,
                                                "merged value", 1)
        != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }

    /*
     * PHASE3: tuning slots resolve to the backend's declared defaults
     * here, so election-time values are always concrete and backends
     * never re-implement defaulting. Merge runs after preconfiguration
     * filled the registry.
     */
    for (i = 0; ngx_http_compression_backends[i] != NULL; i++) {
        /*
         * Hand-rolled rather than ngx_conf_merge_value(): that macro
         * tests against NGX_CONF_UNSET, which is a legal zstd level
         * here. See NGX_HTTP_COMPRESSION_LEVEL_UNSET above.
         */
        if (conf->levels[i] == NGX_HTTP_COMPRESSION_LEVEL_UNSET) {
            conf->levels[i] =
                (prev->levels[i] == NGX_HTTP_COMPRESSION_LEVEL_UNSET)
                ? ngx_http_compression_backends[i]->level_default
                : prev->levels[i];
        }

        ngx_conf_merge_value(conf->window_bits[i], prev->window_bits[i],
                             ngx_http_compression_backends[i]
                                 ->window_bits_default);
    }

    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             ngx_http_compression_default_types)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (conf->order == NULL) {
        conf->order = prev->order;
    }

    /*
     * A level that declares its own compression_dict_file list
     * replaces the inherited one WHOLESALE (the RFC's alias-merge
     * rule; standard array-directive semantics). The pointers target
     * the cycle-global store either way — inheritance shares entries,
     * never bytes.
     */
    if (conf->dicts == NULL) {
        conf->dicts = prev->dicts;

        /*
         * The http-level array is only ever the parent side of a merge,
         * so it is sorted here, at inheritance, and again by every
         * child that inherits it: idempotent and config-time only. The
         * array holds pointers into the cycle-global store, so
         * reordering it invalidates nothing anyone captured.
         */
        ngx_http_compression_dicts_sort(conf->dicts);

    } else {
        /* an owned array: sorted once, after its last push */
        ngx_http_compression_dicts_sort(conf->dicts);
    }

    if (conf->order == NULL) {
        /* shipped default: zstd br gzip (RFC: dynamic prefers the
         * cheap coding; gzip last makes deferral risk-free) — each
         * token joins only when its implementation is in the build */
        conf->order = ngx_array_create(cf->pool, 3,
                                    sizeof(ngx_http_compression_token_t));
        if (conf->order == NULL) {
            return NGX_CONF_ERROR;
        }

#if (NGX_HTTP_COMPRESSION_HAVE_ZSTD)
        t = ngx_array_push(conf->order);
        if (t == NULL) {
            return NGX_CONF_ERROR;
        }
        t->backend = ngx_http_compression_backend_zstd;
#endif

#if (NGX_HTTP_COMPRESSION_HAVE_BROTLI)
        t = ngx_array_push(conf->order);
        if (t == NULL) {
            return NGX_CONF_ERROR;
        }
        t->backend = ngx_http_compression_backend_brotli;
#endif

#if (NGX_HTTP_GZIP)
        /* the gzip token joins the default only when there is a core
         * gzip filter to defer to */
        t = ngx_array_push(conf->order);
        if (t == NULL) {
            return NGX_CONF_ERROR;
        }
        t->backend = NULL;
#endif
    }

    /*
     * No "gzip_vary off" warning any more (parent #163): the header
     * filter now emits Vary: Accept-Encoding by construction on every
     * negotiated response — see ngx_http_compression_vary() — so
     * correctness no longer depends on the gzip_vary directive and
     * there is nothing to warn about.
     */

    return NGX_CONF_OK;
}


static char *
ngx_http_compression_order(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_compression_conf_t *ccf = conf;

    ngx_str_t                       *value;
    ngx_uint_t                       i, j, k;
    ngx_http_compression_token_t    *t;
    ngx_http_compression_backend_t  *b;

    if (ccf->order != NULL && ccf->order->nelts > 0) {
        return "is duplicate";
    }

    ccf->order = ngx_array_create(cf->pool, cf->args->nelts - 1,
                                  sizeof(ngx_http_compression_token_t));
    if (ccf->order == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        b = NULL;

        if (value[i].len == ngx_http_compression_gzip_token.len
            && ngx_strncmp(value[i].data,
                           ngx_http_compression_gzip_token.data,
                           value[i].len) == 0)
        {
#if (NGX_HTTP_GZIP)
            /* gzip: valid token, no backend — defer/veto semantics */
#else
            /* nothing to defer to: better a config error than a token
             * that silently means "identity" */
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"gzip\" in \"compression_order\" requires "
                               "nginx built with ngx_http_gzip_module");
            return NGX_CONF_ERROR;
#endif

        } else {
            for (k = 0; ngx_http_compression_backends[k]; k++) {
                if (value[i].len
                        == ngx_http_compression_backends[k]->coding.len
                    && ngx_strncmp(value[i].data,
                           ngx_http_compression_backends[k]->coding.data,
                           value[i].len) == 0)
                {
                    b = ngx_http_compression_backends[k];
                    break;
                }
            }

            if (b == NULL) {
                const char  *absent =
                    ngx_http_compression_absent_coding(&value[i]);

                if (absent != NULL) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "coding \"%V\" in "
                                       "\"compression_order\" is not "
                                       "available: this nginx was built "
                                       "without %s support",
                                       &value[i], absent);
                    return NGX_CONF_ERROR;
                }

                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "unknown coding \"%V\" in "
                                   "\"compression_order\"", &value[i]);
                return NGX_CONF_ERROR;
            }
        }

        /* a coding may appear once: the order list IS the enable set
         * (backend == NULL is the single gzip token, so pointer
         * equality covers it too) */
        t = ccf->order->elts;
        for (j = 0; j < ccf->order->nelts; j++) {
            if (t[j].backend == b) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "duplicate coding \"%V\" in "
                                   "\"compression_order\"", &value[i]);
                return NGX_CONF_ERROR;
            }
        }

        t = ngx_array_push(ccf->order);
        if (t == NULL) {
            return NGX_CONF_ERROR;
        }
        t->backend = b;
    }

    return NGX_CONF_OK;
}



/*
 * The negotiated-URI Vary: ONE combined line for dictionary locations,
 * the by-construction Accept-Encoding line (#163) otherwise. Factored
 * so the bypass branch and the election path cannot drift — the
 * bypassed identity response is still a variant of a NEGOTIATED URI
 * (CodeRabbit, round 5): a cache that stores it as the URI's first
 * response without an Accept-Encoding dimension can then satisfy
 * non-bypassed requests with it, or worse, key later compressed
 * variants inconsistently. Same sloppy-cache paranoia as #163's
 * emit-by-construction rationale.
 */
static ngx_int_t
ngx_http_compression_emit_vary(ngx_http_request_t *r,
    ngx_http_compression_conf_t *conf)
{
    if (conf->dicts != NULL && conf->dicts->nelts > 0) {
        ngx_table_elt_t  *v;

        v = ngx_list_push(&r->headers_out.headers);
        if (v == NULL) {
            return NGX_ERROR;
        }
        v->hash = 1;
        v->next = NULL;
        ngx_str_set(&v->key, "Vary");
        ngx_str_set(&v->value,
                    "Accept-Encoding, Available-Dictionary, Sec-Fetch-Site");

        return NGX_OK;
    }

    return ngx_http_compression_vary(r);
}


static ngx_int_t
ngx_http_compression_header_filter(ngx_http_request_t *r)
{
    ngx_int_t                        w;
    ssize_t                          plen;
    ngx_uint_t                       i;
#if (NGX_HTTP_GZIP)
    ngx_uint_t                       gzip_listed;
#endif
    ngx_table_elt_t                 *ae;
    ngx_http_compression_ctx_t      *ctx;
    ngx_http_compression_conf_t     *conf;
    ngx_http_compression_token_t    *t;
    ngx_http_compression_dict_t     *dict, *elected_dict;
    ngx_http_compression_tuning_t    tuning;
    ngx_http_compression_backend_t  *elected;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_compression_filter_module);

    /*
     * GATE ORDER (round 5, eilandert's finding — the tier boundaries
     * are load-bearing):
     *
     * SCOPE first — off, subrequest, already-encoded. The module makes
     * no whole-stack claim on these; core gzip legitimately owns them.
     *
     * WHOLE-STACK VETOES second — no-transform and compression_bypass
     * speak for the entire stack, gzip token included, so they must
     * run BEFORE the local eligibility gates: those gates are
     * DEFERRALS to core gzip, and with the vetoes below them,
     * "compression_types application/json" beside "gzip_types
     * text/plain" answered a text/plain no-transform (or bypassed)
     * response with Content-Encoding: gzip — the type mismatch
     * deferred before the veto could latch gzip off.
     *
     * LOCAL ELIGIBILITY last — status set, protocol floor, types,
     * min/max length: this location declines, core gzip still applies
     * its own rules.
     */
    if (!conf->enable
        || r != r->main
        || (r->headers_out.content_encoding != NULL
            && r->headers_out.content_encoding->value.len != 0))
    {
        return ngx_http_next_header_filter(r);
    }

    /*
     * RFC 9110 §7.7 (upstream #251): a response carrying
     * Cache-Control: no-transform must keep its content coding. Sits
     * BEFORE any Vary emission — the skip is keyed on a response
     * header, so the response does not vary on Accept-Encoding.
     * UNIFIED-MODULE DELTA: the gzip token is part of THIS stack, so
     * core gzip is vetoed too (same reasoning as compression_bypass
     * below) — falling through to a core gzip that ignores
     * no-transform would defeat the origin's directive.
     */
    if (ngx_http_zstd_cache_control_no_transform(r)) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "compression: skip, Cache-Control no-transform");

#if (NGX_HTTP_GZIP)
        r->gzip_tested = 1;
        r->gzip_ok = 0;
#endif

        return ngx_http_next_header_filter(r);
    }

    /*
     * PHASE3 bypass (parent zstd_bypass semantics). The operator-named
     * extra Vary field rides BOTH paths — the bypassed identity
     * response and the compressed one — so a shared cache keys on the
     * request header that drove the predicate (the module cannot infer
     * which header that is; compression_bypass_vary names it). A
     * second Vary line is fine: caches union all Vary fields.
     */
    if (conf->bypass_vary.len) {
        ngx_table_elt_t  *bv;

        bv = ngx_list_push(&r->headers_out.headers);
        if (bv == NULL) {
            return NGX_ERROR;
        }

        bv->hash = 1;
        bv->next = NULL;
        ngx_str_set(&bv->key, "Vary");
        bv->value = conf->bypass_vary;
    }

    /*
     * Any predicate variable resolving non-empty and not "0" serves
     * identity — the operator lever for endpoints that must not be
     * compressed (BREACH-style secret+reflection mixes,
     * already-compressed dynamic payloads) without splitting the
     * location. UNIFIED-MODULE DELTA from the parents: the gzip token
     * is part of THIS stack, so bypass vetoes it too — the parents'
     * standalone bypass falls through to core gzip, which would
     * quietly defeat the operator's intent here.
     */
    if (conf->bypass != NULL
        && ngx_http_test_predicates(r, conf->bypass) != NGX_OK)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "compression: bypassed by compression_bypass");

#if (NGX_HTTP_GZIP)
        r->gzip_tested = 1;
        r->gzip_ok = 0;
#endif

        /*
         * The bypassed identity response is still a variant of a
         * NEGOTIATED URI: without the Accept-Encoding dimension a
         * cache can store it as the URI's baseline and key later
         * (non-bypassed, compressed) variants inconsistently
         * (CodeRabbit, round 5). NOT mirrored in the no-transform
         * branch above: that skip is response-header-driven, so the
         * URI serves identity for every client as long as the origin
         * keeps sending no-transform — there is no negotiation to
         * advertise.
         */
        if (ngx_http_compression_emit_vary(r, conf) != NGX_OK) {
            return NGX_ERROR;
        }

        return ngx_http_next_header_filter(r);
    }

    /*
     * PHASE3: the parent zstd filter's status set — every 2xx except
     * 204/205 (no body by definition) and 206 (ranges address the
     * ENCODED representation; compressing a slice would corrupt it),
     * plus 403 and 404, whose bodies are often the most-served
     * compressible content on a busy origin.
     */
    if (r->headers_out.status < NGX_HTTP_OK
        || r->headers_out.status == NGX_HTTP_NO_CONTENT
        || r->headers_out.status == 205  /* Reset Content: no core macro */
        || r->headers_out.status == NGX_HTTP_PARTIAL_CONTENT
        || (r->headers_out.status > 299
            && r->headers_out.status != NGX_HTTP_FORBIDDEN
            && r->headers_out.status != NGX_HTTP_NOT_FOUND)
        /*
         * NO r->header_only skip (parent-audit find): a HEAD response
         * must advertise the same Content-Encoding its GET would
         * produce — core gzip does, and skipping made HEAD and GET
         * disagree. The body filter sees no body on HEAD and simply
         * never runs the encoder.
         */
        /*
         * Protocol floor (Mark's call, gzip_http_version parity,
         * default 1.1): an RFC 1945-era client is gzip-at-best, and
         * HTTP/1.0 frequently means an ancient intermediary. Skipping
         * WITHOUT a latch is a deferral — core gzip below applies its
         * own gzip_http_version rule, which is as good as it gets for
         * those clients.
         */
        || r->http_version < conf->http_version
        || ngx_http_test_content_type(r, &conf->types) == NULL)
    {
        return ngx_http_next_header_filter(r);
    }

    if (r->headers_out.content_length_n != -1
        && r->headers_out.content_length_n < conf->min_length)
    {
        return ngx_http_next_header_filter(r);
    }

    /* known body larger than the compression_max_length ceiling (the
     * parents' zstd_max_length / brotli_max_length worker protection);
     * the RUNNING cap in the body filter covers undeclared lengths */
    if (conf->max_length != NGX_CONF_UNSET
        && r->headers_out.content_length_n != -1
        && r->headers_out.content_length_n > conf->max_length)
    {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "compression: skip, body %O > compression_max_length "
                       "%O", r->headers_out.content_length_n,
                       (off_t) conf->max_length);
        return ngx_http_next_header_filter(r);
    }

    /*
     * Vary before any accept decision, so identity fallbacks vary too.
     *
     * Locations WITHOUT dictionaries emit Vary: Accept-Encoding via the
     * helper (which now does it by construction — parent #163).
     *
     * Locations WITH dictionaries push ONE combined line,
     * "Vary: Accept-Encoding, Available-Dictionary, Sec-Fetch-Site",
     * instead of a delegated AE line plus separate literal lines
     * (review round 2): two Vary lines are legal per RFC 9110, but a
     * fair number of intermediary caches key on the FIRST line only —
     * precisely the hazard this header exists to prevent. Delegation is
     * skipped ON PURPOSE there so the core emitter cannot add a second
     * line. Known narrow corner, accepted and documented: a gzip
     * DEFERRAL in a dict location lets core gzip set r->gzip_vary itself
     * and emit its own AE line beside the combined one — only when gzip
     * is elected ahead of every better coding, and the combined line is
     * still present for caches that read all lines.
     *
     * Sec-Fetch-Site rides in the SAME line (parent #160):
     * match_dict() below refuses dcz for any Sec-Fetch-Site other than
     * absent / "same-origin" / "none", which makes it a
     * response-selection input. Without it in Vary a shared cache
     * filled by a same-origin request would serve the dcz body to a
     * cross-site request whose gate said no (or vice versa) — a hit on
     * the wrong variant across the RFC 9842 §8.3 partition. Pushed
     * unconditionally here for the same reason Available-Dictionary is:
     * every fallback below (plain zstd/brotli, identity) is a variant a
     * cache must not reuse across the gate.
     */
    if (ngx_http_compression_emit_vary(r, conf) != NGX_OK) {
        return NGX_ERROR;
    }

    ae = ngx_http_compression_ae_header(r);

    /*
     * Presence only (parent #215/#275): an empty FIRST line must not
     * mask a meaningful later one — the weights below read the whole
     * comma-joined field, so all-empty lines simply elect nothing.
     */
    if (ae == NULL) {
        return ngx_http_next_header_filter(r);
    }

    /* one store match serves every token the loop considers */
    dict = ngx_http_compression_match_dict(r, conf);

    elected = NULL;
    elected_dict = NULL;
#if (NGX_HTTP_GZIP)
    gzip_listed = 0;
#endif

    t = conf->order->elts;

    for (i = 0; i < conf->order->nelts; i++) {

        if (t[i].backend == NULL) {
            /* without the gzip module this token cannot exist — the
             * order parser rejects it at config load */
#if (NGX_HTTP_GZIP)
            gzip_listed = 1;

            w = ngx_http_compression_request_coding_weight(
                    r, &ngx_http_compression_gzip_token, 1);
            if (w > 0) {
                /*
                 * DEFER: gzip won the election, and gzip is never
                 * implemented here. Stand aside WITHOUT touching the
                 * r->gzip_tested latch — the core gzip filter below
                 * then applies its ENTIRE rule set (gzip_types,
                 * gzip_proxied, gzip_disable, gzip's own on/off).
                 * One-way door by design: if gzip's own gates decline,
                 * there is no second pass back into this election.
                 */
                return ngx_http_next_header_filter(r);
            }

            /*
             * EXPRESSED REFUSAL anywhere in the field — an explicit
             * gzip;q=0 or a *;q=0 with no later override (parent #275,
             * the design's veto half): core gzip reads only the FIRST
             * line and could compress against a refusal it never saw,
             * so latch it off. Absence (-1) deliberately does NOT
             * latch: core reaches identity on its own first-line read,
             * and asserting "refused" where the field merely omits
             * gzip would stamp a wrong verdict (the wildcard corner —
             * core gzip has never honored "*", and the day it does,
             * this module must not have pre-empted it). The one
             * remaining asymmetry is fail-closed: an allowance visible
             * only on a later line defers here and cores declines to
             * identity — never a wrong compression.
             */
            if (w == 0) {
                r->gzip_tested = 1;
                r->gzip_ok = 0;
            }
#endif
            continue;
        }

        /*
         * PHASE1b: at each base token, the dictionary variant runs
         * first. Electable iff the location matched the client's
         * Available-Dictionary AND the backend is dict-ready
         * (wire_prologue != NULL — the round-2 readiness gate) AND
         * the client names the dict coding EXPLICITLY: a "*" wildcard
         * must never elect dcz/dcb, since only a client that actually
         * holds the dictionary can decode them (allow_wildcard=0).
         * A client that accepts dcz but not zstd still gets dcz —
         * it is the coding they asked for.
         */
        if (dict != NULL
            && t[i].backend->dict_coding.len != 0
            && t[i].backend->wire_prologue != NULL)
        {
            w = ngx_http_compression_request_coding_weight(
                    r, &t[i].backend->dict_coding, 0);
            if (w > 0) {
                elected = t[i].backend;
                elected_dict = dict;
                break;
            }
        }

        w = ngx_http_compression_request_coding_weight(
                r, &t[i].backend->coding, 1);
        if (w > 0) {
            elected = t[i].backend;
            break;
        }
    }

    if (elected == NULL) {
#if (NGX_HTTP_GZIP)
        /*
         * VETO: the election concluded and gzip was absent from the
         * list — gzip is genuinely off for this response, latch so the
         * core filter stands down. When gzip WAS listed the client
         * simply didn't accept it; the core filter's own AE check
         * reaches the same conclusion, no latch needed.
         */
        if (!gzip_listed) {
            r->gzip_tested = 1;
            r->gzip_ok = 0;
        }
#endif
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_compression_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->backend = elected;
    ctx->last_in = &ctx->in;    /* empty chain: tail is the head slot */
    ctx->pledged_size = r->headers_out.content_length_n;
    ctx->out_size = elected->out_size(r->headers_out.content_length_n);

    /* operator geometry: an explicit compression_buffers size beats
     * the backend recommendation (the dict-prologue clamp below
     * applies to either source); num caps in-flight bufs */
    if (conf->bufs.size > 0) {
        ctx->out_size = conf->bufs.size;
    }

    ctx->bufs_num = (ngx_uint_t) conf->bufs.num;
    ctx->max_length = conf->max_length;

    /* PHASE3: resolve this coding's tuning slot (concrete post-merge;
     * the dict variant shares the base coding's values) */
    for (i = 0; ngx_http_compression_backends[i] != NULL; i++) {
        if (ngx_http_compression_backends[i] == elected) {
            break;
        }
    }

    if (ngx_http_compression_backends[i] == NULL) {
        /* unreachable: every order token is a registry pointer */
        return NGX_ERROR;
    }

    tuning.level = conf->levels[i];
    tuning.window_bits = conf->window_bits[i];

    if (elected->create(r, &tuning, &ctx->bctx) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "compression: create %V level %i window_bits %i",
                   &elected->coding, tuning.level, tuning.window_bits);

    if (elected->hint_input_size != NULL
        && r->headers_out.content_length_n > 0)
    {
        if (elected->hint_input_size(ctx->bctx,
                                     r->headers_out.content_length_n)
            != NGX_OK)
        {
            /*
             * A refused hint is a lost optimization, not a lost
             * response (round-4 review; the parent logs and continues
             * the same way). Turning it into NGX_ERROR made the
             * header filter 500 a request the encoder would have
             * served fine unpledged.
             */
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "compression: %V input-size hint refused; "
                          "continuing unpledged", &elected->coding);
        }
    }

    if (elected_dict != NULL) {
        /*
         * The lifecycle invariant's last leg: attach AFTER the size
         * hint, BEFORE the first process step. The backend receives
         * raw bytes only — the store's ownership claim, load-bearing
         * to the end — and the prologue derives from the entry's
         * hash, prepared here and spent by the body filter ahead of
         * the first encoder byte.
         */
        if (elected->attach_dictionary(ctx->bctx, &elected_dict->bytes)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        plen = elected->wire_prologue(ctx->bctx, elected_dict->sha256,
                                      ctx->prologue,
                                      sizeof(ctx->prologue));
        if (plen == NGX_ERROR) {
            return NGX_ERROR;
        }
        ctx->prologue_len = (size_t) plen;

        /*
         * The output buffer must hold the prologue (review round 2's
         * blocking find): brotli's out_size is CONTENT-DERIVED —
         * BrotliEncoderMaxCompressedSize(1..29) is smaller than the
         * 36-byte dcb prologue — so a tiny known-length body sized a
         * buffer the prologue memcpy overran (heap write, worker
         * survives, response silently corrupt; ASan-reproduced).
         * The guarantee belongs to whoever sizes the buffer: clamp
         * here, where prologue_len is known, not in any backend.
         */
        if (ctx->out_size < ctx->prologue_len) {
            ctx->out_size = ctx->prologue_len;
        }
    }

    ngx_http_set_ctx(r, ctx, ngx_http_compression_filter_module);

    /*
     * The copy filter must hand the body filter memory buffers —
     * without this, sendfile-backed responses arrive as file bufs and
     * the (deliberate) in-memory-only cut used to fire AFTER the
     * compressed headers had gone out, truncating the response
     * instead of failing cleanly (review round 1). Same line core
     * gzip uses.
     */
    r->main_filter_need_in_memory = 1;

#if (NGX_HTTP_GZIP)
    /* we compress: the core gzip filter must stand down */
    r->gzip_tested = 1;
    r->gzip_ok = 0;
#endif

    r->headers_out.content_encoding =
        ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.content_encoding == NULL) {
        return NGX_ERROR;
    }

    r->headers_out.content_encoding->hash = 1;
    r->headers_out.content_encoding->next = NULL;
    ngx_str_set(&r->headers_out.content_encoding->key, "Content-Encoding");
    r->headers_out.content_encoding->value =
        (elected_dict != NULL) ? elected->dict_coding : elected->coding;

    ngx_http_clear_content_length(r);
    ngx_http_clear_accept_ranges(r);
    ngx_http_weak_etag(r);

    return ngx_http_next_header_filter(r);
}


/*
 * ngx_create_temp_buf() costs two pool allocations per buffer — the
 * ngx_buf_t and its payload (parent #258). One aligned block carries
 * both; the header fields end up identical, so ngx_buf_in_memory(),
 * the writer's special-buf test, and the recycled/tag handling below
 * see no difference.
 */
static ngx_buf_t *
ngx_http_compression_create_temp_buf(ngx_pool_t *pool, size_t size)
{
    size_t      data_offset;
    u_char     *allocation;
    ngx_buf_t  *b;

    data_offset = ngx_align(sizeof(ngx_buf_t), NGX_ALIGNMENT);

    if (size > NGX_MAX_SIZE_T_VALUE - data_offset) {
        return NULL;
    }

    allocation = ngx_palloc(pool, data_offset + size);
    if (allocation == NULL) {
        return NULL;
    }

    b = (ngx_buf_t *) allocation;
    ngx_memzero(b, sizeof(ngx_buf_t));

    b->start = allocation + data_offset;
    b->pos = b->start;
    b->last = b->start;
    b->end = b->start + size;
    b->temporary = 1;

    return b;
}


/*
 * PHASE3: produce the working output buf — a reclaimed one when the
 * free list has any, a fresh allocation while under the
 * compression_buffers cap, or NGX_DECLINED with ctx->nomem latched
 * when neither is possible (production pauses until downstream
 * drains the busy chain).
 */
static ngx_int_t
ngx_http_compression_get_buf(ngx_http_request_t *r,
    ngx_http_compression_ctx_t *ctx)
{
    ngx_chain_t  *cl;

    if (ctx->ob != NULL) {
        return NGX_OK;
    }

    if (ctx->free != NULL) {
        cl = ctx->free;
        ctx->free = cl->next;
        ctx->ob = cl->buf;
        ngx_free_chain(r->pool, cl);

        /*
         * ngx_chain_update_chains() reset pos/last when it reclaimed —
         * but NOT the control flags: a buffer shipped at a
         * FLUSH-completion comes back with flush=1 still set, and the
         * full-buffer ship path assigns no flags, so the stale flag
         * would force a spurious downstream flush on an unrelated
         * later buffer. The parent's get_buf clears these (its P2
         * fix); the first cut of this port missed the four lines, and
         * GetPageSpeed's fork independently rediscovered the same bug
         * class in the tokers line (their 9edfc34, via issue #123) —
         * three codebases, one lesson.
         */
        ctx->ob->flush = 0;
        ctx->ob->sync = 0;
        ctx->ob->last_buf = 0;
        ctx->ob->last_in_chain = 0;
        ctx->ob->shadow = NULL;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "compression: reused output buf %p", ctx->ob);
        return NGX_OK;
    }

    if (ctx->allocated < ctx->bufs_num) {
        ctx->ob = ngx_http_compression_create_temp_buf(r->pool,
                                                       ctx->out_size);
        if (ctx->ob == NULL) {
            return NGX_ERROR;
        }
        ctx->ob->tag = (ngx_buf_tag_t) &ngx_http_compression_filter_module;

        /*
         * Recycled bufs bypass ngx_http_write_filter()'s
         * postpone_output hold: without the flag a sub-1460-byte ship
         * from a tight cap sits postponed, the busy chain never
         * drains, and the cap pause above becomes a deadlock (brotli)
         * or a truncated 200 (zstd) — reproduced with
         * "compression_buffers 2 64" and incompressible input. Set at
         * creation; ngx_chain_update_chains() never clears it, so
         * every reuse inherits it.
         */
        ctx->ob->recycled = 1;

        ctx->allocated++;
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "compression: buffer cap %ui reached, awaiting drain",
                   ctx->bufs_num);
    ctx->nomem = 1;
    return NGX_DECLINED;
}


/*
 * Copy the caller-owned cursor's remaining links onto ctx->in (parent
 * #260): the O(1) tracked-tail append that used to run on EVERY
 * incoming link (#157/#176) now runs only for input that survives its
 * own callback. The buffers are shared, request-lifetime; only the
 * link wrappers are pool-copied — the same split ngx_chain_add_copy()
 * makes. Appends through last_in because an earlier callback's
 * retained links may still queue under downstream backpressure.
 */
static ngx_int_t
ngx_http_compression_retain_input(ngx_http_request_t *r,
    ngx_http_compression_ctx_t *ctx, ngx_chain_t *in)
{
    ngx_chain_t  *cl;

    for ( /* void */ ; in != NULL; in = in->next) {
        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = in->buf;
        cl->next = NULL;

        *ctx->last_in = cl;
        ctx->last_in = &cl->next;
    }

    return NGX_OK;
}


/*
 * Which link feeds the encoder next: retained links (an earlier
 * callback's tail, pool-owned) drain before this callback's cursor —
 * input order is byte order. Extracted (with consume below and
 * retain_input above) so tools/test_input_chain_cursor_unit.sh can
 * compile the ownership/ordering contract against a pool shim: the
 * retained-vs-cursor overlap needs upstream data landing while a tail
 * is retained, a timing window no wire test schedules reliably.
 */
static ngx_buf_t *
ngx_http_compression_next_in_buf(ngx_http_compression_ctx_t *ctx,
    ngx_chain_t *in, ngx_uint_t *retained)
{
    if (ctx->in != NULL) {
        *retained = 1;
        return ctx->in->buf;
    }

    if (in != NULL) {
        *retained = 0;
        return in->buf;
    }

    return NULL;
}


/*
 * Link consumed. A retained link is pool-owned: free it (review round
 * 1 — these used to accumulate for the request's lifetime). A cursor
 * link is CALLER-owned: never free it — ngx_free_chain() overwrites
 * cl->next, which would corrupt the upstream filter's chain while its
 * callback is active — just advance past it (parent #260).
 */
static void
ngx_http_compression_consume_in_link(ngx_http_request_t *r,
    ngx_http_compression_ctx_t *ctx, ngx_chain_t **in, ngx_uint_t retained)
{
    ngx_chain_t  *cl;

    if (retained) {
        cl = ctx->in;
        ctx->in = cl->next;
        ngx_free_chain(r->pool, cl);

        /*
         * Just freed the last retained link: ngx_free_chain() has
         * overwritten cl->next, so ctx->last_in (which pointed at it)
         * is now dangling into the pool free-list. Re-point it at the
         * head slot, or the next tail retention would splice into the
         * free list and hang the request (parent #157's regression).
         */
        if (ctx->in == NULL) {
            ctx->last_in = &ctx->in;
        }

    } else {
        *in = (*in)->next;
    }
}


static ngx_int_t
ngx_http_compression_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                    rc;
    ngx_buf_t                   *b;
    ngx_uint_t                   last_seen, flush_seen, retained, had_input;
    ngx_chain_t                 *out, **last_out, *cl;
    ngx_http_compression_op_e    op;
    ngx_http_compression_io_t    io;
    ngx_http_compression_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_compression_filter_module);

    if (ctx == NULL || ctx->done) {
        return ngx_http_next_body_filter(r, in);
    }

    had_input = (in != NULL);

    if (had_input) {
        /*
         * Lazy retention (parent #260, superseding the #157/#176
         * copy-all append): no link copies up front. The caller-owned
         * chain is consumed through the local `in` cursor in the loop
         * below — its links are safe to walk only while this callback
         * is active, but the BUFFERS have request lifetime, so only
         * link wrappers ever need pool-owned copies, and only for the
         * unconsumed tail at ship: when backpressure makes input
         * survive the callback. The fast path (everything consumed
         * this invocation) allocates no links at all.
         */

        /*
         * Input is now queued here or inside the encoder (parent's
         * set site): publish it so the writer keeps re-poking. The
         * ONLY clear sites are a completed flush and the finish —
         * the two moments the encoder is genuinely drained. The bit
         * must not simply track ctx->started: it sits inside
         * NGX_HTTP_LOWLEVEL_BUFFERED, and holding it across an
         * unbuffered proxy's flush cycles reads as permanent
         * congestion upstream — which truncated exactly the
         * flush-path streams (tools/test_flush_paths.py).
         */
        r->connection->buffered |= NGX_HTTP_GZIP_BUFFERED;
    }

    if (ctx->nomem) {
        /*
         * PHASE3 recycling: the previous invocation hit the buffer
         * cap. Push the busy chain downstream first — a NULL pass
         * lets the write filter drain what it holds — then reclaim
         * whatever drained. Production resumes below with the freed
         * bufs (the loop's get_buf may trip the cap again; each
         * invocation makes the progress the client's drain rate
         * allows, which is the whole point of the cap).
         *
         * The debug line is the observable witness that the GENUINE
         * pause path ran — a same-invocation resume never comes
         * through here, only a writer-driven re-entry after a real
         * cross-invocation pause does (tools/test_slow_drain.py
         * asserts it under forced backpressure).
         */
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "compression: resuming after drain");

        if (ngx_http_next_body_filter(r, NULL) == NGX_ERROR) {
            return NGX_ERROR;
        }

        cl = NULL;
        ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &cl,
                                (ngx_buf_tag_t) &ngx_http_compression_filter_module);

        ctx->nomem = 0;
    }

    /*
     * PHASE1b: the dict coding's wire prologue rides ahead of the
     * first encoder byte, in the same output buffer the first step
     * fills. The buffer is guaranteed to hold it by the clamp at
     * election time — NOT by any assumption about backend out_size:
     * zstd's recommendation is fixed and large, but brotli's is
     * content-derived and can be as small as 7 bytes (review round
     * 2). Emitted on the first invocation that carries input — a
     * zero-body response still gets it, since the last_buf special
     * buf arrives through the input cursor like any other link.
     */
    if (ctx->prologue_len > 0 && !ctx->prologue_sent
        && (ctx->in != NULL || in != NULL))
    {

        /* first invocation with input: the cap cannot be reached yet */
        if (ngx_http_compression_get_buf(r, ctx) != NGX_OK) {
            return NGX_ERROR;
        }

        ngx_memcpy(ctx->ob->last, ctx->prologue, ctx->prologue_len);
        ctx->ob->last += ctx->prologue_len;
        ctx->bytes_out += ctx->prologue_len;
        ctx->prologue_sent = 1;
    }

    /*
     * PHASE3 recycling: the outer cycle is the parent filter's shape —
     * produce until the buffer cap pauses us, ship, reclaim what
     * downstream drained, and RESUME IN THIS INVOCATION when the
     * reclaim freed anything. Returning early with unconsumed input
     * would bet on the caller re-invoking us; nginx's contract makes
     * no such promise on a fast socket (found the hard way: the first
     * cut stalled a capped response to the test timeout). The genuine
     * pause — downstream drained nothing — returns NGX_AGAIN and
     * leans on r->buffered keeping the writer re-poking.
     */
    for ( ;; ) {

    out = NULL;
    last_out = &out;

    while ((b = ngx_http_compression_next_in_buf(ctx, in, &retained))
           != NULL)
    {

        /*
         * PHASE0: in-memory bufs only (wrinkle #9: chassis complexity,
         * no backend hook needed). Belt only — the header filter sets
         * r->main_filter_need_in_memory, so the copy filter converts
         * file bufs before they reach here; if this fires, that
         * contract broke upstream of us.
         */
        if (b->in_file && !ngx_buf_in_memory(b)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "compression: file buffers unsupported in the "
                          "phase-0 prototype");
            return NGX_ERROR;
        }

        last_seen = b->last_buf;
        flush_seen = b->flush;

        for ( ;; ) {

            size_t  data;

            /*
             * Special bufs (flags only) have pos == last == NULL, and
             * NULL pointer arithmetic is UB even when the difference
             * would be zero (review round 1) — gate on
             * ngx_buf_in_memory before touching the cursors.
             */
            data = ngx_buf_in_memory(b) ? (size_t) (b->last - b->pos) : 0;

            if (data > 0) {
                op = NGX_HTTP_COMPRESSION_OP_PROCESS;
            } else if (last_seen) {
                op = NGX_HTTP_COMPRESSION_OP_FINISH;
            } else if (flush_seen) {
                op = NGX_HTTP_COMPRESSION_OP_FLUSH;
            } else {
                break;      /* buf drained, no flags: next link */
            }

            rc = ngx_http_compression_get_buf(r, ctx);

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (rc == NGX_DECLINED) {
                /* buffer cap: stop producing, ship what we have; the
                 * unconsumed remainder stays on ctx->in (this link's
                 * pos is already advanced past what the encoder ate)
                 * for the invocation that follows the drain */
                goto ship;
            }

            ngx_memzero(&io, sizeof(io));
            if (data > 0) {
                io.in = b->pos;
                io.in_len = data;
            }
            io.out = ctx->ob->last;
            io.out_len = ctx->ob->end - ctx->ob->last;

            if (ctx->backend->process(ctx->bctx, &io, op) != NGX_OK) {
                return NGX_ERROR;
            }

            if (io.in_consumed > 0) {
                b->pos += io.in_consumed;
                ctx->started = 1;
                ctx->bytes_in += io.in_consumed;

                /*
                 * Re-assert the held bit on EVERY consuming op, not
                 * only at the invocation's input append (round-4
                 * review, on bc36f47): the completed-flush clear below
                 * runs per op inside this loop, so a chain shaped
                 * [flush][data] — the postpone filter's product —
                 * cleared the bit at the flush link and then encoded
                 * the data link with the bit off and bytes held in the
                 * encoder. If downstream had drained by then, the
                 * writer saw an idle connection and the response sat
                 * until send_timeout. Symmetric per-op tracking
                 * (consume sets, completed flush/finish clears, in
                 * loop order) keeps the bit truthful at every exit
                 * path, ship: included.
                 */
                r->connection->buffered |= NGX_HTTP_GZIP_BUFFERED;

                /*
                 * Length-independent input cap (parent parity): the
                 * header gate only sees the DECLARED length; a chunked
                 * or misdeclaring upstream can stream more. Compression
                 * has started and the client holds a Content-Encoding
                 * header, so the only safe action is failing the
                 * request — protecting the worker beats completing one
                 * runaway response.
                 */
                if (ctx->max_length != NGX_CONF_UNSET
                    && (off_t) ctx->bytes_in > (off_t) ctx->max_length)
                {
                    /*
                     * Name the shape truthfully (parent #283): a
                     * declared length that the stream then overran
                     * is a misdeclaring upstream, not a chunked one,
                     * and the operator's remedy differs.
                     */
                    if (ctx->pledged_size >= 0) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "compression: input exceeded "
                                      "compression_max_length (%O) after "
                                      "%uL bytes on a response with "
                                      "declared Content-Length %O; "
                                      "aborting to protect the worker",
                                      (off_t) ctx->max_length,
                                      ctx->bytes_in, ctx->pledged_size);
                    } else {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "compression: input exceeded "
                                      "compression_max_length (%O) after "
                                      "%uL bytes on a response with no "
                                      "Content-Length; aborting to protect "
                                      "the worker",
                                      (off_t) ctx->max_length,
                                      ctx->bytes_in);
                    }
                    return NGX_ERROR;
                }
            }
            ctx->ob->last += io.out_produced;
            ctx->bytes_out += io.out_produced;

            /*
             * ORDER MATTERS (review round 1's double-FINISH): the
             * completion check must run BEFORE the full-buffer ship.
             * When a FINISH lands its last byte exactly at ob->end,
             * shipping first and looping used to call FINISH again on
             * a finished encoder — zstd silently appends an empty
             * frame, brotli hard-errors mid-response. done means done:
             * the flags ride whatever buffer the op ended in, full or
             * not.
             */
            if (io.done && op != NGX_HTTP_COMPRESSION_OP_PROCESS) {
                ngx_buf_t  *ob;

                /*
                 * The round-1 double-FINISH corner's observable
                 * witness: the op completed with its last byte parked
                 * exactly at ob->end. tools/test_exact_boundary.py
                 * FORCES this case (measure the deterministic
                 * compressed size C, re-run with compression_buffers
                 * sized to C) and asserts this line — upgrading the
                 * boundary from a patrolled neighborhood to a pinned
                 * point.
                 */
                if (ctx->ob->last == ctx->ob->end) {
                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP,
                                   r->connection->log, 0,
                                   "compression: %s landed exactly at "
                                   "buffer end",
                                   op == NGX_HTTP_COMPRESSION_OP_FINISH
                                       ? "finish" : "flush");
                }

                if (op == NGX_HTTP_COMPRESSION_OP_FINISH) {
                    ctx->done = 1;
                }

                /*
                 * A completed flush or finish means the encoder is
                 * fully drained — the parent's two clear sites,
                 * ported: drop the held bit mid-stream at every flush
                 * completion, not just at the end of the response.
                 * The matching set is at the input append above.
                 */
                r->connection->buffered &= ~NGX_HTTP_GZIP_BUFFERED;

                ob = ctx->ob;
                ctx->ob = NULL;

                if (ob->last == ob->pos) {
                    /*
                     * The op's bytes all left in earlier full-buffer
                     * shipments; the flags must not ride a zero-size
                     * temp buf (ngx_output_chain alerts on those) —
                     * use a special buf. The drained buf goes back to
                     * ctx->ob unconditionally (round-4 review): on a
                     * content-less FINISH it used to be abandoned —
                     * neither reusable nor counted out of
                     * ctx->allocated. Harmless with the request over,
                     * but the recycling accounting should stay true
                     * on every path.
                     */
                    ctx->ob = ob;
                    ob = ngx_calloc_buf(r->pool);
                    if (ob == NULL) {
                        return NGX_ERROR;
                    }

                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP,
                                   r->connection->log, 0,
                                   "compression: content-less %s shipped "
                                   "as special buf",
                                   op == NGX_HTTP_COMPRESSION_OP_FINISH
                                       ? "finish" : "flush");
                }

                ob->flush = ctx->done ? 0 : 1;
                ob->last_buf = ctx->done ? 1 : 0;

                cl = ngx_alloc_chain_link(r->pool);
                if (cl == NULL) {
                    return NGX_ERROR;
                }
                cl->buf = ob;
                cl->next = NULL;
                *last_out = cl;
                last_out = &cl->next;

                /* the op consumed this link's data and flags; the
                 * break frees the link and the next one recomputes
                 * last_seen/flush_seen from its own buf */
                break;
            }

            if (ctx->ob->last == ctx->ob->end) {
                /* output space exhausted mid-op: ship it, keep
                 * stepping the SAME op per the vtable contract */
                cl = ngx_alloc_chain_link(r->pool);
                if (cl == NULL) {
                    return NGX_ERROR;
                }
                cl->buf = ctx->ob;
                cl->next = NULL;
                *last_out = cl;
                last_out = &cl->next;
                ctx->ob = NULL;
            }

            /* PROCESS with io.done falls through to the op
             * recomputation above: input drained → flags or next
             * link; io.done == 0 → step the same op again with
             * fresh output space */
        }

        ngx_http_compression_consume_in_link(r, ctx, &in, retained);
    }

ship:

    /*
     * Retain the unconsumed tail (parent #260): every non-error path
     * from here on can return to the caller, and the cursor's links die
     * with its callback — move what survives onto pool-owned links now.
     * One site covers all of them, and the outer cycle's resume path
     * then consumes from ctx->in like any earlier callback's tail. On
     * the fast path `in` is already NULL and this is free. A partial
     * allocation failure deliberately leaves the links already copied
     * on ctx->in: NGX_ERROR is terminal, they are never resumed.
     */
    if (in != NULL) {
        if (ngx_http_compression_retain_input(r, ctx, in) != NGX_OK) {
            return NGX_ERROR;
        }

        in = NULL;
    }

    /*
     * Held-state publication (review round 2, rounds 3/4 refined):
     * after a PROCESS-only invocation the response's bytes live in
     * ctx->ob AND inside the encoder — both libraries buffer
     * internally — while this filter returns without sending
     * anything downstream. Without a buffered bit, ngx_http_writer
     * and finalization can treat the response as idle and stall it
     * until the send timeout. The bit lives on
     * r->connection->buffered, where core gzip and the parent keep
     * it (r->buffered is a four-bit field; OR-ing 0x20 into it
     * truncates to nothing), and follows the parent's set/clear
     * discipline — set at the input append above, cleared only at a
     * completed flush or finish — NOT latched for the stream's
     * lifetime, which upstream's unbuffered path reads as permanent
     * NGX_HTTP_LOWLEVEL_BUFFERED congestion. PHASE0: reuses the core
     * gzip bit — defined in every build, and the elected path
     * latches core gzip off so the owners can never overlap; a
     * dedicated bit ships with productization.
     */

    if (out == NULL) {
        if (!had_input && !ctx->nomem) {
            /*
             * Writer-driven pass (review round 2): nothing of ours to
             * emit, but the chain below may hold undelivered output —
             * forward the poke, then reclaim whatever it drained.
             */
            rc = ngx_http_next_body_filter(r, NULL);
            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            cl = NULL;
            ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &cl,
                                (ngx_buf_tag_t) &ngx_http_compression_filter_module);
            return rc;
        }

        /* input buffered (or the cap paused production): pending
         * shipped output makes this AGAIN, not OK — the writer keeps
         * driving until the busy chain drains */
        return ctx->busy ? NGX_AGAIN : NGX_OK;
    }

    /*
     * Ship, then fold the shipped chain into busy/free — drained bufs
     * come back through get_buf instead of growing the pool. Links of
     * untagged bufs (the flags-only specials) are released to the
     * pool's free-chain list by the same call.
     */
    rc = ngx_http_next_body_filter(r, out);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
                            (ngx_buf_tag_t) &ngx_http_compression_filter_module);

    if (ctx->done || !ctx->nomem) {
        /* finished, or the input was fully consumed this pass */
        return rc;
    }

    if (ctx->free == NULL) {
        /* the cap paused us and the ship drained nothing back —
         * a genuinely slow client. r->buffered is set (started
         * input implies it above), so the writer re-pokes and the
         * entry nomem block resumes us when drain happens. */
        return NGX_AGAIN;
    }

    /* the ship freed buffers: resume producing right now */
    ctx->nomem = 0;

    }   /* outer produce/ship/reclaim cycle */
}


static ngx_int_t
ngx_http_compression_init(ngx_conf_t *cf)
{
    ngx_http_compression_main_conf_t  *cmcf;

    /* the content-phase static handler registers itself from the
     * static MODULE since the split; this module owns the filters */

    /*
     * Skip the header/body filter hooks when "compression" is off in
     * every location (parent #182). any_enabled is latched conservatively
     * at directive parse time (ngx_http_compression_set_enable_slot()),
     * so a build that carries the module but never enables it pays no
     * per-response NULL-ctx pass through this filter.
     */
    cmcf = ngx_http_conf_get_module_main_conf(cf,
                                        ngx_http_compression_filter_module);
    if (cmcf == NULL || !cmcf->any_enabled) {
        return NGX_OK;
    }

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_compression_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_compression_body_filter;

    return NGX_OK;
}
