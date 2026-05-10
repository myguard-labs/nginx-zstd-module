
/*
 * Copyright (C) Alex Zhang
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <zstd.h>

#include "../ngx_http_zstd_common.h"


#define NGX_HTTP_ZSTD_MAX_DICT_SIZE  (10 * 1024 * 1024)  /* 10 MB limit */


typedef struct {
    ngx_str_t                    dict_file;
} ngx_http_zstd_main_conf_t;


typedef struct {
    ngx_flag_t                   enable;
    ngx_int_t                    level;
    ssize_t                      min_length;
    ssize_t                      max_length;

    ngx_hash_t                   types;

    ngx_bufs_t                   bufs;

    ngx_array_t                 *types_keys;

    ZSTD_CDict                  *dict;
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

    size_t                       bytes_in;
    size_t                       bytes_out;

    unsigned                     last:1;
    unsigned                     redo:1;
    unsigned                     flush:1;
    unsigned                     done:1;
    unsigned                     nomem:1;
    unsigned                     ending:1;   /* endStream in progress */

    /* PR #49: Action state machine (COMPRESS, FLUSH, or END) */
    ngx_http_zstd_action_t       action;
} ngx_http_zstd_ctx_t;


/*
 * Per-worker reusable compression context.  Allocated once at worker startup
 * with the system allocator so it can be reused across requests without being
 * tied to any request pool.  Reset between requests via
 * ZSTD_CCtx_reset(ZSTD_reset_session_only).
 */
typedef struct {
    ZSTD_CCtx   *cctx;
} ngx_http_zstd_worker_t;

static ngx_http_zstd_worker_t  ngx_http_zstd_worker;


typedef struct {
    ngx_conf_post_handler_pt  post_handler;
} ngx_http_zstd_comp_level_bounds_t;


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt  ngx_http_next_body_filter;

static ngx_str_t  ngx_http_zstd_ratio = ngx_string("zstd_ratio");


static ngx_int_t ngx_http_zstd_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_zstd_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_zstd_filter_add_data(ngx_http_request_t *r,
    ngx_http_zstd_ctx_t *ctx);
static ngx_int_t ngx_http_zstd_filter_get_buf(ngx_http_request_t *r,
    ngx_http_zstd_ctx_t *ctx);
static ngx_int_t ngx_http_zstd_filter_init_cctx(ngx_http_request_t *r,
    ngx_http_zstd_ctx_t *ctx);
static ngx_int_t ngx_http_zstd_filter_compress(ngx_http_request_t *r,
    ngx_http_zstd_ctx_t *ctx);
static ngx_int_t ngx_http_zstd_filter_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_zstd_init_process(ngx_cycle_t *cycle);
static void ngx_http_zstd_exit_process(ngx_cycle_t *cycle);
static void * ngx_http_zstd_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_zstd_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_zstd_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_zstd_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_zstd_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_zstd_ratio_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *vv, uintptr_t data);
static char *ngx_http_zstd_comp_level(ngx_conf_t *cf, void *post, void *data);
static char *ngx_conf_zstd_set_num_slot_with_negatives(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static void ngx_http_zstd_cleanup_dict(void *data);


static ngx_http_zstd_comp_level_bounds_t  ngx_http_zstd_comp_level_bounds = {
    ngx_http_zstd_comp_level
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

    { ngx_string("zstd_dict_file"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_zstd_main_conf_t, dict_file),
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
    ngx_http_zstd_init_process,             /* init process */
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

    zlcf = ngx_http_get_module_loc_conf(r, ngx_http_zstd_filter_module);

    if (!zlcf->enable
        || (r->headers_out.status < NGX_HTTP_OK         /* < 200 */
            || r->headers_out.status == NGX_HTTP_NO_CONTENT  /* 204: no body */
            || r->headers_out.status == 205              /* 205: no body */
            || (r->headers_out.status > 299
                && r->headers_out.status != NGX_HTTP_FORBIDDEN
                && r->headers_out.status != NGX_HTTP_NOT_FOUND))
       || (r->headers_out.content_encoding
           && r->headers_out.content_encoding->value.len)
       || (r->headers_out.content_length_n != -1
           && r->headers_out.content_length_n < zlcf->min_length)
       || (zlcf->max_length != NGX_CONF_UNSET
           && r->headers_out.content_length_n != -1
           && r->headers_out.content_length_n > zlcf->max_length)
       || ngx_http_test_content_type(r, &zlcf->types) == NULL
       || r->header_only)
    {
        return ngx_http_next_header_filter(r);
    }

    r->gzip_vary = 1;

    if (ngx_http_zstd_ok(r) != NGX_OK) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_zstd_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_zstd_filter_module);

    ctx->request = r;
    ctx->last_out = &ctx->out;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    ngx_str_set(&h->key, "Content-Encoding");
    ngx_str_set(&h->value, "zstd");
    r->headers_out.content_encoding = h;

    r->main_filter_need_in_memory = 1;

    ngx_http_clear_content_length(r);
    ngx_http_clear_accept_ranges(r);
    ngx_http_weak_etag(r);

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_zstd_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    size_t                rv;
    ngx_int_t             flush, rc;
    ngx_chain_t          *cl;
    ngx_http_zstd_ctx_t  *ctx;


    ctx = ngx_http_get_module_ctx(r, ngx_http_zstd_filter_module);

    if (ctx == NULL || ctx->done || r->header_only) {
        return ngx_http_next_body_filter(r, in);
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http zstd filter");

    if (ngx_http_zstd_worker.cctx == NULL) {
        ctx->done = 1;
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "zstd: worker CCtx not initialized");
        return NGX_ERROR;
    }

    if (!ctx->last && ctx->buffer_in.src == NULL) {
        /* First call: configure the reused CCtx for this request. */
        if (ngx_http_zstd_filter_init_cctx(r, ctx) != NGX_OK) {
            goto failed;
        }
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
            /*
             * Reset only the session so parameters (level, dict) are
             * preserved for the next request reusing this worker CCtx.
             */
            rv = ZSTD_CCtx_reset(ngx_http_zstd_worker.cctx,
                                 ZSTD_reset_session_only);
            if (ZSTD_isError(rv)) {
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                              "zstd: ZSTD_CCtx_reset() after done failed: %s",
                              ZSTD_getErrorName(rv));
                rc = NGX_ERROR;
            }

            return rc;
        }
    }

failed:

    ctx->done = 1;

    /* Reset session so the worker CCtx is clean for the next request. */
    rv = ZSTD_CCtx_reset(ngx_http_zstd_worker.cctx, ZSTD_reset_session_only);
    if (ZSTD_isError(rv)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "zstd: ZSTD_CCtx_reset() on failure path failed: %s",
                      ZSTD_getErrorName(rv));
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_zstd_filter_compress(ngx_http_request_t *r, ngx_http_zstd_ctx_t *ctx)
{
    size_t            rc, pos_in, pos_out;
    ZSTD_EndDirective directive;
    ngx_chain_t      *cl;
    ngx_buf_t        *b;

    ngx_log_debug6(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "zstd compress in: src:%p pos:%uz size:%uz "
                   "dst:%p pos:%uz size:%uz",
                   ctx->buffer_in.src,  ctx->buffer_in.pos,
                   ctx->buffer_in.size,
                   ctx->buffer_out.dst, ctx->buffer_out.pos,
                   ctx->buffer_out.size);

    pos_in  = ctx->buffer_in.pos;
    pos_out = ctx->buffer_out.pos;

    /* Determine the compression directive based on action state */
    if (ctx->action == NGX_HTTP_ZSTD_FILTER_END) {
        directive = ZSTD_e_end;
    } else if (ctx->action == NGX_HTTP_ZSTD_FILTER_FLUSH) {
        directive = ZSTD_e_flush;
    } else {
        directive = ZSTD_e_continue;
    }

    rc = ZSTD_compressStream2(ngx_http_zstd_worker.cctx,
                              &ctx->buffer_out, &ctx->buffer_in, directive);

    if (ZSTD_isError(rc)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "zstd: ZSTD_compressStream2() failed: %s",
                      ZSTD_getErrorName(rc));
        return NGX_ERROR;
    }

    ngx_log_debug6(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "zstd compress out: src:%p pos:%uz size:%uz "
                   "dst:%p pos:%uz size:%uz",
                   ctx->buffer_in.src,  ctx->buffer_in.pos,
                   ctx->buffer_in.size,
                   ctx->buffer_out.dst, ctx->buffer_out.pos,
                   ctx->buffer_out.size);

    ctx->in_buf->pos   += ctx->buffer_in.pos  - pos_in;
    ctx->out_buf->last += ctx->buffer_out.pos - pos_out;
    ctx->redo = 0;

    /* PR #49: State machine logic for action transitions */
    if (rc > 0) {
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
         * This prevents premature END transitions that cause 131072-byte truncation.
         */
        ctx->action = NGX_HTTP_ZSTD_FILTER_END;
        ctx->redo   = 1;

        if (ngx_buf_size(ctx->out_buf) == 0) {
            return NGX_AGAIN;
        }

    } else if (ctx->action != NGX_HTTP_ZSTD_FILTER_END) {
        /* Restore to COMPRESS after FLUSH drains (unless transitioning to END) */
        ctx->action = NGX_HTTP_ZSTD_FILTER_COMPRESS;
    }

    if (ngx_buf_size(ctx->out_buf) == 0) {
        return NGX_AGAIN;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    b = ctx->out_buf;
    
    /* PR #23: Allocate fresh buffer if output buffer is empty when transitioning
     * state (e.g., during FLUSH→COMPRESS restore). This prevents infinite loops
     * on empty buffers. */
    if (ngx_buf_size(b) == 0) {
        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }
    }

    if (rc == 0 && (ctx->flush || (ctx->last && ctx->action == NGX_HTTP_ZSTD_FILTER_END))) {
        r->connection->buffered &= ~NGX_HTTP_GZIP_BUFFERED;

        b->flush = ctx->flush && !ctx->last;
        b->last_buf = ctx->last && ctx->action == NGX_HTTP_ZSTD_FILTER_END && rc == 0;

        ctx->done  = b->last_buf;
        ctx->flush = 0;
    }

    ctx->bytes_out += ngx_buf_size(b);

    cl->next = NULL;
    cl->buf  = b;

    *ctx->last_out = cl;
    ctx->last_out  = &cl->next;

    ngx_memzero(&ctx->buffer_out, sizeof(ZSTD_outBuffer));

    return (ctx->last && ctx->action == NGX_HTTP_ZSTD_FILTER_END && rc == 0) ? NGX_OK : NGX_AGAIN;
}


static ngx_int_t
ngx_http_zstd_filter_add_data(ngx_http_request_t *r, ngx_http_zstd_ctx_t *ctx)
{
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

    ctx->in_buf = ctx->in->buf;
    ctx->in = ctx->in->next;

    if (ctx->in_buf->flush) {
        ctx->flush = 1;

    } else if (ctx->in_buf->last_buf) {
        ctx->last = 1;
    }

    ctx->buffer_in.src = ctx->in_buf->pos;
    ctx->buffer_in.pos = 0;
    ctx->buffer_in.size = ngx_buf_size(ctx->in_buf);

    ctx->bytes_in += ngx_buf_size(ctx->in_buf);

    if (ctx->buffer_in.size == 0) {
        /* Empty buffer: only skip to next if there is no pending signal.
         * If last or flush was just set above, return OK so the compress
         * step runs the end/flush immediately without a wasted iteration. */
        return (ctx->last || ctx->flush) ? NGX_OK : NGX_AGAIN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_zstd_filter_get_buf(ngx_http_request_t *r, ngx_http_zstd_ctx_t *ctx)
{
    ngx_chain_t               *cl;
    ngx_http_zstd_loc_conf_t  *zlcf;

    if (ctx->buffer_out.pos < ctx->buffer_out.size) {
        return NGX_OK;
    }

    zlcf = ngx_http_get_module_loc_conf(r, ngx_http_zstd_filter_module);

    if (ctx->free) {
        cl = ctx->free;
        ctx->free = ctx->free->next;
        ctx->out_buf = cl->buf;
        ngx_free_chain(r->pool, cl);

    } else if (ctx->bufs < zlcf->bufs.num) {
        ctx->out_buf = ngx_create_temp_buf(r->pool, zlcf->bufs.size);
        if (ctx->out_buf == NULL) {
            return NGX_ERROR;
        }

        ctx->out_buf->tag = (ngx_buf_tag_t) &ngx_http_zstd_filter_module;
        ctx->out_buf->recycled = 1;
        ctx->bufs++;

    } else {
        ctx->nomem = 1;
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
 * Configure the worker-global CCtx for the current request.
 * Called once per request on first body data.  Uses the current location's
 * compression level and optional dictionary, then resets the session state so
 * any previous request's state is discarded.
 */
static ngx_int_t
ngx_http_zstd_filter_init_cctx(ngx_http_request_t *r,
    ngx_http_zstd_ctx_t *ctx)
{
    size_t                      rc;
    ZSTD_CCtx                  *cctx;
    ngx_http_zstd_loc_conf_t   *zlcf;

    (void)ctx;

    cctx = ngx_http_zstd_worker.cctx;
    zlcf = ngx_http_get_module_loc_conf(r, ngx_http_zstd_filter_module);

    /* Full reset: session state + all parameters. */
    rc = ZSTD_CCtx_reset(cctx, ZSTD_reset_session_and_parameters);
    if (ZSTD_isError(rc)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "zstd: ZSTD_CCtx_reset() failed: %s",
                      ZSTD_getErrorName(rc));
        return NGX_ERROR;
    }

    rc = ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel,
                                 (int) zlcf->level);
    if (ZSTD_isError(rc)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "zstd: ZSTD_CCtx_setParameter(level=%d) failed: %s",
                      (int) zlcf->level, ZSTD_getErrorName(rc));
        return NGX_ERROR;
    }

    if (zlcf->dict) {
        rc = ZSTD_CCtx_refCDict(cctx, zlcf->dict);
        if (ZSTD_isError(rc)) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "zstd: ZSTD_CCtx_refCDict() failed: %s",
                          ZSTD_getErrorName(rc));
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_zstd_init_process(ngx_cycle_t *cycle)
{
    ngx_http_zstd_worker.cctx = ZSTD_createCCtx();
    if (ngx_http_zstd_worker.cctx == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "zstd: ZSTD_createCCtx() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_http_zstd_exit_process(ngx_cycle_t *cycle)
{
    (void)cycle;

    if (ngx_http_zstd_worker.cctx != NULL) {
        ZSTD_freeCCtx(ngx_http_zstd_worker.cctx);
        ngx_http_zstd_worker.cctx = NULL;
    }
}


static void *
ngx_http_zstd_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_zstd_main_conf_t  *zmcf;

    zmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_zstd_main_conf_t));
    if (zmcf == NULL) {
        return NULL;
    }

    return zmcf;
}


static char *
ngx_http_zstd_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_zstd_main_conf_t *zmcf = conf;

    if (zmcf->dict_file.len == 0) {
        return NGX_CONF_OK;
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
    conf->level = NGX_CONF_UNSET;
    conf->min_length = NGX_CONF_UNSET;
    conf->max_length = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_zstd_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_zstd_loc_conf_t *prev = parent;
    ngx_http_zstd_loc_conf_t *conf = child;

    ngx_fd_t                    fd;
    size_t                      size;
    ssize_t                     n;
    char                       *rc;
    u_char                     *buf;
    ngx_file_info_t             info;
    ngx_http_zstd_main_conf_t  *zmcf;

    rc = NGX_OK;
    buf = NULL;
    fd = NGX_INVALID_FILE;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->level, prev->level, 3);
    ngx_conf_merge_value(conf->min_length, prev->min_length, 20);
    ngx_conf_merge_value(conf->max_length, prev->max_length, NGX_CONF_UNSET);

    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             ngx_http_html_default_types))
    {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_ptr_value(conf->dict, prev->dict, NULL);
    ngx_conf_merge_bufs_value(conf->bufs, prev->bufs,
                              (128 * 1024) / ngx_pagesize, ngx_pagesize);

    zmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_zstd_filter_module);

    if (conf->enable && zmcf->dict_file.len > 0) {

        if (conf->level == prev->level && prev->dict != NULL) {
            /*
             * Same compression level and parent already loaded the dict:
             * reuse it to avoid redundant loading.
             */
            conf->dict = prev->dict;

        } else if (conf->dict == NULL) {
            /*
             * Either levels differ or parent was disabled (prev->dict == NULL):
             * load the dict fresh for this location's compression level.
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

            size = ngx_file_size(&info);

            /* Validate dictionary file size to prevent DoS
             * via memory exhaustion */
            if (size > NGX_HTTP_ZSTD_MAX_DICT_SIZE) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "dictionary file too large: %uz bytes "
                                   "(limit: %d bytes)",
                                   size, NGX_HTTP_ZSTD_MAX_DICT_SIZE);

                rc = NGX_CONF_ERROR;
                goto close;
            }

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
                ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                                   ngx_read_fd_n "\"%V incomplete\"",
                                   &zmcf->dict_file);

                rc = NGX_CONF_ERROR;
                goto close;
            }

            conf->dict = ZSTD_createCDict(buf, size, conf->level);
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

    if (rc == NGX_OK && conf->enable) {
        ngx_http_core_loc_conf_t  *clcf;

        clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
        if (clcf != NULL && !clcf->gzip_vary) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "zstd is enabled but \"gzip_vary\" is off; "
                               "add \"gzip_vary on\" to emit "
                               "\"Vary: Accept-Encoding\" so proxies and "
                               "CDNs cache compressed and uncompressed "
                               "responses separately");
        }
    }

    return rc;
}


static ngx_int_t
ngx_http_zstd_filter_init(ngx_conf_t *cf)
{
    (void)cf;

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

    return NGX_OK;
}


static ngx_int_t
ngx_http_zstd_ratio_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *vv, uintptr_t data)
{
    ngx_uint_t            ratio_int, ratio_frac;

    (void)data;
    ngx_http_zstd_ctx_t  *ctx;

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

    ratio_int = (ngx_uint_t) ctx->bytes_in / ctx->bytes_out;
    /* Use uint64_t to prevent integer overflow when multiplying by 1000 */
    ratio_frac = (ngx_uint_t) ((uint64_t) ctx->bytes_in * 1000
                 / ctx->bytes_out % 1000);

    vv->len = ngx_sprintf(vv->data, "%ui.%03ui", ratio_int, ratio_frac)
              - vv->data;

    vv->valid = 1;
    vv->no_cacheable = 1;

    return NGX_OK;
}


static void
ngx_http_zstd_cleanup_dict(void *data)
{
    ZSTD_CDict  *dict = data;

    if (dict != NULL) {
        ZSTD_freeCDict(dict);
    }
}


static char *
ngx_http_zstd_comp_level(ngx_conf_t *cf, void *post, void *data)
{
    ngx_int_t  *np = data;

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

static char *
ngx_conf_zstd_set_num_slot_with_negatives(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_int_t        *np;
    ngx_str_t        *value;
    ngx_conf_post_t  *post;


    np = (ngx_int_t *) (p + cmd->offset);

    if (*np != NGX_CONF_UNSET) {
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
        post = cmd->post;
        return post->post_handler(cf, post, np);
    }

    return NGX_CONF_OK;
}
