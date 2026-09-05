/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Google Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_HAVE_BROTLI_ENC_ENCODE_H)
#include <brotli/enc/encode.h>
#else
#include <brotli/encode.h>
#endif

/* RFC 9842 dcb needs the shared-dictionary encoder API, public since
   brotli 1.1.0. brotli installs no version header, so probe for the
   header that appeared alongside the API. Without it the module builds
   fine and the brotli_dcb_dict_file directive is rejected at config
   load with an actionable error. */
#if defined(__has_include)
#if __has_include(<brotli/shared_dictionary.h>)
#include <brotli/shared_dictionary.h>
#define NGX_HTTP_BROTLI_HAVE_DCB 1
#endif
#endif
#ifndef NGX_HTTP_BROTLI_HAVE_DCB
#define NGX_HTTP_BROTLI_HAVE_DCB 0
#endif

#include "../ngx_http_brotli_common.h"
#include "../ngx_http_brotli_sha256.h"

#define NGX_HTTP_BROTLI_MAX_DICT_SIZE (10 * 1024 * 1024) /* 10 MB limit */

/* RFC 9842 §2.1 dcb framing: the 4-byte magic 0xFF 0x44 0x43 0x42
   followed by the 32-byte SHA-256 of the dictionary, prepended to an
   ordinary brotli stream. Unlike dcz's zstd skippable frame, a plain
   brotli decoder does NOT skip this header — clients negotiate dcb
   explicitly and strip it. */
#define NGX_HTTP_BROTLI_DCB_HEADER_LEN (4 + NGX_HTTP_BROTLI_SHA256_DIGEST_LEN)

/* Brotli and GZip modules never stack, i.e. when one of them sets
   "Content-Encoding" the other becomes a pass-through filter. Consequently,
   it is almost legal to reuse this "buffered" bit.
   IIUC, buffered == some data passed to filter has not been pushed further. */
#define NGX_HTTP_BROTLI_BUFFERED NGX_HTTP_GZIP_BUFFERED

/* One RFC 9842 dictionary, loaded at config parse. `bytes` is the raw
   file content in cf->pool (worker-lifetime; old workers keep their
   forked copy across a reload until they drain), prepared per request
   as a BROTLI_SHARED_DICTIONARY_RAW dictionary. The SHA-256 is the
   negotiation key: what a client's Available-Dictionary header carries
   and what the dcb frame header must embed. */
typedef struct {
  ngx_str_t file;  /* resolved path, for logs */
  ngx_str_t bytes; /* raw dictionary contents */
  u_char hash[NGX_HTTP_BROTLI_SHA256_DIGEST_LEN];
} ngx_http_brotli_dcb_dict_t;

/* Module configuration. */
typedef struct {
  ngx_flag_t enable;

  /* Supported MIME types. */
  ngx_hash_t types;
  ngx_array_t* types_keys;

  /* Minimal required length for compression (if known). */
  ssize_t min_length;

  /* Maximal input length (declared AND running; see body filter). */
  ssize_t max_length;

  /* Per-request bypass predicates (ngx_http_complex_value_t). */
  ngx_array_t* bypass;
  /* Extra Vary field naming the header a bypass predicate varies on. */
  ngx_str_t bypass_vary;

  /* RFC 9842 dictionaries (ngx_http_brotli_dcb_dict_t). */
  ngx_array_t* dcb_dicts;

  ngx_bufs_t deprecated_unused_bufs;

  /* Brotli encoder parameter: quality */
  ngx_int_t quality;

  /* Brotli encoder parameter: (max) lg_win */
  size_t lg_win;
} ngx_http_brotli_conf_t;

/* Main (http-level) configuration. Cycle-owned on purpose: a rejected
   reload takes this state down with its pool (the same reasoning as
   the zstd sibling's dcz counter). */
typedef struct {
  /* Locations where the gzip_vary-off warning was withheld because a
     compression_vary module is loaded (see merge_conf); reported as
     one summary warning from postconfiguration instead of per
     location. */
  ngx_uint_t vary_warn_suppressed;
} ngx_http_brotli_main_conf_t;

/* Instance context. */
typedef struct {
  /* Brotli encoder instance. */
  BrotliEncoderState* encoder;

  /* Payload length; -1, if unknown. */
  off_t content_length;

  /* (uncompressed) bytes pushed to encoder. */
  size_t bytes_in;
  /* (compressed) bytes pulled from encoder. */
  size_t bytes_out;

  /* Input buffer chain. */
  ngx_chain_t* in;

  /* Output chain. */
  ngx_chain_t* out_chain;

  /* Output buffer. */
  ngx_buf_t* out_buf;

  /* Various state flags. */

  /* 1 if encoder is initialized, output chain and buffer are allocated. */
  unsigned initialized : 1;
  /* 1 if compression is finished / failed. */
  unsigned closed : 1;
  /* 1 if compression is finished. */
  unsigned success : 1;

  /* 1 if out_chain is ready to be committed, 0 otherwise. */
  unsigned output_ready : 1;
  /* 1 if output buffer is committed to the next filter and not yet fully used.
     0 otherwise. */
  unsigned output_busy : 1;

  unsigned end_of_input : 1;
  unsigned end_of_block : 1;

  /* the 36-byte dcb frame header has been sent downstream. */
  unsigned dcb_header_sent : 1;

  /* dictionary negotiated via Available-Dictionary; NULL = plain br.
     Points into the loc conf's dcb_dicts array (config-pool lifetime,
     outlives the request). */
  ngx_http_brotli_dcb_dict_t* dcb_dict;

  ngx_http_request_t* request;
} ngx_http_brotli_ctx_t;

/* Forward declarations. */

/* Initializes encoder, output chain and buffer, if necessary. Returns NGX_OK
   if encoder is successfully initialized (have been already initialized),
   and requires objects are allocated. Returns NGX_ERROR otherwise. */
static ngx_int_t ngx_http_brotli_filter_ensure_stream_initialized(
    ngx_http_request_t* r, ngx_http_brotli_ctx_t* ctx);
/* Marks instance as closed and performs cleanup. */
static void ngx_http_brotli_filter_close(ngx_http_brotli_ctx_t* ctx);

static void* ngx_http_brotli_filter_alloc(void* opaque, size_t size);
static void ngx_http_brotli_filter_free(void* opaque, void* address);

static ngx_int_t ngx_http_brotli_check_request(ngx_http_request_t* r);

static ngx_int_t ngx_http_brotli_add_variables(ngx_conf_t* cf);
static ngx_int_t ngx_http_brotli_ratio_variable(ngx_http_request_t* r,
                                                ngx_http_variable_value_t* v,
                                                uintptr_t data);

static void* ngx_http_brotli_create_main_conf(ngx_conf_t* cf);
static void* ngx_http_brotli_create_conf(ngx_conf_t* cf);
static char* ngx_http_brotli_merge_conf(ngx_conf_t* cf, void* parent,
                                        void* child);
static ngx_int_t ngx_http_brotli_filter_init(ngx_conf_t* cf);

static char* ngx_http_brotli_parse_wbits(ngx_conf_t* cf, void* post,
                                         void* data);

static char* ngx_http_brotli_dcb_dict_file(ngx_conf_t* cf, ngx_command_t* cmd,
                                           void* conf);
static ngx_table_elt_t* ngx_http_brotli_find_request_header(
    ngx_http_request_t* r, const char* name, size_t len);
static ngx_http_brotli_dcb_dict_t* ngx_http_brotli_dcb_negotiate(
    ngx_http_request_t* r, ngx_http_brotli_conf_t* conf);
static ngx_int_t ngx_http_brotli_emit_dcb_header(ngx_http_request_t* r,
                                                 ngx_http_brotli_ctx_t* ctx);

/* Configuration literals. */

static ngx_conf_num_bounds_t ngx_http_brotli_comp_level_bounds = {
    ngx_conf_check_num_bounds, BROTLI_MIN_QUALITY, BROTLI_MAX_QUALITY};

static ngx_conf_post_handler_pt ngx_http_brotli_parse_wbits_p =
    ngx_http_brotli_parse_wbits;

static ngx_command_t ngx_http_brotli_filter_commands[] = {
    {ngx_string("brotli"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_HTTP_LIF_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_brotli_conf_t, enable), NULL},

    /* Deprecated, unused. */
    {ngx_string("brotli_buffers"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE2,
     ngx_conf_set_bufs_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_brotli_conf_t, deprecated_unused_bufs), NULL},

    {ngx_string("brotli_types"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_1MORE,
     ngx_http_types_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_brotli_conf_t, types_keys),
     &ngx_http_html_default_types[0]},

    {ngx_string("brotli_comp_level"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_conf_set_num_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_brotli_conf_t, quality),
     &ngx_http_brotli_comp_level_bounds},

    {ngx_string("brotli_window"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_conf_set_size_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_brotli_conf_t, lg_win), &ngx_http_brotli_parse_wbits_p},

    {ngx_string("brotli_min_length"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_conf_set_size_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_brotli_conf_t, min_length), NULL},

    {ngx_string("brotli_max_length"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_conf_set_size_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_brotli_conf_t, max_length), NULL},

    {ngx_string("brotli_bypass"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_1MORE,
     ngx_http_set_predicate_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_brotli_conf_t, bypass), NULL},

    {ngx_string("brotli_bypass_vary"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_brotli_conf_t, bypass_vary), NULL},

    {ngx_string("brotli_dcb_dict_file"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE12,
     ngx_http_brotli_dcb_dict_file, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL},

    ngx_null_command};

/* Module context hooks. */
static ngx_http_module_t ngx_http_brotli_filter_module_ctx = {
    ngx_http_brotli_add_variables, /* pre-configuration */
    ngx_http_brotli_filter_init,   /* post-configuration */

    ngx_http_brotli_create_main_conf, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_http_brotli_create_conf, /* create location configuration */
    ngx_http_brotli_merge_conf   /* merge location configuration */
};

/* Module descriptor. */
ngx_module_t ngx_http_brotli_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_brotli_filter_module_ctx, /* module context */
    ngx_http_brotli_filter_commands,    /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING};

/* Variable names. */
static ngx_str_t ngx_http_brotli_ratio = ngx_string("brotli_ratio");

/* Next filter in the filter chain. */
static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

/* The Accept-Encoding decision lives in ngx_http_brotli_common.h — a
   length-bounded RFC 9110 walker shared with the static module and
   continuously fuzzed (see fuzz/). It replaces the substring scan that
   previously lived here, which missed the "*" wildcard, fabricated br
   tokens out of quoted parameter values, ignored ";Q=0" refusals, and
   treated malformed weights as acceptance. */

/* Process headers and decide if request is eligible for brotli compression. */
static ngx_int_t ngx_http_brotli_header_filter(ngx_http_request_t* r) {
  ngx_table_elt_t* h;
  ngx_http_brotli_ctx_t* ctx;
  ngx_http_brotli_conf_t* conf;
  ngx_http_brotli_dcb_dict_t* dcb;

  conf = ngx_http_get_module_loc_conf(r, ngx_http_brotli_filter_module);

  /* Filter only if enabled. */
  if (!conf->enable) {
    return ngx_http_next_header_filter(r);
  }

  /* Only compress OK / forbidden / not found responses. */
  if (r->headers_out.status != NGX_HTTP_OK &&
      r->headers_out.status != NGX_HTTP_FORBIDDEN &&
      r->headers_out.status != NGX_HTTP_NOT_FOUND) {
    return ngx_http_next_header_filter(r);
  }

  /* Bypass "header only" responses. */
  if (r->header_only) {
    return ngx_http_next_header_filter(r);
  }

  /* Bypass already compressed responses. */
  if (r->headers_out.content_encoding &&
      r->headers_out.content_encoding->value.len) {
    return ngx_http_next_header_filter(r);
  }

  /* If response size is known, do not compress tiny responses. */
  if (r->headers_out.content_length_n != -1 &&
      r->headers_out.content_length_n < conf->min_length) {
    return ngx_http_next_header_filter(r);
  }

  /* If response size is known and exceeds brotli_max_length, do not
     compress. Responses with no declared length are gated by the running
     input cap in the body filter instead. */
  if (conf->max_length != NGX_CONF_UNSET &&
      r->headers_out.content_length_n != -1 &&
      r->headers_out.content_length_n > conf->max_length) {
    return ngx_http_next_header_filter(r);
  }

  /* Compress only certain MIME-typed responses. */
  if (ngx_http_test_content_type(r, &conf->types) == NULL) {
    return ngx_http_next_header_filter(r);
  }

  /* Cache-correctness for request-header/cookie-driven bypass: when the
     decision to compress varies on a request header, a shared cache must
     key on it or it serves the wrong variant. The module cannot infer
     which header drove the predicate, so the operator names it via
     brotli_bypass_vary; emitted on BOTH the bypassed identity response
     and the compressed one (this runs before the bypass return below).
     Caches union all Vary lines. */
  if (conf->bypass_vary.len) {
    ngx_table_elt_t* v;

    v = ngx_list_push(&r->headers_out.headers);
    if (v == NULL) {
      return NGX_ERROR;
    }

    v->hash = 1;
#if nginx_version >= 1023000
    v->next = NULL;
#endif
    ngx_str_set(&v->key, "Vary");
    v->value = conf->bypass_vary;
  }

  /* Per-request bypass: if any brotli_bypass predicate variable resolves
     to a non-empty value other than "0", serve identity. The operator
     lever for endpoints that must not be compressed — e.g. responses
     mixing a secret with attacker-influenced reflected input (a
     BREACH-style exposure) — without splitting the location. */
  if (conf->bypass != NULL &&
      ngx_http_test_predicates(r, conf->bypass) != NGX_OK) {
    return ngx_http_next_header_filter(r);
  }

  r->gzip_vary = 1;

  /* With dictionaries configured, WHICH encoding this location serves
     depends on the request's Available-Dictionary header — the dcb
     variant, the plain br variant a dictionary-less client receives, and
     the identity fallback (a client sending "Accept-Encoding: dcb" only,
     with a hash we do not hold, gets identity NOW but dcb once it
     acquires a dictionary we do hold). A shared cache must key all of
     them on that header. This push therefore sits ABOVE the acceptance
     gate: every earlier return declines for reasons invariant in
     Available-Dictionary; the paths below are not invariant. (This exact
     ordering was a review finding on the sibling dcz implementation —
     nginx-zstd-module PR #92 — baked in here from the start.) */
  if (conf->dcb_dicts != NULL && conf->dcb_dicts->nelts > 0) {
    ngx_table_elt_t* v;

    v = ngx_list_push(&r->headers_out.headers);
    if (v == NULL) {
      return NGX_ERROR;
    }

    v->hash = 1;
#if nginx_version >= 1023000
    v->next = NULL;
#endif
    ngx_str_set(&v->key, "Vary");
    ngx_str_set(&v->value, "Available-Dictionary");
  }

  /* RFC 9842 dcb negotiation first: a client that advertises a
     dictionary we hold and accepts the dcb coding gets dictionary
     compression; everything else falls through to plain br unchanged. */
  dcb = ngx_http_brotli_dcb_negotiate(r, conf);

  if (dcb != NULL) {
    /* Commitment to encode is made below; latch gzip off exactly as
       ngx_http_brotli_check_request() would. */
    r->gzip_tested = 1;
    r->gzip_ok = 0;
  } else if (ngx_http_brotli_check_request(r) != NGX_OK) {
    return ngx_http_next_header_filter(r);
  }

  /* Prepare instance context. */
  ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_brotli_ctx_t));
  if (ctx == NULL) {
    return NGX_ERROR;
  }
  ctx->request = r;
  ctx->content_length = r->headers_out.content_length_n;
  ctx->dcb_dict = dcb;
  ngx_http_set_ctx(r, ctx, ngx_http_brotli_filter_module);

  /* Prepare response headers, so that following filters in the chain will
     notice that response body is compressed. */
  h = ngx_list_push(&r->headers_out.headers);
  if (h == NULL) {
    return NGX_ERROR;
  }

  h->hash = 1;
#if nginx_version >= 1023000
  h->next = NULL;
#endif
  ngx_str_set(&h->key, "Content-Encoding");
  if (dcb != NULL) {
    ngx_str_set(&h->value, "dcb");
  } else {
    ngx_str_set(&h->value, "br");
  }
  r->headers_out.content_encoding = h;

  r->main_filter_need_in_memory = 1;

  ngx_http_clear_content_length(r);
  ngx_http_clear_accept_ranges(r);
  ngx_http_weak_etag(r);

  return ngx_http_next_header_filter(r);
}

/* Response body filtration (compression). */
static ngx_int_t ngx_http_brotli_body_filter(ngx_http_request_t* r,
                                             ngx_chain_t* in) {
  int rc;
  ngx_http_brotli_ctx_t* ctx;
  ngx_http_brotli_conf_t* conf;
  size_t available_output;
  ptrdiff_t available_busy_output;
  size_t input_size;
  size_t available_input;
  const uint8_t* next_input_byte;
  size_t consumed_input;
  BROTLI_BOOL ok;
  u_char* out;
  ngx_chain_t* link;

  ctx = ngx_http_get_module_ctx(r, ngx_http_brotli_filter_module);

  ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "http brotli filter");

  if (ctx == NULL || ctx->closed || r->header_only) {
    return ngx_http_next_body_filter(r, in);
  }

  conf = ngx_http_get_module_loc_conf(r, ngx_http_brotli_filter_module);

  if (ngx_http_brotli_filter_ensure_stream_initialized(r, ctx) != NGX_OK) {
    ngx_http_brotli_filter_close(ctx);
    return NGX_ERROR;
  }

  /* dcb responses start with the fixed 36-byte frame header (RFC 9842
     §2.1), pushed downstream before any compressed output. NGX_AGAIN
     from the next filter just means the bytes are buffered there —
     the header still counts as sent. */
  if (ctx->dcb_dict != NULL && !ctx->dcb_header_sent) {
    if (ngx_http_brotli_emit_dcb_header(r, ctx) == NGX_ERROR) {
      ngx_http_brotli_filter_close(ctx);
      return NGX_ERROR;
    }
  }

  /* If more input is provided - append it to our input chain. */
  if (in) {
    if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
      ngx_http_brotli_filter_close(ctx);
      return NGX_ERROR;
    }
    r->connection->buffered |= NGX_HTTP_BROTLI_BUFFERED;
  }

  /* Main loop:
     - if output is not yet consumed - stop; encoder should not be touched,
       until all the output is consumed
     - if encoder has output - wrap it and send to consumer
     - if encoder is finished (and all output is consumed) - stop
     - if there is more input - push it to encoder */
  for (;;) {
    if (ctx->output_busy || ctx->output_ready) {
      if (ctx->output_busy) {
        available_busy_output = ngx_buf_size(ctx->out_buf);
      } else {
        available_busy_output = 0;
      }

      rc = ngx_http_next_body_filter(r,
                                     ctx->output_ready ? ctx->out_chain : NULL);
      if (ctx->output_ready) {
        ctx->output_ready = 0;
        ctx->output_busy = 1;
      }
      if (ngx_buf_size(ctx->out_buf) == 0) {
        ctx->output_busy = 0;
      }
      if (rc == NGX_OK) {
        if (ctx->output_busy &&
            available_busy_output == ngx_buf_size(ctx->out_buf)) {
          r->connection->buffered |= NGX_HTTP_BROTLI_BUFFERED;
          return NGX_AGAIN;
        }
        continue;
      } else if (rc == NGX_AGAIN) {
        if (ctx->output_busy) {
          /* Can't continue compression, let the outer filer decide. */
          if (ctx->in != NULL) {
            r->connection->buffered |= NGX_HTTP_BROTLI_BUFFERED;
          }
          return NGX_AGAIN;
        } else {
          /* Inner filter has given up, but we can continue processing. */
          continue;
        }
      } else {
        ngx_http_brotli_filter_close(ctx);
        return NGX_ERROR;
      }
    }

    if (BrotliEncoderHasMoreOutput(ctx->encoder)) {
      available_output = 0;
      out = (u_char*)BrotliEncoderTakeOutput(ctx->encoder, &available_output);
      if (out == NULL || available_output == 0) {
        ngx_http_brotli_filter_close(ctx);
        return NGX_ERROR;
      }
      ctx->out_buf->start = out;
      ctx->out_buf->pos = out;
      ctx->out_buf->last = out + available_output;
      ctx->out_buf->end = out + available_output;
      ctx->bytes_out += available_output;
      ctx->out_buf->last_buf = 0;
      ctx->out_buf->flush = 0;
      if (ctx->end_of_input && BrotliEncoderIsFinished(ctx->encoder)) {
        ctx->out_buf->last_buf = 1;
        r->connection->buffered &= ~NGX_HTTP_BROTLI_BUFFERED;
      } else if (ctx->end_of_block) {
        ctx->out_buf->flush = 1;
        r->connection->buffered &= ~NGX_HTTP_BROTLI_BUFFERED;
      }
      ctx->end_of_block = 0;
      ctx->output_ready = 1;
      ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                     "brotli out: %p, size:%uz", ctx->out_buf,
                     ngx_buf_size(ctx->out_buf));
      continue;
    }

    if (BrotliEncoderIsFinished(ctx->encoder)) {
      ctx->success = 1;
      r->connection->buffered &= ~NGX_HTTP_BROTLI_BUFFERED;
      ngx_http_brotli_filter_close(ctx);
      return NGX_OK;
    }

    if (ctx->end_of_input) {
      // Ask the encoder to dump the leftover.
      available_input = 0;
      available_output = 0;
      ok = BrotliEncoderCompressStream(ctx->encoder, BROTLI_OPERATION_FINISH,
                                       &available_input, NULL,
                                       &available_output, NULL, NULL);
      r->connection->buffered |= NGX_HTTP_BROTLI_BUFFERED;
      if (!ok) {
        ngx_http_brotli_filter_close(ctx);
        return NGX_ERROR;
      }
      continue;
    }

    if (ctx->in == NULL) {
      return NGX_OK;
    }

    /* TODO: coalesce tiny inputs, if they are not last/flush. */
    input_size = ngx_buf_size(ctx->in->buf);
    if (input_size == 0) {
      if (!ctx->in->buf->last_buf && !ctx->in->buf->flush) {
        link = ctx->in;
        ctx->in = ctx->in->next;
        ngx_free_chain(r->pool, link);
        continue;
      }
    }

    available_input = input_size;
    next_input_byte = (const uint8_t*)ctx->in->buf->pos;
    available_output = 0;
    ok = BrotliEncoderCompressStream(
        ctx->encoder,
        ctx->in->buf->last_buf ? BROTLI_OPERATION_FINISH
                               : ctx->in->buf->flush ? BROTLI_OPERATION_FLUSH
                                                     : BROTLI_OPERATION_PROCESS,
        &available_input, &next_input_byte, &available_output, NULL, NULL);
    r->connection->buffered |= NGX_HTTP_BROTLI_BUFFERED;
    if (!ok) {
      ngx_http_brotli_filter_close(ctx);
      return NGX_ERROR;
    }

    consumed_input = input_size - available_input;
    ctx->bytes_in += consumed_input;
    ctx->in->buf->pos += consumed_input;

    /* Length-independent input cap. The header filter rejects responses
       whose DECLARED length exceeds brotli_max_length, but that gate only
       sees the declaration: a chunked/streaming response carries none,
       and a misbehaving upstream can stream more than it declared. Either
       way a runaway upstream could feed the encoder unbounded input
       (worker CPU/memory). Compression has already started and the
       client is receiving a br stream, so the only safe action is to
       fail the request — protecting the worker beats completing one
       runaway response. */
    if (conf->max_length != NGX_CONF_UNSET &&
        (off_t)ctx->bytes_in > (off_t)conf->max_length) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "brotli: input exceeded brotli_max_length (%z) on a "
                    "response with no (honest) Content-Length; aborting to "
                    "protect the worker",
                    conf->max_length);
      ngx_http_brotli_filter_close(ctx);
      return NGX_ERROR;
    }

    if (consumed_input == input_size) {
      if (ctx->in->buf->last_buf) {
        ctx->end_of_input = 1;
      } else if (ctx->in->buf->flush) {
        ctx->end_of_block = 1;
      }
      link = ctx->in;
      ctx->in = ctx->in->next;
      ngx_free_chain(r->pool, link);
      continue;
    }

    /* Should never happen, just to make sure we don't enter infinite loop. */
    if (consumed_input == 0) {
      ngx_http_brotli_filter_close(ctx);
      return NGX_ERROR;
    }
  }

  /* unreachable */
  ngx_http_brotli_filter_close(ctx);
  return NGX_ERROR;
}

static ngx_int_t ngx_http_brotli_filter_ensure_stream_initialized(
    ngx_http_request_t* r, ngx_http_brotli_ctx_t* ctx) {
  ngx_http_brotli_conf_t* conf;
  BROTLI_BOOL ok;
  size_t wbits;

  if (ctx->initialized) {
    return NGX_OK;
  }
  ctx->initialized = 1;

  conf = ngx_http_get_module_loc_conf(r, ngx_http_brotli_filter_module);

  /* Tune lg_win, if size is known. */
  if (ctx->content_length > 0) {
    wbits = BROTLI_MIN_WINDOW_BITS;
    while ((wbits < conf->lg_win) && (ctx->content_length > (1 << wbits))) {
      wbits++;
    }
  } else {
    wbits = conf->lg_win;
  }

  ctx->encoder = BrotliEncoderCreateInstance(
      ngx_http_brotli_filter_alloc, ngx_http_brotli_filter_free, r->pool);
  if (ctx->encoder == NULL) {
    ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                  "OOM / BrotliEncoderCreateInstance");
    return NGX_ERROR;
  }

  ok = BrotliEncoderSetParameter(ctx->encoder, BROTLI_PARAM_QUALITY,
                                 (uint32_t)conf->quality);
  if (!ok) {
    ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                  "BrotliEncoderSetParameter(QUALITY, %uD) failed",
                  (uint32_t)conf->quality);
    return NGX_ERROR;
  }

  ok = BrotliEncoderSetParameter(ctx->encoder, BROTLI_PARAM_LGWIN,
                                 (uint32_t)wbits);
  if (!ok) {
    ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                  "BrotliEncoderSetParameter(LGWIN, %uD) failed",
                  (uint32_t)wbits);
    return NGX_ERROR;
  }

  /* When the response length is known (declared Content-Length — the
     common proxied/static case), tell the encoder up front: with a size
     hint it sizes internal structures to the input instead of the worst
     case, a small free speed/ratio win. Purely a hint, so a failure to
     set it is not worth failing the request over — but the API only
     rejects out-of-contract calls, so log loudly rather than silently. */
  if (ctx->content_length > 0) {
    uint32_t hint = (ctx->content_length > (off_t)0xffffffffu)
                        ? 0xffffffffu
                        : (uint32_t)ctx->content_length;
    ok = BrotliEncoderSetParameter(ctx->encoder, BROTLI_PARAM_SIZE_HINT,
                                   hint);
    if (!ok) {
      ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                    "BrotliEncoderSetParameter(SIZE_HINT, %uD) failed",
                    hint);
      return NGX_ERROR;
    }
  }

#if NGX_HTTP_BROTLI_HAVE_DCB
  /* Attach the negotiated RFC 9842 dictionary as raw shared-dictionary
     content. Prepared per request at the location's quality — the
     deliberate MVP trade against caching a prepared dictionary per
     (dictionary, quality) pair; preparation costs roughly a compression
     pass over the dictionary (~ms/MB), and the allocation goes through
     the request-pool hooks so it is reclaimed with the request. Unlike
     zstd's window-bounded prefix, a brotli shared dictionary stays fully
     referenceable regardless of lg_win, so no window math is needed. */
  if (ctx->dcb_dict != NULL) {
    BrotliEncoderPreparedDictionary* prepared;

    prepared = BrotliEncoderPrepareDictionary(
        BROTLI_SHARED_DICTIONARY_RAW, ctx->dcb_dict->bytes.len,
        ctx->dcb_dict->bytes.data, (int)conf->quality,
        ngx_http_brotli_filter_alloc, ngx_http_brotli_filter_free, r->pool);
    if (prepared == NULL) {
      ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                    "BrotliEncoderPrepareDictionary(\"%V\", %uz bytes) failed",
                    &ctx->dcb_dict->file, ctx->dcb_dict->bytes.len);
      return NGX_ERROR;
    }

    ok = BrotliEncoderAttachPreparedDictionary(ctx->encoder, prepared);
    if (!ok) {
      ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                    "BrotliEncoderAttachPreparedDictionary(\"%V\") failed",
                    &ctx->dcb_dict->file);
      return NGX_ERROR;
    }
  }
#endif

  ctx->out_buf = ngx_calloc_buf(r->pool);
  if (ctx->out_buf == NULL) {
    return NGX_ERROR;
  }
  ctx->out_buf->temporary = 1;

  ctx->out_chain = ngx_alloc_chain_link(r->pool);
  if (ctx->out_chain == NULL) {
    return NGX_ERROR;
  }
  ctx->out_chain->buf = ctx->out_buf;
  ctx->out_chain->next = NULL;

  ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "brotli encoder initialized: lvl:%i win:%d", conf->quality,
                 (1 << wbits));

  return NGX_OK;
}

static void* ngx_http_brotli_filter_alloc(void* opaque, size_t size) {
  ngx_pool_t* pool = opaque;
  void* p;

  p = ngx_palloc(pool, size);

#if (NGX_DEBUG)
  ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pool->log, 0, "brotli alloc: %p, size:%uz",
                 p, size);
#endif

  return p;
}

static void ngx_http_brotli_filter_free(void* opaque, void* address) {
  ngx_pool_t* pool = opaque;

#if (NGX_DEBUG)
  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pool->log, 0, "brotli free: %p", address);
#endif

  ngx_pfree(pool, address);
}

static void ngx_http_brotli_filter_close(ngx_http_brotli_ctx_t* ctx) {
  ctx->closed = 1;
  if (ctx->encoder) {
    BrotliEncoderDestroyInstance(ctx->encoder);
    ctx->encoder = NULL;
  }
  if (ctx->out_chain) {
    ngx_free_chain(ctx->request->pool, ctx->out_chain);
    ctx->out_chain = NULL;
  }
  if (ctx->out_buf) {
    ngx_pfree(ctx->request->pool, ctx->out_buf);
    ctx->out_buf = NULL;
  }
}

static ngx_int_t ngx_http_brotli_check_request(ngx_http_request_t* req) {
  /* Commits to a br response (the caller sets Content-Encoding right
     after), so the latching variant is correct here. */
  return ngx_http_brotli_ok(req);
}

/* Case-insensitive lookup of a request header nginx keeps no dedicated
   headers_in slot for (Available-Dictionary, Sec-Fetch-Site). Plain list
   walk — both appear at most once and only on dictionary-aware
   requests. */
static ngx_table_elt_t* ngx_http_brotli_find_request_header(
    ngx_http_request_t* r, const char* name, size_t len) {
  ngx_uint_t i;
  ngx_list_part_t* part;
  ngx_table_elt_t* h;

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

    if (h[i].key.len == len &&
        ngx_strncasecmp(h[i].key.data, (u_char*)name, len) == 0) {
      return &h[i];
    }
  }

  return NULL;
}

/* RFC 9842 dcb negotiation. Returns the configured dictionary this
   response must be compressed against, or NULL for the plain br path.
   Every requirement is a hard gate — on any miss the response falls back
   to ordinary negotiation, never to a broken dcb:

     - the location has brotli_dcb_dict_file dictionaries;
     - the request carries Available-Dictionary, an RFC 8941 byte
       sequence (":base64:") decoding to exactly 32 bytes, matching one
       of ours;
     - Accept-Encoding lists dcb explicitly with q>0 ("*" deliberately
       does NOT match: only a client that actually holds the dictionary
       can decode dcb);
     - Sec-Fetch-Site, when present, is "same-origin" or "none" (§8.3:
       dictionaries are same-origin-partitioned secrets). Browsers
       always send it; absence means a non-browser client, where the
       cross-origin read model does not apply.

   Dictionary-ID is intentionally not parsed: the hash alone is a
   complete, collision-free key. */
static ngx_http_brotli_dcb_dict_t* ngx_http_brotli_dcb_negotiate(
    ngx_http_request_t* r, ngx_http_brotli_conf_t* conf) {
  u_char buf[48];
  ngx_str_t b64;
  ngx_str_t decoded;
  ngx_uint_t i;
  ngx_table_elt_t* h;
  ngx_table_elt_t* ae;
  ngx_http_brotli_dcb_dict_t* dicts;

  if (conf->dcb_dicts == NULL || conf->dcb_dicts->nelts == 0) {
    return NULL;
  }

  if (r != r->main) {
    return NULL;
  }

  ae = r->headers_in.accept_encoding;
  if (ae == NULL) {
    return NULL;
  }

  h = ngx_http_brotli_find_request_header(
      r, "available-dictionary", sizeof("available-dictionary") - 1);
  if (h == NULL) {
    return NULL;
  }

  /* RFC 8941 byte sequence: colon-delimited standard base64. 32 bytes
     encode to 44 characters with padding (43 without); anything longer
     cannot be a SHA-256 and is rejected before decoding. */
  if (h->value.len < 2 || h->value.data[0] != ':' ||
      h->value.data[h->value.len - 1] != ':' || h->value.len - 2 > 44) {
    return NULL;
  }

  b64.data = h->value.data + 1;
  b64.len = h->value.len - 2;

  decoded.data = buf;

  if (ngx_decode_base64(&decoded, &b64) != NGX_OK ||
      decoded.len != NGX_HTTP_BROTLI_SHA256_DIGEST_LEN) {
    return NULL;
  }

  h = ngx_http_brotli_find_request_header(r, "sec-fetch-site",
                                          sizeof("sec-fetch-site") - 1);
  if (h != NULL &&
      !(h->value.len == sizeof("same-origin") - 1 &&
        ngx_strncasecmp(h->value.data, (u_char*)"same-origin",
                        sizeof("same-origin") - 1) == 0) &&
      !(h->value.len == sizeof("none") - 1 &&
        ngx_strncasecmp(h->value.data, (u_char*)"none",
                        sizeof("none") - 1) == 0)) {
    return NULL;
  }

  if (ngx_http_brotli_coding_weight(&ae->value, "dcb", sizeof("dcb") - 1,
                                    0) <= 0) {
    return NULL;
  }

  dicts = conf->dcb_dicts->elts;

  for (i = 0; i < conf->dcb_dicts->nelts; i++) {
    if (ngx_memcmp(dicts[i].hash, decoded.data,
                   NGX_HTTP_BROTLI_SHA256_DIGEST_LEN) == 0) {
      ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                     "brotli dcb: dictionary \"%V\" negotiated",
                     &dicts[i].file);
      return &dicts[i];
    }
  }

  return NULL;
}

/* Push the 36-byte dcb frame header (RFC 9842 §2.1) downstream: the
   magic 0xFF 0x44 0x43 0x42 then the dictionary's SHA-256. Sent as its
   own chain link straight to the next filter, ahead of any encoder
   output. */
static ngx_int_t ngx_http_brotli_emit_dcb_header(ngx_http_request_t* r,
                                                 ngx_http_brotli_ctx_t* ctx) {
  static const u_char magic[4] = {0xff, 0x44, 0x43, 0x42};

  ngx_int_t rc;
  ngx_buf_t* b;
  ngx_chain_t out;

  b = ngx_create_temp_buf(r->pool, NGX_HTTP_BROTLI_DCB_HEADER_LEN);
  if (b == NULL) {
    return NGX_ERROR;
  }

  b->last = ngx_cpymem(b->last, magic, sizeof(magic));
  b->last = ngx_cpymem(b->last, ctx->dcb_dict->hash,
                       NGX_HTTP_BROTLI_SHA256_DIGEST_LEN);

  out.buf = b;
  out.next = NULL;

  rc = ngx_http_next_body_filter(r, &out);
  if (rc == NGX_ERROR) {
    return NGX_ERROR;
  }

  /* NGX_OK or NGX_AGAIN: the header is in flight either way. */
  ctx->bytes_out += NGX_HTTP_BROTLI_DCB_HEADER_LEN;
  ctx->dcb_header_sent = 1;

  return NGX_OK;
}

static ngx_int_t ngx_http_brotli_add_variables(ngx_conf_t* cf) {
  ngx_http_variable_t* var;

  var = ngx_http_add_variable(cf, &ngx_http_brotli_ratio, 0);
  if (var == NULL) {
    return NGX_ERROR;
  }

  var->get_handler = ngx_http_brotli_ratio_variable;

  return NGX_OK;
}

static ngx_int_t ngx_http_brotli_ratio_variable(ngx_http_request_t* r,
                                                ngx_http_variable_value_t* v,
                                                uintptr_t data) {
  ngx_uint_t ratio_int;
  ngx_uint_t ratio_frac;
  ngx_http_brotli_ctx_t* ctx;

  v->valid = 1;
  v->no_cacheable = 0;
  v->not_found = 0;

  ctx = ngx_http_get_module_ctx(r, ngx_http_brotli_filter_module);

  /* Only report variable on non-failing streams. */
  if (ctx == NULL || !ctx->success) {
    v->not_found = 1;
    return NGX_OK;
  }

  v->data = ngx_pnalloc(r->pool, NGX_INT32_LEN + 3);
  if (v->data == NULL) {
    return NGX_ERROR;
  }

  ratio_int = (ngx_uint_t)(ctx->bytes_in / ctx->bytes_out);
  ratio_frac = (ngx_uint_t)((ctx->bytes_in * 100 / ctx->bytes_out) % 100);

  /* Rounding; e.g. 2.125 to 2.13 */
  if ((ctx->bytes_in * 1000 / ctx->bytes_out) % 10 > 4) {
    ratio_frac++;
    if (ratio_frac > 99) {
      ratio_int++;
      ratio_frac = 0;
    }
  }

  v->len = ngx_sprintf(v->data, "%ui.%02ui", ratio_int, ratio_frac) - v->data;

  return NGX_OK;
}

static void* ngx_http_brotli_create_main_conf(ngx_conf_t* cf) {
  /* pcalloc zeroes vary_warn_suppressed — no reset hook needed. */
  return ngx_pcalloc(cf->pool, sizeof(ngx_http_brotli_main_conf_t));
}

static void* ngx_http_brotli_create_conf(ngx_conf_t* cf) {
  ngx_http_brotli_conf_t* conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_brotli_conf_t));
  if (conf == NULL) {
    return NULL;
  }

  /* ngx_pcalloc fills result with zeros ->
       conf->bufs.num = 0;
       conf->types = { NULL };
       conf->types_keys = NULL; */

  conf->enable = NGX_CONF_UNSET;

  conf->quality = NGX_CONF_UNSET;
  conf->lg_win = NGX_CONF_UNSET_SIZE;
  conf->min_length = NGX_CONF_UNSET;
  conf->max_length = NGX_CONF_UNSET;
  conf->bypass = NGX_CONF_UNSET_PTR;
  conf->dcb_dicts = NGX_CONF_UNSET_PTR;

  return conf;
}

static char* ngx_http_brotli_merge_conf(ngx_conf_t* cf, void* parent,
                                        void* child) {
  ngx_http_brotli_conf_t* prev = parent;
  ngx_http_brotli_conf_t* conf = child;
  char* rc;

  ngx_conf_merge_value(conf->enable, prev->enable, 0);

  ngx_conf_merge_value(conf->quality, prev->quality, 6);
  ngx_conf_merge_size_value(conf->lg_win, prev->lg_win, 19);
  ngx_conf_merge_value(conf->min_length, prev->min_length, 20);
  ngx_conf_merge_value(conf->max_length, prev->max_length, NGX_CONF_UNSET);
  ngx_conf_merge_ptr_value(conf->bypass, prev->bypass, NULL);
  ngx_conf_merge_str_value(conf->bypass_vary, prev->bypass_vary, "");

  /* a location declaring its own brotli_dcb_dict_file list replaces the
     inherited one wholesale (standard nginx array-directive semantics) */
  ngx_conf_merge_ptr_value(conf->dcb_dicts, prev->dcb_dicts, NULL);

  /* brotli_bypass_vary names the header a brotli_bypass decision varies
     on; set alone it emits a Vary field no response varies on (silent
     cache hit-rate degradation). Warn so the misconfig stays visible. */
  if (conf->bypass_vary.len && conf->bypass == NULL) {
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"brotli_bypass_vary\" is set without a "
                       "\"brotli_bypass\" predicate; it adds a \"Vary: %V\" "
                       "field no response varies on",
                       &conf->bypass_vary);
  }

  rc = ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                            &prev->types_keys, &prev->types,
                            ngx_http_html_default_types);
  if (rc != NGX_CONF_OK) {
    return NGX_CONF_ERROR;
  }

  /* Whether a response here is br or identity depends on the request's
     Accept-Encoding; without Vary: Accept-Encoding a shared cache can
     hand the compressed variant to a client that cannot decode it.
     nginx only emits that header when the core gzip_vary is on, so warn
     per merged location — the same check the zstd sibling modules ship,
     which has caught real stale "gzip_vary off" workarounds in configs
     predating correct Vary handling in caches. When the
     compression_vary filter module is loaded — it emits the header
     from r->gzip_vary without needing "gzip_vary on" — the
     per-location warning is withheld and counted instead; presence
     alone cannot prove it is enabled here (see
     ngx_http_brotli_vary_handled_externally()), so postconfiguration
     reports one summary warning. */
  if (conf->enable) {
    ngx_http_core_loc_conf_t* clcf =
        ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    if (clcf != NULL && !clcf->gzip_vary) {
      if (ngx_http_brotli_vary_handled_externally(cf)) {
        ngx_http_brotli_main_conf_t* bmcf = ngx_http_conf_get_module_main_conf(
            cf, ngx_http_brotli_filter_module);
        if (bmcf != NULL) {
          bmcf->vary_warn_suppressed++;
        }
      } else {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "brotli is enabled but \"gzip_vary\" is off; add "
                           "\"gzip_vary on\" to emit \"Vary: Accept-Encoding\" "
                           "so proxies and CDNs cache compressed and "
                           "uncompressed responses separately");
      }
    }
  }

  return NGX_CONF_OK;
}

/* Prepend to filter chain. */
static ngx_int_t ngx_http_brotli_filter_init(ngx_conf_t* cf) {
  ngx_http_brotli_main_conf_t* bmcf;

  /* The per-location gzip_vary-off warnings withheld in merge_conf,
     folded into one line. Still a warning rather than silence:
     "compression_vary" defaults to off in that module, so its presence
     does not prove the Vary header is actually emitted for these
     locations — and one module cannot read another's merged
     configuration to check (private conf struct; merge order between
     unrelated modules is unspecified). Postconfiguration runs after
     every merge, so the count is final. */
  bmcf =
      ngx_http_conf_get_module_main_conf(cf, ngx_http_brotli_filter_module);
  if (bmcf != NULL && bmcf->vary_warn_suppressed) {
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "brotli is enabled with \"gzip_vary\" off in %ui "
                       "location(s); the per-location warnings are "
                       "suppressed because "
                       "ngx_http_compression_vary_filter_module is loaded, "
                       "but its \"compression_vary\" directive defaults to "
                       "off; verify \"compression_vary on\" covers those "
                       "locations so \"Vary: Accept-Encoding\" is emitted",
                       bmcf->vary_warn_suppressed);
  }

  ngx_http_next_header_filter = ngx_http_top_header_filter;
  ngx_http_top_header_filter = ngx_http_brotli_header_filter;

  ngx_http_next_body_filter = ngx_http_top_body_filter;
  ngx_http_top_body_filter = ngx_http_brotli_body_filter;

  return NGX_OK;
}

/* brotli_dcb_dict_file <path> — load one RFC 9842 dictionary. The file
   is read and hashed here at config parse (nginx -t validates it), into
   cf->pool so the raw bytes live exactly as long as the configuration
   that references them. Preparation for the encoder happens per request
   (see ensure_stream_initialized) because it bakes in the location's
   quality. */
static char* ngx_http_brotli_dcb_dict_file(ngx_conf_t* cf, ngx_command_t* cmd,
                                           void* conf) {
#if !(NGX_HTTP_BROTLI_HAVE_DCB)
  (void)cf;
  (void)cmd;
  (void)conf;
  return "requires brotli >= 1.1.0 (the shared-dictionary encoder API); "
         "rebuild against a newer libbrotli";
#else
  ngx_http_brotli_conf_t* blcf = conf;

  size_t size;
  ssize_t n;
  ngx_fd_t fd;
  ngx_str_t* value;
  ngx_str_t path;
  ngx_uint_t i;
  ngx_uint_t have_hash;
  ngx_file_info_t info;
  u_char hash[NGX_HTTP_BROTLI_SHA256_DIGEST_LEN];
  ngx_http_brotli_dcb_dict_t* dict;
  ngx_http_brotli_dcb_dict_t* dicts;

  (void)cmd;

  value = cf->args->elts;
  path = value[1];

  if (ngx_conf_full_name(cf->cycle, &path, 1) != NGX_OK) {
    return NGX_CONF_ERROR;
  }

  /* Optional second argument: the dictionary's SHA-256 as 64 hex chars,
     trusted VERBATIM in place of hashing the file here — the win is
     skipping a full read-and-hash pass per dictionary at every config
     parse (nginx -t, every reload), which dominates parse time at
     hundreds of registered dictionaries. The deploy tooling that
     generates the directive list has typically just computed these
     hashes anyway (deduplication). The trade, and why the argument is
     opt-in: with a self-computed hash a file that changes on disk after
     clients stored it simply stops matching (safe fallback to plain
     br); a stale supplied hash instead keeps matching, and the
     responses may fail to decode or silently decode to WRONG content
     (a same-size stale raw dictionary yields wrong bytes — the dcb
     stream carries no content checksum). The generator owns hash
     correctness — content-hashed immutable assets are the intended use.

     Validated before the file is opened so a malformed literal is
     reported as such, not shadowed by file errors. */
  have_hash = (cf->args->nelts == 3);

  if (have_hash) {
    u_char c, hi, lo;

    if (value[2].len != 2 * NGX_HTTP_BROTLI_SHA256_DIGEST_LEN) {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "invalid dcb dictionary hash \"%V\": want %d hex "
                         "characters (the file's SHA-256)",
                         &value[2], 2 * NGX_HTTP_BROTLI_SHA256_DIGEST_LEN);
      return NGX_CONF_ERROR;
    }

    for (i = 0; i < NGX_HTTP_BROTLI_SHA256_DIGEST_LEN; i++) {
      c = value[2].data[2 * i];
      hi = (c >= '0' && c <= '9')   ? (u_char) (c - '0')
           : (c >= 'a' && c <= 'f') ? (u_char) (c - 'a' + 10)
           : (c >= 'A' && c <= 'F') ? (u_char) (c - 'A' + 10)
                                    : 0xff;

      c = value[2].data[2 * i + 1];
      lo = (c >= '0' && c <= '9')   ? (u_char) (c - '0')
           : (c >= 'a' && c <= 'f') ? (u_char) (c - 'a' + 10)
           : (c >= 'A' && c <= 'F') ? (u_char) (c - 'A' + 10)
                                    : 0xff;

      if (hi == 0xff || lo == 0xff) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid dcb dictionary hash \"%V\": "
                           "non-hex character",
                           &value[2]);
        return NGX_CONF_ERROR;
      }

      hash[i] = (u_char) ((hi << 4) | lo);
    }
  }

  if (blcf->dcb_dicts == NGX_CONF_UNSET_PTR) {
    blcf->dcb_dicts =
        ngx_array_create(cf->pool, 2, sizeof(ngx_http_brotli_dcb_dict_t));
    if (blcf->dcb_dicts == NULL) {
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

  size = ngx_file_size(&info);

  if (size == 0) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "dcb dictionary \"%V\" is empty",
                       &path);
    goto failed;
  }

  if (size > NGX_HTTP_BROTLI_MAX_DICT_SIZE) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "dcb dictionary \"%V\" too large: %uz bytes "
                       "(limit: %d bytes)",
                       &path, size, NGX_HTTP_BROTLI_MAX_DICT_SIZE);
    goto failed;
  }

  dict = ngx_array_push(blcf->dcb_dicts);
  if (dict == NULL) {
    goto failed;
  }

  dict->file = path;
  dict->bytes.len = size;
  dict->bytes.data = ngx_palloc(cf->pool, size);
  if (dict->bytes.data == NULL) {
    goto failed;
  }

  n = ngx_read_fd(fd, (void*)dict->bytes.data, size);
  if (n < 0) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                       ngx_read_fd_n " \"%V\" failed", &path);
    goto failed;
  } else if ((size_t)n != size) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       ngx_read_fd_n " \"%V\" incomplete read", &path);
    goto failed;
  }

  if (ngx_close_file(fd) == NGX_FILE_ERROR) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                       ngx_close_file_n " \"%V\" failed", &path);
    return NGX_CONF_ERROR;
  }

  if (have_hash) {
    ngx_memcpy(dict->hash, hash, NGX_HTTP_BROTLI_SHA256_DIGEST_LEN);
  } else {
    ngx_http_brotli_sha256(dict->bytes.data, size, dict->hash);
  }

  /* Two entries with the same hash make the negotiation lookup
     ambiguous (for computed hashes that means identical content under
     two paths — almost certainly a copy meant to be a new version;
     supplied hashes are compared as declared). Fail loudly at load
     rather than silently matching the first. */
  dicts = blcf->dcb_dicts->elts;

  for (i = 0; i + 1 < blcf->dcb_dicts->nelts; i++) {
    if (ngx_memcmp(dicts[i].hash, dict->hash,
                   NGX_HTTP_BROTLI_SHA256_DIGEST_LEN) == 0) {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "dcb dictionary \"%V\" has the same hash as "
                         "\"%V\"",
                         &path, &dicts[i].file);
      return NGX_CONF_ERROR;
    }
  }

  return NGX_CONF_OK;

failed:

  if (ngx_close_file(fd) == NGX_FILE_ERROR) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                       ngx_close_file_n " \"%V\" failed", &path);
  }

  return NGX_CONF_ERROR;
#endif
}

/* Translate "window size" to window bits (log2), and check bounds. */
static char* ngx_http_brotli_parse_wbits(ngx_conf_t* cf, void* post,
                                         void* data) {
  size_t* parameter = data;
  size_t bits;
  size_t wsize;

  for (bits = BROTLI_MIN_WINDOW_BITS; bits <= BROTLI_MAX_WINDOW_BITS; bits++) {
    wsize = 1u << bits;
    if (*parameter == wsize) {
      *parameter = bits;
      return NGX_CONF_OK;
    }
  }

  return "must be 1k, 2k, 4k, 8k, 16k, 32k, 64k, 128k, 256k, 512k, 1m, 2m, 4m, "
         "8m or 16m";
}
