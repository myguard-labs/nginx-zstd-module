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

/* 410 Gone is compressed like 403/404. nginx/nginx#1466 proposes the
   same for core gzip and adds this macro with it; defined here for
   every nginx that does not have it. */
#ifndef NGX_HTTP_GONE
#define NGX_HTTP_GONE 410
#endif

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

  /* RFC 9842 secure-context gate. A dcb response is only offered on a
     secure context: over cleartext, dictionary compression hands a
     network attacker a length oracle over content the dictionary already
     describes (RFC 9842 section 8). Secure means this nginx terminates
     TLS (r->connection->ssl != NULL); off by default. When a
     TLS-terminating proxy fronts nginx (ssl NULL here),
     brotli_dcb_assume_secure_transport on asserts the hop the client
     actually spoke was secure — an operator acknowledgement, never
     inferred from X-Forwarded-Proto or any client-settable header. */
  ngx_flag_t dcb_assume_secure;

  ngx_bufs_t deprecated_unused_bufs;

  /* Brotli encoder parameter: quality */
  ngx_int_t quality;

  /* Brotli encoder parameter: (max) lg_win */
  size_t lg_win;
} ngx_http_brotli_conf_t;

/* Instance context. */
typedef struct {
  /* Brotli encoder instance. */
  BrotliEncoderState* encoder;

  /* Payload length; -1, if unknown. */
  off_t content_length;

  /* (uncompressed) bytes pushed to encoder. uint64_t, not size_t (zstd
     siblings' #200 row m7): on ILP32 a size_t wraps at 4 GiB and silently
     corrupts $brotli_ratio for larger streamed responses. */
  uint64_t bytes_in;
  /* (compressed) bytes pulled from encoder. */
  uint64_t bytes_out;

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

static ngx_int_t ngx_http_brotli_cc_value_no_transform(ngx_table_elt_t* cc);
static ngx_int_t ngx_http_brotli_no_transform(ngx_http_request_t* r);

static ngx_int_t ngx_http_brotli_add_variables(ngx_conf_t* cf);
static ngx_int_t ngx_http_brotli_ratio_variable(ngx_http_request_t* r,
                                                ngx_http_variable_value_t* v,
                                                uintptr_t data);
static ngx_int_t ngx_http_brotli_dcb_dicts_hashed_variable(
    ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);

static void* ngx_http_brotli_create_conf(ngx_conf_t* cf);
static char* ngx_http_brotli_merge_conf(ngx_conf_t* cf, void* parent,
                                        void* child);
static ngx_int_t ngx_http_brotli_filter_init(ngx_conf_t* cf);
static char* ngx_http_brotli_set_enable_slot(ngx_conf_t* cf,
                                             ngx_command_t* cmd, void* conf);

static char* ngx_http_brotli_parse_wbits(ngx_conf_t* cf, void* post,
                                         void* data);

static char* ngx_http_brotli_dcb_dict_file(ngx_conf_t* cf, ngx_command_t* cmd,
                                           void* conf);
static ssize_t ngx_http_brotli_read_dict_file(ngx_fd_t fd, u_char* buf,
                                              size_t size);
static void* ngx_http_brotli_create_main_conf(ngx_conf_t* cf);
static char* ngx_http_brotli_init_main_conf(ngx_conf_t* cf, void* conf);
static ngx_table_elt_t* ngx_http_brotli_find_request_header(
    ngx_http_request_t* r, const char* name, size_t len);
static ngx_http_brotli_dcb_dict_t* ngx_http_brotli_dcb_negotiate(
    ngx_http_request_t* r, ngx_http_brotli_conf_t* conf);
static ngx_int_t ngx_http_brotli_emit_dcb_header(ngx_http_request_t* r,
                                                 ngx_http_brotli_ctx_t* ctx);

/* Cycle-global dictionary trust policy (zstd siblings' #165 + #199).
   MAIN_CONF only: the loaded dictionaries are cycle state, so the
   policy is a property of the whole load, declared once in http{}. */
typedef struct {
  /* brotli_dcb_dict_strict_path: opt-in, off by default. When on, the
     dictionary path is resolved one component at a time with
     openat(O_NOFOLLOW|O_DIRECTORY) -- an intermediate symlink (the
     classic current -> releases/7 layout) is refused, not followed --
     and the file must be owned by the loading principal or root and
     not be writable by group or other. */
  ngx_flag_t dict_strict_path;

  /* Set by ngx_http_brotli_dcb_dict_file() the first time it loads a
     dictionary while dict_strict_path does not yet read as the
     explicit "on" at that point in the parse. Directives are
     conventionally order-independent, so silently treating such a
     load as "strict passed" would fail OPEN; init_main_conf rejects
     the ordering outright when the final value is "on", rather than
     re-opening every dictionary post-parse (which would reintroduce
     the TOCTOU window the fstat-after-open checks close). */
  ngx_flag_t dict_loaded_before_strict_on;
  ngx_str_t dict_loaded_before_strict_on_file;

  /* brotli_dcb_dict_trust_hashes (zstd sibling #198 + #220): default
     off VERIFIES a supplied hash literal against the bytes read -- a
     mismatch fails the load, protecting a pipeline whose config
     generation and file placement are decoupled. "on" restores the
     trusted-verbatim path: the literal IS the negotiation key and the
     load-time SHA-256 is skipped, which at hundreds of dictionaries is
     essentially all of the config-load CPU (the sibling measured 737
     lines: nginx -t 5.1s -> 0.9s, user CPU 4.3s -> 0.03s). Lines
     without a literal are hashed under either policy -- which is also
     the per-line escape hatch under trust. */
  ngx_flag_t dcb_dict_trust_hashes;

  /* Ordering record, same trap and remedy as the strict_path pair
     above: a literal VERIFIED (hashed) because trust did not yet read
     "on" at that point in the parse is correct but silently paid the
     full pass the directive exists to skip; init_main_conf rejects
     the ordering when the final value is "on". */
  ngx_flag_t dcb_dict_verified_before_trust_on;
  ngx_str_t dcb_dict_verified_before_trust_on_file;

  /* Load-time SHA-256 computations over dcb dictionaries in THIS
     configuration ($brotli_dcb_dicts_hashed). Cycle-owned; the
     observable witness that trust_hashes actually skips the pass
     (zero for trusted literals) rather than substituting the literal
     after hashing anyway -- the evidence gap the old trusted-verbatim
     test admitted it could not close. */
  ngx_uint_t dcb_dicts_hashed;

  /* One EVP digest context reused across every hash this config load
     computes (the zstd sibling's #262): lazily created on the first
     computed hash, freed with cf->pool when parsing ends. void* so no
     OpenSSL types leak into this struct; NULL (creation failed, or no
     libcrypto) makes every hash take the portable path -- the same
     total-function contract as before. Only the dict_file handler
     touches it, and only during parse. */
  void* dcb_evp_md_ctx;
  ngx_flag_t dcb_evp_md_ctx_attempted;

  /* Conservative "could this cycle serve a brotli response" latch for
     ngx_http_brotli_filter_init() (zstd siblings' #182). Set at directive
     PARSE time by ngx_http_brotli_set_enable_slot() whenever "brotli" is
     parsed as anything but an explicit "off" anywhere in the config --
     main, srv, loc, or the NGX_HTTP_LIF_CONF conf synthesized for a
     rewrite-phase "if" block, which the location-conf merge walk does
     not provably visit. A false positive (hooks installed, every merged
     location off) costs the two no-op calls this is about; a false
     negative would silently drop compression for a live location, so
     parse time is the safe side. Never read at request time; the
     $brotli_* variables are registered regardless. */
  ngx_flag_t any_enabled;
} ngx_http_brotli_main_conf_t;

/* Configuration literals. */

static ngx_conf_num_bounds_t ngx_http_brotli_comp_level_bounds = {
    ngx_conf_check_num_bounds, BROTLI_MIN_QUALITY, BROTLI_MAX_QUALITY};

static ngx_conf_post_handler_pt ngx_http_brotli_parse_wbits_p =
    ngx_http_brotli_parse_wbits;

static ngx_command_t ngx_http_brotli_filter_commands[] = {
    {ngx_string("brotli"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_HTTP_LIF_CONF | NGX_CONF_FLAG,
     ngx_http_brotli_set_enable_slot, NGX_HTTP_LOC_CONF_OFFSET,
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

    {ngx_string("brotli_dcb_assume_secure_transport"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_FLAG,
     ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_brotli_conf_t, dcb_assume_secure), NULL},

    {ngx_string("brotli_dcb_dict_strict_path"),
     NGX_HTTP_MAIN_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
     NGX_HTTP_MAIN_CONF_OFFSET,
     offsetof(ngx_http_brotli_main_conf_t, dict_strict_path), NULL},

    /* MAIN_CONF like strict_path, same reason: what a supplied hash
       literal MEANS is a property of the whole load's trust model.
       Must precede every brotli_dcb_dict_file carrying a literal
       (enforced in init_main_conf). */
    {ngx_string("brotli_dcb_dict_trust_hashes"),
     NGX_HTTP_MAIN_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
     NGX_HTTP_MAIN_CONF_OFFSET,
     offsetof(ngx_http_brotli_main_conf_t, dcb_dict_trust_hashes), NULL},

    ngx_null_command};

/* Module context hooks. */
static ngx_http_module_t ngx_http_brotli_filter_module_ctx = {
    ngx_http_brotli_add_variables, /* pre-configuration */
    ngx_http_brotli_filter_init,   /* post-configuration */

    ngx_http_brotli_create_main_conf, /* create main configuration */
    ngx_http_brotli_init_main_conf,   /* init main configuration */

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

/* Does one Cache-Control value carry a no-transform DIRECTIVE (RFC 9111
   §5.2.2.6)? Directives are comma-separated; everything from the first
   ';' or '=' onward in a segment is parameter/argument text, so a quoted
   parameter VALUE like extension="no-transform" does not match (parent
   nginx-zstd-module #251's walker, with the '=' cut added). */
static ngx_int_t ngx_http_brotli_cc_value_no_transform(ngx_table_elt_t* cc) {
  u_char* p;
  u_char* last;
  u_char* start;
  u_char* end;
  u_char* cut;
  u_char* seg_end;

  p = cc->value.data;
  last = p + cc->value.len;

  while (p < last) {
    start = p;
    while (start < last && (*start == ' ' || *start == '\t')) {
      start++;
    }

    /* Segment end = the next comma OUTSIDE any quoted string (zstd
       sibling's #274): a quoted extension value may contain commas and
       backslash-escaped characters, and splitting there fabricated a
       matching segment out of the quoted text -- a false compression
       opt-out. Computed once, used for the cut and the advance, so the
       next segment can never start inside a quote. */
    seg_end = start;
    while (seg_end < last && *seg_end != ',') {
      if (*seg_end == '\"') {
        seg_end++;
        while (seg_end < last && *seg_end != '\"') {
          if (*seg_end == '\\' && seg_end + 1 < last) {
            seg_end++;
          }
          seg_end++;
        }
        if (seg_end < last) {
          seg_end++; /* the closing quote */
        }
        continue;
      }
      seg_end++;
    }

    cut = start;
    while (cut < seg_end && *cut != ';' && *cut != '=') {
      cut++;
    }
    end = cut;

    while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
      end--;
    }

    if ((size_t)(end - start) == sizeof("no-transform") - 1 &&
        ngx_strncasecmp(start, (u_char*)"no-transform",
                        sizeof("no-transform") - 1) == 0) {
      return 1;
    }

    p = (seg_end < last) ? seg_end + 1 : seg_end;
  }

  return 0;
}

/* RFC 9110 §7.7: no-transform forbids changing the content coding. The
   walk covers the whole headers_out list rather than the
   headers_out.cache_control chain because only some producers (the
   upstream module) wire that chain — a Cache-Control pushed straight
   onto the list by a module is invisible there. Repeated Cache-Control
   lines are each checked (caches treat them as one combined list). */
static ngx_int_t ngx_http_brotli_no_transform(ngx_http_request_t* r) {
  ngx_uint_t i;
  ngx_list_part_t* part;
  ngx_table_elt_t* h;

  part = &r->headers_out.headers.part;
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

    if (h[i].hash == 0 || h[i].key.len != sizeof("Cache-Control") - 1 ||
        h[i].value.len == 0) {
      continue;
    }

    if (ngx_strncasecmp(h[i].key.data, (u_char*)"Cache-Control",
                        sizeof("Cache-Control") - 1) == 0 &&
        ngx_http_brotli_cc_value_no_transform(&h[i])) {
      return 1;
    }
  }

  return 0;
}

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

  /* Only compress OK / forbidden / not found / gone responses -- core
     gzip's set plus 410, which nginx/nginx#1466 proposes for gzip
     too. */
  if (r->headers_out.status != NGX_HTTP_OK &&
      r->headers_out.status != NGX_HTTP_FORBIDDEN &&
      r->headers_out.status != NGX_HTTP_NOT_FOUND &&
      r->headers_out.status != NGX_HTTP_GONE) {
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

  /* RFC 9110 §7.7 (parent nginx-zstd-module #251): a response carrying
     Cache-Control: no-transform must keep its content coding. Sits
     before any Vary emission — the skip is keyed on a response header,
     so the response does not vary on Accept-Encoding. Matching the
     parent's standalone semantics, core gzip is left alone: this module
     falls through, same as the bypass below. */
  if (ngx_http_brotli_no_transform(r)) {
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

  /* Vary emitted by this module rather than merely requested via
     r->gzip_vary and left to the operator's "gzip_vary" directive —
     whose default is OFF, under which nginx clears the flag and emits
     nothing, so a negotiated response ships with no Vary and a shared
     cache serves the compressed body to a client that cannot decode it
     (parent nginx-zstd-module #163). Every path below negotiates on
     Accept-Encoding (plain br, dcb, and the identity fallbacks), so the
     line must be present. Placed below the bypass return, matching the
     sibling unified module's ordering: the bypassed identity path carries
     its cache-key dimension through the brotli_bypass_vary push above.

     With dictionaries configured, the response ALSO varies on
     Available-Dictionary and on Sec-Fetch-Site. Available-Dictionary
     because the dcb variant, the plain-br variant a dictionary-less
     client gets, and the identity fallback are all keyed on it.
     Sec-Fetch-Site (parent #160) because dcb_negotiate() below refuses
     the dictionary coding for any value other than absent / same-origin
     / none (RFC 9842 §8.3 cross-origin partitioning), which makes that
     header a response-selection input: without it in Vary a shared cache
     filled by a same-origin request would serve the dcb body to a
     cross-site request whose gate said no (or the reverse) — a hit on the
     wrong variant across the partition.

     Emit ONE combined "Vary: Accept-Encoding, Available-Dictionary,
     Sec-Fetch-Site" rather than a delegated Accept-Encoding line plus
     separate literal lines: two Vary lines are legal per RFC 9110, but a
     fair number of intermediary caches key on the FIRST line only —
     exactly the hazard this header exists to prevent. The combined-line
     branch does NOT set r->gzip_vary, so the core emitter cannot add a
     second Accept-Encoding line beside it. */
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
    ngx_str_set(&v->value,
                "Accept-Encoding, Available-Dictionary, Sec-Fetch-Site");

  } else if (ngx_http_brotli_vary_accept_encoding(r) != NGX_OK) {
    return NGX_ERROR;
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
      /* !HasMoreOutput alongside IsFinished (zstd siblings' round-4
         twin): IsFinished alone rests on the undocumented invariant
         that a finished encoder never holds output — marking last_buf
         on this buf while output remained would truncate the stream.
         The conjunct costs nothing. */
      if (ctx->end_of_input && BrotliEncoderIsFinished(ctx->encoder) &&
          !BrotliEncoderHasMoreOutput(ctx->encoder)) {
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

    if (BrotliEncoderIsFinished(ctx->encoder) &&
        !BrotliEncoderHasMoreOutput(ctx->encoder)) {
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
      /* Name the shape truthfully (zstd siblings' #283): a declared length
         the stream then overran is a misdeclaring upstream, not a chunked
         one, and the operator's remedy differs. */
      if (ctx->content_length >= 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "brotli: input exceeded brotli_max_length (%z) after "
                      "%uL bytes on a response with declared "
                      "Content-Length %O; aborting to protect the "
                      "worker",
                      conf->max_length, ctx->bytes_in, ctx->content_length);
      } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "brotli: input exceeded brotli_max_length (%z) after "
                      "%uL bytes on a response with no "
                      "Content-Length; aborting to protect the worker",
                      conf->max_length, ctx->bytes_in);
      }
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
      /* Do what the comment above always promised (zstd siblings'
         round-4 twin): a refused hint is a lost optimization, not a
         lost response — the old return NGX_ERROR here failed a
         request the encoder would have served fine unhinted. */
      ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                    "BrotliEncoderSetParameter(SIZE_HINT, %uD) refused; "
                    "continuing unhinted",
                    hint);
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
  ngx_http_brotli_dcb_dict_t* dicts;

  if (conf->dcb_dicts == NULL || conf->dcb_dicts->nelts == 0) {
    return NULL;
  }

  if (r != r->main) {
    return NULL;
  }

  /* RFC 9842 section 8 secure-context gate, fail-closed and ahead of the
     header parsing: no dcb response over a non-secure connection, because
     a dictionary-compressed response over cleartext is a length oracle
     over content the dictionary already describes. Secure means this
     nginx terminates TLS. The guard mirrors ngx_connection_t's own
     condition for the ssl member (#if (NGX_SSL || NGX_COMPAT)), not
     NGX_SSL alone, so a --with-compat build (where the field exists and
     is always NULL) reads it correctly. HTTP/2 and HTTP/3 both carry a
     non-NULL connection->ssl. A TLS-terminating proxy makes ssl NULL
     here; brotli_dcb_assume_secure_transport on opts back in — an
     operator acknowledgement, never inferred from a client-settable
     forwarded-scheme header. */
  if (!conf->dcb_assume_secure) {
    ngx_flag_t secure;

#if (NGX_SSL || NGX_COMPAT)
    secure = (r->connection->ssl != NULL);
#else
    secure = 0;
#endif

    if (!secure) {
      ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                     "brotli dcb: skip, not a secure context (RFC 9842 "
                     "section 8); set "
                     "\"brotli_dcb_assume_secure_transport on\" if TLS "
                     "terminates upstream");
      return NULL;
    }
  }

  if (r->headers_in.accept_encoding == NULL) {
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

  /* Whole-field lookup; wildcard-suppressed — only a client that
     actually holds the dictionary can decode dcb, so a blanket "*"
     must not turn it on. */
  if (ngx_http_brotli_request_coding_weight(r, "dcb", sizeof("dcb") - 1,
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
  static ngx_str_t dicts_hashed_name =
      ngx_string("brotli_dcb_dicts_hashed");
  ngx_http_variable_t* var;

  var = ngx_http_add_variable(cf, &ngx_http_brotli_ratio, 0);
  if (var == NULL) {
    return NGX_ERROR;
  }

  var->get_handler = ngx_http_brotli_ratio_variable;

  var = ngx_http_add_variable(cf, &dicts_hashed_name, 0);
  if (var == NULL) {
    return NGX_ERROR;
  }

  var->get_handler = ngx_http_brotli_dcb_dicts_hashed_variable;

  return NGX_OK;
}

/* $brotli_dcb_dicts_hashed — load-time SHA-256 passes over dcb
   dictionaries this configuration cycle. Constant after config parse.
   Operators check that trust_hashes actually took effect (zero with
   every line trusted); the suite uses it as the witness that trust
   SKIPS the pass rather than substituting the literal after hashing
   anyway. */
static ngx_int_t ngx_http_brotli_dcb_dicts_hashed_variable(
    ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
  ngx_http_brotli_main_conf_t* bmcf;

  (void)data;

  bmcf = ngx_http_get_module_main_conf(r, ngx_http_brotli_filter_module);

  v->data = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
  if (v->data == NULL) {
    return NGX_ERROR;
  }

  v->len = ngx_sprintf(v->data, "%ui", bmcf->dcb_dicts_hashed) - v->data;
  v->valid = 1;
  v->no_cacheable = 0;
  v->not_found = 0;

  return NGX_OK;
}

/* Split bytes_in/bytes_out into an integer part and THREE exact fractional
   digits without ever overflowing uint64_t (zstd siblings' #294). Either
   counter can approach UINT64_MAX on a long-lived connection, and
   bytes_out may exceed bytes_in whenever the encoder expands
   incompressible input. `bytes_in * 100 / bytes_out` wraps in the
   multiply; dividing first and scaling only the remainder still wraps
   when bytes_out > bytes_in, because the remainder is then bytes_in
   itself. Exact long division instead: per digit the remainder (always
   < divisor) is multiplied by 10, and when that product would not fit,
   whole divisors are peeled off remainder * 10 by addition so nothing
   leaves uint64_t -- the result matches an exact 128-bit
   bytes_in * 1000 / bytes_out for every input pair
   (tools/test_ratio_scaling_unit.sh extracts this verbatim and checks
   it against that oracle). The caller rounds the third digit away. */
static void ngx_http_brotli_ratio_parts(uint64_t bytes_in, uint64_t bytes_out,
                                        ngx_uint_t* ratio_int,
                                        ngx_uint_t* ratio_frac) {
  uint64_t remainder, frac;
  int i;

  *ratio_int = (ngx_uint_t)(bytes_in / bytes_out);

  remainder = bytes_in % bytes_out;
  frac = 0;

  for (i = 0; i < 3; i++) {
    if (remainder <= UINT64_MAX / 10) {
      remainder *= 10;
      frac = frac * 10 + remainder / bytes_out;
      remainder %= bytes_out;
      continue;
    }

    /* remainder * 10 would overflow. Since remainder < bytes_out, that only
       happens for a very large divisor; then remainder * 10 is at most
       10 * bytes_out, so the quotient digit is in [0, 10) and can be found
       exactly without forming the product: peel off whole multiples of
       bytes_out from remainder * 10 one at a time, each step staying inside
       uint64_t. */
    {
      uint64_t acc = remainder;
      uint64_t digit = 0;
      int k;

      /* acc accumulates remainder * 10 modulo bytes_out. */
      for (k = 0; k < 9; k++) {
        acc += remainder;

        if (acc >= bytes_out || acc < remainder) {
          /* wrapped past, or reached, one whole bytes_out */
          acc -= bytes_out;
          digit++;
        }
      }

      frac = frac * 10 + digit;
      remainder = acc;
    }
  }

  *ratio_frac = (ngx_uint_t)frac;
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

  v->data = ngx_pnalloc(r->pool, NGX_INT64_LEN + 3);
  if (v->data == NULL) {
    return NGX_ERROR;
  }

  ngx_http_brotli_ratio_parts(ctx->bytes_in, ctx->bytes_out, &ratio_int,
                              &ratio_frac);

  /* Two decimals, rounded half-up on the exact third digit, as this
     variable has always printed; e.g. 2.125 to 2.13. */
  if (ratio_frac % 10 > 4) {
    ratio_frac = ratio_frac / 10 + 1;
    if (ratio_frac > 99) {
      ratio_int++;
      ratio_frac = 0;
    }
  } else {
    ratio_frac /= 10;
  }

  v->len = ngx_sprintf(v->data, "%ui.%02ui", ratio_int, ratio_frac) - v->data;

  return NGX_OK;
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
  conf->dcb_assume_secure = NGX_CONF_UNSET;

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
  ngx_conf_merge_value(conf->dcb_assume_secure, prev->dcb_assume_secure, 0);

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

  /* No gzip_vary-off warning here anymore (parent #163): the header
     filter emits "Vary: Accept-Encoding" itself on every
     Accept-Encoding-dependent response (see
     ngx_http_brotli_vary_accept_encoding()), so correctness no longer
     depends on the operator setting "gzip_vary on", and warning about a
     directive that no longer changes whether the header appears would be
     actively misleading. */

  return NGX_CONF_OK;
}

/* "brotli on|off" (zstd siblings' #182): the stock flag slot plus a
   parse-time latch of the cycle-global any_enabled bit, so
   ngx_http_brotli_filter_init() can skip installing the filter hooks
   when the module is off in every location. ngx_conf_set_flag_slot()
   accepts exactly "on" and "off", so by the time this runs value[1] is
   one of the two; only the literal "off" leaves the bit clear. */
static char* ngx_http_brotli_set_enable_slot(ngx_conf_t* cf,
                                             ngx_command_t* cmd, void* conf) {
  ngx_str_t* value;
  char* rc;
  ngx_http_brotli_main_conf_t* bmcf;

  rc = ngx_conf_set_flag_slot(cf, cmd, conf);
  if (rc != NGX_CONF_OK) return rc;

  value = cf->args->elts;
  if (value[1].len == 3 && ngx_strncmp(value[1].data, "off", 3) == 0) {
    return NGX_CONF_OK;
  }

  bmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_brotli_filter_module);
  bmcf->any_enabled = 1;

  return NGX_CONF_OK;
}

/* Prepend to filter chain -- unless "brotli" is off everywhere, in which
   case a build that carries the module pays no per-response NULL-ctx
   pass through it (see any_enabled). */
static ngx_int_t ngx_http_brotli_filter_init(ngx_conf_t* cf) {
  ngx_http_brotli_main_conf_t* bmcf;

  bmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_brotli_filter_module);
  if (bmcf == NULL || !bmcf->any_enabled) return NGX_OK;

  ngx_http_next_header_filter = ngx_http_top_header_filter;
  ngx_http_top_header_filter = ngx_http_brotli_header_filter;

  ngx_http_next_body_filter = ngx_http_top_body_filter;
  ngx_http_top_body_filter = ngx_http_brotli_body_filter;

  return NGX_OK;
}

/* Read exactly `size` bytes of a dictionary into `buf`, looping until the
   request is satisfied. Mirrors the sibling nginx-zstd-module's #195:
   ngx_read_fd() is read(2) on POSIX, which may return a SHORT count on a
   regular file — a signal interrupting the read after a partial transfer,
   or a sufficiently large read — so a single read is not enough and the
   caller would reject a valid dictionary as an incomplete read. Retry
   EINTR, resume on a short count, and stop early only on a hard error
   (returns -1) or an unexpected EOF (returns the partial total < size).
   The caller's existing n < 0 / n != size handling is unchanged.

   The EINTR retry is #if !(NGX_WIN32): win32's ngx_errno.h defines no
   NGX_EINTR (ReadFile on a synchronous handle is not interruptible), so
   guarding on the platform states the reason and keeps the MSVC build
   compiling. */
static ssize_t ngx_http_brotli_read_dict_file(ngx_fd_t fd, u_char* buf,
                                              size_t size) {
  ssize_t n;
  size_t done;

  for (done = 0; done < size; /* void */) {
    n = ngx_read_fd(fd, buf + done, size - done);

    if (n < 0) {
#if !(NGX_WIN32)
      if (ngx_errno == NGX_EINTR) {
        continue;
      }
#endif
      return -1;
    }

    if (n == 0) {
      break;  /* EOF before `size`: return the partial */
    }

    done += (size_t)n;
  }

  return (ssize_t)done;
}

#if !(NGX_WIN32)
#include <fcntl.h> /* openat(), O_DIRECTORY, O_NOFOLLOW, AT_FDCWD */
/* AT_FDCWD is the portable signal that the POSIX.1-2008 *at() family is
   available (zstd sibling #199). Where it is absent strict mode has no
   way to resolve a path component-by-component, and it fails CLOSED at
   config load rather than degrading to a leaf-only guarantee. */
#ifdef AT_FDCWD
#define NGX_HTTP_BROTLI_HAVE_STRICT_WALK 1
#else
#define NGX_HTTP_BROTLI_HAVE_STRICT_WALK 0
#endif
#else
#define NGX_HTTP_BROTLI_HAVE_STRICT_WALK 0
#endif

#if (NGX_HTTP_BROTLI_HAVE_STRICT_WALK) && (NGX_HTTP_BROTLI_HAVE_DCB)

/* Strict-mode component-by-component open (zstd sibling #199, M3).

   O_NOFOLLOW on a whole-path open guards ONLY the leaf: the kernel
   resolves every intermediate component normally, so a symlinked
   directory in the path -- the classic current -> releases/7 deploy
   layout -- is followed silently and strict mode selects whatever
   bytes the symlink's owner points it at. Walking the path with
   openat(O_NOFOLLOW|O_DIRECTORY) one component at a time makes an
   intermediate symlink fail the walk (ELOOP) instead of being
   traversed, and the leaf is opened relative to the verified parent
   fd -- symlink-free end to end and TOCTOU-safe against a component
   swap racing the walk. Every directory fd the walk opens (the root
   included) is also vetted for ownership and mode before it is trusted
   as the base of the next openat() (zstd sibling #316): an ancestor a
   local user owns, or can write into, lets that user rename() a
   root-owned 0644 file into the leaf position and pass both leaf
   checks while steering what strict mode loads.

   Absolute paths only: the directive handler has already run the path
   through ngx_conf_full_name(). Returns the leaf fd, or
   NGX_INVALID_FILE having logged the reason. */
/* fstat() one directory fd opened during the strict walk and refuse it
   under the rule the leaf checks apply (zstd sibling #316, A33-F2):
   owned by neither root nor the loading principal, or writable by
   group or other. No sticky-bit exemption: a sticky world-writable
   ancestor (a /tmp-style directory) still lets an unprivileged user
   create the next path component, exactly the steering this refuses.
   `label` names the component for the diagnostic ("/" for the root
   fd, the component bytes otherwise). */
static ngx_int_t ngx_http_brotli_check_strict_dir(ngx_conf_t* cf, int fd,
                                                  const char* label,
                                                  ngx_str_t* path) {
  struct stat st;

  if (fstat(fd, &st) < 0) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                       "fstat(\"%s\") failed while resolving \"%V\" under "
                       "\"brotli_dcb_dict_strict_path on\"",
                       label, path);
    return NGX_ERROR;
  }

  if (st.st_uid != 0 && st.st_uid != geteuid()) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "directory component \"%s\" of \"%V\" is owned by "
                       "uid %uD, neither root nor the loading principal "
                       "(uid %uD); refused by "
                       "\"brotli_dcb_dict_strict_path on\": that owner can "
                       "rename a different file into this directory and "
                       "steer what a later privileged reload loads",
                       label, path, (uint32_t)st.st_uid, (uint32_t)geteuid());
    return NGX_ERROR;
  }

  if (st.st_mode & (S_IWGRP | S_IWOTH)) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "directory component \"%s\" of \"%V\" is writable "
                       "by group or other (no sticky-bit exemption: a "
                       "sticky world-writable directory still lets an "
                       "unprivileged user create the next component); "
                       "refused by \"brotli_dcb_dict_strict_path on\"",
                       label, path);
    return NGX_ERROR;
  }

  return NGX_OK;
}

static ngx_fd_t ngx_http_brotli_open_dict_strict(ngx_conf_t* cf,
                                                 ngx_str_t* path, int flags) {
  u_char* p;
  u_char* start;
  u_char* end;
  int fd, next, oflags;

  if (path->len == 0 || path->data[0] != '/') {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "\"%V\" is not an absolute path; refused by "
                       "\"brotli_dcb_dict_strict_path on\", which resolves "
                       "the path one component at a time and cannot verify "
                       "a relative prefix",
                       path);
    return NGX_INVALID_FILE;
  }

  fd = open("/", O_RDONLY | O_DIRECTORY
#ifdef O_CLOEXEC
                     | O_CLOEXEC
#endif
  );
  if (fd < 0) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                       "open(\"/\") failed while resolving \"%V\" under "
                       "\"brotli_dcb_dict_strict_path on\"",
                       path);
    return NGX_INVALID_FILE;
  }

  /* The root fd is a walked component like any other: vet it before it
     is trusted as the base of every openat() below. On most systems "/"
     is root-owned 0755 and this is a no-op; a container or chroot base
     that fails it is exactly the layout strict mode is meant to refuse. */
  if (ngx_http_brotli_check_strict_dir(cf, fd, "/", path) != NGX_OK) {
    ngx_close_file(fd);
    return NGX_INVALID_FILE;
  }

  start = path->data + 1;
  end = path->data + path->len;

  for (;;) {
    /* Skip any run of separators; a trailing one means no leaf. */
    while (start < end && *start == '/') {
      start++;
    }

    if (start >= end) {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "\"%V\" names a directory, not a dictionary file; "
                         "refused by \"brotli_dcb_dict_strict_path on\"",
                         path);
      ngx_close_file(fd);
      return NGX_INVALID_FILE;
    }

    for (p = start; p < end && *p != '/'; p++) { /* void */
    }

    /* openat() needs a NUL-terminated component. The component is
       COPIED into a local buffer rather than NUL-terminated in place:
       path->data is nginx's own config string, and writing into it --
       even a byte restored immediately afterwards -- would mutate
       shared config memory other directives and the error log still
       read. A component longer than the buffer cannot name a file any
       filesystem will accept, so it is refused rather than silently
       truncated (truncation would open a DIFFERENT name). */
    {
      u_char comp[NGX_MAX_PATH];
      size_t complen = (size_t)(p - start);
      int last;
      u_char* q;

      if (complen >= sizeof(comp)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" has a path component longer than %uz "
                           "bytes; refused by "
                           "\"brotli_dcb_dict_strict_path on\"",
                           path, sizeof(comp) - 1);
        ngx_close_file(fd);
        return NGX_INVALID_FILE;
      }

      ngx_memcpy(comp, start, complen);
      comp[complen] = '\0';

      last = 1;
      for (q = p; q < end; q++) {
        if (*q != '/') {
          last = 0;
          break;
        }
      }

      /* "." and ".." are refused rather than resolved: ".." would
         climb back above a component already verified, which makes
         the walk's guarantee unstatable, and neither has a legitimate
         place in a deployed dictionary path. */
      if (ngx_strcmp(comp, ".") == 0 || ngx_strcmp(comp, "..") == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" contains a \".\" or \"..\" component; "
                           "refused by \"brotli_dcb_dict_strict_path on\"",
                           path);
        ngx_close_file(fd);
        return NGX_INVALID_FILE;
      }

      /* O_CLOEXEC is applied to BOTH arms deliberately: folding it
         into the ternary via a bare "#ifdef ... | O_CLOEXEC" would
         bind it to the else-branch alone by C's precedence rules,
         silently leaving the leaf fd inheritable across an exec. */
      oflags = last ? (flags | O_NOFOLLOW)
                    : (O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
#ifdef O_CLOEXEC
      oflags |= O_CLOEXEC;
#endif

      next = openat(fd, (char*)comp, oflags);

      if (next < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "openat(\"%s\") failed while resolving \"%V\" "
                           "under \"brotli_dcb_dict_strict_path on\" (a "
                           "symlink at any component is refused, not "
                           "followed; a release-symlink deployment needs "
                           "\"brotli_dcb_dict_strict_path off;\", the "
                           "default)",
                           comp, path);
        ngx_close_file(fd);
        return NGX_INVALID_FILE;
      }

      ngx_close_file(fd);
      fd = next;

      if (last) {
        return fd;
      }

      /* A directory fd that will be trusted as the base for the next
         openat(): vet it before it is used for anything else, same rule
         as the root fd above. */
      if (ngx_http_brotli_check_strict_dir(cf, fd, (char*)comp, path) !=
          NGX_OK) {
        ngx_close_file(fd);
        return NGX_INVALID_FILE;
      }

      start = p;
    }
  }
}

#endif /* NGX_HTTP_BROTLI_HAVE_STRICT_WALK && NGX_HTTP_BROTLI_HAVE_DCB */

static void* ngx_http_brotli_create_main_conf(ngx_conf_t* cf) {
  ngx_http_brotli_main_conf_t* bmcf;

  bmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_brotli_main_conf_t));
  if (bmcf == NULL) {
    return NULL;
  }

  /* pcalloc zeroes the ordering records and the hashed counter;
     cycle-owned, no reset hook. */
  bmcf->dict_strict_path = NGX_CONF_UNSET;
  bmcf->dcb_dict_trust_hashes = NGX_CONF_UNSET;

  return bmcf;
}

static char* ngx_http_brotli_init_main_conf(ngx_conf_t* cf, void* conf) {
  ngx_http_brotli_main_conf_t* bmcf = conf;

  ngx_conf_init_value(bmcf->dict_strict_path, 0); /* off by default */

  /* Reject the ordering rather than silently accept an unchecked load
     (zstd siblings' shape): the loader records the first dictionary
     that loaded while dict_strict_path did not yet read as the
     explicit "on". If the flag's FINAL value is "on", that load ran
     without the walk, the ownership check, or the writable-target
     check -- fail the config rather than start with a dictionary the
     operator asked to have vetted but that never was. */
  if (bmcf->dict_strict_path == 1 && bmcf->dict_loaded_before_strict_on) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "\"brotli_dcb_dict_strict_path on\" was declared "
                       "AFTER \"brotli_dcb_dict_file %V\", which had "
                       "already loaded unchecked by that point. nginx "
                       "directives are order-independent by convention, "
                       "but this one is not: move "
                       "\"brotli_dcb_dict_strict_path on;\" before every "
                       "\"brotli_dcb_dict_file\" directive it must apply "
                       "to",
                       &bmcf->dict_loaded_before_strict_on_file);
    return NGX_CONF_ERROR;
  }

  ngx_conf_init_value(bmcf->dcb_dict_trust_hashes, 0); /* verify default */

  /* Same ordering rejection with the opposite polarity: a literal
     that loaded before a later "trust on" was VERIFIED -- correct
     bytes, but the hashing pass the directive exists to skip was
     silently paid, which at hundreds of dictionaries is the entire
     cost. Reject rather than be quietly position-dependent. */
  if (bmcf->dcb_dict_trust_hashes == 1 &&
      bmcf->dcb_dict_verified_before_trust_on) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "\"brotli_dcb_dict_trust_hashes on\" was declared "
                       "AFTER \"brotli_dcb_dict_file %V\", whose hash "
                       "literal had already been verified (hashed) by "
                       "that point. nginx directives are "
                       "order-independent by convention, but this one is "
                       "not: move \"brotli_dcb_dict_trust_hashes on;\" "
                       "before every \"brotli_dcb_dict_file\" directive "
                       "it must apply to",
                       &bmcf->dcb_dict_verified_before_trust_on_file);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

#if (NGX_HTTP_BROTLI_HAVE_DCB) && (NGX_HTTP_BROTLI_HAVE_LIBCRYPTO)

static void ngx_http_brotli_cleanup_evp_md_ctx(void* data) {
  EVP_MD_CTX_free(data);
}

/* Lazy, one-per-config-load EVP context (the zstd sibling's #262):
   created on the first computed hash, freed with cf->pool when parsing
   ends. Any failure leaves the pointer NULL and every hash takes the
   portable path -- attempted is what keeps a failed creation from
   being retried per dictionary. */
static void ngx_http_brotli_init_evp_md_ctx(
    ngx_conf_t* cf, ngx_http_brotli_main_conf_t* bmcf) {
  ngx_pool_cleanup_t* cln;

  bmcf->dcb_evp_md_ctx_attempted = 1;
  bmcf->dcb_evp_md_ctx = EVP_MD_CTX_new();
  if (bmcf->dcb_evp_md_ctx == NULL) {
    return;
  }

  cln = ngx_pool_cleanup_add(cf->pool, 0);
  if (cln == NULL) {
    EVP_MD_CTX_free(bmcf->dcb_evp_md_ctx);
    bmcf->dcb_evp_md_ctx = NULL;
    return;
  }

  cln->handler = ngx_http_brotli_cleanup_evp_md_ctx;
  cln->data = bmcf->dcb_evp_md_ctx;
}

#endif

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
  ngx_http_brotli_main_conf_t* bmcf;
  ngx_flag_t trust;

  (void)cmd;

  value = cf->args->elts;
  path = value[1];

  if (ngx_conf_full_name(cf->cycle, &path, 1) != NGX_OK) {
    return NGX_CONF_ERROR;
  }

  /* Optional second argument: the dictionary's SHA-256 as 64 hex
     chars. By default it is VERIFIED against the bytes read below
     (zstd sibling #198): a declaration of what the operator believes
     the file to be, whose mismatch fails the load -- the deploy-time
     guard for a pipeline whose config generation and file placement
     are decoupled. Under "brotli_dcb_dict_trust_hashes on" (sibling
     #220) the literal is trusted verbatim as the negotiation key and
     the hashing pass is skipped -- the config-load cost at scale is
     the SHA-256 itself, not the read, and the deploy tooling that
     generates the directive list has typically just computed these
     hashes anyway. The trade the opt-in states: a stale supplied hash
     keeps matching, and the responses may fail to decode or silently
     decode to WRONG content (a same-size stale raw dictionary yields
     wrong bytes -- the dcb stream carries no content checksum). The
     generator owns hash correctness; content-hashed immutable assets
     are the intended use.

     Validated before the file is opened so a malformed literal is
     reported as such, not shadowed by file errors -- under either
     policy. */
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

  bmcf =
      ngx_http_conf_get_module_main_conf(cf, ngx_http_brotli_filter_module);

  /* This load is about to run under whatever dict_strict_path reads
     RIGHT NOW; if that is anything but the explicit "on", the strict
     checks below are skipped -- record it so init_main_conf can
     reject the config if a later "brotli_dcb_dict_strict_path on;"
     was meant to cover this load. */
  if (bmcf->dict_strict_path != 1 && !bmcf->dict_loaded_before_strict_on) {
    bmcf->dict_loaded_before_strict_on = 1;
    bmcf->dict_loaded_before_strict_on_file = path;
  }

  /* Same raw-read reasoning for the trust flag: a later
     "brotli_dcb_dict_trust_hashes on;" has not been parsed yet, so a
     literal verified here silently pays the pass the operator asked
     to skip. Record; init_main_conf rejects the ordering if the final
     value is "on". Only literal-carrying lines are affected. */
  trust = (bmcf->dcb_dict_trust_hashes == 1);

  if (have_hash && !trust && !bmcf->dcb_dict_verified_before_trust_on) {
    bmcf->dcb_dict_verified_before_trust_on = 1;
    bmcf->dcb_dict_verified_before_trust_on_file = path;
  }

  /* O_NONBLOCK always (zstd sibling #165): a FIFO at the dictionary
     path would otherwise block the config-parsing master in open()
     until a writer appeared -- nginx -t or a reload would just hang.
     Win32's NGX_FILE_NONBLOCK is 0, a no-op. Under strict mode the
     path is resolved one component at a time instead (sibling #199);
     a strict refusal is a trust decision, so it is always fatal. */
  if (bmcf->dict_strict_path == 1) {

#if (NGX_HTTP_BROTLI_HAVE_STRICT_WALK)
    fd = ngx_http_brotli_open_dict_strict(cf, &path,
                                          O_RDONLY | NGX_FILE_NONBLOCK);
    if (fd == NGX_INVALID_FILE) {
      /* the walk has already logged the precise component */
      return NGX_CONF_ERROR;
    }
#else
    /* Fail CLOSED (sibling #199): without openat() strict mode can
       only offer a leaf-only O_NOFOLLOW guarantee, which an
       intermediate symlink defeats -- accepting the config here would
       let the directive claim a protection the platform cannot
       deliver. */
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "\"brotli_dcb_dict_strict_path on\" is not "
                       "supported on this platform (no openat(); the "
                       "path cannot be resolved one component at a "
                       "time, so an intermediate symlink could not be "
                       "refused). Refusing \"%V\" rather than loading "
                       "it with a weaker guarantee than the directive "
                       "states",
                       &path);
    return NGX_CONF_ERROR;
#endif

  } else {
    fd = ngx_open_file(path.data, NGX_FILE_RDONLY | NGX_FILE_NONBLOCK,
                       NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                         ngx_open_file_n " \"%V\" failed", &path);
      return NGX_CONF_ERROR;
    }
  }

  if (ngx_fd_info(fd, &info) == NGX_FILE_ERROR) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                       ngx_fd_info_n " \"%V\" failed", &path);
    goto failed;
  }

  /* A non-regular target is rejected UNCONDITIONALLY (zstd sibling
     #165): a FIFO/socket/directory/device was never a valid
     dictionary, and the old behaviour against one always eventually
     errored or hung. ngx_is_file() checks S_ISREG. */
  if (!ngx_is_file(&info)) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "dcb dictionary \"%V\" is not a regular file", &path);
    goto failed;
  }

#if !(NGX_WIN32)
  /* Ownership, not just the mode bits (zstd sibling #199, M4): a
     dictionary owned by an unprivileged account at an ordinary 0644
     passes a group/other-writability test while a root master reads
     it -- and that owner can rewrite the file ahead of any privileged
     reload. Strict mode requires the loading principal's euid or
     root. */
  if (bmcf->dict_strict_path == 1 && info.st_uid != geteuid() &&
      info.st_uid != 0) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "dcb dictionary \"%V\" is owned by uid %uD, neither "
                       "the loading principal (uid %uD) nor root; refused "
                       "by \"brotli_dcb_dict_strict_path on\", because "
                       "that owner can rewrite the file and steer what a "
                       "later privileged reload loads",
                       &path, (uint32_t)info.st_uid, (uint32_t)geteuid());
    goto failed;
  }

  /* Strict trust (zstd sibling #165): reject a dictionary writable by
     group or other -- a lower-privileged local writer must not be
     able to swap bytes into every worker on the next reload. Opt-in,
     since a release-managed deployment may legitimately ship such
     permissions. */
  if (bmcf->dict_strict_path == 1 &&
      (ngx_file_access(&info) & (S_IWGRP | S_IWOTH))) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "dcb dictionary \"%V\" is writable by group or "
                       "other and \"brotli_dcb_dict_strict_path\" is on",
                       &path);
    goto failed;
  }

  /* The FIFO-hang risk was only in open(); the file is now confirmed
     regular, so clear O_NONBLOCK before the read loop below -- a
     non-blocking regular-file read can return SHORT on some
     filesystems (observed on a 9p/drvfs mount), which the loader
     would then reject as an incomplete read. */
  {
    int fl = fcntl(fd, F_GETFL);

    if (fl != -1) {
      (void)fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    }
  }
#endif

  /* off_t bound BEFORE the size_t narrowing (zstd siblings' round-4
     R3-9 twin): on ILP32 a 4 GiB file assigned to size_t loads as its
     low 32 bits, sails under the limit, hashes clean, and serves. */
  if (ngx_file_size(&info) > (off_t)NGX_HTTP_BROTLI_MAX_DICT_SIZE) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "dcb dictionary \"%V\" too large: %O bytes "
                       "(limit: %d bytes)",
                       &path, ngx_file_size(&info),
                       NGX_HTTP_BROTLI_MAX_DICT_SIZE);
    goto failed;
  }

  size = ngx_file_size(&info);

  if (size == 0) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "dcb dictionary \"%V\" is empty",
                       &path);
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

  n = ngx_http_brotli_read_dict_file(fd, dict->bytes.data, size);
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

  if (have_hash && trust) {
    /* Trusted verbatim: the literal IS the negotiation key, the
       hashing pass -- including its $brotli_dcb_dicts_hashed
       increment, which is what makes the skip observable -- does not
       run for this line. */
    ngx_memcpy(dict->hash, hash, NGX_HTTP_BROTLI_SHA256_DIGEST_LEN);

  } else {
#if (NGX_HTTP_BROTLI_HAVE_DCB) && (NGX_HTTP_BROTLI_HAVE_LIBCRYPTO)
    if (!bmcf->dcb_evp_md_ctx_attempted) {
      ngx_http_brotli_init_evp_md_ctx(cf, bmcf);
    }
#endif
    ngx_http_brotli_sha256(dict->bytes.data, size, dict->hash,
                           bmcf->dcb_evp_md_ctx);
    bmcf->dcb_dicts_hashed++;

    if (have_hash &&
        ngx_memcmp(hash, dict->hash, NGX_HTTP_BROTLI_SHA256_DIGEST_LEN) !=
            0) {
      u_char hex[2 * NGX_HTTP_BROTLI_SHA256_DIGEST_LEN];
      ngx_str_t hexstr;

      hexstr.data = hex;
      hexstr.len =
          ngx_hex_dump(hex, dict->hash, NGX_HTTP_BROTLI_SHA256_DIGEST_LEN) -
          hex;

      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "dcb dictionary \"%V\" does not match the supplied "
                         "hash \"%V\": the file's SHA-256 is \"%V\" (use "
                         "\"brotli_dcb_dict_trust_hashes on\" only if your "
                         "deploy pipeline owns hash correctness)",
                         &path, &value[2], &hexstr);
      return NGX_CONF_ERROR;
    }
  }

  /* Two entries with the same hash make the negotiation lookup
     ambiguous (for computed or verified hashes that means identical
     content under two paths — almost certainly a copy meant to be a
     new version; under trust_hashes a literal is compared as declared,
     which also catches one literal pasted onto two lines). Fail loudly
     at load rather than silently matching the first. */
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
