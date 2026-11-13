
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Google Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "../ngx_http_brotli_common.h"

/* >> Configuration */

#define NGX_HTTP_BROTLI_STATIC_OFF 0
#define NGX_HTTP_BROTLI_STATIC_ON 1
#define NGX_HTTP_BROTLI_STATIC_ALWAYS 2

typedef struct {
  ngx_uint_t enable;
} configuration_t;

/* Cycle-owned. any_enabled is the conservative "could this cycle serve a
   .br sidecar" latch for init() (zstd siblings' #182): set at directive
   PARSE time by set_enable_slot() whenever "brotli_static" is parsed as
   "on" or "always" anywhere in the config, so the always-declining
   content-phase handler is appended only when some location could use
   it. "brotli_static" takes no NGX_HTTP_LIF_CONF, so there is no "if"
   conf to reason about; parse time is still the safe side (a false
   positive costs the handler's early return, a false negative would
   silently stop sidecars being served). Independent of the filter
   module's own bit. */
typedef struct {
  ngx_flag_t any_enabled;
} main_configuration_t;

static ngx_conf_enum_t kBrotliStaticEnum[] = {
    {ngx_string("off"), NGX_HTTP_BROTLI_STATIC_OFF},
    {ngx_string("on"), NGX_HTTP_BROTLI_STATIC_ON},
    {ngx_string("always"), NGX_HTTP_BROTLI_STATIC_ALWAYS},
    {ngx_null_string, 0}};

/* << Configuration */

/* >> Forward declarations */

static ngx_int_t handler(ngx_http_request_t* req);
static void* create_main_conf(ngx_conf_t* root_cfg);
static void* create_conf(ngx_conf_t* root_cfg);
static char* merge_conf(ngx_conf_t* root_cfg, void* parent, void* child);
static char* set_enable_slot(ngx_conf_t* root_cfg, ngx_command_t* cmd,
                             void* conf);
static ngx_int_t init(ngx_conf_t* root_cfg);

/* << Forward declarations*/

/* >> Module definition */

static ngx_command_t kCommands[] = {
    {ngx_string("brotli_static"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     set_enable_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(configuration_t, enable), &kBrotliStaticEnum},
    ngx_null_command};

static ngx_http_module_t kModuleContext = {
    NULL, /* preconfiguration */
    init, /* postconfiguration */

    create_main_conf, /* create main configuration */
    NULL,             /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    create_conf, /* create location configuration */
    merge_conf   /* merge location configuration */
};

ngx_module_t ngx_http_brotli_static_module = {
    NGX_MODULE_V1,
    &kModuleContext, /* module context */
    kCommands,       /* module directives */
    NGX_HTTP_MODULE, /* module type */
    NULL,            /* init master */
    NULL,            /* init module */
    NULL,            /* init process */
    NULL,            /* init thread */
    NULL,            /* exit thread */
    NULL,            /* exit process */
    NULL,            /* exit master */
    NGX_MODULE_V1_PADDING};

/* << Module definition*/

static const u_char kContentEncoding[] = "Content-Encoding";
static /* const */ char kEncoding[] = "br";
static /* const */ u_char kSuffix[] = ".br";
static const size_t kSuffixLen = 3;

/* The Accept-Encoding decision lives in ngx_http_brotli_common.h — a
   length-bounded RFC 9110 walker shared with the filter module and
   continuously fuzzed (see fuzz/), replacing the hand-maintained copy
   of the filter module's substring scan that previously lived here.

   Deliberately the SIDE-EFFECT-FREE predicate: the old code latched
   r->gzip_ok = 0 here, before knowing whether a .br file exists — so a
   client accepting "br, gzip" with only a .gz file on disk lost the
   gzip_static fallback and got identity. The latch now fires in
   handler() only once the .br file is confirmed. */
static ngx_int_t check_eligility(ngx_http_request_t* req) {
  return ngx_http_brotli_accepts(req);
}

static ngx_int_t handler(ngx_http_request_t* req) {
  configuration_t* cfg;
  ngx_int_t rc;
  u_char* last;
  ngx_str_t path;
  size_t root;
  ngx_log_t* log;
  ngx_http_core_loc_conf_t* location_cfg;
  ngx_open_file_info_t file_info;
  ngx_table_elt_t* content_encoding_entry;
  ngx_buf_t* buf;
  ngx_chain_t out;

  /* Only GET and HEAD requensts are supported. */
  if (!(req->method & (NGX_HTTP_GET | NGX_HTTP_HEAD))) return NGX_DECLINED;

  /* Only files are supported. */
  if (req->uri.data[req->uri.len - 1] == '/') return NGX_DECLINED;

  /* Get configuration and check if module is disabled. */
  cfg = ngx_http_get_module_loc_conf(req, ngx_http_brotli_static_module);
  if (cfg->enable == NGX_HTTP_BROTLI_STATIC_OFF) return NGX_DECLINED;

  /* NGX_HTTP_BROTLI_STATIC_ON's Vary and acceptance check both moved
     BELOW the file checks (zstd siblings' #202, their round-4 ruling):
     Vary is earned by a USABLE .br — here existence + regular file,
     since this module deliberately does no content validation — not by
     the attempt. A URI with no usable .br is not a negotiated variant,
     and stamping Vary on its identity response fragmented shared
     caches for nothing. The flip side, the ruling's condition: the
     probe runs before the acceptance check, so a NON-accepting client
     still learns the URI varies when a usable .br exists — without
     that, its identity response would enter shared caches
     unpartitioned. "always" is unchanged: it ignores Accept-Encoding
     and never varies. */

  /* Get path and append the suffix. */
  last = ngx_http_map_uri_to_path(req, &path, &root, kSuffixLen);
  if (last == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
  /* +1 for reinstating the terminating 0. */
  ngx_cpystrn(last, kSuffix, kSuffixLen + 1);
  path.len += kSuffixLen;

  log = req->connection->log;
  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "http filename: \"%s\"",
                 path.data);

  /* Prepare to read the file. */
  location_cfg = ngx_http_get_module_loc_conf(req, ngx_http_core_module);
  ngx_memzero(&file_info, sizeof(ngx_open_file_info_t));
  file_info.read_ahead = location_cfg->read_ahead;
  file_info.directio = location_cfg->directio;
  file_info.valid = location_cfg->open_file_cache_valid;
  file_info.min_uses = location_cfg->open_file_cache_min_uses;
  file_info.errors = location_cfg->open_file_cache_errors;
  file_info.events = location_cfg->open_file_cache_events;
  rc = ngx_http_set_disable_symlinks(req, location_cfg, &path, &file_info);
  if (rc != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;

  /* Try to fetch file and process errors. */
  rc = ngx_open_cached_file(location_cfg->open_file_cache, &path, &file_info,
                            req->pool);
  if (rc != NGX_OK) {
    ngx_uint_t level;
    switch (file_info.err) {
      case 0:
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

      case NGX_ENOENT:
      case NGX_ENOTDIR:
      case NGX_ENAMETOOLONG:
        return NGX_DECLINED;

#if (NGX_HAVE_OPENAT)
      case NGX_EMLINK:
      case NGX_ELOOP:
#endif
      case NGX_EACCES:
        level = NGX_LOG_ERR;
        break;

      default:
        level = NGX_LOG_CRIT;
        break;
    }
    ngx_log_error(level, log, file_info.err, "%s \"%s\" failed",
                  file_info.failed, path.data);
    return NGX_DECLINED;
  }

  /* So far so good. */
  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "http static fd: %d",
                 file_info.fd);

  /* Only files are supported. */
  if (file_info.is_dir) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "http dir");
    return NGX_DECLINED;
  }
#if !(NGX_WIN32)
  if (!file_info.is_file) {
    ngx_log_error(NGX_LOG_CRIT, log, 0, "\"%s\" is not a regular file",
                  path.data);
    return NGX_HTTP_NOT_FOUND;
  }
#endif

  /* The .br is proven usable: the URI genuinely varies, so the header
     goes out now (parent #163's by-construction emission at #202's
     placement) — on the serve path AND on the non-accepting decline
     below. */
  if (cfg->enable == NGX_HTTP_BROTLI_STATIC_ON) {
    if (ngx_http_brotli_vary_accept_encoding(req) != NGX_OK) {
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Acceptance decides serve-vs-decline, never probe-vs-skip. The
       gzip latch below must NOT fire on this decline: a brotli-refusing
       gzip-accepting client still deserves the gzip_static fallback. */
    rc = check_eligility(req);
    if (rc != NGX_OK) return NGX_DECLINED;

    /* The .br file exists and will be served: NOW suppress a later gzip
       filter/handler (latching before the file was known to exist
       killed the gzip_static fallback). ALWAYS mode never consulted
       Accept-Encoding, so it never latched. */
    req->gzip_tested = 1;
    req->gzip_ok = 0;
  }

  /* Prepare request push the body. */
  req->root_tested = !req->error_page;
  rc = ngx_http_discard_request_body(req);
  if (rc != NGX_OK) return rc;
  log->action = "sending response to client";
  req->headers_out.status = NGX_HTTP_OK;
  req->headers_out.content_length_n = file_info.size;
  req->headers_out.last_modified_time = file_info.mtime;
  rc = ngx_http_set_etag(req);
  if (rc != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
  rc = ngx_http_set_content_type(req);
  if (rc != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;

  /* Set "Content-Encoding" header. */
  content_encoding_entry = ngx_list_push(&req->headers_out.headers);
  if (content_encoding_entry == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
  content_encoding_entry->hash = 1;
#if nginx_version >= 1023000
  content_encoding_entry->next = NULL;
#endif
  ngx_str_set(&content_encoding_entry->key, kContentEncoding);
  ngx_str_set(&content_encoding_entry->value, kEncoding);
  req->headers_out.content_encoding = content_encoding_entry;

  /* gzip_static parity: byte ranges address the selected representation
   * (RFC 9110 §14.2) — the .br bytes on disk — which a client can fetch,
   * resume and concatenate coherently because the validator is strong and
   * the bytes are stable. Ranges only work by opting in: the range filter
   * bails unless allow_ranges is set. */
  req->allow_ranges = 1;

  /* HEAD fast path (parent nginx-zstd-module #179): the response headers
     already carry everything a HEAD needs — Content-Encoding and the Vary
     line are set above — so send them and skip the body ngx_buf_t +
     ngx_file_t allocations below. Strict NGX_HTTP_HEAD, not
     req->header_only, which also covers 304/204 whose existing
     header_only return past the body setup stays correct. */
  if (req->method == NGX_HTTP_HEAD) {
    return ngx_http_send_header(req);
  }

  /* Setup response body. */
  buf = ngx_pcalloc(req->pool, sizeof(ngx_buf_t));
  if (buf == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
  buf->file = ngx_pcalloc(req->pool, sizeof(ngx_file_t));
  if (buf->file == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
  buf->file_pos = 0;
  buf->file_last = file_info.size;
  buf->in_file = buf->file_last ? 1 : 0;
  buf->last_buf = (req == req->main) ? 1 : 0;
  buf->last_in_chain = 1;
  /* An empty sidecar in a subrequest leaves in_file and last_buf both 0;
   * sync marks the flagless zero-size buf deliberate so the output chain
   * does not alert "zero size buf" (gzip_static parity). */
  buf->sync = (buf->last_buf || buf->in_file) ? 0 : 1;
  buf->file->fd = file_info.fd;
  buf->file->name = path;
  buf->file->log = log;
  buf->file->directio = file_info.is_directio;
  out.buf = buf;
  out.next = NULL;

  /* Push the response header. */
  rc = ngx_http_send_header(req);
  if (rc == NGX_ERROR || rc > NGX_OK || req->header_only) {
    return rc;
  }

  /* Push the response body. */
  return ngx_http_output_filter(req, &out);
}

static void* create_conf(ngx_conf_t* root_cfg) {
  configuration_t* cfg;
  cfg = ngx_palloc(root_cfg->pool, sizeof(configuration_t));
  if (cfg == NULL) return NULL;
  cfg->enable = NGX_CONF_UNSET_UINT;
  return cfg;
}

static char* merge_conf(ngx_conf_t* root_cfg, void* parent, void* child) {
  configuration_t* prev = parent;
  configuration_t* cfg = child;
  ngx_conf_merge_uint_value(cfg->enable, prev->enable,
                            NGX_HTTP_BROTLI_STATIC_OFF);

  /* No gzip_vary-off warning here anymore (parent #163): the "on"-mode
     handler emits "Vary: Accept-Encoding" itself via
     ngx_http_brotli_vary_accept_encoding(), so correctness no longer
     depends on "gzip_vary on" and the warning would be misleading. */

  return NGX_CONF_OK;
}

static void* create_main_conf(ngx_conf_t* root_cfg) {
  /* pcalloc: any_enabled starts clear and only set_enable_slot() sets it */
  return ngx_pcalloc(root_cfg->pool, sizeof(main_configuration_t));
}

/* "brotli_static off|on|always": the stock enum slot plus the parse-time
   any_enabled latch (see main_configuration_t). ngx_conf_set_enum_slot()
   accepts exactly the three enum entries, so by the time this runs the
   argument is one of them; only the literal "off" leaves the bit clear. */
static char* set_enable_slot(ngx_conf_t* root_cfg, ngx_command_t* cmd,
                             void* conf) {
  ngx_str_t* value;
  char* rc;
  main_configuration_t* main_cfg;

  rc = ngx_conf_set_enum_slot(root_cfg, cmd, conf);
  if (rc != NGX_CONF_OK) return rc;

  value = root_cfg->args->elts;
  if (value[1].len == 3 && ngx_strncmp(value[1].data, "off", 3) == 0) {
    return NGX_CONF_OK;
  }

  main_cfg = ngx_http_conf_get_module_main_conf(root_cfg,
                                                ngx_http_brotli_static_module);
  main_cfg->any_enabled = 1;

  return NGX_CONF_OK;
}

static ngx_int_t init(ngx_conf_t* root_cfg) {
  ngx_http_core_main_conf_t* core_cfg;
  ngx_http_handler_pt* handler_slot;
  main_configuration_t* main_cfg;

  /* Off everywhere: nothing could serve a sidecar, so do not append the
     always-declining content-phase handler (zstd siblings' #182). */
  main_cfg = ngx_http_conf_get_module_main_conf(root_cfg,
                                                ngx_http_brotli_static_module);
  if (main_cfg == NULL || !main_cfg->any_enabled) return NGX_OK;

  core_cfg = ngx_http_conf_get_module_main_conf(root_cfg, ngx_http_core_module);
  handler_slot =
      ngx_array_push(&core_cfg->phases[NGX_HTTP_CONTENT_PHASE].handlers);
  if (handler_slot == NULL) return NGX_ERROR;
  *handler_slot = handler;
  return NGX_OK;
}
