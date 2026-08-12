
/*
 * Copyright (C) Alex Zhang
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <zstd.h>     /* ZSTD_MAGICNUMBER, ZSTD_MAGIC_SKIPPABLE_* — stable since 0.8.0 */
#include <stdint.h>   /* uint32_t for the magic-number compare */

#if !(NGX_WIN32)
#include <unistd.h>   /* pread(2) for the magic-number probe */
#endif

#include "../ngx_http_zstd_common.h"


#define NGX_HTTP_ZSTD_STATIC_OFF        0
#define NGX_HTTP_ZSTD_STATIC_ON         1
#define NGX_HTTP_ZSTD_STATIC_ALWAYS     2

/*
 * The largest decompression window a served .zst frame may declare:
 * 8 MB, the RFC 8878 §3.1.1.1.2 recommended decoder limit, which web
 * clients enforce for Content-Encoding: zstd — Firefox and Chromium
 * reject any frame declaring more WITHOUT decoding a byte
 * (NS_ERROR_INVALID_CONTENT_ENCODING / ERR_CONTENT_DECODING_FAILED).
 * The trap that makes this worth checking at serve time: streaming
 * encoders that were not told the input size stamp the LEVEL's default
 * window into every frame header (a 93 KB asset compressed by a
 * Node-based build pipeline can declare 128 MB), so the file decodes
 * fine with the zstd CLI yet fails in every browser. Matches the
 * filter module's dcz window cap, which exists for the same client
 * guarantee.
 */
#define NGX_HTTP_ZSTD_STATIC_MAX_WINDOW  (8 * 1024 * 1024)

/*
 * FLOOR for the probe read size under directio: O_DIRECT requires
 * buffer, offset and length aligned to the device's logical block
 * size. Offset 0 is aligned by definition; 4 KB covers 512-byte and
 * 4K-native devices, and the effective size is raised to the
 * operator's directio_alignment when that is larger (the same
 * geometry the core copy filter honours). A short read at EOF is
 * permitted, so files smaller than the probe work too.
 */
#define NGX_HTTP_ZSTD_STATIC_DIO_PROBE   4096


typedef struct {
    ngx_uint_t  enable;
} ngx_http_zstd_static_conf_t;


static ngx_conf_enum_t  ngx_http_zstd_static[] = {
    { ngx_string("off"), NGX_HTTP_ZSTD_STATIC_OFF },
    { ngx_string("on"), NGX_HTTP_ZSTD_STATIC_ON },
    { ngx_string("always"), NGX_HTTP_ZSTD_STATIC_ALWAYS },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_zstd_static_commands[] = {

    { ngx_string("zstd_static"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_static_conf_t, enable),
      &ngx_http_zstd_static },

    ngx_null_command
};


static ngx_int_t ngx_http_zstd_static_handler(ngx_http_request_t *r);
static void * ngx_http_zstd_static_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_zstd_static_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_zstd_static_init(ngx_conf_t *cf);


static ngx_http_module_t  ngx_http_zstd_static_module_ctx = {
    NULL,                                     /* preconfiguration */
    ngx_http_zstd_static_init,                /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    NULL,                                     /* create server configuration */
    NULL,                                     /* merge server configuration */

    ngx_http_zstd_static_create_loc_conf,  /* create location configuration */
    ngx_http_zstd_static_merge_loc_conf,      /* merge location configuration */
};


ngx_module_t  ngx_http_zstd_static_module = {
    NGX_MODULE_V1,
    &ngx_http_zstd_static_module_ctx,       /* module context */
    ngx_http_zstd_static_commands,          /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_zstd_static_handler(ngx_http_request_t *r)
{
    u_char                       *p;
    ngx_int_t                     rc;
    ngx_uint_t                    level;
    size_t                        root;
    ngx_str_t                     path;
    ngx_buf_t                    *b;
    ngx_log_t                    *log;
    ngx_table_elt_t              *h;
    ngx_chain_t                   out;
    ngx_open_file_info_t          of;
    ngx_http_core_loc_conf_t     *clcf;
    ngx_http_zstd_static_conf_t  *zscf;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_DECLINED;
    }

    /* Validate URI length before accessing last byte to prevent underflow.
     * While nginx guarantees non-empty URI, add defensive check for safety. */
    if (r->uri.len == 0 || r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

    zscf = ngx_http_get_module_loc_conf(r, ngx_http_zstd_static_module);

    if (zscf->enable == NGX_HTTP_ZSTD_STATIC_OFF) {
        return NGX_DECLINED;
    }

    if (zscf->enable == NGX_HTTP_ZSTD_STATIC_ON) {
        /*
         * Side-effect-free predicate, NOT ngx_http_zstd_ok(): the latter
         * latches r->gzip_ok = 0, which would suppress a gzip_static / gzip
         * fallback for THIS request even when we go on to decline below
         * (e.g. the .zst file is absent). We only decide here; when we
         * actually serve the .zst the response carries Content-Encoding: zstd,
         * which makes the gzip filter decline on its own.
         */
        rc = ngx_http_zstd_accepts(r);

    } else {
        rc = NGX_OK;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    log = r->connection->log;

    if (!clcf->gzip_vary && rc != NGX_OK) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                       "zstd static: skip, client did not accept zstd and "
                       "gzip_vary is off");
        return NGX_DECLINED;
    }

    p = ngx_http_map_uri_to_path(r, &path, &root, sizeof(".zst"));
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    *p++ = '.';
    *p++ = 'z';
    *p++ = 's';
    *p++ = 't';
    *p = '\0';

    path.len = p - path.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "http filename: \"%s\"", path.data);

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

            return NGX_DECLINED;

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

        return NGX_DECLINED;
    }

    if (zscf->enable == NGX_HTTP_ZSTD_STATIC_ON) {
        r->gzip_vary = 1;

        if (rc != NGX_OK) {
            return NGX_DECLINED;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "http static fd: %d", of.fd);

    if (of.is_dir) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "http dir");
        return NGX_DECLINED;
    }

#if !(NGX_WIN32) /* the not regular files are probably Unix specific */

    if (!of.is_file) {
        ngx_log_error(NGX_LOG_CRIT, log, 0,
                      "\"%s\" is not a regular file", path.data);

        return NGX_HTTP_NOT_FOUND;
    }

#if (NGX_HAVE_PREAD)
    /*
     * Magic-number sanity check on the .zst file.
     *
     * Without this, a truncated, half-downloaded, mistakenly-renamed
     * (e.g. `cp foo.txt foo.zst`), or otherwise non-zstd file would be
     * served with `Content-Encoding: zstd` and the client would get an
     * undecodable body — a confusing outage class that nginx's built-in
     * gzip_static also doesn't defend against. The probe is cheap (one
     * pread(2) of the frame-header prefix at offset 0 — 18 bytes, or one
     * aligned block under directio; pread is offset-explicit so it
     * never moves the open_file_cache's shared fd position — using
     * plain read(2) would do exactly that and corrupt subsequent
     * requests serving the same cached fd). On mismatch we decline, so
     * nginx falls back to serving the uncompressed original (or
     * returns 404 if it is absent), and the operator sees a clear
     * error log line.
     *
     * Both a regular zstd frame (ZSTD_MAGICNUMBER) and a skippable
     * frame (ZSTD_MAGIC_SKIPPABLE_START..+0xF) are accepted, since
     * either is a valid leading frame in a zstd stream.
     *
     * Gated by NGX_HAVE_PREAD: on platforms where nginx's configure
     * could not find pread(2) we silently skip the probe rather than
     * fall back to a read+lseek pair that would mutate the shared fd
     * offset. Every modern POSIX target has it; this guard is
     * essentially a build-time tripwire.
     *
     * When the file was opened with O_DIRECT (of.is_directio, set by
     * ngx_open_cached_file when "directio <size>" is configured and the
     * file meets the threshold), the read must be block-aligned, so the
     * probe preads one block of max(NGX_HTTP_ZSTD_STATIC_DIO_PROBE,
     * directio_alignment) bytes into an equally-aligned pool buffer —
     * honoring the operator's declared geometry the same way the core
     * copy filter does. The window check in particular must not be
     * skipped under directio: oversized declared windows are a
     * systematic build-pipeline product, not rare corruption, and every
     * browser rejects them. If the aligned read STILL fails, the file
     * is DECLINED, not served: for a validation read, falling back to
     * another encoding is safer than certifying a file we could not
     * inspect, and the error log tells the operator which knob
     * (directio_alignment) disagrees with the device.
     */
    {
        /*
         * 18 bytes covers the largest possible frame header prefix this
         * check needs: magic(4) + descriptor(1) + window byte(1) for
         * streaming frames, or magic(4) + descriptor(1) + dictionary
         * id(<=4) + content size(<=8) for single-segment frames. Short
         * files return fewer bytes; each parse path checks it got what
         * that frame layout requires.
         */
        u_char     hdrbuf[18];
        u_char    *hdr;
        size_t     want;
        ssize_t    n;
        uint32_t   mw;

        if (of.size < 4) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "zstd static: \"%s\" too small to be a zstd frame "
                          "(%O bytes)", path.data, of.size);
            return NGX_DECLINED;
        }

        if (of.is_directio) {
            want = NGX_HTTP_ZSTD_STATIC_DIO_PROBE;
            if ((size_t) clcf->directio_alignment > want) {
                want = (size_t) clcf->directio_alignment;
            }

            hdr = ngx_pmemalign(r->pool, want, want);
            if (hdr == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

        } else {
            hdr = hdrbuf;
            want = sizeof(hdrbuf);
        }

        n = pread(of.fd, hdr, want, 0);
        if (n < 4) {
            if (of.is_directio) {
                ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                              "zstd static: %uz-byte aligned probe on "
                              "directio file \"%s\" returned %z — "
                              "declining; check directio_alignment "
                              "against the device geometry",
                              want, path.data, n);
                return NGX_DECLINED;
            }

            ngx_log_error(NGX_LOG_CRIT, log, ngx_errno,
                          "zstd static: pread(\"%s\", frame header) "
                          "returned %z", path.data, n);
            return NGX_DECLINED;
        }

        if (of.is_directio) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                           "zstd static: %uz-byte aligned probe on "
                           "directio file \"%s\"", want, path.data);
        }

        mw = ((uint32_t) hdr[0])
           | ((uint32_t) hdr[1] << 8)
           | ((uint32_t) hdr[2] << 16)
           | ((uint32_t) hdr[3] << 24);

        if (mw != ZSTD_MAGICNUMBER
            && (mw & ZSTD_MAGIC_SKIPPABLE_MASK)
               != ZSTD_MAGIC_SKIPPABLE_START)
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "zstd static: \"%s\" is not a zstd frame "
                          "(leading bytes 0x%02xd%02xd%02xd%02xd)",
                          path.data,
                          (ngx_uint_t) hdr[0], (ngx_uint_t) hdr[1],
                          (ngx_uint_t) hdr[2], (ngx_uint_t) hdr[3]);
            return NGX_DECLINED;
        }

        /*
         * Declared-window check (RFC 8878 §3.1.1.1) on regular frames —
         * see NGX_HTTP_ZSTD_STATIC_MAX_WINDOW for why: a frame
         * declaring more than 8 MB is rejected by every browser before
         * decoding, so serving it produces a page-breaking decode error
         * that curl and the zstd CLI do not reproduce. Declining keeps
         * the site working (the zstd filter, gzip_static or identity
         * takes over) and puts the actionable cause in the error log.
         *
         * The check covers the LEADING frame only. A skippable leading
         * frame is exempt (the real header sits after a variable-length
         * skip), and in a concatenation of regular frames only the
         * first is inspected: a regular frame's header does not declare
         * its compressed length, so walking the sequence would mean
         * decoding every block header in every frame — unbounded I/O
         * for a serve-time guard. Multi-frame .zst web assets are
         * pathological (no common tooling emits them); the README
         * documents the leading-frame scope.
         */
        if (mw == ZSTD_MAGICNUMBER) {
            uint64_t    window;
            ngx_uint_t  i, fhd, fcs_size, off;

            static const ngx_uint_t  did_len[4] = { 0, 1, 2, 4 };

            if (n < 5) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "zstd static: \"%s\" frame header truncated",
                              path.data);
                return NGX_DECLINED;
            }

            fhd = hdr[4];

            if (!(fhd & 0x20)) {
                /* No Single_Segment flag: Window_Descriptor follows. */
                if (n < 6) {
                    ngx_log_error(NGX_LOG_ERR, log, 0,
                                  "zstd static: \"%s\" frame header "
                                  "truncated", path.data);
                    return NGX_DECLINED;
                }

                window = (uint64_t) 1 << (10 + (hdr[5] >> 3));
                window += (window >> 3) * (hdr[5] & 7);

            } else {
                /*
                 * Single_Segment: no Window_Descriptor; the window is
                 * the frame content size, read from behind the optional
                 * dictionary id. Frame_Content_Size_flag 0 means a
                 * 1-byte field here (the flag only means "absent" when
                 * Single_Segment is unset).
                 */
                fcs_size = (fhd >> 6) ? ((ngx_uint_t) 1 << (fhd >> 6)) : 1;
                off = 5 + did_len[fhd & 3];

                if ((size_t) n < off + fcs_size) {
                    ngx_log_error(NGX_LOG_ERR, log, 0,
                                  "zstd static: \"%s\" frame header "
                                  "truncated", path.data);
                    return NGX_DECLINED;
                }

                window = 0;
                for (i = 0; i < fcs_size; i++) {
                    window |= (uint64_t) hdr[off + i] << (8 * i);
                }

                if (fcs_size == 2) {
                    window += 256;  /* RFC 8878: 2-byte field is offset */
                }
            }

            if (window > NGX_HTTP_ZSTD_STATIC_MAX_WINDOW) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "zstd static: \"%s\" declares a %uL-byte "
                              "decompression window, above the 8 MB limit "
                              "browsers enforce for Content-Encoding: zstd "
                              "(RFC 8878) — declining so a fallback "
                              "encoding is used; recompress with a window "
                              "log <= 23 (streaming encoders default to "
                              "the compression level's window when not "
                              "told the input size)",
                              path.data, window);
                return NGX_DECLINED;
            }
        }
    }
#endif /* NGX_HAVE_PREAD */

#endif

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

    /*
     * ngx_http_set_content_type() uses r->exten which is derived from the
     * original URI, not from path. No path manipulation is needed here.
     */
    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    h->hash = 1;
#if (nginx_version >= 1023000)
    h->next = NULL;
#endif
    ngx_str_set(&h->key, "Content-Encoding");
    ngx_str_set(&h->value, "zstd");
    r->headers_out.content_encoding = h;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "zstd static: serving precompressed \"%s\"", path.data);

    /* Byte ranges are meaningless on a compressed body: offsets in the
     * .zst file do not correspond to positions in the original content.
     * RFC 9110 §14.2 — clear Accept-Ranges so clients do not request
     * ranges that would yield undecipherable fragments. */
    ngx_http_clear_accept_ranges(r);

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
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

    b->file->fd = of.fd;
    b->file->name = path;
    b->file->log = log;
    b->file->directio = of.is_directio;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static void *
ngx_http_zstd_static_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_zstd_static_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_zstd_static_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_zstd_static_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_zstd_static_conf_t *prev = parent;
    ngx_http_zstd_static_conf_t *conf = child;

    ngx_http_core_loc_conf_t    *clcf;

    ngx_conf_merge_uint_value(conf->enable, prev->enable,
                              NGX_HTTP_ZSTD_STATIC_OFF);

    /*
     * Warn at config load only when zstd_static is set to "on" (negotiated)
     * for THIS location and the same location has gzip_vary off. The
     * previous version emitted this warning unconditionally from the
     * postconfiguration handler whenever the top-level location lacked
     * gzip_vary, even on configs that load the module but never use
     * the directive — a misleading log line. Mirror the filter
     * module's per-location merge-time check.
     *
     * "always" is deliberately excluded: it ignores Accept-Encoding,
     * intentionally does NOT set r->gzip_vary, and the response carries no
     * Vary header — so asking the operator to add gzip_vary would describe
     * the response incorrectly. See C5.
     */
    if (conf->enable == NGX_HTTP_ZSTD_STATIC_ON) {
        /*
         * As in the filter module: stay quiet when the compression_vary
         * filter module is loaded — it emits Vary: Accept-Encoding from
         * r->gzip_vary without needing "gzip_vary on". See
         * ngx_http_zstd_vary_handled_externally() for the contract.
         */
        clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
        if (clcf != NULL && !clcf->gzip_vary
            && !ngx_http_zstd_vary_handled_externally(cf))
        {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "zstd_static is enabled but "
                               "\"gzip_vary\" is off; add \"gzip_vary "
                               "on\" to emit \"Vary: Accept-Encoding\" "
                               "so proxies and CDNs cache compressed "
                               "and uncompressed responses separately");
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_zstd_static_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_zstd_static_handler;

    return NGX_OK;
}
