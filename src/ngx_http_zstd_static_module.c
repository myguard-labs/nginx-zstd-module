
/*
 * Copyright (C) Alex Zhang
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* ZSTD_MAGICNUMBER, ZSTD_MAGIC_SKIPPABLE_* — stable since 0.8.0 */
#include <zstd.h>
#include <stdint.h>   /* uint32_t for the magic-number compare */

#if !(NGX_WIN32)
#include <unistd.h>   /* pread(2) for the magic-number probe */
#endif

#include "ngx_http_zstd_common.h"


/*
 * Whether the serve-time .zst frame probe is compiled in.
 *
 * The probe needs one thing from the platform: an OFFSET-EXPLICIT read
 * that does NOT move the file position of the descriptor it is handed.
 * That constraint is not cosmetic — the fd comes from
 * ngx_open_cached_file() and is SHARED between every request currently
 * serving the same file, so a read(2)+lseek pair here would corrupt the
 * body another request is streaming (see the long comment at the probe
 * call site).
 *
 *   POSIX    pread(2), when nginx's configure found it (NGX_HAVE_PREAD).
 *            Without it we compile the probe out rather than fall back
 *            to lseek+read — a build-time tripwire, since every modern
 *            POSIX target has pread(2).
 *   Win32    ngx_read_file(), whose Win32 implementation
 *            (src/os/win32/ngx_files.c) issues ReadFile() with an
 *            OVERLAPPED carrying the offset. An OVERLAPPED read does not
 *            advance the HANDLE's file pointer, so it satisfies exactly
 *            the same constraint pread(2) does. nginx's own abstraction
 *            is used rather than a raw ReadFile() call so the platform
 *            details (offset splitting, EOF mapping) stay upstream's.
 *
 * Deliberately NOT `ngx_read_file()` everywhere: on a POSIX build
 * without NGX_HAVE_PREAD, ngx_read_file() IS the lseek+read pair this
 * guard exists to avoid.
 */
#if (NGX_WIN32) || (NGX_HAVE_PREAD)
#define NGX_HTTP_ZSTD_STATIC_HAVE_PROBE  1
#else
#define NGX_HTTP_ZSTD_STATIC_HAVE_PROBE  0
#endif

/*
 * Name of the offset-explicit read primitive, for operator-facing error
 * text. Defined here rather than with an #if inside the ngx_log_error()
 * argument list: a preprocessor directive among the arguments of a
 * function-like macro is undefined behaviour (C11 6.10.3p11). gcc and
 * mingw accept it silently, MSVC rejects it with C2121 -- which is why a
 * mingw cross-build is not sufficient evidence that this file compiles
 * on Windows. (Observed on MSVC x64 static, PR #162.)
 */
#if (NGX_WIN32)
#define NGX_HTTP_ZSTD_STATIC_PREAD_NAME  "ReadFile"
#else
#define NGX_HTTP_ZSTD_STATIC_PREAD_NAME  "pread"
#endif


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


typedef struct {
    /*
     * No fields today: the gzip_vary-off warning counter that lived
     * here was removed with the warning itself (G5 — the handler now
     * emits Vary: Accept-Encoding directly). The struct and its
     * create_main_conf hook are kept because the module context slot
     * is part of the module's shape and future main-scope state has an
     * obvious home; an empty struct is not valid C, so a placeholder
     * holds the space.
     */
    ngx_uint_t  unused;
} ngx_http_zstd_static_main_conf_t;


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
static void * ngx_http_zstd_static_create_main_conf(ngx_conf_t *cf);
static void * ngx_http_zstd_static_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_zstd_static_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_zstd_static_init(ngx_conf_t *cf);


static ngx_http_module_t  ngx_http_zstd_static_module_ctx = {
    NULL,                                     /* preconfiguration */
    ngx_http_zstd_static_init,                /* postconfiguration */

    ngx_http_zstd_static_create_main_conf,    /* create main configuration */
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


#if (NGX_HTTP_ZSTD_STATIC_HAVE_PROBE)

/*
 * Verdicts from ngx_http_zstd_static_probe_frame(). The caller maps each
 * to the log line and return code the inlined probe used to emit, so the
 * split changes no observable behaviour — only where the arithmetic
 * lives.
 */
#define NGX_HTTP_ZSTD_STATIC_FRAME_OK          0
#define NGX_HTTP_ZSTD_STATIC_FRAME_NOT_ZSTD    1
#define NGX_HTTP_ZSTD_STATIC_FRAME_TRUNCATED   2
#define NGX_HTTP_ZSTD_STATIC_FRAME_WINDOW_BIG  3
#define NGX_HTTP_ZSTD_STATIC_FRAME_SKIP        4

/*
 * How many leading skippable frames the caller's walk (in the handler,
 * below) will follow before giving up and declining. A dcz-style prefix
 * (see README "Standards-based dictionary compression") is exactly ONE
 * skippable frame — the 40-byte SHA-256 header — ahead of the real
 * payload frame, so 4 is generous headroom for that shape plus the odd
 * extra marker frame, while still bounding the walk to a handful of
 * pread(2) calls: an attacker cannot turn this into an unbounded scan
 * by chaining skippable frames, because each one past the bound is a
 * hard decline, not a longer search.
 */
#define NGX_HTTP_ZSTD_STATIC_MAX_SKIP_FRAMES   4


/*
 * Pure frame-header probe: decides whether the leading frame of a .zst
 * file may be served, given the first `n` bytes read from offset 0.
 *
 * Reads at most 18 bytes of `hdr` (magic(4) + descriptor(1) + dictionary
 * id(<=4) + content size(<=8)) and NEVER reads past `n`; every layout
 * path checks it got the bytes that layout requires before indexing
 * them. `n` is the byte count the caller's pread(2) actually returned
 * and is >= 4 by contract — the caller rejects a shorter read (and a
 * file smaller than 4 bytes) before calling, because those two cases
 * carry different log lines.
 *
 * On NGX_HTTP_ZSTD_STATIC_FRAME_WINDOW_BIG the declared window is
 * stored through `window` for the caller's error message. On
 * NGX_HTTP_ZSTD_STATIC_FRAME_SKIP the skippable frame's declared
 * 4-byte little-endian skip length (RFC 8878 §3.2) is stored through
 * `window` instead — same out-param, different unit, always read
 * against the matching verdict so there is no ambiguity. `window` is
 * untouched on every other verdict.
 *
 * No I/O, no logging, no allocation, no request state: this is the
 * arithmetic only, so ci/tests/unit/ can state its boundaries directly
 * (a short file, an exact-18-byte file, a valid frame, a bad magic)
 * without standing up an nginx.
 */
static ngx_int_t
ngx_http_zstd_static_probe_frame(const u_char *hdr, size_t n, uint64_t *window)
{
    uint32_t    mw;
    uint64_t    w;
    ngx_uint_t  i, fhd, fcs_size, off;

    static const ngx_uint_t  did_len[4] = { 0, 1, 2, 4 };

    mw = ((uint32_t) hdr[0])
       | ((uint32_t) hdr[1] << 8)
       | ((uint32_t) hdr[2] << 16)
       | ((uint32_t) hdr[3] << 24);

    if (mw != ZSTD_MAGICNUMBER
        && (mw & ZSTD_MAGIC_SKIPPABLE_MASK) != ZSTD_MAGIC_SKIPPABLE_START)
    {
        return NGX_HTTP_ZSTD_STATIC_FRAME_NOT_ZSTD;
    }

    /*
     * Skippable frame (RFC 8878 §3.2): magic(4) + Frame_Size(4, little-
     * endian) + Frame_Size bytes of opaque payload to skip. The
     * declared window guarantee this probe exists for does not apply
     * to a skippable frame directly — there is no window here, only a
     * length to jump — so the caller does not get to serve on this
     * verdict alone. It must resolve the skip, bounded, and probe
     * whatever frame follows: an attacker-controlled skippable prefix
     * must not be a way to dodge the window check on the frame that
     * actually gets decoded (that was the bug: unconditionally OK-ing
     * every skippable magic let a one-byte-longer file bypass the 8 MB
     * guard entirely). TRUNCATED here, same as a regular frame, means
     * "not enough bytes to decide" — the caller's fail-closed path is
     * identical either way.
     */
    if (mw != ZSTD_MAGICNUMBER) {
        if (n < 8) {
            return NGX_HTTP_ZSTD_STATIC_FRAME_TRUNCATED;
        }

        *window = ((uint64_t) hdr[4])
                | ((uint64_t) hdr[5] << 8)
                | ((uint64_t) hdr[6] << 16)
                | ((uint64_t) hdr[7] << 24);

        return NGX_HTTP_ZSTD_STATIC_FRAME_SKIP;
    }

    /*
     * Declared-window check (RFC 8878 §3.1.1.1) on regular frames —
     * see NGX_HTTP_ZSTD_STATIC_MAX_WINDOW for why: a frame declaring
     * more than 8 MB is rejected by every browser before decoding, so
     * serving it produces a page-breaking decode error that curl and
     * the zstd CLI do not reproduce. Declining keeps the site working
     * (the zstd filter, gzip_static or identity takes over) and puts
     * the actionable cause in the error log.
     *
     * The check covers the LEADING regular frame reached after
     * resolving any leading skippable frames (bounded, see the
     * caller). In a concatenation of regular frames only the first is
     * inspected: a regular frame's header does not declare its
     * compressed length, so walking the sequence would mean decoding
     * every block header in every frame — unbounded I/O for a
     * serve-time guard. Multi-regular-frame .zst web assets are
     * pathological (no common tooling emits them); the README
     * documents that scope.
     */

    if (n < 5) {
        return NGX_HTTP_ZSTD_STATIC_FRAME_TRUNCATED;
    }

    fhd = hdr[4];

    if (!(fhd & 0x20)) {
        /* No Single_Segment flag: Window_Descriptor follows. */
        if (n < 6) {
            return NGX_HTTP_ZSTD_STATIC_FRAME_TRUNCATED;
        }

        w = (uint64_t) 1 << (10 + (hdr[5] >> 3));
        w += (w >> 3) * (hdr[5] & 7);

    } else {
        /*
         * Single_Segment: no Window_Descriptor; the window is the
         * frame content size, read from behind the optional dictionary
         * id. Frame_Content_Size_flag 0 means a 1-byte field here (the
         * flag only means "absent" when Single_Segment is unset).
         */
        fcs_size = (fhd >> 6) ? ((ngx_uint_t) 1 << (fhd >> 6)) : 1;
        off = 5 + did_len[fhd & 3];

        if (n < off + fcs_size) {
            return NGX_HTTP_ZSTD_STATIC_FRAME_TRUNCATED;
        }

        w = 0;
        for (i = 0; i < fcs_size; i++) {
            w |= (uint64_t) hdr[off + i] << (8 * i);
        }

        if (fcs_size == 2) {
            w += 256;  /* RFC 8878: 2-byte field is offset */
        }
    }

    if (w > NGX_HTTP_ZSTD_STATIC_MAX_WINDOW) {
        *window = w;
        return NGX_HTTP_ZSTD_STATIC_FRAME_WINDOW_BIG;
    }

    return NGX_HTTP_ZSTD_STATIC_FRAME_OK;
}


/*
 * The probe's only platform-dependent step: fetch up to `size` bytes
 * from `offset` WITHOUT moving the descriptor's file position.
 *
 * Everything above this line — the magic check, the window arithmetic,
 * the skippable-frame length — and everything the caller does with the
 * verdicts is shared, byte for byte, between POSIX and Win32. Only the
 * fetch differs, which is the point: a second copy of the verdict logic
 * is how two platforms drift until one of them stops rejecting what the
 * other rejects (that drift is precisely the hole this function closes:
 * before it, Win32 served .zst files with no magic check, no window
 * guard and no skippable-chain bound at all).
 *
 * Returns the byte count read, or -1 on error, matching pread(2)'s
 * convention so the caller's short-read handling is unchanged. `log`
 * and `name` are only used by the Win32 branch, which routes through
 * ngx_read_file() and therefore needs an ngx_file_t to describe the
 * descriptor (`name` only ever reaches ngx_read_file()'s own error log
 * line); on POSIX both are unused.
 */
static ssize_t
ngx_http_zstd_static_pread(ngx_fd_t fd, u_char *buf, size_t size,
    off_t offset, ngx_log_t *log, ngx_str_t *name)
{
#if (NGX_WIN32)

    ssize_t      n;
    ngx_file_t   file;

    /*
     * A stack ngx_file_t borrowing the cached fd. The Win32
     * ngx_read_file() passes an OVERLAPPED carrying the explicit
     * offset to ReadFile(), so the read is positioned by argument
     * rather than by the handle's own pointer, and the only offset it
     * advances is file.offset — this local, discarded on return.
     *
     * That this is safe on a descriptor shared between concurrent
     * requests is not a deduction from the API docs alone: nginx's own
     * copy filter (src/core/ngx_output_chain.c, ngx_read_file() on
     * src->file) reads every static file body through exactly this
     * call, against exactly this open_file_cache descriptor, on every
     * Windows build. If an OVERLAPPED read here could disturb another
     * in-flight request on the same cached fd, Windows nginx could not
     * serve static files at all.
     */
    ngx_memzero(&file, sizeof(ngx_file_t));

    file.fd = fd;
    file.log = log;
    file.name = *name;

    n = ngx_read_file(&file, buf, size, offset);

    /*
     * ngx_read_file() returns NGX_ERROR (-1) on failure, having already
     * logged the ReadFile() error itself, and 0 at EOF. Both are short
     * reads to the caller, which declines — fail closed. NGX_ERROR is
     * -1 so the value passes through unchanged; assert that here rather
     * than assume it, since the caller's `n < 4` test is what turns
     * this into a decline.
     */
    if (n == NGX_ERROR) {
        return -1;
    }

    return n;

#else

    (void) log;
    (void) name;

    return pread(fd, buf, size, offset);

#endif
}

#endif /* NGX_HTTP_ZSTD_STATIC_HAVE_PROBE */


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
    ngx_http_core_loc_conf_t           *clcf;
    const ngx_http_zstd_static_conf_t  *zscf;

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

    /*
     * Historically this returned early when the client did not accept
     * zstd AND "gzip_vary" was off, on the reasoning that there was
     * then nothing to gain from the stat(): we would decline anyway,
     * and r->gzip_vary would have been cleared by the header filter,
     * so no Vary header could be produced.
     *
     * That shortcut is exactly the caching hazard this module now
     * closes by construction. This module emits "Vary:
     * Accept-Encoding" itself, independent of "gzip_vary", so the
     * probe below is what tells us whether a .zst variant exists — and
     * therefore whether this URI is Accept-Encoding-dependent at all.
     * Skipping it here would serve a Vary-less identity response for
     * precisely the configuration (gzip_vary off) the operator is most
     * likely to be running, and a shared cache would then reuse it for
     * clients that do accept zstd, or reuse an accepting client's
     * stored zstd body for this one.
     *
     * "always" ignores Accept-Encoding and never varies, so it keeps
     * its own shortcut: rc is forced to NGX_OK for it above, which
     * leaves this test false regardless of gzip_vary.
     */
    if (zscf->enable != NGX_HTTP_ZSTD_STATIC_ON && rc != NGX_OK) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                       "zstd static: skip, client did not accept zstd");
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
        /*
         * A .zst variant of this URI exists, so which representation
         * this URI serves depends on Accept-Encoding — including on
         * the decline path just below, where we hand the request back
         * for the identity file to be served by the static handler.
         * That identity response needs the Vary header just as much as
         * the compressed one does: without it a shared cache filled by
         * a non-accepting client keeps serving identity to everyone,
         * and one filled by an accepting client serves zstd to a
         * client that cannot decode it. The header list we push onto
         * survives the NGX_DECLINED, so the field lands on whichever
         * response is finally produced.
         *
         * Emitted directly rather than requested via r->gzip_vary, so
         * correctness does not depend on the operator's "gzip_vary"
         * directive; duplicate-safe in both of its states. See
         * ngx_http_zstd_vary_accept_encoding().
         *
         * "always" is excluded by the enclosing test on purpose: it
         * ignores Accept-Encoding, so its response is not a negotiated
         * variant and must not claim to vary on it. See C5.
         */
        if (ngx_http_zstd_vary_accept_encoding(r) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

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

#endif /* !NGX_WIN32 */

#if (NGX_HTTP_ZSTD_STATIC_HAVE_PROBE)
    /*
     * Magic-number sanity check on the .zst file.
     *
     * Without this, a truncated, half-downloaded, mistakenly-renamed
     * (e.g. `cp foo.txt foo.zst`), or otherwise non-zstd file would be
     * served with `Content-Encoding: zstd` and the client would get an
     * undecodable body — a confusing outage class that nginx's built-in
     * gzip_static also doesn't defend against. The probe is cheap (one
     * offset-explicit read of the frame-header prefix at offset 0 — 18
     * bytes, or one aligned block under directio — via
     * ngx_http_zstd_static_pread(): pread(2) on POSIX, ngx_read_file()
     * on Win32, both of which take the offset as an argument and so
     * never move the open_file_cache's shared fd position. Using plain
     * read(2)/SetFilePointer would do exactly that and corrupt
     * subsequent requests serving the same cached fd). On mismatch we
     * decline, so nginx falls back to serving the uncompressed original (or
     * returns 404 if it is absent), and the operator sees a clear
     * error log line.
     *
     * Both a regular zstd frame (ZSTD_MAGICNUMBER) and a skippable
     * frame (ZSTD_MAGIC_SKIPPABLE_START..+0xF) are accepted, since
     * either is a valid leading frame in a zstd stream.
     *
     * Gated by NGX_HTTP_ZSTD_STATIC_HAVE_PROBE (see its definition):
     * compiled in on Win32 and on any POSIX build whose configure found
     * pread(2). On a POSIX build WITHOUT pread(2) the probe is skipped
     * rather than degraded to a read+lseek pair that would mutate the
     * shared fd offset — every modern POSIX target has it, so that
     * branch is essentially a build-time tripwire.
     *
     * The probe deliberately runs on Win32 too. It used to be compiled
     * out there, which meant a Windows build served ANY .zst with no
     * magic check, no truncation check, no 8 MB window guard and no
     * skippable-frame chain bound — a strictly weaker validation than
     * the POSIX build, on a target the Windows build CI ships. The
     * verdict logic is shared, so the two platforms cannot drift apart
     * again; only the byte fetch differs.
     *
     * When the file was opened with O_DIRECT (of.is_directio, set by
     * ngx_open_cached_file when "directio <size>" is configured and the
     * file meets the threshold), the read must be block-aligned, so the
     * probe reads one block of max(NGX_HTTP_ZSTD_STATIC_DIO_PROBE,
     * directio_alignment) bytes into an equally-aligned pool buffer —
     * honoring the operator's declared geometry the same way the core
     * copy filter does. The window check in particular must not be
     * skipped under directio: oversized declared windows are a
     * systematic build-pipeline product, not rare corruption, and every
     * browser rejects them. If the aligned read STILL fails, the file
     * is DECLINED, not served: for a validation read, falling back to
     * another encoding is safer than certifying a file we could not
     * inspect, and the error log tells the operator which knob
     * (directio_alignment) disagrees with the device. On Win32
     * ngx_directio_on() is an upstream no-op stub, so of.is_directio
     * only ever reflects the operator's "directio" directive there and
     * the aligned path costs one pool allocation with no behavioural
     * difference — it is left shared rather than forked, because a
     * Win32-only bypass of this branch is exactly the kind of split
     * that reintroduces the gap this change closes.
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
        u_char       hdrbuf[18];
        u_char      *hdr;
        size_t       want;
        ssize_t      n;
        uint64_t     window, skip;
        ngx_uint_t   frames;
        off_t        pos;

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

        pos = 0;

        /*
         * Walk a bounded chain of leading skippable frames to reach the
         * first regular frame, so the window guard below cannot be
         * dodged by prepending one (see NGX_HTTP_ZSTD_STATIC_FRAME_SKIP
         * and NGX_HTTP_ZSTD_STATIC_MAX_SKIP_FRAMES). Each iteration
         * pread()s at the current offset, exactly like the original
         * single-shot probe did at offset 0; only the offset and the
         * loop are new.
         */
        for (frames = 0; ; frames++) {

            if (frames >= NGX_HTTP_ZSTD_STATIC_MAX_SKIP_FRAMES) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "zstd static: \"%s\" has more than %ui "
                              "leading skippable frames — declining "
                              "rather than searching further for the "
                              "first regular frame",
                              path.data,
                              (ngx_uint_t)
                                  NGX_HTTP_ZSTD_STATIC_MAX_SKIP_FRAMES);
                return NGX_DECLINED;
            }

            n = ngx_http_zstd_static_pread(of.fd, hdr, want, pos, log,
                                           &path);
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

                /*
                 * The primitive is named in the log because it is the
                 * operator's first clue about which syscall to strace.
                 * The POSIX text is preserved verbatim from before the
                 * Win32 port so existing log tooling keeps matching;
                 * Win32 names ReadFile() instead of claiming a pread(2)
                 * it never issued.
                 */
                ngx_log_error(NGX_LOG_CRIT, log, ngx_errno,
                              "zstd static: " NGX_HTTP_ZSTD_STATIC_PREAD_NAME
                              "(\"%s\", frame header) returned %z",
                              path.data, n);
                return NGX_DECLINED;
            }

            if (of.is_directio) {
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                               "zstd static: %uz-byte aligned probe on "
                               "directio file \"%s\"", want, path.data);
            }

            switch (ngx_http_zstd_static_probe_frame(hdr, (size_t) n,
                                                      &window))
            {

            case NGX_HTTP_ZSTD_STATIC_FRAME_NOT_ZSTD:
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "zstd static: \"%s\" is not a zstd frame "
                              "(leading bytes 0x%02xd%02xd%02xd%02xd)",
                              path.data,
                              (ngx_uint_t) hdr[0], (ngx_uint_t) hdr[1],
                              (ngx_uint_t) hdr[2], (ngx_uint_t) hdr[3]);
                return NGX_DECLINED;

            case NGX_HTTP_ZSTD_STATIC_FRAME_TRUNCATED:
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "zstd static: \"%s\" frame header truncated",
                              path.data);
                return NGX_DECLINED;

            case NGX_HTTP_ZSTD_STATIC_FRAME_WINDOW_BIG:
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

            case NGX_HTTP_ZSTD_STATIC_FRAME_SKIP:

                /*
                 * `window` carries the declared skip length here (see
                 * the probe's doc comment). Prove the 8-byte skippable
                 * header AND the full declared skip both fit within
                 * of.size before trusting the jump — checked
                 * arithmetic throughout, since `skip` is attacker-
                 * controlled and 32-bit-wide enough to overflow a
                 * 32-bit off_t/size_t add on its own.
                 */
                skip = window;

                if ((uint64_t) pos > (uint64_t) of.size
                    || (uint64_t) of.size - (uint64_t) pos < 8)
                {
                    ngx_log_error(NGX_LOG_ERR, log, 0,
                                  "zstd static: \"%s\" skippable frame "
                                  "header runs past end of file",
                                  path.data);
                    return NGX_DECLINED;
                }

                if (skip > (uint64_t) of.size - (uint64_t) pos - 8) {
                    ngx_log_error(NGX_LOG_ERR, log, 0,
                                  "zstd static: \"%s\" skippable frame "
                                  "declares a %uL-byte skip past end of "
                                  "file", path.data, skip);
                    return NGX_DECLINED;
                }

                pos += (off_t) 8 + (off_t) skip;

                continue;

            default:
                break;
            }

            break;
        }
    }
#endif /* NGX_HTTP_ZSTD_STATIC_HAVE_PROBE */

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

    /* gzip_static parity: byte ranges address the SELECTED
     * REPRESENTATION (RFC 9110 §14.2) — here the .zst bytes on disk,
     * which a client can fetch, resume and concatenate coherently
     * because the validator is strong and the bytes are stable. That
     * is why gzip_static has always set r->allow_ranges, and ranges
     * only work by opting in: the range filter bails without the
     * flag. The FILTER module's clear_accept_ranges remains correct
     * for the opposite reason — a stream generated on the fly has
     * nothing stable to seek into. */
    r->allow_ranges = 1;

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

    /* gzip_static parity: a zero-length file served in a subrequest
     * yields a buf with neither in_file nor last_buf — sync marks it
     * so the output chain doesn't reject it as a zero-size buf. Only
     * reachable when the frame-header probe is compiled out (a POSIX
     * build whose configure found no pread(2) — see
     * NGX_HTTP_ZSTD_STATIC_HAVE_PROBE); with the probe active, which
     * now includes Win32, sub-4-byte files never get this far. */
    b->sync = (b->last_buf || b->in_file) ? 0 : 1;

    b->file->fd = of.fd;
    b->file->name = path;
    b->file->log = log;
    b->file->directio = of.is_directio;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static void *
ngx_http_zstd_static_create_main_conf(ngx_conf_t *cf)
{
    return ngx_pcalloc(cf->pool, sizeof(ngx_http_zstd_static_main_conf_t));
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

    ngx_conf_merge_uint_value(conf->enable, prev->enable,
                              NGX_HTTP_ZSTD_STATIC_OFF);

    /*
     * G5: there is no longer a gzip_vary-off warning here. The content
     * handler emits "Vary: Accept-Encoding" itself whenever a .zst
     * variant makes this URI Accept-Encoding-dependent (see
     * ngx_http_zstd_vary_accept_encoding()), so the header no longer
     * depends on the operator setting "gzip_vary on", and warning
     * about that directive would be misleading. "always" still never
     * varies, by construction rather than by warning: it ignores
     * Accept-Encoding and the handler does not emit the field for it.
     */

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_zstd_static_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt               *h;
    ngx_http_core_main_conf_t         *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_zstd_static_handler;

    return NGX_OK;
}
