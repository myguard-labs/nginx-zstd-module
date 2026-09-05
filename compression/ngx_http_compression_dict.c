/*
 * Shared dictionary store implementation — see ngx_http_compression_dict.h
 * for the rules; comments here mark WHERE each rule bites, not what it is.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_compression_dict.h"

/*
 * Unification dividend, not a shortcut: the whole repo gets exactly one
 * SHA-256 implementation — the parent module's header-only one-shot,
 * EVP-accelerated when NGX_HTTP_ZSTD_HAVE_LIBCRYPTO is set. The macro
 * keeps the parent's name because this header keys on it;
 * compression/auto/detect defines it (probe, or nginx's own OpenSSL
 * for static addons), and NGX_HTTP_COMPRESSION_NO_LIBCRYPTO=1 keeps
 * the portable path. EVP matters here on both policies: the verify
 * default hashes every dictionary at config load — supplied literals
 * included — and even under compression_dict_trust_hashes the
 * unsupplied lines and the reference audit still hash.
 */
#include "../src/ngx_http_zstd_sha256.h"


extern ngx_module_t  ngx_http_compression_filter_module;


static ngx_int_t ngx_http_compression_hex_decode(ngx_str_t *hex,
    u_char out[NGX_HTTP_COMPRESSION_SHA256_LEN]);
static void ngx_http_compression_sha256(ngx_conf_t *cf,
    ngx_http_compression_main_conf_t *cmcf, const u_char *data, size_t len,
    u_char digest[NGX_HTTP_COMPRESSION_SHA256_LEN]);
static ssize_t ngx_http_compression_read_dict_file(ngx_fd_t fd, u_char *buf,
    size_t size);
static ngx_int_t ngx_http_compression_dicts_hashed_variable(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);


#if !(NGX_WIN32)
#include <fcntl.h>   /* openat(), O_DIRECTORY, O_NOFOLLOW, AT_FDCWD */
/*
 * AT_FDCWD is the portable signal that the POSIX.1-2008 *at() family is
 * available (parent #199). Where it is absent strict mode has no way to
 * resolve a path component-by-component, and it fails CLOSED at config
 * load rather than silently degrading to the leaf-only O_NOFOLLOW
 * guarantee it used to give.
 */
#ifdef AT_FDCWD
#define NGX_HTTP_COMPRESSION_HAVE_STRICT_WALK  1
#else
#define NGX_HTTP_COMPRESSION_HAVE_STRICT_WALK  0
#endif
#else
#define NGX_HTTP_COMPRESSION_HAVE_STRICT_WALK  0
#endif


#if (NGX_HTTP_COMPRESSION_HAVE_STRICT_WALK)

/*
 * Strict-mode component-by-component open (parent #199, M3).
 *
 * O_NOFOLLOW on the full path guards ONLY the leaf: the kernel resolves
 * every intermediate component normally, so /srv/current/dict.bin with
 * "current" a symlink is followed silently and strict mode selects
 * whatever bytes the symlink's owner points it at — exactly the
 * release-symlink swap the directive defends against. Walking the path
 * with openat(O_NOFOLLOW|O_DIRECTORY) one component at a time makes an
 * intermediate symlink fail the walk (ELOOP) instead of being
 * traversed, and the leaf is then opened relative to the verified
 * parent fd — so the whole resolution, not just its last step, is
 * symlink-free and TOCTOU-safe against a component swap racing the
 * walk. Every directory fd the walk opens (the root included) is also
 * vetted for ownership and mode before it is trusted as the base of the
 * next openat() (parent #316): an ancestor a local user owns, or can
 * write into, lets that user rename() a root-owned 0644 file into the
 * leaf position and pass both leaf checks while steering what strict
 * mode loads, so an unvetted component is the same gap the walk closes
 * for symlinks.
 *
 * Absolute paths only. The directive handler has already run the path
 * through ngx_conf_full_name(), so a dictionary path reaching here is
 * absolute; a relative one would have to be resolved against a cwd
 * this function cannot pin, and strict mode fails CLOSED rather than
 * fall back to a whole-path open.
 *
 * Returns the leaf fd, or NGX_INVALID_FILE having logged the reason.
 */
/*
 * fstat() one directory fd opened during the strict walk and refuse it
 * under the rule the leaf checks apply (parent #316, A33-F2): owned by
 * neither root nor the loading principal, or writable by group or
 * other. Deliberately no sticky-bit exemption: a sticky world-writable
 * ancestor (a /tmp-style directory) still lets an unprivileged user
 * create the next path component, which is exactly the steering this
 * refuses. `label` names the component for the diagnostic ("/" for the
 * root fd, the component bytes otherwise).
 */
static ngx_int_t
ngx_http_compression_check_strict_dir(ngx_conf_t *cf, int fd,
    const char *label, ngx_str_t *path)
{
    struct stat  st;

    if (fstat(fd, &st) < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "fstat(\"%s\") failed while resolving \"%V\" "
                           "under \"compression_dict_strict_path on\"",
                           label, path);
        return NGX_ERROR;
    }

    if (st.st_uid != 0 && st.st_uid != geteuid()) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "directory component \"%s\" of \"%V\" is owned "
                           "by uid %uD, neither root nor the loading "
                           "principal (uid %uD); refused by "
                           "\"compression_dict_strict_path on\": that "
                           "owner can rename a different file into this "
                           "directory and steer what a later privileged "
                           "reload loads", label, path,
                           (uint32_t) st.st_uid, (uint32_t) geteuid());
        return NGX_ERROR;
    }

    if (st.st_mode & (S_IWGRP | S_IWOTH)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "directory component \"%s\" of \"%V\" is "
                           "writable by group or other (no sticky-bit "
                           "exemption: a sticky world-writable directory "
                           "still lets an unprivileged user create the "
                           "next component); refused by "
                           "\"compression_dict_strict_path on\"",
                           label, path);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_fd_t
ngx_http_compression_open_dict_strict(ngx_conf_t *cf, ngx_str_t *path,
    int flags)
{
    u_char  *p, *start, *end;
    int      fd, next, oflags;

    if (path->len == 0 || path->data[0] != '/') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" is not an absolute path; refused by "
                           "\"compression_dict_strict_path on\", which "
                           "resolves the path one component at a time and "
                           "cannot verify a relative prefix", path);
        return NGX_INVALID_FILE;
    }

    fd = open("/", O_RDONLY | O_DIRECTORY
#ifdef O_CLOEXEC
              | O_CLOEXEC
#endif
              );
    if (fd < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "open(\"/\") failed while resolving \"%V\" "
                           "under \"compression_dict_strict_path on\"",
                           path);
        return NGX_INVALID_FILE;
    }

    /*
     * The root fd is a walked component like any other: vet it before
     * it is trusted as the base of every openat() below. On most
     * systems "/" is root-owned 0755 and this is a no-op; a container
     * or chroot base that fails it is exactly the layout strict mode
     * is meant to refuse.
     */
    if (ngx_http_compression_check_strict_dir(cf, fd, "/", path) != NGX_OK) {
        ngx_close_file(fd);
        return NGX_INVALID_FILE;
    }

    start = path->data + 1;
    end = path->data + path->len;

    for ( ;; ) {
        /* skip any run of separators; a trailing one means no leaf */
        while (start < end && *start == '/') {
            start++;
        }

        if (start >= end) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%V\" names a directory, not a "
                               "dictionary file; refused by "
                               "\"compression_dict_strict_path on\"",
                               path);
            ngx_close_file(fd);
            return NGX_INVALID_FILE;
        }

        for (p = start; p < end && *p != '/'; p++) { /* void */ }

        /*
         * openat() needs a NUL-terminated component. The component is
         * COPIED into a local buffer rather than NUL-terminated in
         * place: path->data is nginx's own config string, and writing
         * into it — even a byte restored immediately afterwards —
         * would mutate shared config memory that other directives and
         * the error log still read. A component longer than the buffer
         * cannot name a file any filesystem will accept, so it is
         * refused rather than silently truncated (truncation would
         * open a DIFFERENT name).
         */
        {
            u_char   comp[NGX_MAX_PATH];
            size_t   complen = (size_t) (p - start);
            int      last;
            u_char  *q;

            if (complen >= sizeof(comp)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "\"%V\" has a path component longer "
                                   "than %uz bytes; refused by "
                                   "\"compression_dict_strict_path on\"",
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

            /*
             * "." and ".." are refused rather than resolved: ".."
             * would climb back above a component already verified,
             * which makes the walk's guarantee unstatable, and
             * neither has a legitimate place in a deployed
             * dictionary path.
             */
            if (ngx_strcmp(comp, ".") == 0
                || ngx_strcmp(comp, "..") == 0)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "\"%V\" contains a \".\" or \"..\" "
                                   "component; refused by "
                                   "\"compression_dict_strict_path on\"",
                                   path);
                ngx_close_file(fd);
                return NGX_INVALID_FILE;
            }

            /*
             * O_CLOEXEC is applied to BOTH arms deliberately. Folding
             * it into the ternary via a bare "#ifdef ... | O_CLOEXEC"
             * would bind it to the else-branch alone by C's precedence
             * rules, silently leaving the leaf fd inheritable across
             * an exec.
             */
            oflags = last ? (flags | O_NOFOLLOW)
                          : (O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
#ifdef O_CLOEXEC
            oflags |= O_CLOEXEC;
#endif

            next = openat(fd, (char *) comp, oflags);

            if (next < 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                                   "openat(\"%s\") failed while "
                                   "resolving \"%V\" under "
                                   "\"compression_dict_strict_path on\" "
                                   "(a symlink at any component is "
                                   "refused, not followed; a "
                                   "release-symlink deployment needs "
                                   "\"compression_dict_strict_path "
                                   "off;\", the default)", comp, path);
                ngx_close_file(fd);
                return NGX_INVALID_FILE;
            }

            ngx_close_file(fd);
            fd = next;

            if (last) {
                return fd;
            }

            /*
             * A directory fd that will be trusted as the base for the
             * next openat(): vet it before it is used for anything
             * else, same rule as the root fd above.
             */
            if (ngx_http_compression_check_strict_dir(cf, fd, (char *) comp,
                                                      path)
                != NGX_OK)
            {
                ngx_close_file(fd);
                return NGX_INVALID_FILE;
            }

            start = p;
        }
    }
}

#endif /* NGX_HTTP_COMPRESSION_HAVE_STRICT_WALK */


/*
 * Read exactly `size` bytes of a dictionary into `buf`, looping until the
 * request is satisfied. Mirrors the standalone module's #195
 * (ngx_http_zstd_read_dict_file): ngx_read_fd() is read(2) on POSIX, which
 * may return a SHORT count on a regular file — a signal interrupting the
 * read after a partial transfer, or a sufficiently large read — so a
 * single read is not enough and the caller would reject a valid dictionary
 * as an incomplete read. Retry EINTR, resume on a short count, and stop
 * early only on a hard error (returns -1) or an unexpected EOF (returns
 * the partial total < size). The caller's existing full-read check and
 * optional-vs-fatal logging are unchanged — this only replaces the single
 * ngx_read_fd() that fed them; the O_NONBLOCK clear above still removes the
 * non-blocking short-read case.
 *
 * The EINTR retry is #if !(NGX_WIN32): win32's ngx_errno.h defines no
 * NGX_EINTR (ReadFile on a synchronous handle is not interruptible), so
 * guarding on the platform states the reason and keeps the MSVC build
 * compiling (the #195 lesson).
 */
static ssize_t
ngx_http_compression_read_dict_file(ngx_fd_t fd, u_char *buf, size_t size)
{
    ssize_t  n;
    size_t   done;

    for (done = 0; done < size; /* void */) {
        n = ngx_read_fd(fd, buf + done, size - done);

        if (n < 0) {
#if !(NGX_WIN32)
            if (ngx_errno == NGX_EINTR) {
                continue;
            }
#endif
            return -1;          /* read error */
        }

        if (n == 0) {
            break;              /* EOF before `size`: return the partial */
        }

        done += (size_t) n;
    }

    return (ssize_t) done;
}


static ngx_int_t
ngx_http_compression_hex_decode(ngx_str_t *hex,
    u_char out[NGX_HTTP_COMPRESSION_SHA256_LEN])
{
    u_char      c;
    ngx_uint_t  i, hi;

    if (hex->len != NGX_HTTP_COMPRESSION_SHA256_HEX_LEN) {
        return NGX_ERROR;
    }

    for (i = 0; i < NGX_HTTP_COMPRESSION_SHA256_HEX_LEN; i++) {
        c = ngx_tolower(hex->data[i]);

        if (c >= '0' && c <= '9') {
            hi = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            hi = c - 'a' + 10;
        } else {
            return NGX_ERROR;
        }

        if (i % 2 == 0) {
            out[i / 2] = (u_char) (hi << 4);
        } else {
            out[i / 2] |= (u_char) hi;
        }
    }

    return NGX_OK;
}


static void
ngx_http_compression_hex_encode(const u_char *bin, size_t len, u_char *out)
{
    static const u_char  hex[] = "0123456789abcdef";
    size_t               i;

    for (i = 0; i < len; i++) {
        *out++ = hex[bin[i] >> 4];
        *out++ = hex[bin[i] & 0x0f];
    }
}


#if (NGX_HTTP_ZSTD_HAVE_LIBCRYPTO)

static void
ngx_http_compression_sha256_ctx_cleanup(void *data)
{
    EVP_MD_CTX_free(data);
}

#endif


/*
 * Every computed hash in this store goes through here rather than the
 * parent header's one-shot (parent #262): EVP_Digest() allocates and
 * frees a digest context internally on every call, so a config load
 * over hundreds of dictionaries pays hundreds of transient allocations.
 * One lazily created context, freed with cf->pool when parsing ends,
 * serves them all. Every failure — context creation, cleanup
 * registration, or any EVP stage — falls through to the parent's
 * portable implementation, keeping this a total function; and this
 * wrapper deliberately does NOT call the header's one-shot, so its
 * signature owes nothing to the parent's (#262 changed it upstream —
 * the staged helpers below are the stable surface).
 */
static void
ngx_http_compression_sha256(ngx_conf_t *cf,
    ngx_http_compression_main_conf_t *cmcf, const u_char *data, size_t len,
    u_char digest[NGX_HTTP_COMPRESSION_SHA256_LEN])
{
    ngx_http_zstd_sha256_t  c;

#if (NGX_HTTP_ZSTD_HAVE_LIBCRYPTO)
    unsigned int         mdlen;
    ngx_pool_cleanup_t  *cln;

    if (!cmcf->sha256_evp_ctx_attempted) {
        cmcf->sha256_evp_ctx_attempted = 1;
        cmcf->sha256_evp_ctx = EVP_MD_CTX_new();

        if (cmcf->sha256_evp_ctx != NULL) {
            cln = ngx_pool_cleanup_add(cf->pool, 0);

            if (cln == NULL) {
                EVP_MD_CTX_free(cmcf->sha256_evp_ctx);
                cmcf->sha256_evp_ctx = NULL;

            } else {
                cln->handler = ngx_http_compression_sha256_ctx_cleanup;
                cln->data = cmcf->sha256_evp_ctx;
            }
        }
    }

    mdlen = NGX_HTTP_COMPRESSION_SHA256_LEN;

    if (cmcf->sha256_evp_ctx != NULL
        && EVP_DigestInit_ex(cmcf->sha256_evp_ctx, EVP_sha256(), NULL) == 1
        && EVP_DigestUpdate(cmcf->sha256_evp_ctx, data, len) == 1
        && EVP_DigestFinal_ex(cmcf->sha256_evp_ctx, digest, &mdlen) == 1
        && mdlen == NGX_HTTP_COMPRESSION_SHA256_LEN)
    {
        return;
    }
#else
    (void) cf;
    (void) cmcf;
#endif

    ngx_http_zstd_sha256_init(&c);
    ngx_http_zstd_sha256_update(&c, data, len);
    ngx_http_zstd_sha256_final(&c, digest);
}


char *
ngx_http_compression_dict_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                          *value, path, hex;
    ngx_fd_t                            fd;
    ssize_t                             n;
    ngx_flag_t                          trust;
    ngx_uint_t                          i, supplied, optional;
    ngx_file_info_t                     info;
    ngx_http_compression_dict_t       **d, *entry, **dp, **list;
    ngx_http_compression_main_conf_t   *cmcf;
    ngx_array_t                       **dicts;
    u_char                              want[NGX_HTTP_COMPRESSION_SHA256_LEN];

    /* the loc conf's dicts array field, located via cmd->offset */
    dicts = (ngx_array_t **) ((char *) conf + cmd->offset);

    cmcf = ngx_http_conf_get_module_main_conf(cf,
                                              ngx_http_compression_filter_module);

    value = cf->args->elts;
    path = value[1];

    /*
     * Optional arguments in either order: a 64-hex sha256 and/or the
     * "optional" keyword — the operator-insistence demotion (Mark's
     * outage scenario, an INTENTIONAL DEVIATION from the RFC's
     * fail-fatal rule): a dictionary that cannot be loaded as
     * declared warns and degrades instead of refusing to start the
     * server. Deploy tooling emits it on generated lines; hand-written
     * critical entries stay strict by omitting it. Anything that is
     * neither the keyword nor a plausible hash falls through to the
     * hash validator below, which names the real problem.
     */
    supplied = 0;
    optional = 0;

    for (i = 2; i < cf->args->nelts; i++) {
        if (value[i].len == sizeof("optional") - 1
            && ngx_strncmp(value[i].data, "optional",
                           sizeof("optional") - 1) == 0)
        {
            optional = 1;

        } else if (supplied) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate dictionary hash argument \"%V\"",
                               &value[i]);
            return NGX_CONF_ERROR;

        } else {
            supplied = 1;
            hex = value[i];
        }
    }

    /*
     * Validate the supplied hash BEFORE touching the filesystem (the
     * parent repo's ordering pin): a malformed hash next to a
     * nonexistent path must report the hash, not the open failure —
     * the operator fixes their config once, not twice. Malformed hex
     * stays FATAL even with "optional": a typo is a config bug to fix
     * once, not a deploy race to ride out.
     */
    if (supplied) {
        if (ngx_http_compression_hex_decode(&hex, want) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid dictionary hash \"%V\": want %d "
                               "hex characters (the file's "
                               "SHA-256)", &hex,
                               NGX_HTTP_COMPRESSION_SHA256_HEX_LEN);
            return NGX_CONF_ERROR;
        }
    }

    /*
     * Relative paths resolve against the SERVER prefix (third arg 0),
     * not the conf prefix: dictionaries are data assets like roots
     * and user files, not configuration includes. (The first cut
     * passed 1; invisible while the test harness kept conf and prefix
     * in one directory, caught the moment Test::Nginx split them.)
     */
    if (ngx_conf_full_name(cf->cycle, &path, 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    /*
     * Raw read, same reasoning as dict_strict_path below: a later
     * "compression_dict_trust_hashes on;" has not been parsed yet
     * when this line loads, so a literal verified here silently pays
     * the pass the operator asked to skip. Record the possibility;
     * init_main_conf() rejects the ordering if the flag's final value
     * is "on". Only literal-carrying first loads are affected — the
     * dedup and audit paths hash under their own rules either way.
     */
    trust = (cmcf->dict_trust_hashes == 1);

    if (supplied && !trust && !cmcf->dict_verified_before_trust_on) {
        cmcf->dict_verified_before_trust_on = 1;
        cmcf->dict_verified_before_trust_on_file = path;
    }

    /* ── store lookup by path: the dedup that makes it ONE copy ──────
     * (store holds POINTERS; entry objects are individually allocated
     * so aliases in per-location lists survive array growth) */

    entry = NULL;
    d = cmcf->store.elts;

    for (i = 0; i < cmcf->store.nelts; i++) {
        if (d[i]->path.len == path.len
            && ngx_strncmp(d[i]->path.data, path.data, path.len) == 0)
        {
            entry = d[i];
            break;
        }
    }

    if (entry != NULL) {

        if (supplied) {
            /*
             * Two provenances now describe one file. Verbatim trust
             * never extends to CONFLICT: whatever the existing entry
             * believes (supplied or computed), a differing hash for
             * the same path is a config error, not a shrug.
             */
            if (ngx_memcmp(entry->sha256, want,
                           NGX_HTTP_COMPRESSION_SHA256_LEN)
                != 0)
            {
                if (!optional && !entry->optional) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "conflicting sha256 for dictionary "
                                       "\"%V\": \"%V\" does not match the "
                                       "hash already recorded for this "
                                       "file", &path, &hex);
                    return NGX_CONF_ERROR;
                }

                /* optional: the file's computed truth outranks BOTH
                 * declared values — serving keys stay correct */
                ngx_http_compression_sha256(cf, cmcf, entry->bytes.data,
                                            entry->bytes.len, entry->sha256);
                cmcf->dicts_hashed++;
                entry->verified = 1;
                ngx_http_compression_hex_encode(entry->sha256,
                                     NGX_HTTP_COMPRESSION_SHA256_LEN,
                                     entry->sha256_hex.data);
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "conflicting sha256 values for optional "
                                   "dictionary \"%V\"; the file's computed "
                                   "hash wins", &path);
            }

            if (!entry->supplied) {
                entry->verified = 1;    /* computed earlier, now agreed */
            }

        } else if (entry->supplied && !entry->verified) {
            /*
             * THE RULE: a supplied hash never satisfies a directive
             * that didn't supply one. This directive mandates a
             * computation — and since that pass is paid for anyway,
             * it doubles as a free audit of the earlier verbatim
             * hash: a mismatch here is precisely the stale-supplied-
             * hash hazard (deploy script hashed an older file) that
             * verbatim trust cannot catch on its own.
             */
            ngx_http_compression_sha256(cf, cmcf, entry->bytes.data,
                                        entry->bytes.len, want);
            cmcf->dicts_hashed++;

            if (ngx_memcmp(entry->sha256, want,
                           NGX_HTTP_COMPRESSION_SHA256_LEN)
                != 0)
            {
                if (!optional && !entry->optional) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "dictionary \"%V\": the supplied "
                                       "sha256 does not match the file's "
                                       "actual hash (stale hash from an "
                                       "earlier deploy?)", &path);
                    return NGX_CONF_ERROR;
                }

                /* optional: `want` holds the computed truth — re-key
                 * the entry so clients holding the REAL file still
                 * negotiate */
                ngx_memcpy(entry->sha256, want,
                           NGX_HTTP_COMPRESSION_SHA256_LEN);
                ngx_http_compression_hex_encode(entry->sha256,
                                     NGX_HTTP_COMPRESSION_SHA256_LEN,
                                     entry->sha256_hex.data);
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "optional dictionary \"%V\": stale "
                                   "supplied sha256; the file's computed "
                                   "hash wins", &path);
            }

            entry->verified = 1;
        }

        /* matching hashes (or computed-and-shared): one store entry */

    } else {

        /* ── first sight of this path: load it ─────────────────────── */

        /*
         * This load is about to run under whatever dict_strict_path
         * reads RIGHT NOW. If that is anything but the explicit "on",
         * the O_NOFOLLOW open and the writable-target check below are
         * skipped — record it, so init_main_conf() can reject the
         * config if a later "compression_dict_strict_path on;" line
         * turns out to have been meant to cover this load. See the
         * field's comment in ngx_http_compression_dict.h.
         */
        if (cmcf->dict_strict_path != 1
            && !cmcf->dict_loaded_before_strict_on)
        {
            cmcf->dict_loaded_before_strict_on = 1;
            cmcf->dict_loaded_before_strict_on_file = path;
        }

        /*
         * O_NONBLOCK always (parent #165): a FIFO at the dictionary path
         * would otherwise block the config-parsing master in open()
         * until a writer appeared — nginx -t or a reload would just
         * hang. Win32's NGX_FILE_NONBLOCK is 0, a no-op.
         *
         * Under compression_dict_strict_path the path is resolved one
         * component at a time (parent #199, M3): O_NOFOLLOW on a
         * whole-path open guards only the LEAF, so a symlinked
         * intermediate directory — the classic current -> releases/7
         * layout — walked straight through the old leaf-only check.
         * A strict refusal is fatal even with "optional": like the
         * writable-target check below, strict mode is a trust decision
         * to fix, not a deploy race to ride out.
         */
        if (cmcf->dict_strict_path == 1) {

#if (NGX_HTTP_COMPRESSION_HAVE_STRICT_WALK)
            fd = ngx_http_compression_open_dict_strict(cf, &path,
                                        O_RDONLY | NGX_FILE_NONBLOCK);
            if (fd == NGX_INVALID_FILE) {
                /* the walk has already logged the precise component */
                return NGX_CONF_ERROR;
            }
#else
            /*
             * Fail CLOSED (parent #199): without openat() strict mode
             * can only offer the leaf-only O_NOFOLLOW guarantee, which
             * an intermediate symlink defeats — accepting the config
             * here would let the directive claim a protection the
             * platform cannot deliver.
             */
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"compression_dict_strict_path on\" is "
                               "not supported on this platform (no "
                               "openat(); the path cannot be resolved "
                               "one component at a time, so an "
                               "intermediate symlink could not be "
                               "refused). Refusing \"%V\" rather than "
                               "loading it with a weaker guarantee than "
                               "the directive states", &path);
            return NGX_CONF_ERROR;
#endif

        } else {
            fd = ngx_open_file(path.data,
                               NGX_FILE_RDONLY | NGX_FILE_NONBLOCK,
                               NGX_FILE_OPEN, 0);
        }
        if (fd == NGX_INVALID_FILE) {
            if (optional) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, ngx_errno,
                                   "skipping optional dictionary \"%V\": "
                                   "open() failed; clients holding it "
                                   "degrade to the base coding", &path);
                return NGX_CONF_OK;
            }
            ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                               "open() dictionary \"%V\" failed", &path);
            return NGX_CONF_ERROR;
        }

        if (ngx_fd_info(fd, &info) == NGX_FILE_ERROR || ngx_file_size(&info) == 0) {
            ngx_close_file(fd);
            if (optional) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "skipping optional dictionary \"%V\": "
                                   "empty or unreadable", &path);
                return NGX_CONF_OK;
            }
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "dictionary \"%V\" is empty or unreadable",
                               &path);
            return NGX_CONF_ERROR;
        }

        /*
         * Non-regular target rejected UNCONDITIONALLY (parent #165): a
         * FIFO/socket/directory/device was never a valid dictionary, and
         * there is no compatible config that depended on the old
         * behaviour succeeding against one (it always eventually errored
         * or hung). ngx_is_file() checks S_ISREG.
         */
        if (!ngx_is_file(&info)) {
            ngx_close_file(fd);
            if (optional) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "skipping optional dictionary \"%V\": "
                                   "not a regular file", &path);
                return NGX_CONF_OK;
            }
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "dictionary \"%V\" is not a regular file",
                               &path);
            return NGX_CONF_ERROR;
        }

#if !(NGX_WIN32)
        /*
         * Ownership, not just the group/other bits (parent #199, M4):
         * a dictionary owned by an unprivileged account with a
         * perfectly ordinary mode 0644 passes a group/other-writability
         * test while a root master reads it — and that owner can
         * rewrite the file at will, so the next privileged reload
         * snapshots whatever bytes they chose. Strict mode therefore
         * requires the file to be owned by the loading principal (the
         * effective uid of the config-parsing master) or by root,
         * which is not "less privileged" than any loader that reaches
         * here.
         */
        if (cmcf->dict_strict_path == 1
            && info.st_uid != geteuid() && info.st_uid != 0)
        {
            ngx_close_file(fd);
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "dictionary \"%V\" is owned by uid %uD, "
                               "neither the loading principal (uid %uD) "
                               "nor root; refused by "
                               "\"compression_dict_strict_path on\", "
                               "because that owner can rewrite the file "
                               "and steer what a later privileged reload "
                               "loads", &path,
                               (uint32_t) info.st_uid,
                               (uint32_t) geteuid());
            return NGX_CONF_ERROR;
        }

        /*
         * Strict trust (parent #165): reject a dictionary writable by
         * group or other — a lower-privileged local writer must not be
         * able to swap bytes into every worker on the next reload.
         * Opt-in, since a release-managed deployment may legitimately
         * ship such permissions. malformed-hex-still-fatal spirit: this
         * is fatal even with "optional", because a writable dictionary
         * is a trust decision to fix, not a deploy race to ride out.
         */
        if (cmcf->dict_strict_path == 1
            && (ngx_file_access(&info) & (S_IWGRP | S_IWOTH)))
        {
            ngx_close_file(fd);
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "dictionary \"%V\" is writable by group or "
                               "other and \"compression_dict_strict_path\" "
                               "is on", &path);
            return NGX_CONF_ERROR;
        }

        /*
         * The FIFO-hang risk was only in open(); the file is now
         * confirmed regular, so clear O_NONBLOCK before the single
         * ngx_read_fd() below. A non-blocking regular-file read can
         * return SHORT on some filesystems (observed on a 9p/drvfs
         * mount), which the loader would then reject as an incomplete
         * read. (The parent keeps O_NONBLOCK through the read; on a
         * normal filesystem regular-file reads ignore it, so the hazard
         * is latent there — cleared here to be safe everywhere.)
         */
        {
            int  fl = fcntl(fd, F_GETFL);

            if (fl != -1) {
                (void) fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
            }
        }
#endif

        entry = ngx_pcalloc(cf->pool, sizeof(ngx_http_compression_dict_t));
        if (entry == NULL) {
            ngx_close_file(fd);
            return NGX_CONF_ERROR;
        }

        entry->path = path;

        /*
         * off_t bound BEFORE the size_t narrowing (round-4 review,
         * R3-9; the parent rejects first for the same reason): on
         * ILP32 a 4 GiB file cast to size_t loads as its low 32 bits,
         * hashes clean, and serves. The cap itself is the parent's
         * 10 MB — comfortably above the 8 MB useful-window warning
         * below, far below anything that can wrap. Demoted to
         * skip-with-warning under "optional", like the other
         * size-class load failures.
         */
        if (ngx_file_size(&info) > (off_t) (10 * 1024 * 1024)) {
            ngx_close_file(fd);
            if (optional) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "skipping optional dictionary \"%V\": "
                                   "%O bytes exceeds the 10 MB limit",
                                   &path, ngx_file_size(&info));
                return NGX_CONF_OK;
            }
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "dictionary \"%V\" too large: %O bytes "
                               "(limit: 10 MB)",
                               &path, ngx_file_size(&info));
            return NGX_CONF_ERROR;
        }

        entry->bytes.len = (size_t) ngx_file_size(&info);
        entry->bytes.data = ngx_palloc(cf->pool, entry->bytes.len);
        if (entry->bytes.data == NULL) {
            ngx_close_file(fd);
            return NGX_CONF_ERROR;
        }

        n = ngx_http_compression_read_dict_file(fd, entry->bytes.data,
                                                entry->bytes.len);
        ngx_close_file(fd);

        if (n != (ssize_t) entry->bytes.len) {
            if (optional) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "skipping optional dictionary \"%V\": "
                                   "read() returned %z of %uz bytes",
                                   &path, n, entry->bytes.len);
                return NGX_CONF_OK;
            }
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "read() dictionary \"%V\": %z of %uz bytes",
                               &path, n, entry->bytes.len);
            return NGX_CONF_ERROR;
        }

        /*
         * Parent parity (its zstd-03:13): a dictionary larger than
         * the 8 MB window browsers enforce cannot be fully referenced
         * — with the unpledged-window cap, dcz matches beyond the
         * window's reach are silently lost. Loading proceeds (the
         * near end still helps, and dcb's window rules differ), but
         * the operator should know their dictionary is bigger than
         * its useful range.
         */
        if (entry->bytes.len > 8 * 1024 * 1024) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "dictionary \"%V\" is %uz bytes — larger "
                               "than the 8 MB window browsers enforce for "
                               "Content-Encoding: zstd; content beyond the "
                               "window cannot reference it", &path,
                               entry->bytes.len);
        }

        if (supplied && trust) {
            /*
             * compression_dict_trust_hashes on: verbatim, zero
             * hashing — the operator's pipeline is the authority on
             * the bytes, and the skipped pass (with its
             * $compression_dicts_hashed increment, the observable
             * witness) is the whole point. The unsupplied-reference
             * audit below remains the safety net under trust.
             */
            ngx_memcpy(entry->sha256, want,
                       NGX_HTTP_COMPRESSION_SHA256_LEN);
            entry->supplied = 1;

        } else {
            ngx_http_compression_sha256(cf, cmcf, entry->bytes.data,
                                        entry->bytes.len, entry->sha256);
            cmcf->dicts_hashed++;
            entry->verified = 1;

            /*
             * Verify default (parent #198): the literal declares what
             * the operator believes the file to be, and the computed
             * hash is the truth. "optional" demotes a mismatch to the
             * audit path's exact remedy — warn, and the computed
             * truth keys the entry so clients holding the REAL file
             * still negotiate.
             */
            if (supplied
                && ngx_memcmp(entry->sha256, want,
                              NGX_HTTP_COMPRESSION_SHA256_LEN) != 0)
            {
                if (!optional) {
                    u_char     chex[NGX_HTTP_COMPRESSION_SHA256_HEX_LEN];
                    ngx_str_t  chexs;

                    ngx_http_compression_hex_encode(entry->sha256,
                        NGX_HTTP_COMPRESSION_SHA256_LEN, chex);
                    chexs.data = chex;
                    chexs.len = NGX_HTTP_COMPRESSION_SHA256_HEX_LEN;

                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "dictionary \"%V\" does not match "
                                       "the supplied hash \"%V\": the "
                                       "file's SHA-256 is \"%V\" (use "
                                       "\"compression_dict_trust_hashes "
                                       "on\" only if your deploy pipeline "
                                       "owns hash correctness)",
                                       &path, &hex, &chexs);
                    return NGX_CONF_ERROR;
                }

                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "optional dictionary \"%V\": stale "
                                   "supplied sha256; the file's computed "
                                   "hash wins", &path);
            }

            entry->supplied = supplied ? 1 : 0;
        }

        entry->sha256_hex.len = NGX_HTTP_COMPRESSION_SHA256_HEX_LEN;
        entry->sha256_hex.data =
            ngx_pnalloc(cf->pool, NGX_HTTP_COMPRESSION_SHA256_HEX_LEN);
        if (entry->sha256_hex.data == NULL) {
            return NGX_CONF_ERROR;
        }
        ngx_http_compression_hex_encode(entry->sha256,
                                        NGX_HTTP_COMPRESSION_SHA256_LEN,
                                        entry->sha256_hex.data);

        /*
         * Ambiguity gate: RFC 9842 negotiation keys on the hash alone,
         * so two DIFFERENT files sharing one hash could serve either
         * dictionary for a client's Available-Dictionary. Parent
         * behavior kept: config error, named after the colliding path.
         * Runs BEFORE the entry joins the store, so the scan never has
         * to exclude the newcomer.
         */
        d = cmcf->store.elts;
        for (i = 0; i < cmcf->store.nelts; i++) {
            if (ngx_memcmp(d[i]->sha256, entry->sha256,
                           NGX_HTTP_COMPRESSION_SHA256_LEN)
                == 0)
            {
                if (!optional && !d[i]->optional) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "dictionary \"%V\" has the same "
                                       "hash as \"%V\"", &path,
                                       &d[i]->path);
                    return NGX_CONF_ERROR;
                }

                /* optional: same hash = same bytes = interchangeable —
                 * alias to the entry already in the store */
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "optional dictionary \"%V\" has the "
                                   "same hash as \"%V\"; using the "
                                   "existing entry", &path, &d[i]->path);
                entry = d[i];
                break;
            }
        }

        if (i == cmcf->store.nelts) {
            dp = ngx_array_push(&cmcf->store);
            if (dp == NULL) {
                return NGX_CONF_ERROR;
            }
            *dp = entry;
        }
    }

    if (optional) {
        entry->optional = 1;    /* sticky across lines for this path */
    }

    /* ── append to this level's list (pointer into the store) ──────── */

    if (*dicts == NULL) {
        *dicts = ngx_array_create(cf->pool, 4,
                                  sizeof(ngx_http_compression_dict_t *));
        if (*dicts == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    list = (*dicts)->elts;
    for (i = 0; i < (*dicts)->nelts; i++) {
        if (list[i] == entry) {
            if (optional || entry->optional) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "optional dictionary \"%V\" already in "
                                   "this list; skipping the duplicate",
                                   &path);
                return NGX_CONF_OK;
            }
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate dictionary \"%V\" in this "
                               "\"compression_dict_file\" list", &path);
            return NGX_CONF_ERROR;
        }
    }

    dp = ngx_array_push(*dicts);
    if (dp == NULL) {
        return NGX_CONF_ERROR;
    }
    *dp = entry;

    return NGX_CONF_OK;
}


/* ── $compression_dicts_hashed ─────────────────────────────────────── */

static ngx_int_t
ngx_http_compression_dicts_hashed_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_compression_main_conf_t  *cmcf;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_compression_filter_module);

    /* preformatted once in init_main_conf() — constant for the worker's
     * life, so no per-request ngx_sprintf (parent #154). The bytes live
     * in the cycle config pool, which outlives every request. */
    v->len = cmcf->dicts_hashed_str.len;
    v->data = cmcf->dicts_hashed_str.data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


ngx_int_t
ngx_http_compression_dict_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;
    static ngx_str_t      name =
        ngx_string("compression_dicts_hashed");

    var = ngx_http_add_variable(cf, &name, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_compression_dicts_hashed_variable;

    return NGX_OK;
}
