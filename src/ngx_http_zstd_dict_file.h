/*
 * Copyright (C) 2026 Thijs Eilander
 *
 * THE authoritative copy of the dictionary-file I/O family (#312): the
 * read-to-completion loop both dictionary loaders drive, and the hex
 * nibble decoder behind a supplied dictionary hash literal. No logging,
 * no allocation, no ngx_conf_t -- every consumer (the filter module, the
 * unit fixture, the compression branch's shared dictionary store)
 * includes THIS file instead of carrying a synchronized copy. The read
 * loop existed three times across the two trees and the brotli fork,
 * each copy with its own scripted-read unit fixture; a fix to it would
 * have been ported three times and proven three times.
 *
 * CONSUMER CONTRACT. Inside nginx, include after the nginx headers and
 * everything below resolves. Outside nginx (the unit fixtures), provide
 * before including:
 *     typedef unsigned char  u_char;
 *     typedef int            ngx_fd_t;
 *     typedef struct { size_t len; u_char *data; } ngx_str_t;
 *     #define ngx_read_fd(fd, buf, n)  read(fd, buf, n)   (or a stub)
 *     #define ngx_errno                errno
 *     #define NGX_EINTR                EINTR
 *     #define NGX_INVALID_FILE         -1
 *     #define NGX_MAX_PATH             4096
 *     #define ngx_memcpy               memcpy
 *     #define ngx_strcmp(a, b)         strcmp((const char *) (a), ...)
 *     #define ngx_close_file           close        (or a stub)
 * The strict walk calls open(), openat(), fstat() and geteuid() by their
 * libc names; a fixture that includes the system headers first may
 * redefine those four as function-like macros over scripted fakes
 * (ci/tools/test_dict_walk_unit.c does), so every exit is reachable
 * without a filesystem. When nginx has not defined ngx_inline it expands
 * to nothing: the definitions are already `static`, and an empty
 * fallback keeps a conforming C89 compile valid, where `inline` is not
 * a keyword -- a fixture that uses only part of the family defines
 * ngx_inline as `inline` itself so the unused members do not warn.
 *
 * ngx_http_zstd_hex_nibble() is the filter module's, moved verbatim.
 * ngx_http_zstd_dict_file_read() is the filter module's loop with its
 * two failure arms returning to the caller instead of logging -- the
 * contract the compression branch and the brotli fork already use, so
 * both adopt this file by renaming a call. The module keeps its logging
 * shell around the loop, so its diagnostics are unchanged. The strict
 * walk, ngx_http_zstd_dict_file_open_strict() with
 * ngx_http_zstd_dict_file_check_dir(), is the module's walk with each
 * logged refusal replaced by a code in ngx_http_zstd_dict_walk_t; the
 * module formats the same diagnostics from the code, so the message an
 * operator sees is unchanged and only the directive name in it is per
 * consumer.
 */

#ifndef NGX_HTTP_ZSTD_DICT_FILE_H
#define NGX_HTTP_ZSTD_DICT_FILE_H

#include <stddef.h>
#ifndef NGX_WIN32
#include <sys/types.h>   /* ssize_t */
#endif

#ifndef ngx_inline
#define ngx_inline
#endif


/*
 * One hex digit to its value, either case; 0xff for anything else.
 */
static ngx_inline u_char
ngx_http_zstd_hex_nibble(u_char c)
{
    u_char  lower;

    if (c >= '0' && c <= '9') {
        return (u_char) (c - '0');
    }

    lower = (u_char) (c | 0x20);

    if (lower >= 'a' && lower <= 'f') {
        return (u_char) (lower - 'a' + 10);
    }

    return 0xff;
}


/*
 * Read `size` bytes of a dictionary file into `buf`, or as many as the
 * file holds.
 *
 * Both dictionary loaders (zstd_dict_file and the dcz loader) once
 * issued ONE ngx_read_fd() and treated any short count as fatal. That is
 * wrong twice over:
 *
 *   - read() on a regular file is permitted to return fewer bytes than
 *     requested. It usually does not on a local ext4/xfs file, which is
 *     why the single-read form survived, but it is not a guarantee the
 *     kernel makes. A 9p/drvfs mount (a WSL /mnt/c dictionary, a Plan 9
 *     export) returns a short count on a regular file as normal
 *     behaviour, and a large enough dictionary then fails config load.
 *   - EINTR. A signal delivered mid-read returns early with no bytes
 *     lost and nothing wrong; the caller is expected to reissue. The
 *     master is parsing configuration here, so it is squarely in a
 *     window where signals arrive. This one is independent of the file
 *     system AND of O_NONBLOCK -- clearing that flag (which the opener
 *     does, and should) does not remove it.
 *
 * Loop until the buffer is full, treating a short count as "continue"
 * rather than "fail", and reissue on EINTR. Two outcomes remain for the
 * caller to refuse, and they are reported distinctly because they mean
 * different things to an operator: a read error (the file became
 * unreadable) and early EOF (the file shrank between fstat() and here,
 * so the dictionary on disk is not the dictionary whose size the caller
 * validated and allocated for). Neither may be silently tolerated -- a
 * partially-populated buffer handed to ZSTD_createCDict() is a
 * dictionary made partly of uninitialised heap.
 *
 * Returns the byte count actually read: `size` on success, fewer at
 * EOF, or -1 on a read error with ngx_errno still that of the failing
 * read. Nothing is logged here; the caller knows the path and the
 * directive and formats the diagnostic.
 *
 * Callers have already validated `size` (non-zero, <= MAX_DICT_SIZE) and
 * allocated `buf` for exactly that many bytes.
 */
static ngx_inline ssize_t
ngx_http_zstd_dict_file_read(ngx_fd_t fd, u_char *buf, size_t size)
{
    ssize_t  n;
    size_t   done;

    for (done = 0; done < size; /* void */) {

        n = ngx_read_fd(fd, (void *) (buf + done), size - done);

        if (n < 0) {

#if !(NGX_WIN32)
            /*
             * Interrupted before transferring anything: not an error,
             * reissue. ngx_errno is read immediately so nothing between
             * here and the test can clobber it.
             *
             * POSIX only, and NGX_WIN32 rather than a "does NGX_EINTR
             * exist" test because that is the actual reason: win32's
             * ngx_errno.h defines no NGX_EINTR at all, because ReadFile()
             * on a synchronous handle is not interruptible -- there is no
             * such error to retry. Guarding on the platform says so;
             * guarding on the macro would read as a portability
             * workaround for a value that is merely spelled differently.
             */
            if (ngx_errno == NGX_EINTR) {
                continue;
            }
#endif

            return -1;
        }

        if (n == 0) {
            /*
             * EOF with bytes still owed. Return the partial count and
             * let the caller name the file that changed size under it.
             */
            break;
        }

        done += (size_t) n;
    }

    return (ssize_t) done;
}


/*
 * AT_FDCWD is the portable signal that the POSIX.1-2008 *at() family is
 * available. Where it is absent strict mode has no way to resolve a path
 * component-by-component, and the module fails CLOSED at config load
 * rather than silently degrading to the leaf-only O_NOFOLLOW guarantee
 * it used to give (see ngx_http_zstd_open_dict_file()).
 */
#if !(NGX_WIN32)
#include <fcntl.h>       /* open(), openat(), O_DIRECTORY, O_NOFOLLOW */
#include <sys/stat.h>    /* fstat(), S_IWGRP, S_IWOTH */
#include <unistd.h>      /* geteuid() */
#ifdef AT_FDCWD
#define NGX_HTTP_ZSTD_HAVE_STRICT_WALK  1
#else
#define NGX_HTTP_ZSTD_HAVE_STRICT_WALK  0
#endif
#else
#define NGX_HTTP_ZSTD_HAVE_STRICT_WALK  0
#endif


#if (NGX_HTTP_ZSTD_HAVE_STRICT_WALK)

/*
 * Why the strict walk refused. Every value but OK names one exit of
 * ngx_http_zstd_dict_file_open_strict(); the consumer turns it into a
 * diagnostic with its own directive name, which is the only axis on
 * which the module, the compression branch and the brotli fork ever
 * differed in this code.
 */
typedef enum {
    NGX_HTTP_ZSTD_DICT_WALK_OK = 0,
    NGX_HTTP_ZSTD_DICT_WALK_RELATIVE,        /* not an absolute path */
    NGX_HTTP_ZSTD_DICT_WALK_OPEN_ROOT,       /* open("/") failed: err */
    NGX_HTTP_ZSTD_DICT_WALK_DIRECTORY,       /* names a directory, no leaf */
    NGX_HTTP_ZSTD_DICT_WALK_COMPONENT_LONG,  /* a component >= NGX_MAX_PATH */
    NGX_HTTP_ZSTD_DICT_WALK_DOT,             /* a "." or ".." component */
    NGX_HTTP_ZSTD_DICT_WALK_OPENAT,          /* openat(component) failed: err */
    NGX_HTTP_ZSTD_DICT_WALK_DIR_FSTAT,       /* fstat(directory) failed: err */
    NGX_HTTP_ZSTD_DICT_WALK_DIR_OWNER,       /* directory owner is neither
                                                root nor the loader: uid */
    NGX_HTTP_ZSTD_DICT_WALK_DIR_WRITABLE     /* directory writable by group
                                                or other */
} ngx_http_zstd_dict_walk_rc_t;


/*
 * The walk's report. `component` is the offending path component,
 * NUL-terminated ("/" for the root directory itself), for every code
 * that names one; `err` is the failing call's errno for OPEN_ROOT,
 * OPENAT and DIR_FSTAT, captured before any close() can clobber it;
 * `uid` is the directory's owner for DIR_OWNER. The component buffer
 * doubles as the walk's working copy of the component it is opening --
 * see the note above the copy in the walk -- so it must be NGX_MAX_PATH
 * bytes.
 */
typedef struct {
    ngx_http_zstd_dict_walk_rc_t  rc;
    int                           err;
    uid_t                         uid;
    u_char                        component[NGX_MAX_PATH];
} ngx_http_zstd_dict_walk_t;


/*
 * fstat() one directory fd opened during the strict walk and refuse it
 * under the same rule the leaf ownership/mode checks apply (M4, see
 * ngx_http_zstd_open_dict_file()): owned by neither root nor the
 * loading principal, or writable by group or other.
 *
 * The walk's whole point is to make resolution of the ENTIRE path
 * symlink-free and TOCTOU-safe, not just the leaf -- so a directory
 * component left unvetted is the same class of gap M3 closed for
 * symlinks. A local user who owns, or can write into, an ancestor
 * directory can rename() a root-owned 0644 file into the leaf position
 * and pass both leaf checks while still having fully steered which
 * bytes strict mode loads. Deliberately NO sticky-bit exemption: a
 * sticky world-writable ancestor (a /tmp-style directory) still lets an
 * unprivileged user create the next path component, which is exactly
 * the steering this function exists to refuse.
 *
 * walk->component already names the directory for the consumer's
 * diagnostic ("/" for the root fd, the component bytes otherwise).
 */
static ngx_inline ngx_http_zstd_dict_walk_rc_t
ngx_http_zstd_dict_file_check_dir(int fd, ngx_http_zstd_dict_walk_t *walk)
{
    struct stat  st;

    if (fstat(fd, &st) < 0) {
        walk->err = ngx_errno;
        return NGX_HTTP_ZSTD_DICT_WALK_DIR_FSTAT;
    }

    if (st.st_uid != 0 && st.st_uid != geteuid()) {
        walk->uid = st.st_uid;
        return NGX_HTTP_ZSTD_DICT_WALK_DIR_OWNER;
    }

    if (st.st_mode & (S_IWGRP | S_IWOTH)) {
        return NGX_HTTP_ZSTD_DICT_WALK_DIR_WRITABLE;
    }

    return NGX_HTTP_ZSTD_DICT_WALK_OK;
}


/*
 * Strict-mode component-by-component open (M3).
 *
 * O_NOFOLLOW on the full path guards ONLY the leaf: the kernel resolves
 * every intermediate component normally, so /srv/current/dict.bin with
 * "current" a symlink is followed silently and strict mode selects
 * whatever bytes the symlink's owner points it at -- exactly the
 * release-symlink swap the directive's README warning says strict mode
 * defends against. Walking the path with openat(O_NOFOLLOW|O_DIRECTORY)
 * one component at a time makes an intermediate symlink fail the walk
 * (ELOOP) instead of being traversed, and the leaf is then opened
 * relative to the verified parent fd -- so the whole resolution, not
 * just its last step, is symlink-free and TOCTOU-safe against a
 * component swap racing the walk.
 *
 * Absolute paths only. nginx has already run the config path through
 * ngx_conf_full_name(), so a dictionary path reaching here is absolute;
 * a relative one would have to be resolved against a cwd this function
 * cannot pin, and strict mode fails CLOSED rather than fall back to a
 * whole-path open.
 *
 * Returns the leaf fd, or NGX_INVALID_FILE with walk->rc (and the
 * fields that code uses) saying why; every fd the walk opened along the
 * way is closed before it returns either way. Nothing is logged here.
 */
static ngx_inline ngx_fd_t
ngx_http_zstd_dict_file_open_strict(ngx_str_t *path, int flags,
    ngx_http_zstd_dict_walk_t *walk)
{
    u_char  *p, *start, *end;
    int      fd, next, oflags;

    walk->rc = NGX_HTTP_ZSTD_DICT_WALK_OK;
    walk->err = 0;
    walk->uid = 0;
    walk->component[0] = '/';
    walk->component[1] = '\0';

    if (path->len == 0 || path->data[0] != '/') {
        walk->rc = NGX_HTTP_ZSTD_DICT_WALK_RELATIVE;
        return NGX_INVALID_FILE;
    }

    fd = open("/", O_RDONLY | O_DIRECTORY
#ifdef O_CLOEXEC
              | O_CLOEXEC
#endif
              );
    if (fd < 0) {
        walk->err = ngx_errno;
        walk->rc = NGX_HTTP_ZSTD_DICT_WALK_OPEN_ROOT;
        return NGX_INVALID_FILE;
    }

    /*
     * The root fd is a walked component like any other -- vet it with
     * the same rule before it is trusted as the base of every openat()
     * below. On most systems "/" is root-owned 0755 and this is a
     * no-op; a container or chroot base that fails this is exactly the
     * layout strict mode is meant to refuse.
     */
    walk->rc = ngx_http_zstd_dict_file_check_dir(fd, walk);
    if (walk->rc != NGX_HTTP_ZSTD_DICT_WALK_OK) {
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
            walk->rc = NGX_HTTP_ZSTD_DICT_WALK_DIRECTORY;
            ngx_close_file(fd);
            return NGX_INVALID_FILE;
        }

        for (p = start; p < end && *p != '/'; p++) { /* void */ }

        /*
         * openat() needs a NUL-terminated component. The component is
         * COPIED into the report's buffer rather than NUL-terminated in
         * place: path->data is nginx's own config string, and writing
         * into it -- even a byte restored immediately afterwards -- would
         * mutate shared config memory that other directives and the
         * error log still read. A component longer than the buffer
         * cannot name a file any filesystem will accept, so it is
         * refused rather than silently truncated (truncation would open
         * a DIFFERENT name).
         */
        {
            u_char  *comp = walk->component;
            size_t   complen = (size_t) (p - start);
            int      last;
            u_char  *q;

            if (complen >= sizeof(walk->component)) {
                walk->rc = NGX_HTTP_ZSTD_DICT_WALK_COMPONENT_LONG;
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
             * "." and ".." are refused rather than resolved: ".." would
             * climb back above a component already verified, which
             * makes the walk's guarantee unstatable, and neither has a
             * legitimate place in a deployed dictionary path.
             */
            if (ngx_strcmp(comp, ".") == 0 || ngx_strcmp(comp, "..") == 0) {
                walk->rc = NGX_HTTP_ZSTD_DICT_WALK_DOT;
                ngx_close_file(fd);
                return NGX_INVALID_FILE;
            }

            /*
             * O_CLOEXEC is applied to BOTH arms deliberately. Folding it
             * into the ternary via a bare "#ifdef ... | O_CLOEXEC" would
             * bind it to the else-branch alone by C's precedence rules,
             * silently leaving the leaf fd inheritable across an exec.
             */
            oflags = last ? (flags | O_NOFOLLOW)
                          : (O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
#ifdef O_CLOEXEC
            oflags |= O_CLOEXEC;
#endif

            next = openat(fd, (char *) comp, oflags);

            if (next < 0) {
                /* errno first: the close below is free to clobber it */
                walk->err = ngx_errno;
                walk->rc = NGX_HTTP_ZSTD_DICT_WALK_OPENAT;
                ngx_close_file(fd);
                return NGX_INVALID_FILE;
            }

            ngx_close_file(fd);
            fd = next;

            if (last) {
                return fd;
            }

            /*
             * `next`/`fd` is a directory fd that will be trusted as the
             * base for the next openat() -- vet it before it is used
             * for anything else, same rule as the root fd above.
             */
            walk->rc = ngx_http_zstd_dict_file_check_dir(fd, walk);
            if (walk->rc != NGX_HTTP_ZSTD_DICT_WALK_OK) {
                ngx_close_file(fd);
                return NGX_INVALID_FILE;
            }

            start = p;
        }
    }
}

#endif /* NGX_HTTP_ZSTD_HAVE_STRICT_WALK */


#endif /* NGX_HTTP_ZSTD_DICT_FILE_H */
