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
 * everything below resolves. Outside nginx (the unit fixture), provide
 * before including:
 *     typedef unsigned char  u_char;
 *     typedef int            ngx_fd_t;
 *     #define ngx_read_fd(fd, buf, n)  read(fd, buf, n)   (or a stub)
 *     #define ngx_errno                errno
 *     #define NGX_EINTR                EINTR
 * When nginx has not defined ngx_inline it expands to nothing: the
 * definitions are already `static`, and an empty fallback keeps a
 * conforming C89 compile valid, where `inline` is not a keyword.
 *
 * ngx_http_zstd_hex_nibble() is the filter module's, moved verbatim.
 * ngx_http_zstd_dict_file_read() is the filter module's loop with its
 * two failure arms returning to the caller instead of logging -- the
 * contract the compression branch and the brotli fork already use, so
 * both adopt this file by renaming a call. The module keeps its logging
 * shell around the loop, so its diagnostics are unchanged.
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


#endif /* NGX_HTTP_ZSTD_DICT_FILE_H */
