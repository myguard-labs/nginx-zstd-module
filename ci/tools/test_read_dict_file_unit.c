/*
 * Unit fixture for the dictionary read loop, in both its layers:
 *
 *   - ngx_http_zstd_dict_file_read(), THE authoritative loop in
 *     src/ngx_http_zstd_dict_file.h, included directly (the frame-probe
 *     and ratio fixtures' shape): no extracted or hand-copied duplicate
 *     here to drift from production.
 *   - ngx_http_zstd_read_dict_file(), the filter module's logging shell
 *     around it, still `static` inside src/ngx_http_zstd_filter_module.c
 *     and so extracted verbatim by test_read_dict_file_unit.sh into the
 *     generated file included below. That pins the shell's contract --
 *     NGX_OK only for a complete read, exactly one diagnostic per
 *     failure, the failing read's errno handed to the logger -- and,
 *     because the script refuses an extraction that still contains a
 *     read call, that the module routes through the header.
 *
 * WHY A UNIT FIXTURE AND NOT A CONFIG FIXTURE. The three behaviours that
 * matter here are short reads, EINTR, and early EOF. None is reachable
 * from ci/tools/test_dict_path_hardening.sh: read() on a local tmpfs/ext4
 * regular file never returns a short count, a signal cannot be steered
 * into the master's read window from a shell, and shrinking the file
 * between fstat() and read() is a race, not a fixture. Measured: with the
 * loop reverted to a single read whose short count is fatal, EVERY
 * config-level fixture still passed -- including a 1 MiB dictionary. A
 * config fixture cannot discriminate this change; a stubbed read can.
 *
 * ngx_read_fd is a macro over read(2) in the shipped tree. Here it is a
 * scripted stub so each call's return value and errno are chosen by the
 * test, which is what makes the loop's three exits (continue-on-short,
 * retry-on-EINTR, stop-on-EOF) directly observable.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>   /* ssize_t */
#include <unistd.h>      /* close(), for the walk's contract */

/* --- minimal nginx type/macro surface the header and the shell need --- */

typedef intptr_t   ngx_int_t;
typedef uintptr_t  ngx_uint_t;
typedef int        ngx_fd_t;
typedef unsigned char u_char;

#define NGX_OK        0
#define NGX_ERROR    -1
#define NGX_EINTR     EINTR
#define ngx_errno     errno
#define ngx_read_fd_n "read()"

/* the strict walk's contract: compiled in with the header, unused here */
#define NGX_INVALID_FILE  -1
#define NGX_MAX_PATH      4096
#define ngx_memcpy        memcpy
#define ngx_strcmp(a, b)  strcmp((const char *) (a), (const char *) (b))
#define ngx_close_file    close

typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct { int unused; } ngx_conf_t;

#define NGX_LOG_EMERG 2

/*
 * The loop guards its EINTR retry with #if !(NGX_WIN32). Define it to 0
 * explicitly: an undefined macro already evaluates to 0 in #if, so this
 * changes nothing, but it makes the POSIX build the stated intent rather
 * than a side effect of the macro being absent -- and it is the branch
 * the EINTR assertion below exercises.
 */
#define NGX_WIN32 0

/*
 * Diagnostics are counted, not printed: the assertions below care that
 * the shell REPORTS (exactly once, on the right exit, with the right
 * errno), not about the wording. Variadic and ignoring its format so any
 * message the shipped code uses compiles unchanged.
 */
static int  log_calls;
static int  log_last_err;
static void ngx_conf_log_error(int level, ngx_conf_t *cf, int err,
    const char *fmt, ...)
{
    (void) level; (void) cf; (void) fmt;
    log_calls++;
    log_last_err = err;
}

/* --- scripted ngx_read_fd stub ---------------------------------------
 *
 * Each entry is one call's outcome: n >= 0 is a byte count to deliver
 * (0 = EOF), n < 0 is a failure carrying `err` in errno. The stub fills
 * the destination with a byte pattern derived from the running offset so
 * the test can prove the bytes landed CONTIGUOUSLY and in order -- a loop
 * that re-read into the wrong offset would still satisfy a length check.
 */
typedef struct { ssize_t n; int err; } step_t;

static step_t  steps[16];
static int     nsteps;
static int     step_i;
static size_t  delivered;

static ssize_t
ngx_read_fd(ngx_fd_t fd, void *buf, size_t size)
{
    step_t  *s;
    size_t   i, give;

    (void) fd;

    if (step_i >= nsteps) {
        fprintf(stderr, "FAIL: stub ran out of scripted steps "
                        "(loop called read() more times than expected)\n");
        return -1;
    }

    s = &steps[step_i++];

    if (s->n < 0) {
        errno = s->err;
        return -1;
    }

    give = (size_t) s->n;
    if (give > size) {
        fprintf(stderr, "FAIL: scripted step %d returns %zu for a %zu-byte "
                        "request -- the loop asked for less than it should\n",
                step_i - 1, give, size);
        return -1;
    }

    for (i = 0; i < give; i++) {
        ((u_char *) buf)[i] = (u_char) ((delivered + i) & 0xff);
    }

    delivered += give;
    return (ssize_t) give;
}

/*
 * The header's members are `static ngx_inline`; this fixture uses the
 * loop and the hex decoder but not the strict walk, so ngx_inline must
 * be a real `inline` here or -Werror=unused-function fires on the walk.
 * (The C89 pass in the .sh keeps the empty fallback and allows unused.)
 */
#define ngx_inline  inline

#include "../../src/ngx_http_zstd_dict_file.h"
#include "generated_read_dict_file.inc"

/* --- harness ---------------------------------------------------------- */

static int  failures;

static void
reset(void)
{
    nsteps = 0; step_i = 0; delivered = 0; log_calls = 0; log_last_err = 0;
}

static void
push(ssize_t n, int err)
{
    steps[nsteps].n = n;
    steps[nsteps].err = err;
    nsteps++;
}

static void
check(const char *name, long got, long want)
{
    if (got != want) {
        printf("✗ %s: got %ld want %ld\n", name, got, want);
        failures++;
        return;
    }
    printf("✓ %s\n", name);
}

/* Verify the buffer holds the contiguous 0,1,2,... pattern for `size`. */
static int
pattern_ok(const u_char *buf, size_t size)
{
    size_t  i;

    for (i = 0; i < size; i++) {
        if (buf[i] != (u_char) (i & 0xff)) {
            printf("  buffer diverges at offset %zu: got %u want %u\n",
                   i, buf[i], (unsigned) (i & 0xff));
            return 0;
        }
    }
    return 1;
}

int
main(void)
{
    u_char      buf[4096];
    ngx_str_t   path;
    ngx_conf_t  cf;
    ssize_t     n;
    ngx_int_t   rc;
    int         read_errno;

    path.len = 4;
    path.data = (u_char *) "d.dc";

    printf("# ngx_http_zstd_dict_file_read() -- the header's loop\n");

    /* 1. One full read: the ordinary case must still work. */
    reset();
    memset(buf, 0xee, sizeof(buf));
    push(1024, 0);
    n = ngx_http_zstd_dict_file_read(3, buf, 1024);
    check("single complete read returns size", (long) n, 1024);
    if (n == 1024 && !pattern_ok(buf, 1024)) { failures++; }

    /*
     * 2. THE REGRESSION THE LOOP EXISTS FOR. Three short counts that add
     * up to the requested size must complete. The single-read form
     * stopped at the first partial count.
     */
    reset();
    memset(buf, 0xee, sizeof(buf));
    push(100, 0); push(400, 0); push(524, 0);
    n = ngx_http_zstd_dict_file_read(3, buf, 1024);
    check("short reads are resumed, not fatal", (long) n, 1024);
    if (n == 1024 && !pattern_ok(buf, 1024)) { failures++; }
    check("short-read case issued exactly three reads", step_i, 3);

    /* 3. A single-byte dribble still completes (worst-case chunking). */
    reset();
    memset(buf, 0xee, sizeof(buf));
    push(1, 0); push(1, 0); push(1, 0); push(1, 0); push(1, 0);
    n = ngx_http_zstd_dict_file_read(3, buf, 5);
    check("one-byte-at-a-time reads complete", (long) n, 5);
    if (n == 5 && !pattern_ok(buf, 5)) { failures++; }

    /*
     * 4. EINTR is retried and must NOT lose progress. The interrupt lands
     * BETWEEN two partial reads, which is the arrangement that catches a
     * retry that restarts at offset 0.
     */
    reset();
    memset(buf, 0xee, sizeof(buf));
    push(600, 0); push(-1, EINTR); push(424, 0);
    n = ngx_http_zstd_dict_file_read(3, buf, 1024);
    check("EINTR is retried", (long) n, 1024);
    if (n == 1024 && !pattern_ok(buf, 1024)) { failures++; }
    check("EINTR retry resumed at the right offset (three reads)", step_i, 3);

    /*
     * 5. Early EOF with bytes still owed returns the PARTIAL count, not
     * an error: the caller compares it with the size it validated and
     * names the file that changed under it. The bytes that did land are
     * intact.
     */
    reset();
    memset(buf, 0xee, sizeof(buf));
    push(500, 0); push(0, 0);
    n = ngx_http_zstd_dict_file_read(3, buf, 1024);
    check("early EOF returns the partial count", (long) n, 500);
    if (n == 500 && !pattern_ok(buf, 500)) { failures++; }

    /*
     * 6. A hard read error returns -1 with the failing read's errno
     * intact: the shell logs ngx_errno after the call, so the loop must
     * return without touching it.
     */
    reset();
    errno = 0;
    push(500, 0); push(-1, EIO);
    n = ngx_http_zstd_dict_file_read(3, buf, 1024);
    read_errno = errno;     /* before check() prints: stdio may set errno */
    check("read error returns -1", (long) n, -1);
    check("read error leaves the failing read's errno in place", read_errno,
          EIO);
    check("read error is not retried", step_i, 2);

    /*
     * 7. An immediate EOF on a size the caller believed non-zero is the
     * "file shrank to nothing between fstat() and read()" case.
     */
    reset();
    push(0, 0);
    n = ngx_http_zstd_dict_file_read(3, buf, 1024);
    check("immediate EOF returns 0", (long) n, 0);

    printf("# ngx_http_zstd_hex_nibble() -- the supplied-hash digit decoder\n");

    /*
     * 13. Every byte value against a reference: the sixteen digits in
     * either case decode to their value, everything else -- including the
     * bytes adjacent to each run, and the high half -- to 0xff. This is
     * the decoder that decides whether a supplied hash literal is trusted
     * verbatim, so a stray accepted byte is a silently wrong key.
     */
    {
        unsigned  c, bad = 0;

        for (c = 0; c < 256; c++) {
            unsigned  want = 0xff;

            if (c >= '0' && c <= '9') {
                want = c - '0';
            } else if (c >= 'a' && c <= 'f') {
                want = c - 'a' + 10;
            } else if (c >= 'A' && c <= 'F') {
                want = c - 'A' + 10;
            }

            if (ngx_http_zstd_hex_nibble((u_char) c) != want) {
                if (bad < 5) {
                    printf("  hex_nibble(0x%02x) = 0x%02x, want 0x%02x\n", c,
                           ngx_http_zstd_hex_nibble((u_char) c), want);
                }
                bad++;
            }
        }

        check("hex_nibble decodes all 256 byte values as the reference does",
              (long) bad, 0);
    }

    printf("# ngx_http_zstd_read_dict_file() -- the module's logging shell\n");

    /* 8. A complete read is NGX_OK and logs nothing. */
    reset();
    push(100, 0); push(924, 0);
    rc = ngx_http_zstd_read_dict_file(&cf, 3, &path, buf, 1024);
    check("shell: complete read is NGX_OK", (long) rc, NGX_OK);
    check("shell: complete read logs nothing", log_calls, 0);

    /* 9. EINTR mid-file is transparent to the shell: no diagnostic. */
    reset();
    push(600, 0); push(-1, EINTR); push(424, 0);
    rc = ngx_http_zstd_read_dict_file(&cf, 3, &path, buf, 1024);
    check("shell: EINTR retry is NGX_OK", (long) rc, NGX_OK);
    check("shell: EINTR retry logs nothing", log_calls, 0);

    /* 10. Early EOF is NGX_ERROR with exactly one diagnostic, errno 0. */
    reset();
    push(500, 0); push(0, 0);
    rc = ngx_http_zstd_read_dict_file(&cf, 3, &path, buf, 1024);
    check("shell: early EOF is NGX_ERROR", (long) rc, NGX_ERROR);
    check("shell: early EOF logs exactly once", log_calls, 1);
    check("shell: early EOF is logged without an errno", log_last_err, 0);

    /* 11. A read error is NGX_ERROR, logged once WITH the read's errno. */
    reset();
    push(500, 0); push(-1, EIO);
    rc = ngx_http_zstd_read_dict_file(&cf, 3, &path, buf, 1024);
    check("shell: read error is NGX_ERROR", (long) rc, NGX_ERROR);
    check("shell: read error logs exactly once", log_calls, 1);
    check("shell: read error is logged with the read's errno", log_last_err,
          EIO);

    /* 12. Immediate EOF: the shell reports it like any other short file. */
    reset();
    push(0, 0);
    rc = ngx_http_zstd_read_dict_file(&cf, 3, &path, buf, 1024);
    check("shell: immediate EOF is NGX_ERROR", (long) rc, NGX_ERROR);
    check("shell: immediate EOF logs exactly once", log_calls, 1);

    if (failures) {
        printf("❌ %d read_dict_file unit assertion(s) failed\n", failures);
        return 1;
    }

    printf("✓ all read_dict_file unit assertions passed\n");
    return 0;
}
