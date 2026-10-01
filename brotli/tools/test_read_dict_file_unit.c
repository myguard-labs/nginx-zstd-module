/*
 * Unit fixture for ngx_http_brotli_read_dict_file().
 *
 * The helper is `static` inside filter/ngx_http_brotli_filter_module.c, so
 * it cannot be linked from outside that TU. test_read_dict_file_unit.sh
 * extracts it verbatim by line range and #includes the generated file
 * here, so this test always exercises the CURRENT shipped implementation
 * rather than a hand-copied duplicate. (Same technique as the sibling
 * nginx-zstd-module's test_read_dict_file_unit.sh / #195.)
 *
 * WHY A UNIT FIXTURE AND NOT A CONFIG FIXTURE. The behaviours that matter
 * -- short reads resumed, EINTR retried, early EOF still rejected -- are
 * not reachable from a Test::Nginx block: read() on a local ext4/tmpfs
 * regular file never returns a short count, a signal cannot be steered
 * into the master's read window from a config, and shrinking the file
 * between fstat() and read() is a race, not a fixture. A stubbed
 * ngx_read_fd makes each call's return value the test's choice.
 *
 * This helper is COUNT-RETURNING: `size` on a full read, the partial total
 * on early EOF, and -1 on a hard read error.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>   /* ssize_t */

/* --- minimal nginx type/macro surface the extracted function needs --- */

typedef int            ngx_fd_t;
typedef unsigned char  u_char;

#define NGX_EINTR   EINTR
#define ngx_errno   errno

/*
 * The extracted function guards its EINTR retry with #if !(NGX_WIN32).
 * Define it to 0 explicitly: an undefined macro already evaluates to 0 in
 * #if, so this changes nothing, but it makes the POSIX build the stated
 * intent -- and it is the branch the EINTR assertion below exercises.
 */
#define NGX_WIN32 0

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

#include "generated_read_dict_file.inc"

/* --- harness ---------------------------------------------------------- */

static int  failures;

static void
reset(void)
{
    nsteps = 0; step_i = 0; delivered = 0;
}

static void
push(ssize_t n, int err)
{
    steps[nsteps].n = n;
    steps[nsteps].err = err;
    nsteps++;
}

static void
check(const char *name, ssize_t got, ssize_t want)
{
    if (got != want) {
        printf("x %s: rc=%zd want=%zd\n", name, got, want);
        failures++;
        return;
    }
    printf("ok %s\n", name);
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
    u_char   buf[4096];
    ssize_t  rc;

    /* 1. One full read: the ordinary case must still work. */
    reset();
    memset(buf, 0xee, sizeof(buf));
    push(1024, 0);
    rc = ngx_http_brotli_read_dict_file(3, buf, 1024);
    check("single complete read returns size", rc, 1024);
    if (rc == 1024 && !pattern_ok(buf, 1024)) { failures++; }

    /*
     * 2. THE REGRESSION THIS FIX EXISTS FOR. Three short counts that add
     * up to the requested size must be resumed to a full total. The
     * pre-fix code returned 100 here and the caller rejected it.
     */
    reset();
    memset(buf, 0xee, sizeof(buf));
    push(100, 0); push(400, 0); push(524, 0);
    rc = ngx_http_brotli_read_dict_file(3, buf, 1024);
    check("short reads are resumed to full size", rc, 1024);
    if (rc == 1024 && !pattern_ok(buf, 1024)) { failures++; }
    if (rc == 1024 && step_i != 3) {
        printf("x short-read case used %d reads, expected 3\n", step_i);
        failures++;
    }

    /* 3. A single-byte dribble still completes (worst-case chunking). */
    reset();
    memset(buf, 0xee, sizeof(buf));
    push(1, 0); push(1, 0); push(1, 0); push(1, 0); push(1, 0);
    rc = ngx_http_brotli_read_dict_file(3, buf, 5);
    check("one-byte-at-a-time reads complete", rc, 5);
    if (rc == 5 && !pattern_ok(buf, 5)) { failures++; }

    /*
     * 4. EINTR is retried and must NOT consume progress. The interrupt
     * lands BETWEEN two partial reads, the arrangement that catches a
     * retry that restarts at offset 0.
     */
    reset();
    memset(buf, 0xee, sizeof(buf));
    push(600, 0); push(-1, EINTR); push(424, 0);
    rc = ngx_http_brotli_read_dict_file(3, buf, 1024);
    check("EINTR is retried, progress preserved", rc, 1024);
    if (rc == 1024 && !pattern_ok(buf, 1024)) { failures++; }

    /*
     * 5. Early EOF with bytes still owed returns the PARTIAL total (< size)
     * so the caller rejects the truncated file. push(500) then EOF -> 500.
     */
    reset();
    push(500, 0); push(0, 0);
    rc = ngx_http_brotli_read_dict_file(3, buf, 1024);
    check("early EOF returns the partial total", rc, 500);

    /* 6. A hard read error returns -1 immediately (not retried). */
    reset();
    push(500, 0); push(-1, EIO);
    rc = ngx_http_brotli_read_dict_file(3, buf, 1024);
    check("read error returns -1", rc, -1);

    /*
     * 7. Immediate EOF on a size the caller believed non-zero is the
     * "file shrank to nothing between fstat() and read()" case -> 0.
     */
    reset();
    push(0, 0);
    rc = ngx_http_brotli_read_dict_file(3, buf, 1024);
    check("immediate EOF returns 0", rc, 0);

    if (failures) {
        printf("FAILED: %d read_dict_file unit assertion(s) failed\n",
               failures);
        return 1;
    }

    printf("ok all read_dict_file unit assertions passed\n");
    return 0;
}
