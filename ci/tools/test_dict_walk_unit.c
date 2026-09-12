/*
 * Unit fixture for ngx_http_zstd_dict_file_open_strict() and
 * ngx_http_zstd_dict_file_check_dir() -- the strict-mode
 * component-by-component dictionary open in src/ngx_http_zstd_dict_file.h,
 * THE authoritative copy, included directly.
 *
 * WHY A UNIT FIXTURE BESIDE THE CONFIG MATRIX. ci/tools/test_dict_path_hardening.sh
 * and ci/t/02-conf-warn.t drive the walk through nginx against real
 * directories, and they stay the witnesses that the diagnostics an
 * operator sees are unchanged. But several of the walk's exits cannot be
 * staged from a shell: open("/") failing, fstat() failing on a directory
 * the walk just opened, a foreign-owned ancestor (needs root to chown),
 * a component of NGX_MAX_PATH bytes (no filesystem accepts one), and the
 * errno-before-close ordering that the openat() diagnostic depends on.
 * Here the four system calls the walk makes are function-like macros
 * over scripted fakes, so every exit is reached deterministically, the
 * exact openat() flag words are observable, and fd hygiene -- every fd
 * the walk opened is closed exactly once, the returned leaf never -- is
 * asserted on every path.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* --- minimal nginx surface the header needs --------------------------- */

typedef intptr_t   ngx_int_t;
typedef uintptr_t  ngx_uint_t;
typedef int        ngx_fd_t;
typedef unsigned char u_char;
typedef struct { size_t len; u_char *data; } ngx_str_t;

#define NGX_INVALID_FILE  -1
#define NGX_MAX_PATH      4096
#define NGX_EINTR         EINTR
#define ngx_errno         errno
#define ngx_memcpy        memcpy
#define ngx_strcmp(a, b)  strcmp((const char *) (a), (const char *) (b))
#define ngx_read_fd(fd, buf, n)  read(fd, buf, n)

/* --- the fake filesystem ----------------------------------------------
 *
 * A node is one directory entry the walk may openat(): its parent fd,
 * its name, what openat() should return, and what fstat() on the
 * resulting fd reports. fds are handed out from 100 upward so a leaked
 * or double-closed fd is unmistakable.
 */
typedef struct {
    int          parent;      /* the dirfd openat() must be called with */
    const char  *name;
    int          open_errno;  /* 0: opens; otherwise openat() fails so */
    int          fstat_errno; /* 0: fstat works; otherwise it fails so */
    uid_t        uid;
    mode_t       mode;
} node_t;

#define MAX_NODES  16
#define ROOT_FD    100

static node_t   nodes[MAX_NODES];
static int      nnodes;
static int      root_open_errno;   /* open("/") fails with this if set */
static int      root_fstat_errno;
static uid_t    root_uid;
static mode_t   root_mode;
static uid_t    fake_euid = 500;

/*
 * Declared before the fakes: a violated fixture invariant -- open() of
 * anything but "/", openat() through a closed dirfd, close() of an fd
 * that is not open -- must FAIL the run, not just print. The walk
 * ignores close()'s return and check_hygiene() counts only fds still
 * open, so nothing else would notice a double close.
 */
static int      failures;

/* per-fd bookkeeping: fd -> node index (-1 for the root), open state */
static int      fd_node[256];
static int      fd_open[256];
static int      next_fd;
static int      opens, closes;

/* the exact openat() calls, in order, for sequence assertions */
typedef struct { int dirfd; char name[64]; int flags; } call_t;
static call_t   calls[32];
static int      ncalls;

static void
fs_reset(void)
{
    memset(nodes, 0, sizeof(nodes));
    memset(fd_node, 0, sizeof(fd_node));
    memset(fd_open, 0, sizeof(fd_open));
    memset(calls, 0, sizeof(calls));
    nnodes = 0; ncalls = 0; opens = 0; closes = 0;
    next_fd = ROOT_FD;
    root_open_errno = 0; root_fstat_errno = 0;
    root_uid = 0; root_mode = S_IFDIR | 0755;
}

static int
fs_add(int parent, const char *name, uid_t uid, mode_t mode)
{
    node_t  *n = &nodes[nnodes];

    n->parent = parent; n->name = name; n->uid = uid; n->mode = mode;
    return nnodes++;
}

static int
fake_open(const char *name, int flags)
{
    int  fd;

    (void) flags;

    if (strcmp(name, "/") != 0) {
        fprintf(stderr, "FAIL: open(\"%s\"): the walk opens only \"/\"\n", name);
        failures++;
        errno = EINVAL;
        return -1;
    }

    if (root_open_errno) {
        errno = root_open_errno;
        return -1;
    }

    fd = next_fd++;
    fd_node[fd] = -1; fd_open[fd] = 1; opens++;
    return fd;
}

/*
 * Nodes are matched on (dirfd, name). A name with no node under that
 * dirfd is ENOENT, which is also what a component opened from the WRONG
 * parent gets -- so the sequence is checked by construction, not just
 * by the recorded calls.
 */
static int
fake_openat(int dirfd, const char *name, int flags)
{
    int  i, fd;

    if (ncalls < 32) {
        size_t  n = strlen(name);

        /* the record keeps a bounded prefix: the sequence assertions
         * compare short component names, and the NGX_MAX_PATH-byte
         * component is asserted through the walk's own report */
        if (n > sizeof(calls[ncalls].name) - 1) {
            n = sizeof(calls[ncalls].name) - 1;
        }

        calls[ncalls].dirfd = dirfd;
        memcpy(calls[ncalls].name, name, n);
        calls[ncalls].name[n] = '\0';
        calls[ncalls].flags = flags;
    }
    ncalls++;

    if (dirfd < 0 || dirfd >= 256 || !fd_open[dirfd]) {
        fprintf(stderr, "FAIL: openat() on fd %d, which is not open\n", dirfd);
        failures++;
        errno = EBADF;
        return -1;
    }

    for (i = 0; i < nnodes; i++) {
        if (nodes[i].parent == dirfd && strcmp(nodes[i].name, name) == 0) {
            if (nodes[i].open_errno) {
                errno = nodes[i].open_errno;
                return -1;
            }
            fd = next_fd++;
            fd_node[fd] = i; fd_open[fd] = 1; opens++;
            return fd;
        }
    }

    errno = ENOENT;
    return -1;
}

static int
fake_fstat(int fd, struct stat *st)
{
    int  e;

    if (fd < 0 || fd >= 256 || !fd_open[fd]) {
        errno = EBADF;
        return -1;
    }

    memset(st, 0, sizeof(*st));

    if (fd_node[fd] == -1) {
        e = root_fstat_errno;
        st->st_uid = root_uid; st->st_mode = root_mode;
    } else {
        e = nodes[fd_node[fd]].fstat_errno;
        st->st_uid = nodes[fd_node[fd]].uid;
        st->st_mode = nodes[fd_node[fd]].mode;
    }

    if (e) {
        errno = e;
        return -1;
    }

    return 0;
}

static uid_t
fake_geteuid(void)
{
    return fake_euid;
}

/*
 * close() deliberately CLOBBERS errno: the walk must have captured the
 * failing call's errno before closing, or the diagnostic names the wrong
 * error. A double close is a hard failure of the fixture.
 */
static int
fake_close(int fd)
{
    if (fd < 0 || fd >= 256 || !fd_open[fd]) {
        fprintf(stderr, "FAIL: close(%d) on an fd that is not open\n", fd);
        failures++;
        errno = EBADF;
        return -1;
    }

    fd_open[fd] = 0; closes++;
    errno = EBADF;
    return 0;
}

#define open(name, flags)          fake_open(name, flags)
#define openat(dfd, name, flags)   fake_openat(dfd, name, flags)
#define fstat(fd, st)              fake_fstat(fd, st)
#define geteuid()                  fake_geteuid()
#define ngx_close_file(fd)         fake_close(fd)

/*
 * The header's members are `static ngx_inline`; this fixture uses the
 * walk but not the read loop or the hex decoder, so ngx_inline must be a
 * real `inline` here or -Werror=unused-function fires on those.
 */
#define ngx_inline  inline

#include "../../src/ngx_http_zstd_dict_file.h"

/*
 * POSIX only: without the *at() family the header defines no walk and the
 * first call below fails to compile, which is the intended outcome. No
 * #error spells that out, deliberately: the repository's standalone
 * cppcheck pass sees no system headers, so AT_FDCWD is undefined there
 * and a preprocessor error would abort its analysis of this file.
 */

/* --- harness ---------------------------------------------------------- */

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

static void
check_str(const char *name, const char *got, const char *want)
{
    if (strcmp(got, want) != 0) {
        printf("✗ %s: got \"%s\" want \"%s\"\n", name, got, want);
        failures++;
        return;
    }
    printf("✓ %s\n", name);
}

static ngx_str_t
str(const char *s)
{
    ngx_str_t  r;

    r.len = strlen(s);
    r.data = (u_char *) s;
    return r;
}

#define FILE_FLAGS  (O_RDONLY | O_NONBLOCK)

#ifdef O_CLOEXEC
#define CLOEXEC  O_CLOEXEC
#else
#define CLOEXEC  0
#endif

/*
 * Every fd the walk opened must be closed exactly once, except the leaf
 * it returned (which must still be open, and must be the last fd it
 * opened).
 */
static void
check_hygiene(const char *name, ngx_fd_t returned)
{
    int   fd, still_open = 0;
    char  label[128];

    for (fd = ROOT_FD; fd < next_fd; fd++) {
        if (fd_open[fd]) {
            still_open++;
        }
    }

    snprintf(label, sizeof(label), "%s: fds closed except the returned leaf",
             name);
    check(label, still_open, returned == NGX_INVALID_FILE ? 0 : 1);

    if (returned != NGX_INVALID_FILE) {
        snprintf(label, sizeof(label), "%s: the returned fd is the open one",
                 name);
        check(label, fd_open[returned] && returned == next_fd - 1, 1);
    }
}

/* A three-component happy path: / -> srv -> dicts -> a.dict. */
static int
layout_happy(void)
{
    int  srv, dicts;

    fs_reset();
    srv = fs_add(ROOT_FD, "srv", 0, S_IFDIR | 0755);
    (void) srv;
    /* fds are allocated in walk order: root=100, srv=101, dicts=102 */
    dicts = fs_add(101, "dicts", fake_euid, S_IFDIR | 0750);
    (void) dicts;
    fs_add(102, "a.dict", fake_euid, S_IFREG | 0644);
    return 0;
}

int
main(void)
{
    ngx_http_zstd_dict_walk_t  walk;
    ngx_str_t                  path;
    ngx_fd_t                   fd;

    printf("# happy path\n");

    layout_happy();
    path = str("/srv/dicts/a.dict");
    fd = ngx_http_zstd_dict_file_open_strict(&path, FILE_FLAGS, &walk);
    check("absolute three-component path opens the leaf", fd, 103);
    check("rc is OK", walk.rc, NGX_HTTP_ZSTD_DICT_WALK_OK);
    check("three openat() calls", ncalls, 3);
    check("first openat() is relative to the root fd", calls[0].dirfd, ROOT_FD);
    check_str("first component", calls[0].name, "srv");
    check("second openat() is relative to srv's fd", calls[1].dirfd, 101);
    check_str("second component", calls[1].name, "dicts");
    check("leaf openat() is relative to dicts' fd", calls[2].dirfd, 102);
    check_str("leaf component", calls[2].name, "a.dict");
    check("intermediate flags: O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC",
          calls[0].flags, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | CLOEXEC);
    check("leaf flags: caller's flags | O_NOFOLLOW | O_CLOEXEC",
          calls[2].flags, FILE_FLAGS | O_NOFOLLOW | CLOEXEC);
    check("leaf is not opened O_DIRECTORY",
          (calls[2].flags & O_DIRECTORY) != 0, 0);
    check_hygiene("happy path", fd);

    /* repeated separators name the same components */
    layout_happy();
    path = str("//srv///dicts//a.dict");
    fd = ngx_http_zstd_dict_file_open_strict(&path, FILE_FLAGS, &walk);
    check("repeated separators: same leaf", fd, 103);
    check("repeated separators: same three calls", ncalls, 3);
    check_hygiene("repeated separators", fd);

    /* a trailing separator still opens the last component as the leaf */
    layout_happy();
    path = str("/srv/dicts/a.dict/");
    fd = ngx_http_zstd_dict_file_open_strict(&path, FILE_FLAGS, &walk);
    check("trailing separator: last component is the leaf", fd, 103);
    check("trailing separator: leaf opened with the file flags",
          calls[2].flags, FILE_FLAGS | O_NOFOLLOW | CLOEXEC);
    check_hygiene("trailing separator", fd);

    printf("# refusals before any file is touched\n");

    layout_happy();
    path = str("srv/dicts/a.dict");
    fd = ngx_http_zstd_dict_file_open_strict(&path, FILE_FLAGS, &walk);
    check("relative path is refused", fd, NGX_INVALID_FILE);
    check("relative path: rc RELATIVE", walk.rc, NGX_HTTP_ZSTD_DICT_WALK_RELATIVE);
    check("relative path: nothing opened", opens, 0);

    layout_happy();
    path = str("");
    fd = ngx_http_zstd_dict_file_open_strict(&path, FILE_FLAGS, &walk);
    check("empty path is refused as relative", walk.rc,
          NGX_HTTP_ZSTD_DICT_WALK_RELATIVE);
    check("empty path: nothing opened", opens, 0);

    printf("# the root directory\n");

    layout_happy();
    root_open_errno = EACCES;
    path = str("/srv/dicts/a.dict");
    fd = ngx_http_zstd_dict_file_open_strict(&path, FILE_FLAGS, &walk);
    check("open(\"/\") failure is refused", fd, NGX_INVALID_FILE);
    check("open(\"/\") failure: rc OPEN_ROOT", walk.rc,
          NGX_HTTP_ZSTD_DICT_WALK_OPEN_ROOT);
    check("open(\"/\") failure: errno reported", walk.err, EACCES);
    check_hygiene("open root failure", fd);

    layout_happy();
    root_fstat_errno = EIO;
    fd = ngx_http_zstd_dict_file_open_strict(&path, FILE_FLAGS, &walk);
    check("fstat(\"/\") failure: rc DIR_FSTAT", walk.rc,
          NGX_HTTP_ZSTD_DICT_WALK_DIR_FSTAT);
    check("fstat(\"/\") failure: errno captured before close()", walk.err, EIO);
    check_str("fstat(\"/\") failure: component is \"/\"",
              (const char *) walk.component, "/");
    check("fstat(\"/\") failure: no openat() issued", ncalls, 0);
    check_hygiene("fstat root failure", fd);

    layout_happy();
    root_uid = 1000;
    fd = ngx_http_zstd_dict_file_open_strict(&path, FILE_FLAGS, &walk);
    check("foreign-owned root: rc DIR_OWNER", walk.rc,
          NGX_HTTP_ZSTD_DICT_WALK_DIR_OWNER);
    check("foreign-owned root: uid reported", (long) walk.uid, 1000);
    check_str("foreign-owned root: component is \"/\"",
              (const char *) walk.component, "/");
    check_hygiene("foreign-owned root", fd);

    layout_happy();
    root_mode = S_IFDIR | 0777;
    fd = ngx_http_zstd_dict_file_open_strict(&path, FILE_FLAGS, &walk);
    check("world-writable root: rc DIR_WRITABLE", walk.rc,
          NGX_HTTP_ZSTD_DICT_WALK_DIR_WRITABLE);
    check_hygiene("world-writable root", fd);

    layout_happy();
    path = str("/");
    fd = ngx_http_zstd_dict_file_open_strict(&path, FILE_FLAGS, &walk);
    check("\"/\" alone names a directory: rc DIRECTORY", walk.rc,
          NGX_HTTP_ZSTD_DICT_WALK_DIRECTORY);
    check("\"/\" alone: no openat() issued", ncalls, 0);
    check_hygiene("root only", fd);

    layout_happy();
    path = str("///");
    fd = ngx_http_zstd_dict_file_open_strict(&path, FILE_FLAGS, &walk);
    check("\"///\" names a directory: rc DIRECTORY", walk.rc,
          NGX_HTTP_ZSTD_DICT_WALK_DIRECTORY);
    check_hygiene("root only, repeated", fd);

    printf("# components\n");

    layout_happy();
    path = str("/srv/./a.dict");
    fd = ngx_http_zstd_dict_file_open_strict(&path, FILE_FLAGS, &walk);
    check("\".\" component: rc DOT", walk.rc, NGX_HTTP_ZSTD_DICT_WALK_DOT);
    check_str("\".\" component named", (const char *) walk.component, ".");
    check("\".\" component: not passed to openat()", ncalls, 1);
    check_hygiene("dot", fd);

    layout_happy();
    path = str("/srv/../etc/a.dict");
    fd = ngx_http_zstd_dict_file_open_strict(&path, FILE_FLAGS, &walk);
    check("\"..\" component: rc DOT", walk.rc, NGX_HTTP_ZSTD_DICT_WALK_DOT);
    check_str("\"..\" component named", (const char *) walk.component, "..");
    check_hygiene("dotdot", fd);

    {
        static char  longpath[NGX_MAX_PATH + 16];
        size_t       i;

        layout_happy();
        longpath[0] = '/';
        for (i = 1; i < NGX_MAX_PATH + 1; i++) {
            longpath[i] = 'x';
        }
        longpath[NGX_MAX_PATH + 1] = '\0';
        path = str(longpath);
        fd = ngx_http_zstd_dict_file_open_strict(&path, FILE_FLAGS, &walk);
        check("component of NGX_MAX_PATH bytes: rc COMPONENT_LONG", walk.rc,
              NGX_HTTP_ZSTD_DICT_WALK_COMPONENT_LONG);
        check("component of NGX_MAX_PATH bytes: not passed to openat()",
              ncalls, 0);
        check_hygiene("long component", fd);

        /* one byte shorter fits the buffer and reaches openat() (ENOENT) */
        layout_happy();
        longpath[NGX_MAX_PATH] = '\0';
        path = str(longpath);
        fd = ngx_http_zstd_dict_file_open_strict(&path, FILE_FLAGS, &walk);
        check("component of NGX_MAX_PATH-1 bytes reaches openat()", ncalls, 1);
        check("component of NGX_MAX_PATH-1 bytes: rc OPENAT (ENOENT)",
              walk.rc, NGX_HTTP_ZSTD_DICT_WALK_OPENAT);
        check("component of NGX_MAX_PATH-1 bytes: NUL-terminated copy",
              (long) strlen((const char *) walk.component), NGX_MAX_PATH - 1);
        check_hygiene("long component that fits", fd);
    }

    printf("# openat() failures\n");

    layout_happy();
    nodes[1].open_errno = ELOOP;      /* "dicts" is a symlink */
    path = str("/srv/dicts/a.dict");
    fd = ngx_http_zstd_dict_file_open_strict(&path, FILE_FLAGS, &walk);
    check("symlinked intermediate: rc OPENAT", walk.rc,
          NGX_HTTP_ZSTD_DICT_WALK_OPENAT);
    check("symlinked intermediate: ELOOP captured before close()",
          walk.err, ELOOP);
    check_str("symlinked intermediate: component named",
              (const char *) walk.component, "dicts");
    check("symlinked intermediate: walk stopped there", ncalls, 2);
    check_hygiene("symlinked intermediate", fd);

    layout_happy();
    nodes[2].open_errno = ELOOP;      /* the leaf is a symlink */
    fd = ngx_http_zstd_dict_file_open_strict(&path, FILE_FLAGS, &walk);
    check("symlinked leaf: rc OPENAT", walk.rc, NGX_HTTP_ZSTD_DICT_WALK_OPENAT);
    check_str("symlinked leaf: component named",
              (const char *) walk.component, "a.dict");
    check_hygiene("symlinked leaf", fd);

    layout_happy();
    path = str("/srv/dicts/missing.dict");
    fd = ngx_http_zstd_dict_file_open_strict(&path, FILE_FLAGS, &walk);
    check("missing leaf: rc OPENAT", walk.rc, NGX_HTTP_ZSTD_DICT_WALK_OPENAT);
    check("missing leaf: ENOENT reported", walk.err, ENOENT);
    check_hygiene("missing leaf", fd);

    printf("# intermediate directory vetting\n");

    layout_happy();
    nodes[1].mode = S_IFDIR | 0777;
    path = str("/srv/dicts/a.dict");
    fd = ngx_http_zstd_dict_file_open_strict(&path, FILE_FLAGS, &walk);
    check("world-writable intermediate: rc DIR_WRITABLE", walk.rc,
          NGX_HTTP_ZSTD_DICT_WALK_DIR_WRITABLE);
    check_str("world-writable intermediate: component named",
              (const char *) walk.component, "dicts");
    check("world-writable intermediate: leaf never opened", ncalls, 2);
    check_hygiene("world-writable intermediate", fd);

    layout_happy();
    nodes[1].mode = S_IFDIR | S_ISVTX | 0777;
    fd = ngx_http_zstd_dict_file_open_strict(&path, FILE_FLAGS, &walk);
    check("sticky world-writable intermediate: still DIR_WRITABLE", walk.rc,
          NGX_HTTP_ZSTD_DICT_WALK_DIR_WRITABLE);
    check_hygiene("sticky intermediate", fd);

    layout_happy();
    nodes[1].mode = S_IFDIR | 0775;
    fd = ngx_http_zstd_dict_file_open_strict(&path, FILE_FLAGS, &walk);
    check("group-writable intermediate: DIR_WRITABLE", walk.rc,
          NGX_HTTP_ZSTD_DICT_WALK_DIR_WRITABLE);
    check_hygiene("group-writable intermediate", fd);

    layout_happy();
    nodes[0].uid = 1000;
    fd = ngx_http_zstd_dict_file_open_strict(&path, FILE_FLAGS, &walk);
    check("foreign-owned intermediate: rc DIR_OWNER", walk.rc,
          NGX_HTTP_ZSTD_DICT_WALK_DIR_OWNER);
    check("foreign-owned intermediate: uid reported", (long) walk.uid, 1000);
    check_str("foreign-owned intermediate: component named",
              (const char *) walk.component, "srv");
    check("foreign-owned intermediate: walk stopped there", ncalls, 1);
    check_hygiene("foreign-owned intermediate", fd);

    layout_happy();
    nodes[0].uid = fake_euid;         /* owned by the loader: accepted */
    fd = ngx_http_zstd_dict_file_open_strict(&path, FILE_FLAGS, &walk);
    check("loader-owned intermediate is accepted", fd, 103);
    check_hygiene("loader-owned intermediate", fd);

    layout_happy();
    nodes[1].fstat_errno = EIO;
    fd = ngx_http_zstd_dict_file_open_strict(&path, FILE_FLAGS, &walk);
    check("fstat() failure on an intermediate: rc DIR_FSTAT", walk.rc,
          NGX_HTTP_ZSTD_DICT_WALK_DIR_FSTAT);
    check("fstat() failure: errno captured before close()", walk.err, EIO);
    check_str("fstat() failure: component named",
              (const char *) walk.component, "dicts");
    check_hygiene("fstat intermediate failure", fd);

    /*
     * The leaf is NOT vetted by the walk: ownership and mode of the file
     * itself are the caller's fstat()-side checks. A world-writable leaf
     * therefore opens here.
     */
    layout_happy();
    nodes[2].mode = S_IFREG | 0666;
    fd = ngx_http_zstd_dict_file_open_strict(&path, FILE_FLAGS, &walk);
    check("leaf mode is the caller's business: the walk opens it", fd, 103);
    check_hygiene("world-writable leaf", fd);

    if (failures) {
        printf("❌ %d dict walk unit assertion(s) failed\n", failures);
        return 1;
    }

    printf("✓ all dict walk unit assertions passed\n");
    return 0;
}
