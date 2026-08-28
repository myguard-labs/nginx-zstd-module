/*
 * Unit fixture for ngx_http_zstd_release_cctx().
 *
 * The function is `static` inside src/ngx_http_zstd_filter_module.c, so it
 * cannot be linked from outside that TU. test_release_cctx_unit.sh extracts
 * it verbatim by line range (the repo's established precedent -- see
 * test_freecctxparams_unit.sh and test_read_dict_file_unit.sh) and
 * #includes the generated file here, so this test always exercises the
 * CURRENT shipped implementation rather than a hand-copied duplicate.
 *
 * THE DEFECT CLASS THIS GUARDS. release_cctx() resets the slot's context
 * with ZSTD_CCtx_reset(ZSTD_reset_session_only) before returning it to the
 * ring. If that reset fails and the slot is handed back with slot->busy
 * cleared anyway, the slot is "poisoned": it looks reusable (cctx != NULL,
 * busy == 0) to ngx_http_zstd_acquire_cctx()'s profile-match walk, gets
 * lent out again, and the borrower's own full reset in
 * ngx_http_zstd_filter_init_cctx() fails too -- forever, since nothing
 * ever clears the underlying wedged state. The fix must instead retire the
 * slot on a release-time reset failure: free the context and null it out,
 * landing on cctx == NULL && busy == 0, the exact pair
 * ngx_http_zstd_acquire_cctx() already treats as "empty AND not busy" ->
 * re-seedable via ZSTD_createCCtx().
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

/* --- minimal nginx type/macro surface the extracted function needs ----- */

typedef unsigned long   ngx_uint_t;

#define NGX_LOG_ALERT   3

/* Stand-ins for the two nginx globals the extracted function references
 * outside a request (release_cctx only receives a slot pointer, not r). */
typedef struct { int unused; } ngx_log_t;
typedef struct { ngx_log_t *log; } ngx_cycle_t;

static ngx_log_t    fake_log;
static ngx_cycle_t  fake_cycle = { &fake_log };
static ngx_cycle_t *ngx_cycle = &fake_cycle;

/*
 * Diagnostics are counted, not printed: the assertions below care that a
 * retirement is REPORTED (the shipped code always does on that exit), not
 * about wording. Variadic and ignoring its arguments so any format string
 * the shipped code uses compiles unchanged.
 */
static int   log_calls;
static int   log_level_seen;
static void
ngx_log_error(int level, ngx_log_t *log, int err, const char *fmt, ...)
{
    (void) log; (void) err; (void) fmt;
    log_calls++;
    log_level_seen = level;
}

/* --- real zstd.h for types/macros/enum only; every ZSTD_* function below
 * is faked in this file, not linked from libzstd. */
#include <zstd.h>

/* --- scripted fake ZSTD_* layer -----------------------------------------
 *
 * ZSTD_CCtx is opaque outside ZSTD_STATIC_LINKING_ONLY (only forward-
 * declared as `struct ZSTD_CCtx_s`), which this fixture does not need or
 * define -- ZSTD_CCtx_reset/ZSTD_freeCCtx are ordinary public API. A plain
 * byte stands in for the real struct; the extracted function only ever
 * holds a pointer to it, so identity -- not contents -- is what "the same
 * cctx" means here.
 */
static char   sentinel_cctx;
static int    reset_should_fail;
static int    reset_calls;
static int    free_calls;
static void  *freed_ptr;

size_t
ZSTD_CCtx_reset(ZSTD_CCtx *cctx, ZSTD_ResetDirective reset)
{
    (void) cctx; (void) reset;
    reset_calls++;
    return reset_should_fail ? (size_t) -1 : 0;
}

size_t
ZSTD_freeCCtx(ZSTD_CCtx *cctx)
{
    if (cctx != NULL) {
        free_calls++;
        freed_ptr = cctx;
    }
    return 0;
}

unsigned
ZSTD_isError(size_t code)
{
    return code == (size_t) -1;
}

const char *
ZSTD_getErrorName(size_t code)
{
    (void) code;
    return "fake-error";
}

#include "generated_release_cctx.inc"

/* --- harness ------------------------------------------------------------ */

static int  failures;

static void
reset_fakes(void)
{
    reset_should_fail = 0;
    reset_calls = 0;
    free_calls = 0;
    freed_ptr = NULL;
    log_calls = 0;
    log_level_seen = 0;
}

/*
 * check(), same shape as test_static_pread_unit.c's helper: one line per
 * assertion, `what` is printed only on failure so a red run names the
 * exact condition that broke rather than requiring the reader to re-derive
 * it from a boolean.
 */
static void
check(const char *name, int cond, const char *what)
{
    if (!cond) {
        printf("\xe2\x9c\x97 %s: %s\n", name, what);
        failures++;
    }
}

int
main(void)
{
    ngx_http_zstd_cctx_slot_t  slot;
    char                        buf[256];

    /*
     * 1. Reset succeeds -- the ordinary path. The slot must stay exactly
     * as it was, still holding its cctx, only busy cleared. This is the
     * BEFORE-and-AFTER-both-pass sanity case: it must never go red on
     * either version of the function, so a red run here would mean the
     * fixture itself, not the fix, is broken.
     */
    reset_fakes();
    memset(&slot, 0, sizeof(slot));
    slot.cctx = (ZSTD_CCtx *) (void *) &sentinel_cctx;
    slot.busy = 1;

    ngx_http_zstd_release_cctx(&slot);

    check("reset succeeds/cctx",
          slot.cctx == (ZSTD_CCtx *) (void *) &sentinel_cctx,
          "slot->cctx changed, want unchanged");
    check("reset succeeds/busy", slot.busy == 0, "slot->busy != 0");
    check("reset succeeds/no-free", free_calls == 0,
          "ZSTD_freeCCtx called on a clean reset -- context must survive");

    /*
     * 2. Reset FAILS -- the defect this fixture exists to catch. This is
     * the assertion that discriminates the unfixed code from the fix: the
     * unfixed function does `(void) ZSTD_CCtx_reset(...)` and unconditionally
     * clears busy, so slot.cctx stays == &sentinel_cctx (non-NULL) with
     * busy == 0 -- exactly the "reusable" state ngx_http_zstd_acquire_cctx()
     * matches on, i.e. the slot is poisoned back into the ring. The fixed
     * function must instead free the context, null slot->cctx, and still
     * clear busy, landing on the "empty AND not busy" pair acquire_cctx()
     * treats as re-seedable -- and it must not double-free or leak: exactly
     * one ZSTD_freeCCtx call, on the same pointer the slot held.
     */
    reset_fakes();
    memset(&slot, 0, sizeof(slot));
    slot.cctx = (ZSTD_CCtx *) (void *) &sentinel_cctx;
    slot.busy = 1;
    reset_should_fail = 1;

    ngx_http_zstd_release_cctx(&slot);

    check("reset fails/cctx-nulled", slot.cctx == NULL,
          "slot->cctx != NULL -- a non-NULL cctx here means the slot is "
          "handed back to the ring in a poisoned, unreset state");
    check("reset fails/busy-cleared", slot.busy == 0,
          "slot->busy != 0 -- a retired slot must still be non-busy so "
          "acquire_cctx() can re-seed it");
    snprintf(buf, sizeof(buf),
             "ZSTD_freeCCtx called %d time(s), want exactly 1 "
             "(0 = leaked context, 2+ = double free)", free_calls);
    check("reset fails/freed-once", free_calls == 1, buf);
    check("reset fails/freed-right-ptr", freed_ptr == (void *) &sentinel_cctx,
          "freed pointer != the slot's cctx");
    check("reset fails/logged", log_calls >= 1,
          "slot retired but no diagnostic logged");
    check("reset fails/log-level", log_level_seen == NGX_LOG_ALERT,
          "logged at the wrong level, want NGX_LOG_ALERT to match the "
          "acquire-path reset-failure log");

    /*
     * 3. NULL slot and NULL slot->cctx -- must not crash and must not
     * touch the fakes. Not the defect under test, but load-bearing for
     * not regressing the existing early-return guard while changing the
     * function around it.
     */
    reset_fakes();
    ngx_http_zstd_release_cctx(NULL);
    check("NULL slot/untouched",
          reset_calls == 0 && free_calls == 0 && log_calls == 0,
          "NULL slot touched a fake -- the early return regressed");

    reset_fakes();
    memset(&slot, 0, sizeof(slot));
    slot.cctx = NULL;
    slot.busy = 1;
    ngx_http_zstd_release_cctx(&slot);
    check("NULL cctx/untouched",
          reset_calls == 0 && free_calls == 0 && log_calls == 0,
          "NULL slot->cctx touched a fake -- the early return regressed");
    check("NULL cctx/busy-unchanged", slot.busy == 1,
          "busy changed on an empty slot -- an empty slot is never a live "
          "loan");

    if (failures) {
        printf("\xe2\x9d\x8c %d release_cctx unit assertion(s) failed\n",
               failures);
        return 1;
    }

    printf("\xe2\x9c\x93 all release_cctx unit assertions passed\n");
    return 0;
}
