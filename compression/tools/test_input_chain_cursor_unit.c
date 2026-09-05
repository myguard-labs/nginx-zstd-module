/*
 * Deterministic ownership/ordering oracle for the compression body
 * filter's input cursor (the parent repo's test_input_chain_cursor_unit,
 * re-derived for this module's three extracted helpers). The production
 * functions are included verbatim from generated_input_cursor.inc; only
 * the nginx types and pool operations are shimmed here.
 *
 * This exists because the property it pins is not wire-testable: the
 * retained-before-cursor drain order only matters when NEW input lands
 * while an earlier callback's tail is retained, and no socket-driven
 * test schedules that overlap reliably (a drain-order mutation survived
 * the full suite plus all three proxy tools when the #260 analog
 * landed).
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef intptr_t   ngx_int_t;
typedef uintptr_t  ngx_uint_t;

#define NGX_OK      0
#define NGX_ERROR  -1

typedef struct ngx_buf_s ngx_buf_t;
typedef struct ngx_chain_s ngx_chain_t;
typedef struct ngx_pool_s ngx_pool_t;

struct ngx_buf_s {
    unsigned char  *pos;
    unsigned char  *last;
    unsigned        flush;
    unsigned        last_buf;
    int             id;      /* shim-only: consumption-order witness */
};

struct ngx_chain_s {
    ngx_buf_t    *buf;
    ngx_chain_t  *next;
};

struct ngx_pool_s {
    size_t        calls;     /* alloc_chain_link invocations */
    size_t        fail_at;   /* 1-based call that returns NULL; 0 = never */
    size_t        frees;
    ngx_chain_t  *chain;     /* the pool free-chain list (LIFO, like nginx) */
};

typedef struct {
    ngx_chain_t   *in;
    ngx_chain_t  **last_in;
} ngx_http_compression_ctx_t;

typedef struct {
    ngx_pool_t  *pool;
} ngx_http_request_t;

static ngx_chain_t *
ngx_alloc_chain_link(ngx_pool_t *pool)
{
    ngx_chain_t  *cl;

    pool->calls++;
    if (pool->fail_at != 0 && pool->calls == pool->fail_at) {
        return NULL;
    }

    if (pool->chain != NULL) {
        cl = pool->chain;
        pool->chain = cl->next;
        return cl;
    }

    cl = malloc(sizeof(ngx_chain_t));
    if (cl == NULL) {
        abort();
    }
    return cl;
}

static void
ngx_free_chain(ngx_pool_t *pool, ngx_chain_t *cl)
{
    pool->frees++;
    cl->next = pool->chain;   /* the overwrite the last_in fix guards */
    pool->chain = cl;
}

/* Forward declarations matching the production statics. */
static ngx_int_t ngx_http_compression_retain_input(ngx_http_request_t *r,
    ngx_http_compression_ctx_t *ctx, ngx_chain_t *in);
static ngx_buf_t *ngx_http_compression_next_in_buf(
    ngx_http_compression_ctx_t *ctx, ngx_chain_t *in, ngx_uint_t *retained);
static void ngx_http_compression_consume_in_link(ngx_http_request_t *r,
    ngx_http_compression_ctx_t *ctx, ngx_chain_t **in, ngx_uint_t retained);

#include "generated_input_cursor.inc"

static int failures;

static void
check(int ok, const char *what)
{
    if (ok) {
        printf("ok - %s\n", what);
    } else {
        printf("not ok - %s\n", what);
        failures++;
    }
}

static ngx_buf_t *
mkbuf(int id)
{
    ngx_buf_t  *b = calloc(1, sizeof(ngx_buf_t));

    if (b == NULL) {
        abort();
    }
    b->id = id;
    return b;
}

static ngx_chain_t *
mkchain(int first_id, int n)
{
    int           i;
    ngx_chain_t  *head = NULL, **tail = &head, *cl;

    for (i = 0; i < n; i++) {
        cl = malloc(sizeof(ngx_chain_t));
        if (cl == NULL) {
            abort();
        }
        cl->buf = mkbuf(first_id + i);
        cl->next = NULL;
        *tail = cl;
        tail = &cl->next;
    }
    return head;
}

/*
 * Drive the production take/consume pair to exhaustion, recording the
 * consumption order by buf id. Returns the number of links consumed.
 */
static size_t
drain(ngx_http_request_t *r, ngx_http_compression_ctx_t *ctx,
    ngx_chain_t **in, int *order, size_t cap)
{
    size_t       n = 0;
    ngx_uint_t   retained;
    ngx_buf_t   *b;

    while ((b = ngx_http_compression_next_in_buf(ctx, *in, &retained))
           != NULL)
    {
        if (n < cap) {
            order[n] = b->id;
        }
        n++;
        ngx_http_compression_consume_in_link(r, ctx, in, retained);
        if (n > 100000) {   /* runaway backstop, far above any scenario */
            check(0, "drain did not terminate");
            return n;
        }
    }
    return n;
}

int
main(void)
{
    printf("1..25\n");   /* CodeRabbit round 5: 25 check() calls, not 24 */

    /* ── 1: retained drains BEFORE the cursor, in order ──────────────── */
    {
        ngx_pool_t                  pool = {0, 0, 0, NULL};
        ngx_http_request_t          r = { &pool };
        ngx_http_compression_ctx_t  ctx;
        ngx_chain_t                *retained_src, *cursor;
        int                         order[8] = {0};
        size_t                      n;

        ctx.in = NULL;
        ctx.last_in = &ctx.in;
        retained_src = mkchain(1, 2);                 /* R1 R2 */
        check(ngx_http_compression_retain_input(&r, &ctx, retained_src)
              == NGX_OK, "seed retention succeeds");
        cursor = mkchain(10, 2);                      /* C10 C11 */

        n = drain(&r, &ctx, &cursor, order, 8);
        check(n == 4, "all four links consumed");
        check(order[0] == 1 && order[1] == 2
              && order[2] == 10 && order[3] == 11,
              "retained links drained before the cursor, both in order");
        check(pool.frees == 2,
              "exactly the two retained (pool-owned) links were freed");
        check(ctx.in == NULL && ctx.last_in == &ctx.in,
              "retained queue empty with last_in re-pointed at the head");
        check(cursor == NULL, "the cursor advanced to its end");
    }

    /* ── 2: cursor-only fast path allocates nothing ──────────────────── */
    {
        ngx_pool_t                  pool = {0, 0, 0, NULL};
        ngx_http_request_t          r = { &pool };
        ngx_http_compression_ctx_t  ctx;
        ngx_chain_t                *cursor, *keep;
        int                         order[8] = {0};
        size_t                      n;

        ctx.in = NULL;
        ctx.last_in = &ctx.in;
        cursor = mkchain(20, 3);
        keep = cursor;

        n = drain(&r, &ctx, &cursor, order, 8);
        check(n == 3, "three cursor links consumed");
        check(pool.calls == 0 && pool.frees == 0,
              "fast path made zero link allocations and zero frees");
        check(keep->next != NULL && keep->next->next != NULL,
              "caller-owned links were never modified, only walked");
    }

    /* ── 3: retain_input copies the tail -- links copied, bufs shared ── */
    {
        ngx_pool_t                  pool = {0, 0, 0, NULL};
        ngx_http_request_t          r = { &pool };
        ngx_http_compression_ctx_t  ctx;
        ngx_chain_t                *cursor;

        ctx.in = NULL;
        ctx.last_in = &ctx.in;
        cursor = mkchain(30, 2);

        check(ngx_http_compression_retain_input(&r, &ctx, cursor) == NGX_OK,
              "tail retention succeeds");
        check(pool.calls == 2, "one pool link per retained buffer");
        check(ctx.in != NULL && ctx.in != cursor
              && ctx.in->next != cursor->next,
              "retained links are pool copies, not the caller's links");
        check(ctx.in->buf == cursor->buf
              && ctx.in->next->buf == cursor->next->buf,
              "the BUFFERS are shared (request lifetime), never copied");
        check(ctx.last_in == &ctx.in->next->next,
              "last_in tracks the new tail");
    }

    /* ── 4: retention APPENDS behind an earlier callback's tail ──────── */
    {
        ngx_pool_t                  pool = {0, 0, 0, NULL};
        ngx_http_request_t          r = { &pool };
        ngx_http_compression_ctx_t  ctx;
        ngx_chain_t                *first, *second, *cursor = NULL;
        int                         order[8] = {0};
        size_t                      n;

        ctx.in = NULL;
        ctx.last_in = &ctx.in;
        first = mkchain(40, 1);
        second = mkchain(41, 2);
        check(ngx_http_compression_retain_input(&r, &ctx, first) == NGX_OK
              && ngx_http_compression_retain_input(&r, &ctx, second)
                 == NGX_OK,
              "two retention rounds succeed");

        n = drain(&r, &ctx, &cursor, order, 8);
        check(n == 3 && order[0] == 40 && order[1] == 41 && order[2] == 42,
              "generations drain FIFO -- append, never prepend");
    }

    /* ── 5: allocation failure mid-retention ─────────────────────────── */
    {
        ngx_pool_t                  pool = {0, 2, 0, NULL};   /* 2nd fails */
        ngx_http_request_t          r = { &pool };
        ngx_http_compression_ctx_t  ctx;
        ngx_chain_t                *cursor, *keep;

        ctx.in = NULL;
        ctx.last_in = &ctx.in;
        cursor = mkchain(50, 3);
        keep = cursor;

        check(ngx_http_compression_retain_input(&r, &ctx, cursor)
              == NGX_ERROR, "mid-chain allocation failure reports NGX_ERROR");
        check(ctx.in != NULL && ctx.in->buf->id == 50
              && ctx.in->next == NULL,
              "the link copied before the failure stays on ctx->in "
              "(terminal path, never resumed)");
        check(keep->next != NULL && keep->next->buf->id == 51,
              "the caller-owned chain is unmodified by the failure");
    }

    /* ── 6: long-chain retention and drain keep last_in coherent ─────── */
    {
        enum { N = 512 };
        ngx_pool_t                  pool = {0, 0, 0, NULL};
        ngx_http_request_t          r = { &pool };
        ngx_http_compression_ctx_t  ctx;
        ngx_chain_t                *cursor = NULL, *big;
        int                         order[4] = {0};
        size_t                      n;

        ctx.in = NULL;
        ctx.last_in = &ctx.in;
        big = mkchain(0, N);
        check(ngx_http_compression_retain_input(&r, &ctx, big) == NGX_OK,
              "512-link retention succeeds");
        n = drain(&r, &ctx, &cursor, order, 4);
        check(n == N && pool.frees == N,
              "512 links drained and every pool-owned link freed");
        check(ctx.last_in == &ctx.in,
              "last_in re-pointed at the head after the final free");
    }

    /* ── 7: freed links are REUSED by the next retention ─────────────── */
    {
        ngx_pool_t                  pool = {0, 0, 0, NULL};
        ngx_http_request_t          r = { &pool };
        ngx_http_compression_ctx_t  ctx;
        ngx_chain_t                *cursor = NULL, *a, *b2;
        int                         order[8] = {0};
        ngx_chain_t                *recycled;

        ctx.in = NULL;
        ctx.last_in = &ctx.in;
        a = mkchain(60, 2);
        check(ngx_http_compression_retain_input(&r, &ctx, a) == NGX_OK,
              "first retention succeeds");
        drain(&r, &ctx, &cursor, order, 8);
        recycled = pool.chain;
        check(recycled != NULL, "drained links landed on the pool free list");

        b2 = mkchain(70, 1);
        check(ngx_http_compression_retain_input(&r, &ctx, b2) == NGX_OK
              && ctx.in == recycled,
              "the next retention reuses the freed link, not fresh memory");
        drain(&r, &ctx, &cursor, order, 8);
    }

    if (failures) {
        printf("# %d failure(s)\n", failures);
        return 1;
    }
    return 0;
}
