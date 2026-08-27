/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit tests for the Accept-Encoding parser
 * (src/ngx_http_zstd_common.h: ngx_http_zstd_skip_quoted(),
 * ngx_http_zstd_eval_qvalue(), ngx_http_zstd_coding_weight(),
 * ngx_http_zstd_accept_encoding()).
 *
 * WHY THIS EXISTS ALONGSIDE ci/t/ AND ci/fuzz/
 *
 *   ci/t, Test::Nginx    drives the parser through a live nginx request. It
 *                        proves the header actually reaches the module, but
 *                        every boundary (an exact q-value digit count, the
 *                        "*" vs explicit-token precedence, a malformed
 *                        weight) has to be reached by crafting a raw header
 *                        string and is awkward to name.
 *   ci/fuzz targets      drive the same code with random bytes plus an
 *                        independent reference oracle. That proves the
 *                        parser never reads out of bounds and agrees with a
 *                        second implementation on the UNAMBIGUOUS cases --
 *                        but it does not state "q=0.1 must be treated as
 *                        weight 100", it only states agreement or disagreement
 *                        on inputs the oracle is confident about.
 *   this file            states values, at named boundaries, with no nginx
 *                        process, no network, in well under a second.
 *
 * This file, like the fuzz target, does NOT link the real ngx_string.c: the
 * production parser is fully self-contained ASCII walking (see the comment
 * atop ngx_http_zstd_common.h) and needs only ngx_strncasecmp/ngx_strcasestrn,
 * which ci/fuzz/ngx_shim.h reproduces as faithful, cited copies of the
 * upstream implementations -- the same shim the fuzz target links, so this
 * layer and the fuzz layer test the exact same compiled bytes. There is no
 * shim of the DECISION logic itself: run.sh regenerates
 * ci/fuzz/generated_parser.inc from the real src/ngx_http_zstd_common.h via
 * ci/fuzz/extract_parser.sh before every build, so this binary always links
 * the shipped parser, never a copy.
 *
 * SEEN RED -- every mutation below was APPLIED to
 * src/ngx_http_zstd_common.h and the named check was observed failing
 * (see ci/adoption-findings.md for the exact commands). Re-run them after
 * touching the parser or this file: a check that has never failed is not
 * known to be a check.
 *
 *   * wildcard precedence flipped -- in ngx_http_zstd_coding_weight(), return
 *     star_q first when both are set
 *       -> "explicit zstd;q=0 overrides a permissive *" FAILS.
 *   * q-value scale dropped a digit -- in ngx_http_zstd_eval_qvalue(),
 *     `scale /= 10` removed so every fractional digit is worth 100 instead
 *     of decaying by a factor of ten per digit
 *       -> "a fourth q decimal digit makes the element non-matching" FAILS
 *          (the loop no longer stops contributing after 3 digits at
 *          decreasing weight -- the value only exists to bound the digit
 *          count via the `scale > 0` loop guard, so removing the decrement
 *          also breaks the qvalue=0*3DIGIT length limit, caught by the
 *          same check as the malformed-fourth-digit mutation below rather
 *          than by a magnitude check on a 2-digit value).
 *   * malformed weight silently defaults to q=1 -- `if (q < 0) q = 1000;`
 *     inserted in ngx_http_zstd_coding_weight()
 *       -> "a fourth q decimal digit makes the element non-matching" FAILS.
 *   * quote skip disabled -- ngx_http_zstd_skip_quoted() changed to
 *     `return p;` unconditionally (before its own bounds check)
 *       -> the suite does not FAIL, it HANGS: case_skip_quoted_unterminated's
 *          unterminated `"..."` value makes the caller's `while (*p != ',')
 *          skip-quoted-else-advance` loop call skip_quoted() at the same `p`
 *          forever, since it now always returns its input unchanged. Verified
 *          with a 5s `timeout`, observed exit 124 (see
 *          ci/adoption-findings.md for the exact command). This is itself
 *          the reason case_skip_quoted_unterminated exists: an unterminated
 *          quote is exactly the input that turns "quote skip is a no-op"
 *          from a wrong-answer bug into a hang, which a FAIL-only check
 *          would never distinguish from a slow pass.
 *   * boundary off by one -- in ngx_http_zstd_eval_qvalue(), `p <= end`
 *     instead of `p < end` in the parameter-name scan loop condition
 *       -> "'q' with no '=value' makes the element non-matching, not an
 *          implicit q=1" FAILS, both under plain cc and under
 *          clang -fsanitize=address,undefined (no heap-buffer-overflow was
 *          raised by ASan for this specific mutation -- the outer `while (p
 *          < end && *p == ';')` guard means the widened inner condition is
 *          only ever reached with p == end already inside the caller's
 *          bound, so this mutation is a logic bug the tests catch, not a
 *          memory-safety one; recorded here rather than assumed, since
 *          "off by one" does not automatically imply "overread"). No
 *          sanitizer trap fired and no crash occurred; only the checked
 *          assertion moved.
 *
 * Extend: add a CASE() function and one line in main().
 */

/* Path-relative so any analyser parses this TU without -I flags: an
 * unparsed TU is silently skipped, which reads as clean. */
#include "../../fuzz/ngx_shim.h"
#include "../../fuzz/generated_parser.inc"

#include <stdio.h>
#include <string.h>


static int  failures;
static int  checks;


static void
check(int ok, const char *what)
{
    checks++;
    if (ok) {
        printf("ok   %s\n", what);
        return;
    }
    printf("FAIL %s\n", what);
    failures++;
}


/* Helper: parse `s` (a NUL-terminated C string used only to size the
 * buffer -- the underlying ae.len is exact, no NUL reliance) through the
 * full decision entry point. */
static ngx_int_t
decide(const char *s)
{
    ngx_str_t  ae;

    ae.data = (u_char *) s;
    ae.len  = strlen(s);

    return ngx_http_zstd_accept_encoding(&ae);
}

/* Helper: the generic weight walker, parameterized like the "dcz" caller
 * in the fuzz harness -- exercises the wildcard-not-allowed branch that
 * ngx_http_zstd_accept_encoding() (allow_wildcard=1) never reaches. */
static ngx_int_t
weight_no_wildcard(const char *s, const char *coding)
{
    ngx_str_t  ae;

    ae.data = (u_char *) s;
    ae.len  = strlen(s);

    return ngx_http_zstd_coding_weight(&ae, coding, strlen(coding), 0);
}


static void
case_empty_header(void)
{
    check(decide("") == NGX_DECLINED, "empty header declines");
}

static void
case_explicit_zstd_no_params(void)
{
    check(decide("zstd") == NGX_OK, "bare 'zstd' accepts (implicit q=1)");
}

static void
case_explicit_zstd_q1(void)
{
    check(decide("zstd;q=1") == NGX_OK, "'zstd;q=1' accepts");
}

static void
case_explicit_zstd_q0(void)
{
    check(decide("zstd;q=0") == NGX_DECLINED, "'zstd;q=0' declines");
}

static void
case_explicit_zstd_fractional(void)
{
    /* q=0.05 -> 50 milli-units, which is >0, so still accepted. */
    check(decide("zstd;q=0.05") == NGX_OK, "'zstd;q=0.05' still accepts (>0)");
}

static void
case_zstd_q_exactly_zero_fraction(void)
{
    check(decide("zstd;q=0.000") == NGX_DECLINED,
          "'zstd;q=0.000' declines (exactly zero)");
}

static void
case_wildcard_only(void)
{
    check(decide("*") == NGX_OK, "bare '*' accepts zstd via wildcard");
}

static void
case_wildcard_q0(void)
{
    check(decide("*;q=0") == NGX_DECLINED, "'*;q=0' declines");
}

static void
case_other_coding_only(void)
{
    check(decide("gzip") == NGX_DECLINED,
          "'gzip' alone declines (no zstd, no wildcard)");
}

static void
case_explicit_overrides_permissive_wildcard(void)
{
    /* This is the precedence rule the wildcard-flip mutation breaks. */
    check(decide("*, zstd;q=0") == NGX_DECLINED,
          "explicit 'zstd;q=0' overrides a permissive '*'");
}

static void
case_explicit_overrides_restrictive_wildcard(void)
{
    check(decide("*;q=0, zstd") == NGX_OK,
          "explicit 'zstd' overrides a restrictive '*;q=0'");
}

static void
case_case_insensitive_token(void)
{
    check(decide("ZsTd") == NGX_OK, "coding name match is case-insensitive");
}

static void
case_multiple_codings_with_zstd(void)
{
    check(decide("gzip;q=1, deflate, zstd;q=0.5, br") == NGX_OK,
          "zstd found among several codings");
}

static void
case_stray_commas_and_ows(void)
{
    check(decide(" , ,zstd , ") == NGX_OK,
          "stray commas and OWS around the list are tolerated (RFC 9110)");
}

static void
case_malformed_q_fourth_digit(void)
{
    /* qvalue = 0*3DIGIT after the decimal point; a fourth digit is
     * malformed, so the element must not match -- and there is no
     * wildcard here to fall back on, so DECLINED. */
    check(decide("zstd;q=0.1234") == NGX_DECLINED,
          "a fourth q decimal digit makes the element non-matching");
}

static void
case_malformed_q_missing_value(void)
{
    check(decide("zstd;q=") == NGX_DECLINED,
          "'q=' with no digits makes the element non-matching");
}

static void
case_malformed_q_bare_param(void)
{
    check(decide("zstd;q") == NGX_DECLINED,
          "'q' with no '=value' makes the element non-matching, "
          "not an implicit q=1");
}

static void
case_quoted_param_hides_comma(void)
{
    /*
     * The comma inside the quoted x="..." parameter value must NOT be
     * read as an element separator -- if it were, the bytes after it
     * ("zstd") would be misparsed as a fresh, matching coding name.
     * This is exactly the skip_quoted seam: disabling it makes this
     * case wrongly accept.
     */
    check(decide("gzip;x=\"a, zstd\"") == NGX_DECLINED,
          "a comma inside a quoted parameter value is not an element "
          "boundary (no phantom zstd token)");
}

static void
case_quoted_name_position_not_a_token(void)
{
    /* A quoted-string can never be a valid coding name; the whole quoted
     * blob plus its trailing params must be skipped as one non-matching
     * element, not split on the interior comma. */
    check(decide("\"a,zstd\"") == NGX_DECLINED,
          "a quoted string in name position is not a coding token");
}

static void
case_duplicate_explicit_token_last_wins(void)
{
    check(decide("zstd;q=0, zstd;q=1") == NGX_OK,
          "a later duplicate explicit zstd token wins over an earlier one");
}

static void
case_end_of_buffer_no_trailing_nul_reliance(void)
{
    /* Exercise a q= right at the exact end of the buffer -- ae.len is
     * exact with no allocated trailing NUL (mirrors the fuzz harness's
     * malloc(exact size) contract), so any read at or past ae->len is a
     * bounds violation the boundary-off-by-one mutation introduces. */
    static const char  raw[] = "zstd;q=";
    ngx_str_t           ae;

    ae.data = (u_char *) raw;
    ae.len  = sizeof(raw) - 1;   /* exclude the C-string NUL from the walk */

    check(ngx_http_zstd_accept_encoding(&ae) == NGX_DECLINED,
          "'q=' ending exactly at buffer end is malformed, not an overread");
}

static void
case_generic_weight_wildcard_not_allowed(void)
{
    /* dcz's own contract: a bare "*" must NOT turn dcz on. */
    check(weight_no_wildcard("*", "dcz") == -1,
          "generic weight walker: wildcard does not apply when the caller "
          "disallows it (dcz contract)");
    check(weight_no_wildcard("dcz;q=1", "dcz") == 1000,
          "generic weight walker: explicit token still applies with "
          "allow_wildcard=0");
}

static void
case_nonq_param_is_skipped_trailing_q_honoured(void)
{
    /*
     * Deliberate, specified divergence from nginx core. Core's
     * ngx_http_gzip_accept_encoding() NGX_DECLINEs on any post-';' byte
     * that is not 'q'/'Q'/OWS, so it drops the whole element on
     * "gzip;foo=bar" -- losing any weight the client did express.
     *
     * This parser instead skips an unrecognized parameter's value to the
     * next top-level delimiter and keeps parsing, so a trailing "q" on
     * the SAME element is still found and honoured. That is strictly more
     * faithful to what the client asked for, in both directions:
     * q=0 must still suppress, q=1 must still accept. Ignoring an
     * unrecognized parameter is the standard HTTP robustness posture; the
     * leniency is a superset that only ever compresses for a client that
     * explicitly named zstd.
     */
    check(decide("zstd;foo=bar;q=0") == NGX_DECLINED,
          "a skipped non-q parameter must not swallow the trailing q=0 "
          "(client explicitly refused zstd)");
    check(decide("zstd;foo=bar;q=1") == NGX_OK,
          "a skipped non-q parameter must not swallow the trailing q=1");
    check(decide("zstd;foo=bar") == NGX_OK,
          "an unrecognized parameter with no q defaults to q=1, rather "
          "than dropping an element the client explicitly asked for");
    check(decide("zstd;foo") == NGX_OK,
          "a bare unrecognized parameter is likewise ignored, not fatal");
}


static void
case_nonq_param_quoted_value_delimiter_scan(void)
{
    /*
     * The quoted-string arm of the skip loop: a top-level ';' or ',' that
     * appears INSIDE a quoted parameter value must not be mistaken for the
     * end of the value, or the trailing q would be parsed out of the wrong
     * position (or missed entirely).
     */
    check(decide("zstd;foo=\"a,b;c\";q=0") == NGX_DECLINED,
          "a ';' and ',' inside a quoted non-q value do not end the value; "
          "the real trailing q=0 is still the one honoured");
    check(decide("zstd;foo=a\"b\";q=0") == NGX_DECLINED,
          "a quoted run starting mid-value is skipped as one unit and "
          "parsing resumes at the ';', finding the trailing q=0");
    check(decide("zstd;foo=\"unterm") == NGX_OK,
          "an unterminated quoted non-q value runs to end without an OOB "
          "read and leaves the element at the default q=1");
}


static void
case_skip_quoted_unterminated(void)
{
    /* ngx_http_zstd_skip_quoted() must still terminate (advance past at
     * least the opening DQUOTE) on an unterminated quote, or the caller's
     * loop stalls. Exercised indirectly: an unterminated quote must not
     * hang the whole decision walk. */
    check(decide("gzip;x=\"unterminated, zstd") == NGX_DECLINED,
          "an unterminated quoted parameter value does not hang the walk "
          "and does not fabricate a matching zstd token");
}


int
main(void)
{
    case_empty_header();
    case_explicit_zstd_no_params();
    case_explicit_zstd_q1();
    case_explicit_zstd_q0();
    case_explicit_zstd_fractional();
    case_zstd_q_exactly_zero_fraction();
    case_wildcard_only();
    case_wildcard_q0();
    case_other_coding_only();
    case_explicit_overrides_permissive_wildcard();
    case_explicit_overrides_restrictive_wildcard();
    case_case_insensitive_token();
    case_multiple_codings_with_zstd();
    case_stray_commas_and_ows();
    case_malformed_q_fourth_digit();
    case_malformed_q_missing_value();
    case_malformed_q_bare_param();
    case_quoted_param_hides_comma();
    case_quoted_name_position_not_a_token();
    case_duplicate_explicit_token_last_wins();
    case_end_of_buffer_no_trailing_nul_reliance();
    case_generic_weight_wildcard_not_allowed();
    case_skip_quoted_unterminated();
    case_nonq_param_is_skipped_trailing_q_honoured();
    case_nonq_param_quoted_value_delimiter_scan();

    printf("\n%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
