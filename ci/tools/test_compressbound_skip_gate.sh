#!/bin/bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Unit fixture for the ZSTD_compressBound() skip gate in
# ngx_http_zstd_filter_module.c's get_buf() -- the
# "#if NGX_MAX_OFF_T_VALUE <= ... && SIZE_MAX >= ..." block
# that decides, at PREPROCESSING time, whether a build is allowed to skip
# the real ZSTD_compressBound() call for a first output buffer whose
# pledged size is already >= the configured buffer size.
#
# WHY THIS EXISTS: the skip is only safe if libzstd's own
# ZSTD_MAX_INPUT_SIZE is provably above every off_t this build can pledge.
# zstd.h defines that constant as size_t-width-dependent:
#
#   #define ZSTD_MAX_INPUT_SIZE \
#       ((sizeof(size_t)==8) ? 0xFF00FF00FF00FF00ULL : 0xFF00FF00U)
#
# so a build with a 32-bit size_t (ILP32) has a MUCH smaller real ceiling
# (0xFF00FF00) than a build with a 64-bit size_t, regardless of what
# off_t's own width is -- an ILP32 target commonly builds with a 64-bit
# off_t (_FILE_OFFSET_BITS=64), so an off_t-only gate is satisfied on a
# platform where the skip is NOT actually safe. This repo builds and
# tests only on LP64 hosts, so the wrong (off_t-only) gate and the
# corrected (off_t AND size_t) gate evaluate IDENTICALLY here -- there is
# no way to observe the difference by just building and testing on this
# host. This fixture evaluates the LITERAL gate expression shipped in
# src/ngx_http_zstd_filter_module.c, extracted verbatim (never
# hand-copied) under substituted NGX_MAX_OFF_T_VALUE / SIZE_MAX
# pairs standing in for the four width combinations a real build can have,
# which is the cheap alternative to standing up an actual cross-compiled
# ILP32 CI leg (out of proportion for this row).
#
# No nginx tree, no libzstd needed: pure preprocessor evaluation.
set -euo pipefail

# ci/tools/ -> ci/ -> repo root.
cd "$(dirname "$0")/../.."

SRC="src/ngx_http_zstd_filter_module.c"
CC="${CC:-cc}"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/zstd-compressbound-gate-unit.XXXXXX")"
trap 'rm -rf "$OUT"' EXIT
mkdir -p "$OUT"

# Locate the gate's #if...#endif verbatim, by its distinctive opening line,
# so a future edit to the comment or the guarded body cannot silently
# desync this fixture from the shipped condition -- only the #if/#endif
# pair itself is extracted.
START_LINE="$(grep -n '^#if NGX_MAX_OFF_T_VALUE <= 0xFF00FF00FF00FF00ULL' "$SRC" \
              | head -1 | cut -d: -f1)"
if [ -z "$START_LINE" ]; then
    echo "FAIL: could not locate the compressBound skip gate's #if in $SRC" >&2
    exit 1
fi

# The matching #endif: the first "#endif" at or after START_LINE whose
# nesting returns to zero. The gate's own block has no nested #if, so the
# first #endif after START_LINE is it.
REL_END="$(tail -n "+${START_LINE}" "$SRC" | grep -n '^#endif' | head -1 | cut -d: -f1)"
if [ -z "$REL_END" ]; then
    echo "FAIL: could not locate the gate's matching #endif in $SRC" >&2
    exit 1
fi
END_LINE=$((START_LINE + REL_END - 1))

sed -n "${START_LINE},${END_LINE}p" "$SRC" > "$OUT/generated_gate.inc"

if ! grep -q 'SIZE_MAX' "$OUT/generated_gate.inc"; then
    echo "FAIL: extracted gate does not reference SIZE_MAX" \
         "-- extraction range wrong, or the gate regressed to the" \
         "off_t-only form this row exists to fix" >&2
    cat "$OUT/generated_gate.inc" >&2
    exit 1
fi
if ! grep -q 'NGX_MAX_OFF_T_VALUE' "$OUT/generated_gate.inc"; then
    echo "FAIL: extracted gate does not reference NGX_MAX_OFF_T_VALUE" \
         "-- extraction range wrong" >&2
    exit 1
fi

# run_case OFF_MAX SIZE_MAX EXPECT_SKIP LABEL
#
# Compile a tiny TU that #defines NGX_MAX_OFF_T_VALUE/SIZE_MAX
# to the given stand-in values (mirroring what auto/types/sizeof would have
# produced for that width), #includes the extracted gate verbatim, and
# reports via a preprocessor #if/#else whether SKIP_TAKEN got defined.
# EXPECT_SKIP is "1" (gate must compile the skip in) or "0" (gate must
# compile out to the always-call path).
run_case() {
    local off_max="$1" size_max="$2" expect="$3" label="$4"
    local tu="$OUT/case.c"

    # Wrap the extracted gate in a function body with stand-in identifiers
    # matching the production call site ((size_t) ctx->pledged_size,
    # buf_size). The extracted text is exactly:
    #
    #   #if COND
    #               if ((size_t) ctx->pledged_size >= buf_size) {
    #                   /* Skip: ... */
    #               } else
    #   #endif
    #
    # so #include-ing it immediately followed by "{ took_call = 1; }"
    # reproduces the production shape "#if ... if (cond) {SKIP} else
    # #endif {CALL}" verbatim: took_call starts 0 and is set to 1 by
    # whichever branch's trailing statement is that block --
    #   * COND false: the whole #if/#else/#endif vanishes, leaving just
    #     the plain "{ took_call = 1; }" -- call always taken.
    #   * COND true and pledged_size >= buf_size: the "if" arm runs (its
    #     body is a comment only) and the "else" -- and therefore the
    #     following block -- is skipped. took_call stays 0: skip taken.
    #   * COND true and pledged_size < buf_size: the "if" arm is skipped,
    #     "else" runs, which is "else { took_call = 1; }" (the following
    #     block is the else-statement) -- call taken, matching the real
    #     ZSTD_compressBound() path.
    cat > "$tu" <<EOF
/* <stddef.h>, not <stdint.h>: only size_t is needed, and per C99/C11
 * <stddef.h> never defines SIZE_MAX itself, so the #define below cannot
 * collide with a real one. Do not switch this to <stdint.h> without
 * dropping the #define -- a live SIZE_MAX would make this a redefinition
 * error under -Werror instead of the intended stand-in. */
#include <stddef.h>

#define NGX_MAX_OFF_T_VALUE  ${off_max}
#define SIZE_MAX ${size_max}

/* Stand-in for the ctx field the real call site reads -- same name, so
 * the #included gate compiles unmodified. */
struct fake_ctx { long long pledged_size; };

static int
gate_took_skip(struct fake_ctx *ctx, size_t buf_size)
{
    int took_call = 0;

    /* When the #if below is false, the whole guarded if/else vanishes and
     * neither ctx nor buf_size is referenced anywhere in this function --
     * that IS the property being tested (the gate compiling out), so
     * silence the resulting -Wunused-parameter rather than weakening it. */
    (void) ctx;
    (void) buf_size;

#include "generated_gate.inc"
    {
        took_call = 1;
    }

    return !took_call;
}

int
main(void)
{
    struct fake_ctx ctx;
    int             took_skip;

    /* pledged_size == buf_size: the exact boundary the real call site's
     * "(size_t) ctx->pledged_size >= buf_size" turns on. Above the
     * boundary is gate-irrelevant (the C comparison itself, not the
     * #if, decides it) -- this fixture is only about whether the #if
     * compiles the fast path in AT ALL for a given width pair. */
    ctx.pledged_size = 1000;
    took_skip = gate_took_skip(&ctx, (size_t) 1000);

    if (took_skip != ${expect}) {
        return 1;
    }

    return 0;
}
EOF

    "$CC" -Wall -Wextra -Werror -O1 -I"$OUT" -o "$OUT/case" "$tu" 2>"$OUT/case.err" \
        || { echo "FAIL: $label did not compile"; cat "$OUT/case.err" >&2; exit 1; }

    if ! "$OUT/case"; then
        echo "FAIL: $label -- gate took the wrong arm (expected skip=${expect})" >&2
        exit 1
    fi

    echo "OK: $label"
}

# Four width combinations an auto/types/sizeof run can actually produce.
#
# NGX_MAX_OFF_T_VALUE stand-ins are the exact values auto/types/sizeof
# emits for 8-byte and 4-byte types (2147483647 / 9223372036854775807LL --
# see auto/types/sizeof). SIZE_MAX stand-ins are the true (unsigned) max
# of an 8-byte or 4-byte size_t (0xFFFFFFFFFFFFFFFFULL /
# 0xFFFFFFFFU) -- NOT nginx's NGX_MAX_SIZE_T_VALUE, which is the signed
# max and is smaller than the 0xFF00FF00FF00FF00 bound on every width
# (see the header comment above); using it would have made this fixture
# assert a gate that can never fire, silently disabling the optimization
# on every platform instead of proving anything width-specific.
#
#   LP64   (8-byte off_t, 8-byte size_t): the common server target.
#          ZSTD_MAX_INPUT_SIZE is the 64-bit constant -> skip is safe.
run_case 9223372036854775807LL 0xFFFFFFFFFFFFFFFFULL 1 \
    "LP64 (8-byte off_t, 8-byte size_t) -- skip compiled IN"

#   ILP32 with 64-bit off_t (_FILE_OFFSET_BITS=64): off_t alone looks
#   64-bit-safe, but size_t is 32-bit, so ZSTD_MAX_INPUT_SIZE is really
#   0xFF00FF00. THIS is the case the false proof got wrong -- the OLD
#   off_t-only gate would have compiled the skip IN here; the corrected
#   gate must compile it OUT.
run_case 9223372036854775807LL 0xFFFFFFFFU 0 \
    "ILP32 + 64-bit off_t (_FILE_OFFSET_BITS=64) -- skip compiled OUT"

#   Plain ILP32 (4-byte off_t, 4-byte size_t): off_t's own range already
#   excludes it (NGX_MAX_OFF_T_VALUE > the 64-bit constant is false only
#   when off_t is 8 bytes) -- also must compile out.
run_case 2147483647 0xFFFFFFFFU 0 \
    "plain ILP32 (4-byte off_t, 4-byte size_t) -- skip compiled OUT"

#   Hypothetical 8-byte off_t with a narrower still-valid size_t is
#   covered by the ILP32+64-bit-off_t case above; a 4-byte off_t can never
#   pair with an 8-byte size_t on any real ABI, so that combination is not
#   modelled here.

echo "OK: compressBound skip gate is size_t-width-correct across all" \
     "modelled platform combinations (extracted from current $SRC," \
     "lines ${START_LINE}-${END_LINE})"
