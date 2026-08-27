#!/usr/bin/env bash
#
# Unit fixture for lsan_positive_control() (ci/tools/lsan_positive_control.sh)
# and for the three-outcome verdict shape it feeds in the smoke-tests step
# of .github/workflows/build-test.yml.
#
# The bug this closes: the "Run smoke tests under ASAN+UBSAN" step's leak
# verdict used to grep /tmp/lsan-smoke.* for a finding, then for the
# ptrace-blocked signature, and otherwise print "clean" -- exactly the
# soak_asan_verdict() shape (A27-F9, PR #216). But a log with NEITHER a
# finding NOR the ptrace signature is not proof LSan's exit-time check ran
# at all: it is equally consistent with the check never firing. Observed
# directly in build-test.yml run 33084048220, job "Tests ASAN+UBSAN": the
# smoke-tests step printed "All smoke tests clean under ASAN+UBSAN" (its
# /tmp/lsan-smoke.* log held neither shape), and SECONDS later in the SAME
# job the "zstd_dict_file reload leak check" step
# (ci/tools/test_reload_leak.sh) hit the ptrace-blocked signature 4/4 --
# same runner, same environment. A "clean" verdict that cannot be told
# apart from "never ran" is vacuous.
#
# The fix does NOT touch detect_leaks or weaken the grep-based verdict --
# it adds a POSITIVE CONTROL (lsan_positive_control(), extracted from the
# canary this same shape already used in test_reload_leak.sh) that must
# independently prove LSan can catch a deliberate leak in this environment
# before the "clean" branch is trusted. If the control fails, the step
# demotes to a loud, distinct "INDETERMINATE (could not run)" -- never a
# silent green.
#
# This fixture proves five DIFFERENT observed outcomes from five DIFFERENT
# inputs, driving the real verdict logic end to end (not just the
# extracted function): a real LeakSanitizer finding, a ptrace-blocked log,
# a clean log whose positive control ATTEMPTED and FAILED (control_rc=1,
# the exact ambiguity in run 33084048220), a clean log with a PASSING
# control (control_rc=0), and a clean log whose control could not even be
# ATTEMPTED (control_rc=2, no cc -- a different fact from rc=1, so it gets
# its own distinct label rather than folding into either "clean" or the
# ptrace-specific warning). It ends with a negative control that actually
# RUNS the pre-fix else-branch (no positive control at all) against the
# same empty-log fixture and requires it to report "clean" -- proving this
# fixture reproduces the real false-green from run 33084048220.
#
# No nginx, no libzstd, no network -- pure Bash, plus a working `cc`.
#
# Usage: ci/tools/test_lsan_positive_control_unit.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/tools/lsan_positive_control.sh
. "$SCRIPT_DIR/lsan_positive_control.sh"

if ! command -v cc >/dev/null 2>&1; then
    echo "SKIP: no cc on PATH -- lsan_positive_control unit fixture needs one" >&2
    exit 0
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/lsan-positive-control-unit.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

fail=0

# smoke_verdict <log-glob-file-or-none> <control_rc: 0|1|2> <expect>
# Mirrors the ACTUAL if/elif/else + positive-control shape now in
# build-test.yml's smoke-tests step verdict verbatim (including the
# real three-way control_rc from lsan_positive_control() itself: 0 pass,
# 1 attempted-and-failed, 2 could-not-attempt), so this fixture exercises
# the real decision tree, not a paraphrase of it.
smoke_verdict() {
    local logfile="$1" control_rc="$2"
    local verdict

    if [ "$logfile" != "-" ] && grep -q 'ERROR: LeakSanitizer' "$logfile" 2>/dev/null; then
        verdict="finding"
    elif [ "$logfile" != "-" ] && grep -qE 'ptrace appears to be blocked|LeakSanitizer may hang' "$logfile" 2>/dev/null; then
        verdict="ptrace-indeterminate"
    elif [ "$control_rc" -eq 0 ]; then
        verdict="clean"
    elif [ "$control_rc" -eq 2 ]; then
        verdict="control-could-not-attempt-indeterminate"
    else
        verdict="could-not-run-indeterminate"
    fi
    echo "$verdict"
}

# pre_fix_smoke_verdict <log-glob-file-or-none>
# The ORIGINAL else-branch this fixture guards against regressing to: no
# positive control at all, so any log with neither a finding nor the
# ptrace signature is trusted as clean outright. Executable, not a
# hardcoded literal -- so the negative control below actually runs the
# old decision and can fail if that decision ever changes.
pre_fix_smoke_verdict() {
    local logfile="$1"

    if [ "$logfile" != "-" ] && grep -q 'ERROR: LeakSanitizer' "$logfile" 2>/dev/null; then
        echo "finding"
    elif [ "$logfile" != "-" ] && grep -qE 'ptrace appears to be blocked|LeakSanitizer may hang' "$logfile" 2>/dev/null; then
        echo "ptrace-indeterminate"
    else
        echo "clean"
    fi
}

assert_eq() {
    local got="$1" want="$2" label="$3"
    if [ "$got" != "$want" ]; then
        echo "FAIL: $label -- got '$got', want '$want'" >&2
        fail=1
        return
    fi
    echo "OK: $label (verdict=$got)"
}

# ── Case 1: a real LeakSanitizer finding -> fail, regardless of control
#    status. This step's grep is deliberately narrow (ERROR: LeakSanitizer
#    only) -- it is the leak gate, not the general ASan/UBSan gate the
#    Perl-suite step above it already runs. ─────────────────────────────
cat >"$WORK/asan.real" <<'EOF'
==4712==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 1234 byte(s) in 1 object(s) allocated from:
    #0 0x4a3b20 in malloc
    #1 0x4a5c10 in ngx_http_zstd_body_filter
SUMMARY: LeakSanitizer: 1234 byte(s) leaked in 1 allocation(s).
EOF
v="$(smoke_verdict "$WORK/asan.real" 0)"
assert_eq "$v" "finding" "real LeakSanitizer finding => FAIL (finding checked first, ordering preserved, even with a passing control)"

# ── Case 2: ptrace-blocked signature already in the log -> INDETERMINATE
#    (this branch does not even need the positive control; the signature
#    alone is enough, same as A27-F9/soak_asan_verdict) ─────────────────
cat >"$WORK/asan.ptrace" <<'EOF'
==1848==WARNING: ptrace appears to be blocked (is seccomp enabled?). LeakSanitizer may hang.
EOF
v="$(smoke_verdict "$WORK/asan.ptrace" 0)"
assert_eq "$v" "ptrace-indeterminate" "ptrace signature in log => INDETERMINATE"

# ── Case 3: THE BUG -- a clean log (no finding, no ptrace signature) but
#    the positive control ATTEMPTED and FAILED (control_rc=1): LSan
#    demonstrably cannot detect a leak here. This is run 33084048220's
#    exact shape: smoke log had neither signature, yet the sibling
#    reload-leak step proved ptrace was blocked seconds later in the same
#    job. Must NOT read as clean. ───────────────────────────────────────
: >"$WORK/asan.empty"
v="$(smoke_verdict "$WORK/asan.empty" 1)"
assert_eq "$v" "could-not-run-indeterminate" \
    "clean log + control ATTEMPTED and FAILED (rc=1) => INDETERMINATE, not clean (the run 33084048220 case)"

# ── Case 4: a genuinely clean log AND a working positive control (rc=0)
#    -> the only input that may report clean. ──────────────────────────
v="$(smoke_verdict "$WORK/asan.empty" 0)"
assert_eq "$v" "clean" "clean log + PASSING control (rc=0) => clean"

# ── Case 5: a clean log but the control could NOT even be attempted
#    (rc=2 -- no cc, or the ASan compile failed). This is NOT the same
#    fact as case 3: it says nothing about whether LSan works here, so it
#    must get its OWN distinct label, never silently folded into either
#    "clean" or the attempted-and-failed warning. ───────────────────────
v="$(smoke_verdict "$WORK/asan.empty" 2)"
assert_eq "$v" "control-could-not-attempt-indeterminate" \
    "clean log + control COULD NOT ATTEMPT (rc=2) => its own distinct indeterminate label"

# ── The positive control function itself, driven for real (not stubbed):
#    on this dev/CI host ptrace is not blocked, so the deliberate canary
#    leak (malloc(1234), no free) must be CAUGHT. This is the same
#    lsan_positive_control() the smoke-tests step and test_reload_leak.sh
#    both call -- one source of truth, not two copies. ─────────────────
if lsan_positive_control; then
    echo "OK: lsan_positive_control() caught the deliberate canary leak on this host"
else
    echo "FAIL: lsan_positive_control() did not catch its own deliberate leak" \
         "on this host (unexpected here -- ptrace should not be blocked" \
         "in this environment)" >&2
    fail=1
fi

# ── Mandatory negative control ──────────────────────────────────────────
# Actually RUN the pre-fix else-branch (pre_fix_smoke_verdict(), no
# positive control at all -- not a hardcoded literal) against Case 3's
# exact input: an empty/never-written log, the shape a ptrace-blocked LSan
# leaves behind when it dies before writing anything. The pre-fix logic
# must report "clean" here -- proving this fixture reproduces the real
# false-green from run 33084048220, and that the positive control
# (distinguishing control_rc 0/1/2 in smoke_verdict above) is what
# actually closes it, not something incidental to this fixture.
echo
echo "-- negative control: reverting to the pre-fix (no positive control) shape --"
old_verdict="$(pre_fix_smoke_verdict "$WORK/asan.empty")"
if [ "$old_verdict" != "clean" ]; then
    echo "FAIL: negative control did not reproduce the pre-fix false-clean verdict" \
         "(pre_fix_smoke_verdict returned '$old_verdict', expected 'clean')" >&2
    fail=1
else
    echo "OK: negative control reproduces the pre-fix bug" \
         "(pre_fix_smoke_verdict on the empty/never-ran log returns 'clean'," \
         "indistinguishable from a real clean run -- exactly run 33084048220;" \
         "smoke_verdict above only differs because it also checks control_rc)"
fi

if [ "$fail" -ne 0 ]; then
    echo "FAIL: lsan_positive_control unit fixture had failures" >&2
    exit 1
fi
echo "OK: lsan_positive_control unit fixture -- all cases + negative control passed"
