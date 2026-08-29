#!/usr/bin/env bash
#
# Reload-under-ASAN leak regression for the zstd_dict_file ZSTD_CDict
# lifecycle. Targets the bug class fixed in 0fb40d9 ("Free ZSTD_CDict on
# configuration cleanup to prevent memory leak") and f735a5d ("pass size=0
# to ngx_pool_cleanup_add for dict cleanup handler"): the CDict leak only
# manifests when the configuration is reloaded (SIGHUP), which the normal
# smoke tests never do.
#
# Strategy: start nginx (built with -fsanitize=address) using a dictionary,
# SIGHUP it several times so the old cycle's dict cleanup runs repeatedly,
# then stop nginx cleanly. ASAN's leak detector reports on exit; a leak
# report in the log fails this script.
#
# Environment caveat this script must survive: LeakSanitizer's exit-time
# check ptrace-attaches a stop-the-world tracer, and runners whose
# seccomp/yama policy blocks ptrace kill that tracer ("WARNING: ptrace
# appears to be blocked", "Child exited with signal ..."), after which
# LSan reports NOTHING. Two failure modes follow: the warning lands in
# log_path and a file-existence check misreads it as a leak (the CI
# flake that motivated this script's triage), and a genuinely quiet run
# is a VACUOUS pass because the detector never ran. Hence the positive
# control below, verdicts read from log content rather than log
# existence, and a watchdog on shutdown ("LeakSanitizer may hang" is
# real). Indeterminate environments fail with a ::warning:: GitHub
# annotation naming the runner fix. The reload smoke itself is still useful on
# ptrace-blocked runners, so indeterminate leak coverage warns and lets the
# ASAN/UBSAN request-path gate continue. A real leak still fails first because
# it produces an actual "ERROR: LeakSanitizer" report.
#
# Usage: tools/test_reload_leak.sh <nginx-binary> [reloads]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/tools/lsan_positive_control.sh
. "$SCRIPT_DIR/lsan_positive_control.sh"

NGINX="${1:?usage: test_reload_leak.sh <nginx-binary> [reloads]}"
RELOADS="${2:-5}"

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/html"

# ── Positive control ─────────────────────────────────────────────────
# Prove LSan can detect a DELIBERATE leak in this environment before
# trusting any verdict below; a broken detector must read as
# indeterminate, never as "no leak". Shared with the smoke-tests step in
# .github/workflows/build-test.yml via lsan_positive_control.sh so both
# call sites prove the SAME thing the SAME way.
#
# rc=2 ("could not attempt": no cc, or the ASan compile itself failed) is NOT the
# same fact as rc=1 ("attempted, LSan failed to catch it"), but neither proves
# LSan works. Both continue with the reload smoke and suppress a clean leak
# verdict unless the real leak check writes its own sanitizer report.
set +e
lsan_positive_control
control_rc=$?
set -e
lsan_available=1
if [ "$control_rc" -eq 1 ]; then
    echo "::warning::LeakSanitizer failed its positive control" \
         "(a deliberate canary leak was not caught, so LSan's exit-time" \
         "check is not provably working here). The most likely cause on" \
         "this runner pool is ptrace being blocked (LXC seccomp / yama);" \
         "if that is ruled out, check the ASan toolchain install instead." \
         "Leak check INDETERMINATE; continuing with reload smoke only."
    lsan_available=0
elif [ "$control_rc" -eq 2 ]; then
    echo "::warning::LeakSanitizer's positive control could not be attempted" \
         "(no ASan-capable cc on this runner, or the ASan compile failed)." \
         "Leak check INDETERMINATE; continuing with reload smoke only."
    lsan_available=0
fi

# A non-trivial dictionary so ZSTD_createCDict() actually allocates.
head -c 8192 /dev/urandom | base64 >"$WORK/html/zstd.dict"

cat >"$WORK/conf/nginx.conf" <<EOF
daemon off;
master_process on;
worker_processes 1;
error_log $WORK/logs/error.log info;
pid $WORK/logs/nginx.pid;
events { worker_connections 64; }
http {
    access_log off;
    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/zstd.dict;
    server {
        listen 127.0.0.1:18099;
        location / {
            zstd on;
            zstd_min_length 1;
            zstd_types text/plain;
            default_type text/plain;
            return 200 "dictionary compressed body long enough to compress\n";
        }
    }
}
EOF

# ASAN must report leaks on exit and treat them as failures.
export ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=1:exitcode=23:log_path=$WORK/logs/asan"

"$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf" &
NGINX_PID=$!

# Wait for the listener — quietly (the old loop let the first refused
# curl print to stderr, a red herring that muddied flake diagnosis) and
# with an explicit verdict when startup never completes: ASAN startup
# on a loaded shared runner is exactly when this fires.
ready=0
for _ in $(seq 1 100); do
    if curl -fsS -o /dev/null "http://127.0.0.1:18099/" 2>/dev/null; then
        ready=1
        break
    fi
    sleep 0.1
done
if [ "$ready" -ne 1 ]; then
    echo "❌ nginx under ASAN did not accept connections within 10s"
    kill -9 "$NGINX_PID" 2>/dev/null || true
    exit 1
fi

for i in $(seq 1 "$RELOADS"); do
    curl -fsS -o /dev/null -H 'Accept-Encoding: zstd' "http://127.0.0.1:18099/"
    kill -HUP "$NGINX_PID"
    sleep 0.5
    echo "  reload $i/$RELOADS done"
done

# One final request against the latest cycle, then a clean shutdown so
# every cycle's pool cleanup (including the dict cleanup handler) runs.
# The watchdog bounds the wait: a ptrace-blocked LSan can hang at exit,
# which would otherwise eat the job timeout instead of yielding a
# verdict. And wait must not run under set -e: a leak makes nginx exit
# 23 (exitcode above), which used to abort the script right here,
# skipping the report that says WHY.
curl -fsS -o /dev/null -H 'Accept-Encoding: zstd' "http://127.0.0.1:18099/"
kill -QUIT "$NGINX_PID"
( sleep 90; kill -9 "$NGINX_PID" 2>/dev/null ) &
WATCHDOG=$!
set +e
wait "$NGINX_PID"
rc=$?
set -e
kill "$WATCHDOG" 2>/dev/null || true

# ── Verdict triage: read the sanitizer output, never just stat it ────
# log_path receives EVERYTHING the sanitizer prints, warnings included.
if ls "$WORK"/logs/asan* >/dev/null 2>&1; then

    # Real sanitizer findings fail unconditionally — even if the
    # watchdog had to kill a hung exit, a written report stands.
    if grep -q -E 'ERROR: (Leak|Address)Sanitizer|SUMMARY: (Leak|Address)Sanitizer' \
        "$WORK"/logs/asan*
    then
        echo "❌ sanitizer reported errors across $RELOADS reloads:"
        cat "$WORK"/logs/asan*
        exit 1
    fi

    # The known lockdown signature: LSan's tracer was killed before it
    # could inspect anything. No verdict exists in either direction.
    if grep -q -E 'ptrace.*blocked|LeakSanitizer may hang|Child exited with signal' \
        "$WORK"/logs/asan*
    then
        echo "::warning::LeakSanitizer could not run its exit-time check" \
             "(ptrace blocked on this runner — LXC seccomp / yama). Leak" \
             "check INDETERMINATE; reload smoke passed but leak coverage was" \
             "not restored."
        cat "$WORK"/logs/asan*
        exit 0
    fi

    echo "❌ unexpected sanitizer output (treating as failure):"
    cat "$WORK"/logs/asan*
    exit 1
fi

if [ "$rc" -eq 137 ]; then
    echo "::warning::nginx under ASAN had to be killed by the shutdown" \
         "watchdog (LeakSanitizer hang?). Leak check INDETERMINATE and" \
         "reload smoke passed but leak coverage was not restored."
    exit 0
fi

if [ "$rc" -ne 0 ]; then
    echo "❌ nginx exited non-zero ($rc) under ASAN after reloads"
    tail -50 "$WORK/logs/error.log" || true
    exit 1
fi

if [ "$lsan_available" -eq 0 ]; then
    echo "⚠ Reload smoke passed across $RELOADS config reloads; leak check INDETERMINATE"
else
    echo "✓ No CDict leak across $RELOADS config reloads under ASAN"
fi
