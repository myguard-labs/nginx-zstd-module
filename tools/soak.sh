#!/usr/bin/env bash
#
# Sustained mixed-load soak for the zstd filter. Drives a real nginx
# (ideally an ASAN/UBSAN build, optionally under valgrind) with
# concurrent, varied requests for a fixed duration, then asserts the
# worker survived cleanly: no sanitizer report, no crash, no leak, no
# error-log [alert]/[emerg]. This is the "survives production-shaped
# load" check that synthetic single-shot tests do not give.
#
# Usage:
#   tools/soak.sh <nginx-binary> [duration_seconds] [concurrency]
#   USE_VALGRIND=1 tools/soak.sh <nginx-binary> 120 8
#
# Exit non-zero on ANY of: sanitizer error, valgrind error, nginx
# crash/non-clean exit, error-log alert/emerg, or a corrupted response.

set -euo pipefail

NGINX="${1:?usage: soak.sh <nginx-binary> [duration] [concurrency]}"
DURATION="${2:-60}"
CONC="${3:-8}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/html"

# Mixed payload sizes: tiny (sub-min_length), medium, large (multi-buffer),
# and a chunked/no-Content-Length upstream path.
head -c 50            /dev/urandom | base64 > "$WORK/html/tiny"
head -c 200000        /dev/urandom | base64 > "$WORK/html/medium"
head -c 4000000       /dev/urandom | base64 > "$WORK/html/large"
printf 'AAAAAAAAAA%.0s' $(seq 1 20000)      > "$WORK/html/compressible"

cat > "$WORK/conf/nginx.conf" <<EOF
daemon off;
master_process on;
worker_processes 2;
error_log $WORK/logs/error.log info;
pid $WORK/logs/nginx.pid;
events { worker_connections 256; }
http {
    access_log off;
    zstd_window_log 21;
    server {
        listen 127.0.0.1:18222;
        root $WORK/html;
        default_type text/plain;
        location / {
            zstd on;
            zstd_min_length 100;
            zstd_max_length 8m;
            zstd_types text/plain;
        }
        location /bypass {
            zstd on;
            zstd_min_length 1;
            zstd_types text/plain;
            zstd_bypass \$arg_nozstd;
            alias $WORK/html/medium;
        }
    }
}
EOF

ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=1:abort_on_error=1:exitcode=42:log_path=$WORK/logs/asan"
export ASAN_OPTIONS
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-}:print_stacktrace=1:halt_on_error=1"

RUN=("$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf")
if [ "${USE_VALGRIND:-0}" = "1" ]; then
    SUPP="$(cd "$(dirname "$0")/.." && pwd)/valgrind.suppress"
    RUN=(valgrind --error-exitcode=99 --leak-check=full
         --errors-for-leak-kinds=definite
         --suppressions="$SUPP" --log-file="$WORK/logs/valgrind.%p"
         "${RUN[@]}")
elif [ "${USE_HELGRIND:-0}" = "1" ]; then
    # Data-race / lock-order checking under helgrind (thread pool + any
    # shared state). Reuses the same suppression file.
    SUPP="$(cd "$(dirname "$0")/.." && pwd)/valgrind.suppress"
    RUN=(valgrind --tool=helgrind --error-exitcode=99
         --suppressions="$SUPP" --log-file="$WORK/logs/helgrind.%p"
         "${RUN[@]}")
fi

"${RUN[@]}" &
NGINX_PID=$!

for _ in $(seq 1 100); do
    curl -fsS -o /dev/null "http://127.0.0.1:18222/tiny" 2>/dev/null && break
    sleep 0.1
done

echo "soak: ${DURATION}s, concurrency ${CONC}$( [ "${USE_VALGRIND:-0}" = 1 ] && echo ' (valgrind)'; [ "${USE_HELGRIND:-0}" = 1 ] && echo ' (helgrind)')"
END=$(( $(date +%s) + DURATION ))
fail=0

worker() {
    local wid="$1"
    local paths=(/tiny /medium /large /compressible
                 "/bypass" "/bypass?nozstd=1")
    local i=0
    while [ "$(date +%s)" -lt "$END" ]; do
        p=${paths[$((RANDOM % ${#paths[@]}))]}
        # Vary Accept-Encoding incl. clients that do not support zstd.
        ae=$([ $((RANDOM % 4)) -eq 0 ] && echo "gzip" || echo "zstd")
        i=$((i + 1))
        body="$WORK/r.${wid}.${i}"
        if curl -fsS -H "Accept-Encoding: $ae" \
                "http://127.0.0.1:18222$p" -o "$body" 2>/dev/null; then
            # If it came back zstd-encoded, it must decode cleanly.
            if head -c4 "$body" | od -An -tx1 | grep -q '28 b5 2f fd'; then
                zstd -dq -c "$body" >/dev/null 2>&1 || { echo "BAD zstd $p"; return 1; }
            fi
        fi
        rm -f "$body"
    done
}

pids=()
for w in $(seq 1 "$CONC"); do worker "$w" & pids+=($!); done
for pid in "${pids[@]}"; do wait "$pid" || fail=1; done

# Clean shutdown so all pool cleanups (incl. CCtx/CDict) run.
kill -QUIT "$NGINX_PID" 2>/dev/null || true
wait "$NGINX_PID" 2>/dev/null; rc=$?

problems=0
if ls "$WORK"/logs/asan* >/dev/null 2>&1; then
    echo "FAIL: ASAN/UBSAN report:"; cat "$WORK"/logs/asan*; problems=1
fi
if ls "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* >/dev/null 2>&1; then
    if grep -qE 'ERROR SUMMARY: [1-9]|definitely lost: [1-9]' \
            "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* 2>/dev/null; then
        echo "FAIL: valgrind/helgrind errors:"
        grep -E 'ERROR SUMMARY|definitely lost' \
            "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* 2>/dev/null
        problems=1
    fi
fi
if grep -nE '\[alert\]|\[emerg\]' "$WORK/logs/error.log" 2>/dev/null; then
    echo "FAIL: alert/emerg in error.log"; problems=1
fi
if [ "$fail" -ne 0 ]; then
    echo "FAIL: a worker reported a corrupted response"; problems=1
fi
# QUIT is a clean exit; valgrind uses 99, ASAN 42 on error.
if [ "$rc" -ne 0 ] && [ "$rc" -ne 130 ]; then
    echo "FAIL: nginx exited $rc"; tail -40 "$WORK/logs/error.log" || true
    problems=1
fi

[ "$problems" -ne 0 ] && exit 1
echo "✓ soak clean: ${DURATION}s @ ${CONC} concurrent, no sanitizer/leak/crash"
