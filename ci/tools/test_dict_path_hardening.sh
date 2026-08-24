#!/usr/bin/env bash
#
# Fixture matrix for two G5 hardening rows against zstd_dict_file and
# zstd_dcz_dict_file, both of which route through the shared
# ngx_http_zstd_open_dict_file() helper:
#
#   1. "Reject non-regular dictionary inputs without letting FIFOs block
#      config test/reload" -- neither loader used to test ngx_is_file()
#      before reading. A FIFO opened O_RDONLY blocks the config-parsing
#      master until a writer appears; a directory/device reaches a
#      confusing later error. Every fixture below runs under `timeout`
#      so a regression HANGS THE SCRIPT, not the CI job, and is reported
#      as a failure either way.
#
#   2. "Strict dictionary-path trust policy for privileged reloads" --
#      zstd_dict_strict_path on (default off) refuses a symlink and a
#      group/world-writable target so a less-privileged local writer
#      cannot steer or mutate what the master snapshots on the next
#      reload. A rejected reload (SIGHUP against a mutated dictionary)
#      must leave the OLD cycle serving, not tear the worker down.
#
# Usage: ci/tools/test_dict_path_hardening.sh <nginx-binary> <module-dir>
#
# <module-dir> holds ngx_http_zstd_filter_module.so (and the static
# module, unused here but harmless to have loaded).

set -euo pipefail

NGINX="${1:?usage: test_dict_path_hardening.sh <nginx-binary> <module-dir>}"
MODDIR="${2:?usage: test_dict_path_hardening.sh <nginx-binary> <module-dir>}"

FILTER_MOD="$MODDIR/ngx_http_zstd_filter_module.so"
if [ ! -f "$FILTER_MOD" ]; then
    echo "❌ $FILTER_MOD not found"
    exit 1
fi

WORK="$(mktemp -d)"
cleanup() {
    if [ -n "${NGINX_PID:-}" ]; then
        kill -9 "$NGINX_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/html"

fail=0

# ── nginx -t against one http_config snippet, bounded ────────────────
# Echoes "OK"/"FAIL: <reason>" on stdout. The `timeout` is the control
# for fixture class 1: a regression (no O_NONBLOCK) blocks in open() on
# a FIFO, so this would hang without it rather than merely fail.
conf_test() {
    local snippet="$1"
    cat >"$WORK/conf/nginx.conf" <<EOF
daemon off;
master_process off;
load_module $FILTER_MOD;
error_log $WORK/logs/error.log info;
pid $WORK/logs/nginx.pid;
events { worker_connections 16; }
http {
    access_log off;
$snippet
    server {
        listen 127.0.0.1:18199;
        location / {
            zstd on;
            zstd_min_length 1;
            zstd_types text/plain;
            default_type text/plain;
            return 200 "ok\n";
        }
    }
}
EOF
    if timeout 10 "$NGINX" -t -p "$WORK" -c "$WORK/conf/nginx.conf" \
        >"$WORK/logs/t.out" 2>&1
    then
        echo "OK"
    else
        if [ "$?" -eq 124 ]; then
            echo "FAIL: nginx -t TIMED OUT (hung open — the FIFO-block regression)"
        else
            echo "FAIL: $(tail -3 "$WORK/logs/t.out" | tr '\n' ' ')"
        fi
    fi
}

check() {
    local name="$1" want="$2" got="$3"
    if [ "$want" = "regular" ] && [ "$got" = "OK" ]; then
        echo "✓ $name: OK (expected)"
    elif [ "$want" = "reject" ] && [[ "$got" == FAIL:* ]] && [[ "$got" != *TIMED\ OUT* ]]; then
        echo "✓ $name: rejected cleanly ($got)"
    else
        echo "✗ $name: want=$want got=$got"
        fail=1
    fi
}

# ── Fixture: regular file, must still load ───────────────────────────
# chmod explicit: umask can leave this group-writable (e.g. 0002 ->
# 0664), which would spuriously trip the strict-mode fixtures below
# that are meant to start from a clean, non-writable baseline.
head -c 8192 /dev/urandom | base64 >"$WORK/html/regular.dict"
chmod 0644 "$WORK/html/regular.dict"
r=$(conf_test "    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/regular.dict;")
check "regular file (zstd_dict_file)" regular "$r"

r=$(conf_test "    zstd_dcz_dict_file $WORK/html/regular.dict;")
check "regular file (zstd_dcz_dict_file)" regular "$r"

# ── Fixture: FIFO ─────────────────────────────────────────────────────
mkfifo "$WORK/html/fifo.dict"
r=$(conf_test "    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/fifo.dict;")
check "FIFO (zstd_dict_file)" reject "$r"

r=$(conf_test "    zstd_dcz_dict_file $WORK/html/fifo.dict;")
check "FIFO (zstd_dcz_dict_file)" reject "$r"

# ── Fixture: directory ────────────────────────────────────────────────
mkdir -p "$WORK/html/dir.dict"
r=$(conf_test "    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/dir.dict;")
check "directory (zstd_dict_file)" reject "$r"

r=$(conf_test "    zstd_dcz_dict_file $WORK/html/dir.dict;")
check "directory (zstd_dcz_dict_file)" reject "$r"

# ── Fixture: UNIX domain socket ────────────────────────────────────────
if command -v python3 >/dev/null 2>&1; then
    python3 - "$WORK/html/sock.dict" <<'PYEOF'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sys.argv[1])
PYEOF
    r=$(conf_test "    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/sock.dict;")
    check "socket (zstd_dict_file)" reject "$r"

    r=$(conf_test "    zstd_dcz_dict_file $WORK/html/sock.dict;")
    check "socket (zstd_dcz_dict_file)" reject "$r"
else
    echo "::warning::python3 not found; socket fixture skipped"
fi

# ── Fixture: character device (always present, harmless to open RDONLY) ─
r=$(conf_test "    zstd_dict_file_unsafe on;
    zstd_dict_file /dev/null;")
check "device /dev/null (zstd_dict_file)" reject "$r"

r=$(conf_test "    zstd_dcz_dict_file /dev/null;")
check "device /dev/null (zstd_dcz_dict_file)" reject "$r"

# ── Fixture: symlink, non-strict (default) accepts ────────────────────
ln -s "$WORK/html/regular.dict" "$WORK/html/link.dict"
r=$(conf_test "    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/link.dict;")
check "symlink, strict off / default (zstd_dict_file)" regular "$r"

r=$(conf_test "    zstd_dcz_dict_file $WORK/html/link.dict;")
check "symlink, strict off / default (zstd_dcz_dict_file)" regular "$r"

# ── Fixture: symlink, strict on rejects (the release-symlink escape
#    hatch is validated by the line above: default OFF still follows it) ─
r=$(conf_test "    zstd_dict_strict_path on;
    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/link.dict;")
check "symlink, strict on (zstd_dict_file)" reject "$r"

r=$(conf_test "    zstd_dict_strict_path on;
    zstd_dcz_dict_file $WORK/html/link.dict;")
check "symlink, strict on (zstd_dcz_dict_file)" reject "$r"

# ── Fixture: world-writable regular file, strict on rejects ───────────
cp "$WORK/html/regular.dict" "$WORK/html/writable.dict"
chmod 0666 "$WORK/html/writable.dict"
r=$(conf_test "    zstd_dict_strict_path on;
    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/writable.dict;")
check "world-writable, strict on (zstd_dict_file)" reject "$r"

r=$(conf_test "    zstd_dict_strict_path on;
    zstd_dcz_dict_file $WORK/html/writable.dict;")
check "world-writable, strict on (zstd_dcz_dict_file)" reject "$r"

# ── Regression: zstd_dict_strict_path AFTER the dcz directive must not
#    silently skip the check for a dictionary already loaded by that
#    point. ngx_conf_parse() runs top-to-bottom, so a bare
#    "zstd_dict_strict_path on" placed after zstd_dcz_dict_file used to
#    read the flag as still-unset at load time and treat it as off --
#    the dictionary loaded successfully with no error, which is the
#    same as strict mode being silently ignored. init_main_conf() now
#    rejects this ordering outright (a config-load error naming the
#    file), which is what "reject" below actually verifies -- this is
#    NOT the same case as the strict-on-BEFORE fixtures above, and
#    without this case the ordering hazard has zero coverage.
r=$(conf_test "    zstd_dcz_dict_file $WORK/html/writable.dict;
    zstd_dict_strict_path on;")
check "world-writable, strict on declared AFTER dcz directive (ordering)" reject "$r"

r=$(conf_test "    zstd_dcz_dict_file $WORK/html/link.dict;
    zstd_dict_strict_path on;")
check "symlink, strict on declared AFTER dcz directive (ordering)" reject "$r"

# ── Fixture: same world-writable file, strict off (default) accepts ───
r=$(conf_test "    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/writable.dict;")
check "world-writable, strict off / default (zstd_dict_file)" regular "$r"

# ── Behavior: rejected reload leaves the OLD cycle serving ────────────
# Start nginx on a known-good regular dictionary with strict on, then
# SIGHUP after swapping the path in for a symlink. The reload must be
# refused (error.log line) and the OLD worker must keep answering --
# proving a rejected reload does not tear down the running cycle.
cp "$WORK/html/regular.dict" "$WORK/html/live.dict"
chmod 0644 "$WORK/html/live.dict"
cat >"$WORK/conf/nginx.conf" <<EOF
daemon off;
master_process on;
worker_processes 1;
load_module $FILTER_MOD;
error_log $WORK/logs/error.log info;
pid $WORK/logs/nginx.pid;
events { worker_connections 16; }
http {
    access_log off;
    zstd_dict_strict_path on;
    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/live.dict;
    server {
        listen 127.0.0.1:18198;
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

"$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf" &
NGINX_PID=$!

ready=0
for _ in $(seq 1 100); do
    if curl -fsS -o /dev/null "http://127.0.0.1:18198/" 2>/dev/null; then
        ready=1
        break
    fi
    sleep 0.1
done

if [ "$ready" -ne 1 ]; then
    echo "✗ old-cycle-active fixture: nginx did not start"
    fail=1
else
    # Swap the trusted path for a symlink out from under the running
    # config -- exactly the local-writer scenario the row defends
    # against -- then ask for a reload.
    rm "$WORK/html/live.dict"
    ln -s "$WORK/html/regular.dict" "$WORK/html/live.dict"
    kill -HUP "$NGINX_PID"
    sleep 1

    # O_NOFOLLOW makes the open() itself fail (ELOOP, "Too many levels
    # of symbolic links") before ngx_is_link()'s own message can fire;
    # accept either wording as proof the symlink swap was refused.
    if curl -fsS -o /dev/null "http://127.0.0.1:18198/" 2>/dev/null \
        && grep -qE "is a symlink; refused|levels of symbolic links" \
            "$WORK/logs/error.log"
    then
        echo "✓ old-cycle-active fixture: reload refused, old cycle still serving"
    else
        echo "✗ old-cycle-active fixture: refusal not logged or old cycle stopped answering"
        tail -10 "$WORK/logs/error.log" || true
        fail=1
    fi

    kill -QUIT "$NGINX_PID" 2>/dev/null || true
    wait "$NGINX_PID" 2>/dev/null || true
    NGINX_PID=""
fi

if [ "$fail" -ne 0 ]; then
    echo "❌ dictionary path hardening: one or more fixtures failed"
    exit 1
fi

echo "✓ all dictionary path hardening fixtures passed"
