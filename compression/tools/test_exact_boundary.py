#!/usr/bin/env python3
"""Pin the FINISH-lands-exactly-at-ob->end boundary deterministically.

The idea (Mark's, inverted): the compressed size of a response cannot
be controlled precisely, but for a DETERMINISTIC input it is a
deterministic value C — and the OUTPUT BUFFER size is an operator
directive. So instead of generating content that hits a fixed
boundary, move the boundary onto the content:

1. Serve a fixed incompressible fixture, small enough that both
   encoders buffer all input through PROCESS and emit the whole
   stream at FINISH (nothing reaches ob before the FINISH op).
2. Measure C with a generous buffer.
3. Restart nginx with per-location ``compression_buffers 2 <B>`` for
   B in {C, C/2 (two exact fills: a full-buffer ship AT the boundary
   mid-op, then done-at-boundary), C-1, C+1, C-2, C+2}.
4. B == C and B == C/2 MUST log the module's witness line
   ("finish landed exactly at buffer end") — the round-1
   double-FINISH corner provably executed — and every case must
   decode byte-exact (zstd's pre-fix symptom was a silently appended
   empty frame; brotli's was a hard error mid-response).

This upgrades what WRINKLES honestly called an unpinnable patrol into
a pinned point, per coding. Requires an nginx built --with-debug with
the compression module compiled in, plus the zstd and brotli CLIs.
"""
from __future__ import annotations

import argparse
import os
import pathlib
import re
import socket
import subprocess
import sys
import tempfile
import time

# small enough that PROCESS emits nothing (zstd buffers ~128 KB
# internally; brotli holds far more than this at q6/lgwin19)
SIZE = 16384

CODINGS = {
    "zstd": {"decode": ["zstd", "-d", "-q", "-c"]},
    "br":   {"decode": ["brotli", "-d", "-c"]},
}

WITNESS = "landed exactly at buffer end"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--nginx-binary", required=True)
    p.add_argument("--port", type=int, default=18193)
    # The sanitizer mode, same contract as test_slow_drain's: at debug
    # log level, stock nginx's OWN logging traps UBSan's
    # nonnull-attribute check on every query-less request
    # (ngx_http_output_filter's "%V?%V" hands ngx_sprintf_str a NULL
    # r->args.data — upstream-nginx work in flight, PRs #1671/#1672
    # and #1679-#1682). At warn the boundary is still FORCED by the
    # measured buffer sizing and the byte-exact decode oracles still
    # gate; only the witness-count assertion is skipped, and the
    # non-sanitized suites job still asserts it.
    p.add_argument("--log-level", choices=("debug", "warn"),
                   default="debug")
    return p.parse_args()


def fixture_bytes(n: int) -> bytes:
    buf = bytearray(n)
    x = (n * 2654435761) & 0xFFFFFFFF
    for i in range(n):
        x = (x * 1103515245 + 12345) & 0xFFFFFFFF
        buf[i] = (x >> 16) & 0xFF
    return bytes(buf)


def wait_port(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"nothing listening on 127.0.0.1:{port}")


def get(port: int, path: str, coding: str, timeout: float = 30.0) -> bytes:
    s = socket.create_connection(("127.0.0.1", port), timeout)
    s.settimeout(timeout)
    s.sendall((f"GET {path} HTTP/1.0\r\nHost: t\r\n"
               f"Accept-Encoding: {coding}\r\n\r\n").encode("latin1"))
    raw = b""
    while True:
        piece = s.recv(65536)
        if not piece:
            break
        raw += piece
    s.close()
    head, _, body = raw.partition(b"\r\n\r\n")
    m = re.search(r"(?im)^content-encoding:\s*(\S+)",
                  head.decode("latin1", "replace"))
    got = m.group(1) if m else None
    if got != coding:
        raise RuntimeError(f"{path}: Content-Encoding {got!r}, "
                           f"wanted {coding!r}")
    return body


def decode(coding: str, blob: bytes) -> bytes:
    r = subprocess.run(CODINGS[coding]["decode"], input=blob,
                       capture_output=True, check=False)
    if r.returncode != 0:
        raise RuntimeError(
            f"{coding} decode failed (truncated/corrupt stream): "
            + r.stderr.decode("utf-8", "replace").strip())
    return r.stdout


def write_conf(root: pathlib.Path, port: int,
               locations: dict[str, tuple[str, int]],
               log_level: str = "debug") -> pathlib.Path:
    """locations: name -> (coding, buffer_size); size 0 = generous."""
    locs = ""
    for name, (coding, bsize) in locations.items():
        bufs = f"compression_buffers 2 {bsize};" if bsize else \
               "compression_buffers 2 1m;"
        locs += f"""        location /{name}/ {{
            alias {root}/html/;
            compression on;
            compression_order {coding};
            compression_http_version 1.0;
            {bufs}
            compression_min_length 1;
            compression_types application/octet-stream;
            gzip_vary on;
        }}
"""
    conf = root / "nginx.conf"
    conf.write_text(f"""worker_processes 1;
error_log {root}/logs/error.log {log_level};
pid {root}/nginx.pid;
events {{ worker_connections 64; }}
http {{
    access_log off;
    default_type application/octet-stream;
    server {{
        listen 127.0.0.1:{port};
{locs}    }}
}}
""", encoding="utf-8")
    return conf


def run_nginx(nginx: pathlib.Path, root: pathlib.Path,
              conf: pathlib.Path) -> subprocess.Popen:
    return subprocess.Popen(
        [str(nginx), "-p", str(root), "-c", str(conf),
         "-g", "daemon off; master_process off;"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def stop_nginx(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=30)


def main() -> int:
    args = parse_args()
    nginx = pathlib.Path(args.nginx_binary)
    if not nginx.exists():
        raise FileNotFoundError(nginx)

    v = subprocess.run([str(nginx), "-V"], capture_output=True, text=True, check=False)
    if "compression" not in v.stderr:
        raise RuntimeError("nginx -V shows no compression module")
    if args.log_level == "debug" and "--with-debug" not in v.stderr:
        raise RuntimeError("the witness is an ngx_log_debug line: this "
                           "tool needs an nginx built --with-debug "
                           "(or --log-level warn to skip the witness)")

    os.umask(0o022)
    with tempfile.TemporaryDirectory(prefix="compression-exact-") as td:
        os.chmod(td, 0o755)
        root = pathlib.Path(td)
        (root / "logs").mkdir()
        (root / "html").mkdir()
        expected = fixture_bytes(SIZE)
        (root / "html" / "fix").write_bytes(expected)

        # ── phase 1: measure C per coding with a generous buffer ────
        conf = write_conf(root, args.port,
                          {name: (name, 0) for name in CODINGS},
                          args.log_level)
        proc = run_nginx(nginx, root, conf)
        c_of: dict[str, int] = {}
        try:
            wait_port(args.port)
            for name in CODINGS:
                body = get(args.port, f"/{name}/fix", name)
                if decode(name, body) != expected:
                    raise RuntimeError(f"{name}: probe decode mismatch")
                c_of[name] = len(body)
                print(f"  {name}: C = {c_of[name]} compressed bytes")
        finally:
            stop_nginx(proc)

        # ── phase 2: park the boundary on C ──────────────────────────
        locations: dict[str, tuple[str, int]] = {}
        exact: list[str] = []
        for name, c in c_of.items():
            cases = {f"{name}-c": c,
                     f"{name}-cm1": c - 1, f"{name}-cp1": c + 1,
                     f"{name}-cm2": c - 2, f"{name}-cp2": c + 2}
            exact.append(f"{name}-c")
            if c % 2 == 0:
                cases[f"{name}-half"] = c // 2
                exact.append(f"{name}-half")
            for loc, b in cases.items():
                locations[loc] = (name, b)

        (root / "logs" / "error.log").unlink()
        conf = write_conf(root, args.port, locations, args.log_level)
        proc = run_nginx(nginx, root, conf)
        failures: list[str] = []
        try:
            wait_port(args.port)
            for loc, (name, b) in locations.items():
                try:
                    body = get(args.port, f"/{loc}/fix", name)
                    plain = decode(name, body)
                except Exception as exc:  # noqa: BLE001
                    failures.append(f"{loc} (B={b}): {exc}")
                    continue
                if plain != expected:
                    failures.append(
                        f"{loc} (B={b}): decoded {len(plain)}B != "
                        f"{len(expected)}B source (boundary corruption)")
        finally:
            stop_nginx(proc)

        if args.log_level == "debug":
            elog = (root / "logs" / "error.log").read_text(
                "utf-8", "replace")
            n = elog.count(WITNESS)
            # every exact-case FINISH plus, for the half cases, nothing
            # extra (the mid-op exact fill ships WITHOUT done, by design
            # — only completion-at-boundary logs)
            if n < len(exact):
                failures.append(
                    f"witness {WITNESS!r} logged {n} times, expected >= "
                    f"{len(exact)} ({', '.join(exact)}) — the "
                    f"exact-boundary case did not execute (did PROCESS "
                    f"emit early? fixture too large?)")
            else:
                print(f"  witness: {WITNESS!r} x{n} across {exact}")
        else:
            print(f"  witnesses skipped (--log-level {args.log_level}); "
                  f"boundary still forced by measured sizing, decode "
                  f"oracles gated above")

        if failures:
            sys.stderr.write(f"exact-boundary FAILED ({len(failures)}):\n")
            for f in failures:
                sys.stderr.write(f"  - {f}\n")
            return 1

        print(f"OK: FINISH parked exactly on ob->end for "
              f"{', '.join(exact)} and every neighbor decoded byte-exact")
        return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
