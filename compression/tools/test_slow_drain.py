#!/usr/bin/env python3
"""Slow-client backpressure + data-less flush test for the filter.

Scenario 1 — the recycling pause path. The Test::Nginx suites prove
the buffer cap's SAME-invocation pause/reclaim/resume
(t/06-buffers.t) — on a local socket everything drains instantly, so
the genuine cross-invocation pause (ship drained nothing back, filter
returns NGX_AGAIN, r->buffered keeps the writer re-poking, the entry
nomem block resumes later) is unreachable there. This tool forces it:
a small listen sndbuf, ``compression_buffers 2``, a ~1 MB
incompressible body, and a client that reads deliberately slowly.
Under that geometry the write filter cannot drain the busy chain
within an invocation, so the genuine pause MUST occur, and its
dedicated witness line ("resuming after drain" — logged ONLY on the
writer-driven re-entry, never on a same-invocation resume) MUST
appear, alongside the cap-pause and buf-reuse lines.

Scenario 2 — the content-less flush (ported back from the standalone
repo's twin of this tool, where building it found the mechanism):
nginx's non-buffered upstream path sends a data-less NGX_HTTP_FLUSH
special before relaying any body (``ngx_http_upstream_send_response``,
ngx_http_upstream.c:3657), and a backend that sends its headers alone
and its body strictly later guarantees that special reaches an EMPTY
encoder. The filter must run the FLUSH op with nothing pending and
ship the completion as a special buf (the zero-size-temp-buf
alert-avoidance branch), witnessed by "content-less flush shipped as
special buf" — once per zstd response. Brotli is exercised through
the same scenario but its first flush emits stream-header bits, so
its completion carries content and cannot land in the special-buf
branch (the phase-0 "done is per-op, per-backend" asymmetry, live).

Oracles per coding: byte-exact decode of both scenarios' bodies, and
at debug log level the witness lines above with per-scenario floors.

``--log-level warn`` exists for sanitizer builds: a UBSAN nginx
(-fno-sanitize-recover) fatally traps core's own debug logging —
every "%V?%V" line passes NULL for empty r->args into
ngx_sprintf_str's nonnull argument (reported upstream:
nginx/nginx#1671, fix PR #1672) — so a sanitized binary cannot log at
debug at all. At warn the forced paths still run and the roundtrip
oracles still gate; only the log-witness assertions are skipped.
Retire the concession when the upstream fix is in the pinned nginx.

Requires an nginx binary built ``--with-debug`` (the witnesses are
ngx_log_debug lines) with the compression module compiled in, plus
the ``zstd`` and ``brotli`` CLIs.
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
import threading
import time

SIZE = 1_000_000
READ_CHUNK = 16384
READ_DELAY = 0.02

PROXY_PART = 40_000
PROXY_REPEAT = 4
HEADER_BODY_GAP = 0.3
INTER_PART_GAP = 0.15

CODINGS = {
    "zstd": {"decode": ["zstd", "-d", "-q", "-c"], "loc": "zs"},
    "br":   {"decode": ["brotli", "-d", "-c"],     "loc": "br"},
}

DRAIN_WITNESSES = [
    "buffer cap 2 reached",
    "reused output buf",
    "resuming after drain",
]
FLUSH_WITNESS = "content-less flush shipped as special buf"


def parse_args() -> argparse.Namespace:
    """Parse the CLI arguments (binary, ports, log level)."""
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--nginx-binary", required=True)
    p.add_argument("--port", type=int, default=18192)
    p.add_argument("--backend-port", type=int, default=18193,
                   help="Mock slow-headers upstream port.")
    p.add_argument("--log-level", choices=("debug", "warn"),
                   default="debug",
                   help="Location error_log level. Witnesses are only "
                        "asserted at debug; use warn under sanitizer "
                        "builds, where nginx core's own debug logging "
                        "is fatal (nginx/nginx#1671).")
    return p.parse_args()


def fixture_bytes(n: int) -> bytes:
    """Deterministic pseudorandom (incompressible) fixture of n bytes."""
    buf = bytearray(n)
    x = (n * 2654435761) & 0xFFFFFFFF
    for i in range(n):
        x = (x * 1103515245 + 12345) & 0xFFFFFFFF
        buf[i] = (x >> 16) & 0xFF
    return bytes(buf)


def wait_port(port: int, timeout: float = 10.0) -> None:
    """Block until something accepts connections on 127.0.0.1:port."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"nothing listening on 127.0.0.1:{port}")


class SlowHeaderBackend(threading.Thread):
    """Sends 200 + headers immediately, then the body only after a
    pause — so nginx's non-buffered data-less FLUSH special always
    reaches the filter before a single body byte does."""

    def __init__(self, port: int, body: bytes) -> None:
        """Bind the listener up front so wait-for-port has a target."""
        super().__init__(daemon=True)
        self.port = port
        self.body = body
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", port))
        self.srv.listen(8)

    def run(self) -> None:
        """Accept loop: headers immediately, body in two paused halves."""
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            try:
                conn.settimeout(10)
                buf = b""
                while b"\r\n\r\n" not in buf:
                    piece = conn.recv(4096)
                    if not piece:
                        break
                    buf += piece
                conn.sendall(b"HTTP/1.1 200 OK\r\n"
                             b"Content-Type: application/octet-stream\r\n"
                             b"Connection: close\r\n\r\n")
                time.sleep(HEADER_BODY_GAP)
                half = len(self.body) // 2
                conn.sendall(self.body[:half])
                time.sleep(INTER_PART_GAP)
                conn.sendall(self.body[half:])
            except OSError:
                pass
            finally:
                conn.close()

    def stop(self) -> None:
        """Close the listener; the accept loop exits on the next OSError."""
        self.srv.close()


def http_get(port: int, path: str, coding: str, slow: bool,
             timeout: float = 120.0) -> bytes:
    """GET path expecting Content-Encoding: <coding>; slow=True
    throttles reads through a small SO_RCVBUF to create real
    backpressure."""
    s = socket.create_connection(("127.0.0.1", port), timeout)
    s.settimeout(timeout)
    if slow:
        # Without a small SO_RCVBUF the kernel buffers the whole
        # compressed response client-side and nginx never feels the
        # backpressure this test exists to create.
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16384)
    req = (f"GET {path} HTTP/1.0\r\n"
           f"Host: t\r\nAccept-Encoding: {coding}\r\n\r\n")
    s.sendall(req.encode("latin1"))
    raw = b""
    while True:
        piece = s.recv(READ_CHUNK)
        if not piece:
            break
        raw += piece
        if slow:
            time.sleep(READ_DELAY)
    s.close()
    head, _, body = raw.partition(b"\r\n\r\n")
    headers = head.decode("latin1", "replace")
    status = headers.splitlines()[0] if headers else "<no response>"
    if " 200 " not in f"{status} ":
        raise RuntimeError(f"{path}: expected 200, got {status!r} "
                           f"({len(body)}B body)")
    m = re.search(r"(?im)^content-encoding:\s*(\S+)", headers)
    got = m.group(1) if m else None
    if got != coding:
        raise RuntimeError(f"{path}: Content-Encoding {got!r}, "
                           f"wanted {coding!r} (status {status!r}, "
                           f"{len(body)}B body)")
    return body


def decode(coding: str, blob: bytes) -> bytes:
    """Decompress with the reference CLI; nonzero exit = truncation."""
    r = subprocess.run(CODINGS[coding]["decode"], input=blob,
                       capture_output=True, check=False)
    if r.returncode != 0:
        raise RuntimeError(
            f"{coding} decode failed (truncated/corrupt stream): "
            + r.stderr.decode("utf-8", "replace").strip())
    return r.stdout


def main() -> int:
    """Launch nginx + mock backend, run both scenarios, check witnesses."""
    args = parse_args()
    nginx = pathlib.Path(args.nginx_binary)
    if not nginx.exists():
        raise FileNotFoundError(nginx)

    v = subprocess.run([str(nginx), "-V"], capture_output=True, text=True, check=False)
    if "compression" not in v.stderr:
        raise RuntimeError("nginx -V shows no compression module")
    if "--with-debug" not in v.stderr:
        raise RuntimeError("the witnesses are ngx_log_debug lines: "
                           "this tool needs an nginx built --with-debug")

    proxy_body = fixture_bytes(2 * PROXY_PART)
    backend = SlowHeaderBackend(args.backend_port, proxy_body)
    backend.start()

    os.umask(0o022)
    with tempfile.TemporaryDirectory(prefix="compression-drain-") as td:
        os.chmod(td, 0o755)
        root = pathlib.Path(td)
        (root / "logs").mkdir()
        html = root / "html" / "d"
        html.mkdir(parents=True)
        (html / "big").write_bytes(fixture_bytes(SIZE))

        lvl = args.log_level
        locs = "".join(
            f"""        location /{c['loc']}/ {{
            error_log {root}/logs/error.log {lvl};
            alias {html}/;
            compression on;
            compression_order {name};
            compression_http_version 1.0;
            compression_buffers 2;
            compression_min_length 1;
            compression_types application/octet-stream;
            gzip_vary on;
        }}
        location /px-{c['loc']} {{
            error_log {root}/logs/error.log {lvl};
            proxy_pass http://127.0.0.1:{args.backend_port};
            proxy_buffering off;
            compression on;
            compression_order {name};
            compression_http_version 1.0;
            compression_min_length 1;
            compression_types application/octet-stream;
            gzip_vary on;
        }}
""" for name, c in CODINGS.items())

        conf = root / "nginx.conf"
        conf.write_text(f"""worker_processes 1;
error_log {root}/logs/error.log warn;
pid {root}/nginx.pid;
events {{ worker_connections 64; }}
http {{
    access_log off;
    default_type application/octet-stream;
    server {{
        listen 127.0.0.1:{args.port} sndbuf=16384;
{locs}    }}
}}
""", encoding="utf-8")

        # nginx's own stdout/stderr to a file, not a PIPE: nothing
        # drains a pipe here, and on failure the tail is the diagnosis.
        nlog_path = root / "logs" / "nginx-stdout.log"
        # SIM115 suppressed: the handle must outlive this block -- it is
        # Popen's stdout for the whole server lifetime; a with-block
        # would close it while nginx is still writing (master's shape).
        nlog = open(nlog_path, "w", encoding="utf-8")  # noqa: SIM115
        proc = subprocess.Popen(
            [str(nginx), "-p", str(root), "-c", str(conf),
             "-g", "daemon off; master_process off;"],
            stdout=nlog, stderr=subprocess.STDOUT, text=True)

        def alive_or_die(when: str) -> None:
            """Fail with nginx's captured output if the process exited —
            a bind conflict or sanitizer abort otherwise masquerades as
            responses from a stale listener on the same port."""
            if proc.poll() is not None:
                nlog.flush()
                tail = nlog_path.read_text("utf-8", "replace")[-2000:]
                raise RuntimeError(
                    f"nginx exited (rc={proc.returncode}) {when}; "
                    f"output tail:\n{tail}")

        try:
            wait_port(args.port)
            alive_or_die("during startup")
            failures: list[str] = []
            expected = fixture_bytes(SIZE)

            for name, c in CODINGS.items():
                label = f"{name} slow-drain"
                try:
                    t0 = time.time()
                    body = http_get(args.port, f"/{c['loc']}/big", name,
                                    slow=True)
                    took = time.time() - t0
                    plain = decode(name, body)
                except Exception as exc:  # noqa: BLE001
                    failures.append(f"{label}: {exc}")
                    continue
                if plain != expected:
                    failures.append(
                        f"{label}: decoded {len(plain)}B, expected "
                        f"{len(expected)}B — the pause/resume seams "
                        f"corrupted or truncated the stream")
                    continue
                print(f"  {label}: {len(body)}B compressed drained in "
                      f"{took:.1f}s, decoded byte-exact")

            alive_or_die("after the slow-drain scenario")

            for name, c in CODINGS.items():
                ok = 0
                for i in range(PROXY_REPEAT):
                    try:
                        body = http_get(args.port, f"/px-{c['loc']}",
                                        name, slow=False)
                        if decode(name, body) != proxy_body:
                            failures.append(
                                f"{name} proxy #{i}: decode mismatch")
                            break
                        ok += 1
                    except Exception as exc:  # noqa: BLE001
                        failures.append(f"{name} proxy #{i}: {exc}")
                        break
                if ok:
                    print(f"  {name} proxy: {ok}/{PROXY_REPEAT} "
                          f"unbuffered responses decoded byte-exact")

            alive_or_die("after the proxy scenario")

            elog = (root / "logs" / "error.log").read_text(
                "utf-8", "replace")
            if lvl != "debug":
                print("  witnesses skipped (--log-level warn: sanitizer "
                      "builds cannot log at debug — paths still forced, "
                      "roundtrips still gate)")
            # The upstream FLUSH special is unconditional per non-
            # buffered response, but only ZSTD's completion is
            # deterministically content-less: a fresh zstd encoder
            # flushes to zero bytes, while brotli's first flush emits
            # its stream-header bits, so the brotli completion carries
            # content and rides a data buf (measured: exactly
            # PROXY_REPEAT witnesses, all zstd — a live example of the
            # phase-0 "done is defined per-op, per-backend" lesson).
            # Floor = the zstd responses; a lower bound, not an exact
            # pin (nginx may emit further data-less specials
            # mid-relay). Drain-witness counts depend on scheduling;
            # only their existence is pinned.
            witness_floors = ()
            if lvl == "debug":
                witness_floors = tuple(
                    [(w, 1) for w in DRAIN_WITNESSES]
                    + [(FLUSH_WITNESS, PROXY_REPEAT)])
            for witness, floor in witness_floors:
                n = elog.count(witness)
                if n < floor:
                    failures.append(
                        f"witness short: {witness!r} x{n}, expected at "
                        f"least x{floor} — the forced path did not run "
                        f"(geometry drift, or the filter's debug lines "
                        f"changed)")
                else:
                    print(f"  witness: {witness!r} x{n}")

            if failures:
                sys.stderr.write(f"slow-drain FAILED ({len(failures)}):\n")
                for f in failures:
                    sys.stderr.write(f"  - {f}\n")
                # CI runs are not reproducible interactively: ship the
                # evidence with the verdict.
                nlog.flush()
                sys.stderr.write("--- nginx stdout/stderr tail:\n")
                sys.stderr.write(
                    nlog_path.read_text("utf-8", "replace")[-2000:] + "\n")
                sys.stderr.write("--- error.log tail (non-debug):\n")
                sys.stderr.write("\n".join(
                    ln for ln in elog.splitlines()
                    if "[debug]" not in ln)[-3000:] + "\n")
                return 1

            proof = ("witnessed" if lvl == "debug"
                     else "roundtripped (witnesses skipped)")
            print(f"OK: both codings survived forced backpressure and "
                  f"data-less flushes, {proof}, streams byte-exact")
            return 0
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=30)
            nlog.close()
            backend.stop()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
