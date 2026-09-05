#!/usr/bin/env python3
"""Mid-stream FLUSH exerciser for the unified compression module.

What this covers that the Test::Nginx suites cannot
---------------------------------------------------
The suites' ``return``-based responses arrive in one chain: the body
filter sees PROCESS steps and one FINISH, never a mid-stream FLUSH.
This tool reproduces the production shape that generates them —
``proxy_buffering off`` in front of a chunked upstream that writes
with real delays — so every delayed segment reaches the filter with a
flush flag and the FLUSH op executes end to end, for both codings.

Two oracles per case:

* **Incremental arrival**: the client reads the raw socket with
  timestamps and requires >= 2 inter-segment gaps matching the
  upstream's deliberate long pauses. Compressed bytes arriving BEFORE
  the response ends is the observable proof that FLUSH produced
  decodable output mid-stream rather than buffering to FINISH.
* **Byte-exact decode**: the reassembled body decodes through the
  reference CLI and must equal the origin fixture exactly (the
  parent repo's bug-B discipline: never trust a 200 or a non-empty
  body).

The chunk-size matrix varies the per-flush output sizes widely, which
is the honest form of the FLUSH/FINISH-lands-exactly-at-ob->end
coverage: the boundary cannot be forced deterministically (compressed
sizes are not controllable), so this patrols the neighborhood with
fresh sizes every run. WRINKLES records that framing.

Requires: python3 stdlib, the ``zstd`` and ``brotli`` CLIs, and an
nginx binary with the compression module compiled in.
"""
from __future__ import annotations

import argparse
import os
import pathlib
import re
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

# (total size, upstream chunk size). Sizes straddle brotli's 32 KiB
# step bufs and zstd's ~128 KiB recommendation; chunk sizes vary the
# flush granularity (1000 forces many tiny flushes, 31000 crosses the
# brotli step per flush).
CASES = [
    (200000, 1000),
    (200000, 16384),
    (131073, 7000),
    (65536, 31000),
]

SHORT_DELAY = 0.01   # between ordinary chunks: distinct upstream writes
LONG_DELAY = 0.35    # at the witness positions: the arrival evidence


def long_positions(nchunks: int) -> set[int]:
    """Inter-chunk sleep indexes that get the LONG delay: quartile
    positions when there are enough chunks, every position when the
    chunk size makes the response only a handful of writes (the first
    cut used every-8th and asserted 2 gaps — a 3-chunk case can never
    produce them)."""
    if nchunks <= 4:
        return set(range(1, nchunks))
    return {max(1, nchunks // 4), max(1, nchunks // 2),
            max(1, (3 * nchunks) // 4)}


def witness_required(nchunks: int) -> int:
    return min(2, max(1, nchunks - 1))

CODINGS = {
    "zstd": {"decode": ["zstd", "-d", "-q", "-c"], "loc": "zs"},
    "br":   {"decode": ["brotli", "-d", "-c"],     "loc": "br"},
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--nginx-binary", required=True)
    p.add_argument("--port", type=int, default=18190)
    p.add_argument("--backend-port", type=int, default=18191)
    return p.parse_args()


def fixture_bytes(n: int) -> bytes:
    # Deterministic, low-compressibility (the parent tool's LCG) so
    # compressed output genuinely crosses buffers and a wrong-body
    # response is detectable.
    buf = bytearray(n)
    x = (n * 2654435761) & 0xFFFFFFFF
    for i in range(n):
        x = (x * 1103515245 + 12345) & 0xFFFFFFFF
        buf[i] = (x >> 16) & 0xFF
    return bytes(buf)


class _Backend(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _Handler(socketserver.StreamRequestHandler):
    """Chunked, no-Content-Length, with REAL delays between writes so
    nginx's unbuffered proxy forwards each segment with a flush."""

    def handle(self):
        line = self.rfile.readline().decode("latin1")
        while True:
            h = self.rfile.readline()
            if h in (b"\r\n", b"\n", b""):
                break
        m = re.match(r"GET /[a-z]+/s/(\d+)/(\d+) ", line)
        if not m:
            self.wfile.write(b"HTTP/1.1 404 Not Found\r\n"
                             b"Content-Length: 0\r\n\r\n")
            return
        total, chunk = int(m.group(1)), int(m.group(2))
        data = fixture_bytes(total)
        nchunks = (total + chunk - 1) // chunk
        longs = long_positions(nchunks)
        self.wfile.write(b"HTTP/1.1 200 OK\r\n"
                         b"Content-Type: application/octet-stream\r\n"
                         b"Transfer-Encoding: chunked\r\n\r\n")
        self.wfile.flush()
        sent = 0
        i = 0
        while sent < total:
            piece = data[sent:sent + chunk]
            self.wfile.write(b"%X\r\n" % len(piece) + piece + b"\r\n")
            self.wfile.flush()
            sent += len(piece)
            i += 1
            if sent < total:
                time.sleep(LONG_DELAY if i in longs else SHORT_DELAY)
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()


def wait_port(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"nothing listening on 127.0.0.1:{port}")


def timed_get(port: int, path: str, coding: str,
              timeout: float = 60.0) -> tuple[bytes, list[float]]:
    """HTTP/1.0 GET (no chunked framing on the client side: body runs
    to EOF) returning (body, arrival timestamps per read)."""
    s = socket.create_connection(("127.0.0.1", port), timeout)
    s.settimeout(timeout)
    req = (f"GET {path} HTTP/1.0\r\n"
           f"Host: t\r\nAccept-Encoding: {coding}\r\n\r\n")
    s.sendall(req.encode("latin1"))
    raw = b""
    stamps: list[float] = []
    while True:
        piece = s.recv(65536)
        if not piece:
            break
        raw += piece
        stamps.append(time.time())
    s.close()
    head, _, body = raw.partition(b"\r\n\r\n")
    headers = head.decode("latin1", "replace")
    m = re.search(r"(?im)^content-encoding:\s*(\S+)", headers)
    got = m.group(1) if m else None
    if got != coding:
        raise RuntimeError(f"{path}: Content-Encoding {got!r}, "
                           f"wanted {coding!r}")
    return body, stamps


def decode(coding: str, blob: bytes) -> bytes:
    r = subprocess.run(CODINGS[coding]["decode"], input=blob,
                       capture_output=True, check=False)
    if r.returncode != 0:
        raise RuntimeError(
            f"{coding} decode failed (truncated/corrupt stream): "
            + r.stderr.decode("utf-8", "replace").strip())
    return r.stdout


def main() -> int:
    args = parse_args()
    nginx = pathlib.Path(args.nginx_binary)
    if not nginx.exists():
        raise FileNotFoundError(nginx)

    v = subprocess.run([str(nginx), "-V"], capture_output=True, text=True, check=False)
    if "compression" not in v.stderr:
        raise RuntimeError("nginx -V shows no compression module "
                           "(--add-module=.../compression missing?)")

    os.umask(0o022)
    with tempfile.TemporaryDirectory(prefix="compression-flush-") as td:
        os.chmod(td, 0o755)   # root-run: workers must enter the prefix
        root = pathlib.Path(td)
        (root / "logs").mkdir()

        backend = _Backend(("127.0.0.1", args.backend_port), _Handler)
        threading.Thread(target=backend.serve_forever, daemon=True).start()
        try:
            wait_port(args.backend_port)

            locs = "".join(
                f"""        location /{c['loc']}/ {{
            compression on;
            compression_order {name};
            compression_http_version 1.0;
            compression_min_length 1;
            compression_types application/octet-stream;
            gzip_vary on;
            proxy_pass http://127.0.0.1:{args.backend_port};
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_buffering off;
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
        listen 127.0.0.1:{args.port};
{locs}    }}
}}
""", encoding="utf-8")

            proc = subprocess.Popen(
                [str(nginx), "-p", str(root), "-c", str(conf),
                 "-g", "daemon off; master_process off;"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            try:
                wait_port(args.port)
                failures: list[str] = []
                for name, c in CODINGS.items():
                    for total, chunk in CASES:
                        label = f"{name} size={total} chunk={chunk}"
                        path = f"/{c['loc']}/s/{total}/{chunk}"
                        try:
                            body, stamps = timed_get(args.port, path, name)
                            plain = decode(name, body)
                        except Exception as exc:  # noqa: BLE001
                            failures.append(f"{label}: {exc}")
                            continue
                        expected = fixture_bytes(total)
                        if plain != expected:
                            failures.append(
                                f"{label}: decoded {len(plain)}B, "
                                f"expected {len(expected)}B "
                                f"({'TRUNCATION' if len(plain) != len(expected) else 'CORRUPTION'})")
                            continue
                        nchunks = (total + chunk - 1) // chunk
                        need = witness_required(nchunks)
                        gaps = sum(1 for a, b in zip(stamps, stamps[1:])
                                   if b - a > LONG_DELAY * 0.5)
                        if gaps < need:
                            failures.append(
                                f"{label}: {gaps}/{need} inter-segment "
                                f"gaps > {LONG_DELAY * 0.5:.2f}s — output "
                                f"was buffered to FINISH instead of "
                                f"flushing mid-stream")

                if failures:
                    sys.stderr.write(
                        f"flush-paths FAILED ({len(failures)}):\n")
                    for f in failures[:20]:
                        sys.stderr.write(f"  - {f}\n")
                    return 1

                print(f"OK: {len(CODINGS) * len(CASES)} unbuffered-proxy "
                      f"responses flushed mid-stream and decoded "
                      f"byte-exact for both codings")
                return 0
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=30)
        finally:
            backend.shutdown()
            backend.server_close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
