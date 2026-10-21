#!/usr/bin/env python3
"""End-to-end brotli encoding smoke test against a real nginx.

Starts the given nginx binary with the brotli filter enabled, fetches a
generated JavaScript fixture with and without `Accept-Encoding: br`,
decodes the compressed variant with the brotli CLI, and byte-compares
both variants against the origin file. This is the minimal correctness
gate: whatever else changes in the module, a compressed response must
decode byte-exact and a client that did not ask for br must get
identity.
"""

import argparse
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run an end-to-end brotli encoding smoke test."
    )
    parser.add_argument(
        "--nginx-binary",
        required=True,
        help="Path to the nginx binary to start for the smoke test.",
    )
    parser.add_argument(
        "--filter-module",
        help=(
            "Optional path to ngx_http_brotli_filter_module.so. "
            "If omitted, a sibling module next to the nginx binary is used."
        ),
    )
    parser.add_argument(
        "--static-module",
        help=(
            "Optional path to ngx_http_brotli_static_module.so. "
            "If omitted, a sibling module next to the nginx binary is used."
        ),
    )
    parser.add_argument(
        "--port",
        type=int,
        default=18180,
        help="Local TCP port for the temporary nginx instance.",
    )
    parser.add_argument(
        "--brotli-bin",
        default=shutil.which("brotli") or "brotli",
        help="Path to the brotli CLI used for decompression.",
    )
    parser.add_argument(
        "--fixture-lines",
        type=int,
        default=4096,
        help="Number of repeated lines in the generated fixture.",
    )
    return parser.parse_args()


def detect_module(explicit, nginx: pathlib.Path, name: str):
    if explicit:
        return pathlib.Path(explicit)
    sib = nginx.parent / name
    return sib if sib.exists() else None


def wait_for_port(port: int, timeout: float = 10.0, stderr_file=None) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)

    detail = ""
    if stderr_file is not None and stderr_file.exists():
        text = stderr_file.read_text(errors="replace").strip()
        if text:
            detail = f"; nginx stderr:\n{text}"
    raise RuntimeError(
        f"nginx did not start listening on 127.0.0.1:{port}{detail}"
    )


def build_fixture(path: pathlib.Path, lines: int) -> bytes:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("// brotli roundtrip fixture\n")
        for index in range(lines):
            handle.write(
                f'console.log("line-{index:05d}:'
                f' brotli-fixture-abcdefghijklmnopqrstuvwxyz0123456789");\n'
            )
    return path.read_bytes()


def fetch(port: int, headers: dict):
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/app.js", headers=headers
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.headers, response.read()


def main() -> int:
    args = parse_args()
    failures = []

    def check(name: str, condition: bool, detail: str = "") -> None:
        if condition:
            print(f"ok - {name}")
        else:
            print(f"FAIL - {name} {detail}")
            failures.append(name)

    nginx_path = pathlib.Path(args.nginx_binary)
    modules = [
        m
        for m in (
            detect_module(args.filter_module, nginx_path,
                          "ngx_http_brotli_filter_module.so"),
            detect_module(args.static_module, nginx_path,
                          "ngx_http_brotli_static_module.so"),
        )
        if m
    ]
    load = "".join(f"load_module {m};\n" for m in modules)

    with tempfile.TemporaryDirectory(prefix="ngx-brotli-") as tmp:
        root = pathlib.Path(tmp)
        # mkdtemp gives 0700: run as root, workers drop to the
        # compiled-in nginx user and cannot enter it -> 403s
        os.chmod(root, 0o755)
        (root / "conf").mkdir()
        (root / "logs").mkdir()
        (root / "html").mkdir()

        resource = build_fixture(root / "html" / "app.js",
                                 args.fixture_lines)

        conf = root / "conf" / "nginx.conf"
        conf.write_text(
            f"""{load}
worker_processes 1;
daemon off;
error_log logs/error.log warn;
pid logs/nginx.pid;
events {{ }}
http {{
    access_log off;
    types {{ application/javascript js; }}
    default_type application/octet-stream;
    gzip_vary on;
    brotli on;
    brotli_min_length 64;
    brotli_types application/javascript;
    server {{
        listen 127.0.0.1:{args.port};
        root html;
    }}
}}
""",
            encoding="utf-8",
            newline="\n",
        )

        stderr_file = root / "nginx-stderr.log"
        with stderr_file.open("wb") as stderr_handle:
            nginx = subprocess.Popen(
                [args.nginx_binary, "-p", str(root), "-c", str(conf)],
                stdout=subprocess.DEVNULL,
                stderr=stderr_handle,
            )
        try:
            wait_for_port(args.port, stderr_file=stderr_file)

            headers, body = fetch(args.port, {"Accept-Encoding": "br"})
            ce = (headers.get("Content-Encoding") or "identity").strip()
            check("br client negotiates br", ce == "br", f"(got {ce})")

            src = root / "response.br"
            src.write_bytes(body)
            decoded = subprocess.run(
                [args.brotli_bin, "-d", "-c", str(src)],
                check=True,
                capture_output=True,
            ).stdout
            check(
                "br body decodes byte-exact",
                decoded == resource,
                f"(decoded {len(decoded)} bytes, want {len(resource)})",
            )
            check(
                "compression engaged (smaller than origin)",
                len(body) < len(resource),
                f"({len(body)} vs {len(resource)})",
            )

            vary = ",".join(headers.get_all("Vary") or []).lower()
            check(
                "Vary: Accept-Encoding present",
                "accept-encoding" in vary,
                f"(vary: {vary!r})",
            )

            headers, body = fetch(args.port, {})
            ce = (headers.get("Content-Encoding") or "identity").strip()
            check(
                "no Accept-Encoding -> identity",
                ce == "identity" and body == resource,
                f"(got {ce}, {len(body)} bytes)",
            )

        finally:
            nginx.terminate()
            try:
                # 30s, not 10: an instrumented nginx flushing profile
                # data at exit on a loaded runner can outlive a tight
                # reap budget; teardown runs after the verdict, so
                # patience costs nothing when healthy. Mirrors
                # nginx-zstd-module #114/#115.
                nginx.wait(timeout=30)
            except subprocess.TimeoutExpired:
                nginx.kill()
                nginx.wait(timeout=30)

    if failures:
        print(f"FAILED: {len(failures)} check(s): {', '.join(failures)}")
        return 1

    print("OK: verified brotli roundtrip and identity fallback")
    return 0


if __name__ == "__main__":
    sys.exit(main())
