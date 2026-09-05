#!/usr/bin/env python3
"""End-to-end RFC 9842 dcb test against a real nginx.

Covers what a TAP suite cannot: the bytes on the wire. Asserts the
negotiated Content-Encoding for every gate, and for dcb responses the
36-byte frame header (magic 0xFF 0x44 0x43 0x42 + dictionary SHA-256),
decodes the remainder with `brotli -d -D <dict>`, byte-compares against
origin, and requires the dcb body to be smaller than the plain br body —
proof the dictionary engaged, not just that framing parses. The
dictionary is a simulated previous version of the resource.
"""

import argparse
import base64
import hashlib
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

DCB_MAGIC = bytes([0xFF, 0x44, 0x43, 0x42])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run an end-to-end RFC 9842 dcb test against nginx."
    )
    parser.add_argument(
        "--nginx-binary",
        required=True,
        help="Path to the nginx binary to start for the test.",
    )
    parser.add_argument(
        "--filter-module",
        help="Optional path to ngx_http_brotli_filter_module.so.",
    )
    parser.add_argument(
        "--static-module",
        help="Optional path to ngx_http_brotli_static_module.so.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=18190,
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
        default=600,
        help="Generated source lines shared between dictionary and "
        "resource.",
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


def build_fixtures(root: pathlib.Path, lines: int) -> tuple[bytes, bytes]:
    shared = [
        f"function widget_{i}() {{ return compute({i}) + render('{'x' * 20}'); }}"
        for i in range(lines)
    ]
    v1 = "\n".join(shared) + "\n"
    v2_lines = shared[:]
    for i in range(0, lines, 50):
        v2_lines.insert(i, f"// added in v2: handler {i}")
    v2 = "\n".join(v2_lines) + "\n"

    (root / "dicts").mkdir()
    (root / "html").mkdir()
    (root / "dicts" / "app-v1.js").write_text(v1, encoding="utf-8",
                                              newline="\n")
    (root / "html" / "app.js").write_text(v2, encoding="utf-8", newline="\n")
    return (root / "dicts" / "app-v1.js").read_bytes(), (
        root / "html" / "app.js"
    ).read_bytes()


def fetch(port: int, headers: dict):
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/app.js", headers=headers
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.headers, response.read()


def content_encoding(headers) -> str:
    value = headers.get("Content-Encoding")
    return value.strip() if value else "identity"


def vary_values(headers) -> str:
    return ",".join(headers.get_all("Vary") or []).lower()


def main() -> int:
    args = parse_args()
    failures: list[str] = []

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

    with tempfile.TemporaryDirectory(prefix="ngx-dcb-") as tmp:
        root = pathlib.Path(tmp)
        # mkdtemp gives 0700: run as root, workers drop to the
        # compiled-in nginx user and cannot enter it -> 403s
        os.chmod(root, 0o755)
        (root / "conf").mkdir()
        (root / "logs").mkdir()
        dict_bytes, resource = build_fixtures(root, args.fixture_lines)
        dict_hash = hashlib.sha256(dict_bytes).digest()
        dict_b64 = base64.b64encode(dict_hash).decode()
        bad_b64 = base64.b64encode(b"\x01" * 32).decode()

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
    brotli_dcb_dict_file {root}/dicts/app-v1.js;
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

            # -- plain br client: baseline and cache-key contract
            headers, plain_body = fetch(args.port, {"Accept-Encoding": "br"})
            check(
                "plain client negotiates br",
                content_encoding(headers) == "br",
                f"(got {content_encoding(headers)})",
            )
            check(
                "plain variant varies on Available-Dictionary",
                "available-dictionary" in vary_values(headers),
                f"(vary: {vary_values(headers)!r})",
            )
            check(
                "plain variant varies on Accept-Encoding",
                "accept-encoding" in vary_values(headers),
                f"(vary: {vary_values(headers)!r})",
            )

            # -- the dcb happy path
            headers, dcb_body = fetch(
                args.port,
                {
                    "Accept-Encoding": "br, dcb",
                    "Available-Dictionary": f":{dict_b64}:",
                },
            )
            check(
                "dictionary client negotiates dcb",
                content_encoding(headers) == "dcb",
                f"(got {content_encoding(headers)})",
            )
            check(
                "dcb variant varies on Available-Dictionary",
                "available-dictionary" in vary_values(headers),
            )
            check(
                "dcb body starts with the RFC 9842 magic",
                dcb_body[:4] == DCB_MAGIC,
                f"(got {dcb_body[:4].hex()})",
            )
            check(
                "dcb header embeds the dictionary SHA-256",
                dcb_body[4:36] == dict_hash,
            )

            # decode: strip the 36-byte header, then brotli -d -D <dict>
            src = root / "response.dcb.br"
            src.write_bytes(dcb_body[36:])
            decoded = subprocess.run(
                [
                    args.brotli_bin,
                    "-d",
                    "-c",
                    "-D",
                    str(root / "dicts" / "app-v1.js"),
                    str(src),
                ],
                check=True,
                capture_output=True,
            ).stdout
            check(
                "dcb body decodes byte-exact with the dictionary",
                decoded == resource,
                f"(decoded {len(decoded)} bytes, want {len(resource)})",
            )
            check(
                "dictionary actually engaged (dcb smaller than plain br)",
                len(dcb_body) < len(plain_body),
                f"(dcb {len(dcb_body)} vs br {len(plain_body)})",
            )

            # -- every gate miss must fall back to br, never break
            fallback_cases = [
                (
                    "unknown dictionary hash",
                    {
                        "Accept-Encoding": "br, dcb",
                        "Available-Dictionary": f":{bad_b64}:",
                    },
                ),
                (
                    "no dcb token in Accept-Encoding",
                    {
                        "Accept-Encoding": "br",
                        "Available-Dictionary": f":{dict_b64}:",
                    },
                ),
                (
                    "explicit dcb;q=0 refusal",
                    {
                        "Accept-Encoding": "br, dcb;q=0",
                        "Available-Dictionary": f":{dict_b64}:",
                    },
                ),
                (
                    "wildcard does not enable dcb",
                    {
                        "Accept-Encoding": "br, *",
                        "Available-Dictionary": f":{dict_b64}:",
                    },
                ),
                (
                    "cross-site request refused",
                    {
                        "Accept-Encoding": "br, dcb",
                        "Available-Dictionary": f":{dict_b64}:",
                        "Sec-Fetch-Site": "cross-site",
                    },
                ),
                (
                    "malformed Available-Dictionary",
                    {
                        "Accept-Encoding": "br, dcb",
                        "Available-Dictionary": "junk",
                    },
                ),
            ]
            for name, case_headers in fallback_cases:
                headers, _body = fetch(args.port, case_headers)
                check(
                    f"fallback: {name} -> br",
                    content_encoding(headers) == "br",
                    f"(got {content_encoding(headers)})",
                )

            # identity fallback still carries the Available-Dictionary
            # cache key (the hoisted-Vary contract from the dcz review)
            headers, _body = fetch(
                args.port,
                {
                    "Accept-Encoding": "dcb",
                    "Available-Dictionary": f":{bad_b64}:",
                },
            )
            check(
                "identity fallback varies on Available-Dictionary",
                content_encoding(headers) == "identity"
                and "available-dictionary" in vary_values(headers),
                f"(ce {content_encoding(headers)}, "
                f"vary {vary_values(headers)!r})",
            )

            # plain br fallback must decode without any dictionary
            src = root / "plain.br"
            src.write_bytes(plain_body)
            plain_decoded = subprocess.run(
                [args.brotli_bin, "-d", "-c", str(src)],
                check=True,
                capture_output=True,
            ).stdout
            check(
                "plain br variant decodes without the dictionary",
                plain_decoded == resource,
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
        print(f"FAILED: {len(failures)} dcb check(s): {', '.join(failures)}")
        return 1

    print("OK: verified RFC 9842 dcb negotiation, framing, and roundtrip")
    return 0


if __name__ == "__main__":
    sys.exit(main())
