#!/usr/bin/env python3
"""End-to-end RFC 9842 dcz test against a real nginx.

Covers what t/03-dcz.t cannot: the bytes on the wire. For every case the
test asserts the negotiated Content-Encoding, and for dcz responses it
additionally verifies the 40-byte frame header (skippable-frame magic +
dictionary SHA-256), decodes the body with `zstd -d -D <dict>` under the
RFC's 8 MB client window guarantee (--memory), and byte-compares against
the origin fixture. The dictionary is a simulated "previous version" of
the resource, so the test also asserts the dictionary actually engaged:
the dcz body must be smaller than the plain zstd body.
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

DCZ_MAGIC = bytes([0x5E, 0x2A, 0x4D, 0x18, 0x20, 0x00, 0x00, 0x00])
RFC_CLIENT_WINDOW = 8 * 1024 * 1024


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run an end-to-end RFC 9842 dcz test against nginx."
    )
    parser.add_argument(
        "--nginx-binary",
        required=True,
        help="Path to the nginx binary to start for the test.",
    )
    parser.add_argument(
        "--filter-module",
        help=(
            "Optional path to ngx_http_zstd_filter_module.so. "
            "If omitted, a sibling module next to the nginx binary is used."
        ),
    )
    parser.add_argument(
        "--static-module",
        help=(
            "Optional path to ngx_http_zstd_static_module.so. "
            "If omitted, a sibling module next to the nginx binary is used."
        ),
    )
    parser.add_argument(
        "--port",
        type=int,
        default=18106,
        help="Local TCP port for the temporary nginx instance.",
    )
    parser.add_argument(
        "--zstd-bin",
        default=shutil.which("zstd") or "zstd",
        help="Path to the zstd CLI used for decompression.",
    )
    parser.add_argument(
        "--fixture-lines",
        type=int,
        default=600,
        help="Number of generated source lines shared between dictionary and resource.",
    )
    return parser.parse_args()


def detect_module(explicit, nginx: pathlib.Path, name: str):
    """A dynamic-module build (--add-dynamic-module, e.g. the Coverage CI
    job) needs load_module lines or `zstd on;` is an unknown directive
    and nginx dies at config parse; a static build has no .so and needs
    none. Mirror the sibling tools: an explicit path wins, else use a
    module sitting next to the nginx binary if present."""
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

    # A config-parse failure would otherwise surface only as this silent
    # timeout; include what nginx actually said on stderr.
    detail = ""
    if stderr_file is not None and stderr_file.exists():
        text = stderr_file.read_text(errors="replace").strip()
        if text:
            detail = f"; nginx stderr:\n{text}"
    raise RuntimeError(f"nginx did not start listening on 127.0.0.1:{port}{detail}")


def build_fixtures(root: pathlib.Path, lines: int) -> tuple[bytes, bytes]:
    """Dictionary = version 1; served resource = version 2 sharing most
    of its content. Returns (dict_bytes, resource_bytes)."""
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
    dict_path = root / "dicts" / "app-v1.js"
    dict_path.write_text(v1, encoding="utf-8", newline="\n")
    (root / "html" / "app.js").write_text(v2, encoding="utf-8", newline="\n")
    return dict_path.read_bytes(), (root / "html" / "app.js").read_bytes()


def write_config(root: pathlib.Path, port: int, modules) -> pathlib.Path:
    conf_dir = root / "conf"
    conf_dir.mkdir()
    (root / "logs").mkdir()
    load = "".join(f"load_module {m};\n" for m in modules)
    conf = conf_dir / "nginx.conf"
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
    zstd on;
    zstd_min_length 64;
    zstd_dcz_dict_file {root}/dicts/app-v1.js;
    server {{
        listen 127.0.0.1:{port};
        root html;
    }}
}}
""",
        encoding="utf-8",
        newline="\n",
    )
    return conf


def fetch(port: int, headers: dict):
    """Returns (email.message.Message, body). The Message preserves
    repeated header lines — the module legitimately emits two Vary
    lines (Accept-Encoding via gzip_vary, Available-Dictionary its own),
    and a dict would silently keep only one of them."""
    request = urllib.request.Request(f"http://127.0.0.1:{port}/app.js", headers=headers)
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.headers, response.read()


def content_encoding(headers) -> str:
    value = headers.get("Content-Encoding")
    return value.strip() if value else "identity"


def vary_values(headers) -> str:
    return ",".join(headers.get_all("Vary") or []).lower()


def decode_dcz(
    zstd_bin: str, body: bytes, dict_path: pathlib.Path, work: pathlib.Path
) -> bytes:
    """Decode a full dcz body (skippable header + frame) with the
    dictionary, capped at the RFC 9842 client window guarantee so a frame
    demanding a larger window fails here instead of on real clients."""
    src = work / "response.dcz"
    dst = work / "response.out"
    src.write_bytes(body)
    subprocess.run(
        [
            zstd_bin,
            "-d",
            "-q",
            "-f",
            f"--memory={RFC_CLIENT_WINDOW}",
            "-D",
            str(dict_path),
            "-o",
            str(dst),
            str(src),
        ],
        check=True,
        capture_output=True,
    )
    return dst.read_bytes()


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
            detect_module(
                args.filter_module, nginx_path, "ngx_http_zstd_filter_module.so"
            ),
            detect_module(
                args.static_module, nginx_path, "ngx_http_zstd_static_module.so"
            ),
        )
        if m
    ]

    # Everything below must stay readable by the workers when run as
    # root (they drop to the compiled-in nginx user): a restrictive
    # inherited umask (e.g. 077) would strip group/other bits from
    # every fixture and subdir created here, 403ing the workers even
    # with the scratch root itself opened up.
    os.umask(0o022)
    with tempfile.TemporaryDirectory(prefix="zstd-dcz-") as tmp:
        # mkdtemp gives 0700: run as root, workers drop to the
        # compiled-in nginx user and cannot enter it -> 403s
        os.chmod(tmp, 0o755)
        root = pathlib.Path(tmp)
        dict_bytes, resource = build_fixtures(root, args.fixture_lines)
        conf = write_config(root, args.port, modules)
        dict_hash = hashlib.sha256(dict_bytes).digest()
        dict_b64 = base64.b64encode(dict_hash).decode()
        bad_b64 = base64.b64encode(b"\x01" * 32).decode()

        stderr_file = root / "nginx-stderr.log"
        with stderr_file.open("wb") as stderr_handle:
            nginx = subprocess.Popen(
                [args.nginx_binary, "-p", str(root), "-c", str(conf)],
                stdout=subprocess.DEVNULL,
                stderr=stderr_handle,
            )
        try:
            wait_for_port(args.port, stderr_file=stderr_file)

            # -- plain zstd client: baseline and cache-key contract
            headers, plain_body = fetch(args.port, {"Accept-Encoding": "zstd"})
            check(
                "plain client negotiates zstd",
                content_encoding(headers) == "zstd",
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

            # -- the dcz happy path
            headers, dcz_body = fetch(
                args.port,
                {
                    "Accept-Encoding": "zstd, dcz",
                    "Available-Dictionary": f":{dict_b64}:",
                },
            )
            check(
                "dictionary client negotiates dcz",
                content_encoding(headers) == "dcz",
                f"(got {content_encoding(headers)})",
            )
            check(
                "dcz variant varies on Available-Dictionary",
                "available-dictionary" in vary_values(headers),
                f"(vary: {vary_values(headers)!r})",
            )
            check(
                "dcz body starts with the RFC 9842 magic",
                dcz_body[:8] == DCZ_MAGIC,
                f"(got {dcz_body[:8].hex()})",
            )
            check(
                "dcz header embeds the dictionary SHA-256",
                dcz_body[8:40] == dict_hash,
            )

            decoded = decode_dcz(
                args.zstd_bin, dcz_body, root / "dicts" / "app-v1.js", root
            )
            check(
                "dcz body decodes byte-exact with the dictionary "
                "within the 8 MB client window",
                decoded == resource,
                f"(decoded {len(decoded)} bytes, want {len(resource)})",
            )
            check(
                "dictionary actually engaged (dcz smaller than plain zstd)",
                len(dcz_body) < len(plain_body),
                f"(dcz {len(dcz_body)} vs zstd {len(plain_body)})",
            )

            # -- content checksum (defence in depth): the inner zstd frame
            # starts right after the 40-byte dcz header, so byte 44 is its
            # Frame_Header_Descriptor; Content_Checksum_flag is bit 2.
            fhd = dcz_body[44] if len(dcz_body) > 44 else None
            check(
                "dcz frame declares a content checksum (FHD bit 2)",
                fhd is not None and (fhd & 0x04) != 0,
                f"(FHD {fhd:#04x})" if fhd is not None else "(body too short)",
            )

            # The property the checksum exists for: decoding against a
            # WRONG dictionary of the same size structurally succeeds and
            # yields wrong bytes (raw-prefix references stay in range and
            # nothing else in the frame ties the output to the content).
            # With the checksum the decoder must reject it loudly instead
            # of handing wrong content to the caller.
            dict_path = root / "dicts" / "app-v1.js"
            wrong_dict = root / "wrong-same-size.js"
            wrong_dict.write_bytes(b"Z" * dict_path.stat().st_size)
            wrong_src = root / "response-wrongdict.dcz"
            wrong_src.write_bytes(dcz_body)
            wrong_out = root / "response-wrongdict.out"
            wrong_rc = subprocess.run(
                [
                    args.zstd_bin,
                    "-d",
                    "-q",
                    "-f",
                    f"--memory={RFC_CLIENT_WINDOW}",
                    "-D",
                    str(wrong_dict),
                    "-o",
                    str(wrong_out),
                    str(wrong_src),
                ],
                capture_output=True,
                check=False,
            )
            if wrong_rc.returncode == 0:
                wrong_len = len(wrong_out.read_bytes()) if wrong_out.exists() else 0
                wrong_detail = f"(rc=0, {wrong_len} bytes of wrong content accepted)"
            else:
                wrong_detail = ""
            check(
                "wrong same-size dictionary fails the decode "
                "(checksum turns silent corruption into a loud error)",
                wrong_rc.returncode != 0,
                wrong_detail,
            )

            # -- every gate miss must fall back to zstd, never break
            fallback_cases = [
                (
                    "unknown dictionary hash",
                    {
                        "Accept-Encoding": "zstd, dcz",
                        "Available-Dictionary": f":{bad_b64}:",
                    },
                ),
                (
                    "no dcz token in Accept-Encoding",
                    {
                        "Accept-Encoding": "zstd",
                        "Available-Dictionary": f":{dict_b64}:",
                    },
                ),
                (
                    "explicit dcz;q=0 refusal",
                    {
                        "Accept-Encoding": "zstd, dcz;q=0",
                        "Available-Dictionary": f":{dict_b64}:",
                    },
                ),
                (
                    "wildcard does not enable dcz",
                    {
                        "Accept-Encoding": "zstd, *",
                        "Available-Dictionary": f":{dict_b64}:",
                    },
                ),
                (
                    "cross-site request refused",
                    {
                        "Accept-Encoding": "zstd, dcz",
                        "Available-Dictionary": f":{dict_b64}:",
                        "Sec-Fetch-Site": "cross-site",
                    },
                ),
                (
                    "malformed Available-Dictionary",
                    {
                        "Accept-Encoding": "zstd, dcz",
                        "Available-Dictionary": "junk",
                    },
                ),
            ]
            for name, case_headers in fallback_cases:
                headers, _body = fetch(args.port, case_headers)
                check(
                    f"fallback: {name} -> zstd",
                    content_encoding(headers) == "zstd",
                    f"(got {content_encoding(headers)})",
                )

            # zstd fallbacks must still decode without any dictionary
            src = root / "plain.zst"
            src.write_bytes(plain_body)
            plain_decoded = subprocess.run(
                [args.zstd_bin, "-d", "-q", "-c", str(src)],
                check=True,
                capture_output=True,
            ).stdout
            check(
                "plain zstd variant decodes without the dictionary",
                plain_decoded == resource,
            )

        finally:
            nginx.terminate()
            try:
                # 30s, not 10: gcov-instrumented nginx flushing .gcda
                # at exit on a loaded runner can outlive a tight reap
                # budget; teardown runs after the verdict, so patience
                # costs nothing when healthy.
                nginx.wait(timeout=30)
            except subprocess.TimeoutExpired:
                nginx.kill()
                nginx.wait(timeout=30)

    if failures:
        print(f"FAILED: {len(failures)} dcz check(s): {', '.join(failures)}")
        return 1

    print("OK: verified RFC 9842 dcz negotiation, framing, and roundtrip")
    return 0


if __name__ == "__main__":
    sys.exit(main())
