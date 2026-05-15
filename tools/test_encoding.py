#!/usr/bin/env python3
import argparse
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

FIXTURE_SENTINEL = "END-OF-ZSTD-TRUNCATION-FIXTURE-9f4c3d1b"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run an end-to-end zstd encoding smoke test against nginx."
    )
    parser.add_argument(
        "--nginx-binary",
        required=True,
        help="Path to the nginx binary to start for the smoke test.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=18080,
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
        default=8192,
        help="Number of repeated lines to generate in the JavaScript fixture.",
    )
    return parser.parse_args()


def wait_for_port(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"nginx did not start listening on 127.0.0.1:{port}")


def build_fixture(path: pathlib.Path, lines: int) -> bytes:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("// zstd truncation regression fixture\n")
        handle.write("const payload = [\n")
        for index in range(lines):
            handle.write(
                f'  "line-{index:05d}: zstd-regression-payload-abcdefghijklmnopqrstuvwxyz0123456789",\n'
            )
        handle.write("];\n")
        handle.write(
            "globalThis.__zstd_fixture_checksum = `${payload.length}:${payload[0]}:${payload[payload.length - 1]}`;\n"
        )
        handle.write(f'globalThis.__zstd_fixture_end = "{FIXTURE_SENTINEL}";\n')
        handle.write("console.log(globalThis.__zstd_fixture_checksum);\n")
        handle.write("console.log(globalThis.__zstd_fixture_end);\n")
    data = path.read_bytes()
    if len(data) <= 131072:
        raise RuntimeError(
            f"fixture too small to catch truncation bugs: {len(data)} bytes"
        )
    return data


def write_config(conf_path: pathlib.Path, root_dir: pathlib.Path, port: int) -> None:
    conf_path.write_text(
        f"""
worker_processes  1;
error_log  logs/error.log info;
pid        logs/nginx.pid;

events {{
    worker_connections  128;
}}

http {{
    access_log logs/access.log;
    default_type application/octet-stream;
    sendfile off;
    keepalive_timeout 5;
    server {{
        listen 127.0.0.1:{port};
        server_name localhost;
        root {root_dir};
        location = /test.js {{
            types {{
                application/javascript js;
            }}
            default_type application/javascript;
            zstd on;
            zstd_min_length 1;
            zstd_types application/javascript;
        }}
    }}
}}
""".lstrip(),
        encoding="utf-8",
    )


def fetch_response(port: int) -> tuple[bytes, bytes, str]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/test.js",
        headers={"Accept-Encoding": "zstd", "User-Agent": "zstd-ci-smoke-test/1.0"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        compressed = response.read()
        header = response.headers.get("Content-Encoding", "")
    return compressed, header.encode("utf-8"), header


def decompress_payload(zstd_bin: str, compressed: bytes) -> bytes:
    result = subprocess.run(
        [zstd_bin, "-d", "-q", "-c"],
        input=compressed,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"zstd decompression failed: {stderr.strip()}")
    return result.stdout


def read_if_exists(path: pathlib.Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def main() -> int:
    args = parse_args()
    nginx_binary = pathlib.Path(args.nginx_binary)
    if not nginx_binary.exists():
        raise FileNotFoundError(f"nginx binary not found: {nginx_binary}")
    if shutil.which(args.zstd_bin) is None and not pathlib.Path(args.zstd_bin).exists():
        raise FileNotFoundError(f"zstd CLI not found: {args.zstd_bin}")

    with tempfile.TemporaryDirectory(prefix="zstd-ci-smoke-") as temp_dir_str:
        temp_dir = pathlib.Path(temp_dir_str)
        html_dir = temp_dir / "html"
        conf_dir = temp_dir / "conf"
        logs_dir = temp_dir / "logs"
        html_dir.mkdir()
        conf_dir.mkdir()
        logs_dir.mkdir()

        fixture_path = html_dir / "test.js"
        expected = build_fixture(fixture_path, args.fixture_lines)
        conf_path = conf_dir / "nginx.conf"
        write_config(conf_path, html_dir, args.port)

        process = subprocess.Popen(
            [
                str(nginx_binary),
                "-p",
                str(temp_dir),
                "-c",
                str(conf_path),
                "-g",
                "daemon off; master_process off;",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        try:
            wait_for_port(args.port)
            compressed, _, encoding = fetch_response(args.port)
            if encoding.lower() != "zstd":
                raise RuntimeError(f"expected Content-Encoding=zstd, got {encoding!r}")
            decoded = decompress_payload(args.zstd_bin, compressed)
            if decoded != expected:
                raise RuntimeError(
                    "decompressed response does not match source fixture; "
                    f"expected {len(expected)} bytes, got {len(decoded)} bytes"
                )
            if FIXTURE_SENTINEL.encode("utf-8") not in decoded:
                raise RuntimeError("fixture sentinel missing from decoded response")
            print(
                f"OK: verified zstd response integrity for {len(expected)}-byte JavaScript fixture"
            )
            return 0
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

            output = process.stdout.read() if process.stdout is not None else ""
            error_log = read_if_exists(logs_dir / "error.log")
            if process.returncode not in (0, -15):
                sys.stderr.write("nginx stdout/stderr:\n")
                sys.stderr.write(output)
                sys.stderr.write("\nnginx error log:\n")
                sys.stderr.write(error_log)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
