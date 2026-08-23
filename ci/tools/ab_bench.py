#!/usr/bin/env python3
"""Request-path A/B benchmark harness: drives a real nginx over the zstd
filter under `wrk` load, interleaved between two arms to cancel machine
drift, and reports throughput/latency/RSS per (arm, concurrency, body size).

This is the gating dependency for the CCtx-ring, per-profile-slot,
one-reset-per-request and first-buffer-sizing TODO rows, all of which say
"do NOT guess -- measure". It exists to answer "did this change help, on
what body sizes, at what concurrency" with a number, not a guess.

What it measures
-----------------
- requests/sec, p50 and p99 latency, and peak WORKER (not master) RSS, per
  (arm, concurrency, body-size class), under a real nginx + `wrk` load.
- Two arms (two nginx binaries, or one binary run under two labelled
  configs) run in INTERLEAVED rounds -- not sequentially -- because a
  sequential A-then-B run confounds the comparison with machine drift
  (thermal throttling, background load, cache warmth). The existing
  worker-CCtx-cache +79% measurement used exactly this: 3 interleaved
  rounds. Reported numbers are the per-arm MEDIAN across rounds, plus the
  delta.
- Body-size mix matters and is never collapsed into one number: the +79%
  win above was measured on 8 KB bodies and was ZERO on 64 KB, where
  compression itself dominates. Defaults to both sizes, reported
  separately, specifically so nobody can quote a blanket speedup that
  doesn't hold at every size.

Why bodies are proxied through a paced backend, not served static
-------------------------------------------------------------------
The worker-lifetime CCtx loan (acquire_cctx sets the busy flag; only
request CLEANUP clears it -- src/ngx_http_zstd_filter_module.c:1847 and
:2896) is held for the FULL lifetime of one compression, so two
compressions only contend when their lifetimes actually overlap on one
worker. A location serving a static, fully-buffered, known-length body
from page cache completes inside a single event-loop turn; `wrk`
connections then queue rather than overlap, and every concurrency in the
sweep reports the same meaningless 100% hit rate with worker RSS that
never moves -- indistinguishable, from the debug pass's own numbers,
from a real single-slot cache never actually contending. An earlier
version of this harness did exactly that and it was caught in review
before the numbers were trusted.

Every body is therefore served by PacedBackend: a mock upstream, proxied
with `proxy_buffering off`, that sends chunked-transfer headers
immediately and then the body in small pieces with a short sleep between
each. The filter's compression session for one response stays open
across many event-loop turns while other connections are being
accepted, so a second concurrent request can reach acquire_cctx while
the first still holds the loan -- the only way this workload can
demonstrate the contention the ring-sizing row is about.

The harness self-checks this rather than trusting it: the debug pass
requires the hit rate at the LOWEST swept concurrency to be measurably
higher than at the HIGHEST -- a relative fall, because "decays toward
1/N" is itself a relative claim -- plus an absolute floor on `created`
witnesses at the highest concurrency, and raises a RuntimeError (harness
error, non-zero exit) if either does not hold. A flat 100% hit rate at
every concurrency is never printed as a result -- it is either real
contention whose hit rate genuinely falls with concurrency, which the
self-check has independently confirmed, or the self-check itself fails
loudly instead.

What it deliberately does NOT do
---------------------------------
- It does NOT report a cache-engagement hit rate alongside release
  throughput. The reuse/create witnesses
  ("zstd: reusing worker cctx" / "zstd: created cctx") are ngx_log_debug
  lines that only exist in a --with-debug build's debug-level log, and
  emitting them under 128-connection load would distort the very
  throughput being measured. The harness therefore runs the RELEASE pass
  (throughput/latency/RSS, error_log at `warn`) and the DEBUG pass (witness
  counts and hit rate, error_log at `debug`, only if a --with-debug binary
  is supplied) as two structurally separate passes with separate result
  sections -- see BenchResult vs WitnessResult below -- so it is not
  possible to accidentally print one pass's numbers as if measured
  together with the other's. If only a release-mode binary is given, the
  hit rate is reported as unmeasured, never inferred.
- It does NOT trust a flat hit rate. See "Why bodies are proxied" above --
  the debug pass's own self-check must independently prove contention
  happened before its numbers are printed at all.
- It is not a pass/fail gate on the MODULE's performance. Exit non-zero
  only on a harness error (missing wrk/nginx, nginx failed to start, zero
  successful requests for an arm, or the contention self-check failing)
  -- same contract as ci/tools/benchmark.py. A "slow" result is a result,
  not a failure; a workload that cannot contend IS a harness failure,
  because it cannot back up any hit-rate number it would otherwise print.
- It is not wired into any CI workflow. This is a manual measurement tool
  the TODO rows above call out as their prerequisite; running it is a
  deliberate step a human (or a grind worker sizing the ring) takes, not
  something every PR pays for.

Usage
-----
    # A/B: two release binaries, default concurrency sweep (8, 32, 128)
    python3 ci/tools/ab_bench.py \\
        --arm-a .build/nginx-baseline/objs/nginx:baseline \\
        --arm-b .build/nginx-ring/objs/nginx:ring \\
        --json results.json

    # Single binary, release pass only (no A/B, still gives a baseline table)
    python3 ci/tools/ab_bench.py --arm-a .build/nginx-1.31.4/objs/nginx

    # Add the debug pass (separate, clearly-labelled section) for one arm
    python3 ci/tools/ab_bench.py \\
        --arm-a .build/nginx-1.31.4/objs/nginx:release \\
        --debug-binary .build/nginx-1.31.4/objs/nginx

Exit non-zero only on harness error, never on a "slow" result.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import pathlib
import re
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time

REPO = pathlib.Path(__file__).resolve().parent.parent.parent

DEFAULT_CONCURRENCY = [8, 32, 128]
DEFAULT_ROUNDS = 3
DEFAULT_DURATION = "10s"
WARMUP_DURATION = "3s"

# Body-size classes. 8 KB is where the worker-CCtx-cache win showed up
# (+79%); 64 KB is where it was measured as zero because the compression
# work itself dominates over context-creation overhead. Keeping both by
# default is deliberate -- see the module docstring.
BODY_SIZES: dict[str, int] = {
    "8kb": 8 * 1024,
    "64kb": 64 * 1024,
}

CREATE_WITNESS = "zstd: created cctx"
REUSE_WITNESS = "zstd: reusing worker cctx"

# The loan (ngx_http_zstd_worker_cctx_busy) is held from acquire_cctx
# until REQUEST CLEANUP, so two compressions only actually CONTEND when
# their lifetimes overlap on one worker. A location that serves a static,
# fully-buffered, known-length body from page cache completes inside one
# event-loop turn -- wrk connections then queue rather than overlap, and
# the harness would silently report a meaningless 100% hit rate at every
# concurrency (caught in review: flat 100% at 8/32/128 conn plus
# unmoving worker RSS is the signature of a workload that never
# contends, not of a healthy cache). Bodies are therefore served via
# PacedBackend + `proxy_buffering off` below: the backend sends headers
# immediately, then the body in small chunked pieces with a sleep
# between each, so the filter's compression session for one response
# stays open across many event-loop turns while other connections are
# being accepted -- long enough for a second concurrent request to
# reach acquire_cctx while the first still holds the loan.
PACE_CHUNK = 512
PACE_DELAY_S = 0.004

# Self-check thresholds for the debug pass -- see run_debug_pass. An
# absolute "created > 1" floor and a relative created-fraction rise
# were both tried and rejected (see the comment at the check itself);
# the check that survived compares the HIT RATE at the lowest vs the
# highest swept concurrency, since "decays toward 1/N" is a relative
# claim about the hit rate and this is its negative control.
CONTENTION_MIN_CREATED = 2
CONTENTION_MIN_RELATIVE_RISE = 1.5


@dataclasses.dataclass
class Arm:
    label: str
    binary: pathlib.Path
    filter_module: pathlib.Path | None = None
    static_module: pathlib.Path | None = None


@dataclasses.dataclass
class BenchSample:
    """One wrk run's result for one (arm, concurrency, body size)."""

    rps: float
    p50_ms: float
    p99_ms: float
    peak_rss_kb: int
    requests: int
    errors: int


@dataclasses.dataclass
class WitnessSample:
    """Cache-engagement counts from ONE debug-pass run. Never carries a
    throughput number -- the debug pass's own throughput is deliberately
    unreliable (see module docstring) and must never be read as
    comparable to a release-pass BenchSample.
    """

    created: int
    reused: int

    @property
    def hit_rate(self) -> float | None:
        total = self.created + self.reused
        if total == 0:
            return None
        return self.reused / total


def parse_arm(spec: str) -> tuple[str, str]:
    """ "path[:label]" -> (path, label). Label defaults to the basename."""
    if ":" in spec:
        path, label = spec.rsplit(":", 1)
        if path and label:
            return path, label
    return spec, pathlib.Path(spec).name


def detect_module(binary: pathlib.Path, name: str) -> pathlib.Path | None:
    sibling = binary.parent / name
    return sibling if sibling.exists() else None


def wait_for_port(port: int, timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def body_bytes(size: int) -> bytes:
    """Realistic ~6:1-compressible HTML-ish body of the given size --
    matches the fixture the existing +79% measurement used, not
    incompressible random bytes (which would exercise a different, less
    representative code path in the compressor).
    """
    unit = b"<div class='row'><span>item</span><a href='/x'>link text here</a></div>\n"
    reps = size // len(unit) + 1
    return (unit * reps)[:size]


class PacedBackend(threading.Thread):
    """Mock upstream: sends chunked-transfer headers immediately, then
    the body in PACE_CHUNK-sized pieces with a PACE_DELAY_S sleep
    between each. One handler thread per accepted connection so it
    scales to the harness's own concurrency sweep without becoming the
    bottleneck itself.

    This is what makes compression sessions overlap. Proxied through
    nginx with `proxy_buffering off`, the filter processes each chunk as
    it streams in rather than compressing one fully-buffered body in a
    single event-loop turn -- so the worker-lifetime CCtx loan
    (acquired at acquire_cctx, released only at request cleanup, per
    src/ngx_http_zstd_filter_module.c:1847/:2896) stays held for the
    whole paced duration instead of being taken and returned before the
    next request is even accepted. A static, fully-buffered,
    known-length body completes inside one event-loop turn and can
    never contend, however high the connection count -- that was the
    workload bug this class exists to fix.
    """

    def __init__(self, port: int, bodies: dict[str, bytes]) -> None:
        super().__init__(daemon=True)
        self.port = port
        self.bodies = bodies
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", port))
        self.srv.listen(256)
        self._stopping = False

    def stop(self) -> None:
        self._stopping = True
        try:
            self.srv.close()
        except OSError:
            pass

    def run(self) -> None:
        while not self._stopping:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve_conn, args=(conn,), daemon=True).start()

    def _serve_conn(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(15)
            buf = b""
            while b"\r\n\r\n" not in buf:
                piece = conn.recv(4096)
                if not piece:
                    return
                buf += piece
            request_line = buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            path = request_line.split(" ")[1] if " " in request_line else "/"
            name = path.strip("/").split("/")[-1] or "8kb"
            body = self.bodies.get(name, next(iter(self.bodies.values())))

            conn.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/octet-stream\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"Connection: close\r\n\r\n"
            )
            for i in range(0, len(body), PACE_CHUNK):
                piece = body[i : i + PACE_CHUNK]
                conn.sendall(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
                time.sleep(PACE_DELAY_S)
            conn.sendall(b"0\r\n\r\n")
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


def write_conf(
    root: pathlib.Path,
    port: int,
    backend_port: int,
    arm: Arm,
    workers: int,
    log_level: str,
) -> pathlib.Path:
    load = ""
    filt = arm.filter_module or detect_module(
        arm.binary, "ngx_http_zstd_filter_module.so"
    )
    static = arm.static_module or detect_module(
        arm.binary, "ngx_http_zstd_static_module.so"
    )
    if filt:
        load += f"load_module {filt};\n"
    if static:
        load += f"load_module {static};\n"

    conf = root / "nginx.conf"
    conf.write_text(
        f"""daemon off;
master_process on;
worker_processes {workers};
{load}error_log {root}/error.log {log_level};
pid {root}/nginx.pid;
events {{ worker_connections 4096; }}
http {{
    access_log off;
    zstd on;
    zstd_min_length 1;
    zstd_types application/octet-stream;
    server {{
        listen 127.0.0.1:{port};
        default_type application/octet-stream;
        location / {{
            # Paced, chunked, unbuffered upstream -- see PacedBackend.
            # A static in-page-cache body completes in one event-loop
            # turn and can never make two compressions overlap.
            proxy_pass http://127.0.0.1:{backend_port};
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_buffering off;
        }}
    }}
}}
""",
        encoding="utf-8",
    )
    return conf


def start_nginx(arm: Arm, conf: pathlib.Path, root: pathlib.Path) -> subprocess.Popen:
    log = open(root / "stdout.log", "w", encoding="utf-8")  # noqa: SIM115
    return subprocess.Popen(
        [str(arm.binary), "-p", str(root), "-c", str(conf)],
        stdout=log,
        stderr=subprocess.STDOUT,
    )


def rss_monitor_start(master_pid: int, stop_path: pathlib.Path) -> subprocess.Popen:
    """A tiny standalone poller so RSS sampling continues during the wrk
    run without the harness process itself needing a thread juggling
    subprocess I/O. Writes the peak seen to `stop_path` on receipt of
    SIGTERM, then exits -- polled by the caller after wrk finishes.
    """
    script = f"""
import os, signal, sys, time
peak = 0
stop = False
def _stop(signum, frame):
    global stop
    stop = True
signal.signal(signal.SIGTERM, _stop)
while not stop:
    try:
        out = os.popen("pgrep -P {master_pid}").read()
        pids = [int(x) for x in out.split() if x.strip()]
    except Exception:
        pids = []
    total = 0
    for pid in pids:
        try:
            with open(f"/proc/{{pid}}/status") as fh:
                for line in fh:
                    if line.startswith("VmRSS:"):
                        total += int(line.split()[1])
                        break
        except (FileNotFoundError, ProcessLookupError):
            pass
    peak = max(peak, total)
    time.sleep(0.1)
with open({str(stop_path)!r}, "w") as fh:
    fh.write(str(peak))
"""
    return subprocess.Popen([sys.executable, "-c", script])


def _to_ms(value: float, unit: str) -> float:
    return {"us": value / 1000, "ms": value, "s": value * 1000}[unit]


def parse_wrk_percentiles(text: str) -> tuple[float, float]:
    """Extract p50 / p99 from `wrk --latency` output's distribution table."""
    p50 = p99 = 0.0
    for line in text.splitlines():
        m = re.match(r"\s*(50|99)%\s+([\d.]+)(us|ms|s)", line)
        if not m:
            continue
        pct, val, unit = m.groups()
        ms = _to_ms(float(val), unit)
        if pct == "50":
            p50 = ms
        else:
            p99 = ms
    return p50, p99


def run_wrk(
    url: str, connections: int, duration: str, threads: int
) -> tuple[float, float, float, int, int]:
    wrk_bin = shutil.which("wrk")
    assert wrk_bin
    proc = subprocess.run(
        [
            wrk_bin,
            "-t",
            str(threads),
            "-c",
            str(connections),
            "-d",
            duration,
            "--latency",
            "-H",
            "Accept-Encoding: zstd",
            url,
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    out = proc.stdout
    rps_m = re.search(r"Requests/sec:\s*([\d.]+)", out)
    req_m = re.search(r"(\d+) requests in", out)
    err_m = re.search(r"Non-2xx or 3xx responses:\s*(\d+)", out)
    rps = float(rps_m.group(1)) if rps_m else 0.0
    requests = int(req_m.group(1)) if req_m else 0
    errors = int(err_m.group(1)) if err_m else 0
    p50, p99 = parse_wrk_percentiles(out)
    if rps_m is None:
        raise RuntimeError(f"wrk produced no parseable output:\n{out}\n{proc.stderr}")
    return rps, p50, p99, requests, errors


def bench_one(
    arm: Arm,
    root: pathlib.Path,
    port: int,
    body: str,
    conc: int,
    duration: str,
) -> BenchSample:
    master = None
    for _ in range(50):
        master_pids = [
            p
            for p in subprocess.run(
                ["pgrep", "-f", f"{arm.binary} -p {root}"],
                capture_output=True,
                text=True,
                check=False,
            ).stdout.split()
        ]
        if master_pids:
            master = int(master_pids[0])
            break
        time.sleep(0.05)
    stop_file = root / f"rss.{body}.{conc}.peak"
    monitor = None
    if master is not None:
        monitor = rss_monitor_start(master, stop_file)

    url = f"http://127.0.0.1:{port}/{body}"
    threads = min(conc, os.cpu_count() or 4)
    rps, p50, p99, requests, errors = run_wrk(url, conc, duration, threads)

    peak_rss = 0
    if monitor is not None:
        monitor.send_signal(signal.SIGTERM)
        try:
            monitor.wait(timeout=5)
        except subprocess.TimeoutExpired:
            monitor.kill()
        if stop_file.exists():
            try:
                peak_rss = int(stop_file.read_text().strip() or "0")
            except ValueError:
                peak_rss = 0

    return BenchSample(
        rps=rps,
        p50_ms=p50,
        p99_ms=p99,
        peak_rss_kb=peak_rss,
        requests=requests,
        errors=errors,
    )


def run_release_pass(
    arms: list[Arm],
    concurrencies: list[int],
    rounds: int,
    duration: str,
    workers: int,
    base_port: int,
) -> dict:
    """Interleaved A/B rounds. Returns {arm_label: {conc: {body: [samples]}}}."""
    samples: dict[str, dict[int, dict[str, list[BenchSample]]]] = {
        arm.label: {c: {b: [] for b in BODY_SIZES} for c in concurrencies}
        for arm in arms
    }

    bodies = {name: body_bytes(size) for name, size in BODY_SIZES.items()}
    procs: dict[str, tuple[subprocess.Popen, pathlib.Path, int]] = {}
    backends: list[PacedBackend] = []
    workdirs: list[pathlib.Path] = []
    try:
        for i, arm in enumerate(arms):
            root = pathlib.Path(tempfile.mkdtemp(prefix=f"ab-bench-{arm.label}-"))
            workdirs.append(root)
            port = base_port + i * 2
            backend_port = port + 1
            backend = PacedBackend(backend_port, bodies)
            backend.start()
            backends.append(backend)
            conf = write_conf(root, port, backend_port, arm, workers, "warn")
            proc = start_nginx(arm, conf, root)
            if not wait_for_port(port, timeout=10):
                tail = ""
                log = root / "stdout.log"
                if log.exists():
                    tail = log.read_text("utf-8", "replace")[-2000:]
                raise RuntimeError(
                    f"arm {arm.label!r}: nginx never became ready on port "
                    f"{port}. Log tail:\n{tail}"
                )
            procs[arm.label] = (proc, root, port)

        # Warmup: one short untimed-ish run per arm/body so the cache is
        # warm before the FIRST measured round -- otherwise round 1 is
        # biased cold for every arm equally, which would still be fair for
        # an A/B delta but would understate absolute rps for both.
        for arm in arms:
            _proc, root, port = procs[arm.label]
            for body in BODY_SIZES:
                run_wrk(f"http://127.0.0.1:{port}/{body}", 8, WARMUP_DURATION, 4)

        for _rnd in range(rounds):
            for conc in concurrencies:
                for body in BODY_SIZES:
                    # Interleave arms WITHIN each (round, conc, body) cell:
                    # this is what actually cancels drift, since it puts
                    # each arm's measurement for the same condition
                    # adjacent in wall-clock time rather than in two
                    # separate blocks.
                    for arm in arms:
                        _proc, root, port = procs[arm.label]
                        sample = bench_one(arm, root, port, body, conc, duration)
                        samples[arm.label][conc][body].append(sample)
    finally:
        for proc, _root, _port in procs.values():
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        for backend in backends:
            backend.stop()
        for root in workdirs:
            shutil.rmtree(root, ignore_errors=True)

    return samples


def run_debug_pass(
    arm: Arm,
    concurrencies: list[int],
    duration: str,
    workers: int,
    base_port: int,
) -> dict[int, WitnessSample]:
    """Separate pass, debug-level logging, only for engagement witnesses.
    Its own throughput is NOT reported -- see module docstring.

    Runs the FULL concurrency sweep against ONE long-lived nginx
    instance (never restarted between concurrencies) so `created` and
    `reused` accumulate across the whole sweep and the ring-sizing row's
    actual question -- does the hit rate DEGRADE as concurrency rises --
    is something this pass can show directly, not just a single
    snapshot.

    Raises RuntimeError (a harness error, not a "slow result") if the
    workload never demonstrates genuine RELATIVE contention: the hit
    rate at the lowest swept concurrency must be materially higher than
    at the highest (CONTENTION_MIN_RELATIVE_RISE), with at least
    CONTENTION_MIN_CREATED "created cctx" witnesses at the highest
    concurrency. An absolute `created > 1` floor alone is too weak, and
    a relative created-fraction check saturates near 1.0 once
    contention is heavy -- both were tried and rejected, see the
    comment at the check itself. A flat or barely-falling hit rate
    across the sweep is indistinguishable from a workload that never
    contends, which is a broken measurement, not a real 100% hit rate.
    See PacedBackend's docstring for why the workload needs pacing to
    make genuine overlap possible at all.
    """
    root = pathlib.Path(tempfile.mkdtemp(prefix=f"ab-bench-debug-{arm.label}-"))
    bodies = {name: body_bytes(size) for name, size in BODY_SIZES.items()}
    backend_port = base_port + 1
    backend = PacedBackend(backend_port, bodies)
    results: dict[int, WitnessSample] = {}
    try:
        backend.start()
        port = base_port
        conf = write_conf(root, port, backend_port, arm, workers, "debug")
        proc = start_nginx(arm, conf, root)
        try:
            if not wait_for_port(port, timeout=10):
                tail = ""
                log = root / "stdout.log"
                if log.exists():
                    tail = log.read_text("utf-8", "replace")[-2000:]
                raise RuntimeError(
                    f"debug pass: nginx never became ready. Log tail:\n{tail}"
                )
            elog_path = root / "error.log"
            prev_created = 0
            prev_reused = 0
            for conc in concurrencies:
                # Throughput-not-reported run purely to generate witness
                # lines under realistic concurrent load.
                run_wrk(f"http://127.0.0.1:{port}/8kb", conc, duration, min(conc, 4))
                time.sleep(0.3)  # let the debug log flush
                elog = elog_path.read_text("utf-8", "replace")
                total_created = len(re.findall(re.escape(CREATE_WITNESS), elog))
                total_reused = len(re.findall(re.escape(REUSE_WITNESS), elog))
                # Per-cell delta, not the running total, so each concurrency's
                # own hit rate is reported rather than a cumulative blend.
                created = total_created - prev_created
                reused = total_reused - prev_reused
                prev_created, prev_reused = total_created, total_reused
                results[conc] = WitnessSample(created=created, reused=reused)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
    finally:
        backend.stop()
        shutil.rmtree(root, ignore_errors=True)

    # Self-check. Two things were tried and rejected before this one:
    #   1. An ABSOLUTE `created > 1` floor -- too weak. Even a
    #      near-instant single-chunk send through the proxy hop picks
    #      up a handful of "created" witnesses from ordinary
    #      thread-scheduling jitter, which let a workload that barely
    #      contends pass silently.
    #   2. A RELATIVE rise in created-fraction (created / total) from
    #      the lowest to the highest concurrency -- also wrong, because
    #      created-fraction saturates near 1.0 once contention is heavy
    #      (measured: 87.8% -> 96.9%, only a 1.10x rise) and compresses
    #      all the signal into a narrow band exactly where the ring row
    #      needs resolution.
    # The metric that actually has headroom is the HIT RATE itself
    # (reused / total): on a genuinely contending run it dropped 12.2%
    # -> 3.1%, a 3.9x fall, because it is not pinned near a ceiling. The
    # check below requires the hit rate at the lowest swept concurrency
    # to be MEASURABLY HIGHER than at the highest -- "decays toward
    # 1/N" is exactly this claim -- plus an absolute floor on `created`
    # at the highest concurrency so a pass can't come from two
    # single-digit witness counts dividing favourably.
    lo_conc, hi_conc = min(concurrencies), max(concurrencies)
    lo, hi = results.get(lo_conc), results.get(hi_conc)
    lo_hr = lo.hit_rate if lo is not None else None
    hi_hr = hi.hit_rate if hi is not None else None
    hi_created_ok = hi is not None and hi.created >= CONTENTION_MIN_CREATED
    degrades = (
        lo_hr is not None
        and hi_hr is not None
        and lo_hr >= hi_hr * CONTENTION_MIN_RELATIVE_RISE
    )
    if len(concurrencies) < 2 or not hi_created_ok or not degrades:
        raise RuntimeError(
            "harness self-check FAILED: the paced workload did not "
            f"demonstrate genuine single-slot contention. At {lo_conc} "
            f"conn the hit rate was "
            f"{'n/a' if lo_hr is None else f'{lo_hr * 100:.1f}%'}; "
            f"at {hi_conc} conn it was "
            f"{'n/a' if hi_hr is None else f'{hi_hr * 100:.1f}%'} "
            f"(need the {lo_conc}-conn rate >= "
            f"{CONTENTION_MIN_RELATIVE_RISE}x the {hi_conc}-conn rate, "
            f"and >= {CONTENTION_MIN_CREATED} 'created cctx' witnesses "
            f"at {hi_conc} conn). A single-slot worker cache can only "
            "show a real hit rate when concurrent compressions "
            "genuinely overlap and that overlap actually WORSENS as "
            "concurrency rises -- a flat or barely-falling hit rate "
            "across the sweep means this run never demonstrated that, "
            "so any hit rate it reported would be a workload artifact, "
            "not a measurement. This is the harness's own negative "
            "control failing, not a benign 100% hit rate."
        )
    return results


def check_with_debug(binary: pathlib.Path) -> None:
    v = subprocess.run([str(binary), "-V"], capture_output=True, text=True, check=False)
    if "--with-debug" not in v.stderr:
        raise RuntimeError(
            f"{binary}: debug pass needs an nginx built --with-debug "
            f"(the reuse witnesses are ngx_log_debug lines); got: "
            f"{v.stderr.strip()}"
        )


def print_release_table(
    arms: list[Arm], concurrencies: list[int], samples: dict
) -> None:
    header = (
        f"{'arm':<14}{'conc':>6}{'body':>7}{'rps(med)':>11}"
        f"{'p50(ms)':>10}{'p99(ms)':>10}{'peakRSS(MB)':>13}{'rounds':>8}"
    )
    print(header)
    print("-" * len(header))
    medians: dict[str, dict[int, dict[str, float]]] = {}
    for arm in arms:
        medians[arm.label] = {}
        for conc in concurrencies:
            medians[arm.label][conc] = {}
            for body in BODY_SIZES:
                sset = samples[arm.label][conc][body]
                rps_med = statistics.median(s.rps for s in sset)
                p50_med = statistics.median(s.p50_ms for s in sset)
                p99_med = statistics.median(s.p99_ms for s in sset)
                rss_peak = max((s.peak_rss_kb for s in sset), default=0) / 1024
                medians[arm.label][conc][body] = rps_med
                print(
                    f"{arm.label:<14}{conc:>6}{body:>7}{rps_med:>11.1f}"
                    f"{p50_med:>10.2f}{p99_med:>10.2f}{rss_peak:>13.1f}"
                    f"{len(sset):>8}"
                )
        print()

    if len(arms) == 2:
        a, b = arms[0].label, arms[1].label
        print(f"delta ({b} vs {a}), rps median:")
        dheader = f"{'conc':>6}{'body':>7}{a + ' rps':>14}{b + ' rps':>14}{'delta':>10}"
        print(dheader)
        print("-" * len(dheader))
        for conc in concurrencies:
            for body in BODY_SIZES:
                ra = medians[a][conc][body]
                rb = medians[b][conc][body]
                delta = f"{((rb - ra) / ra * 100):+.1f}%" if ra > 0 else "n/a"
                print(f"{conc:>6}{body:>7}{ra:>14.1f}{rb:>14.1f}{delta:>10}")
        print()
        print(
            "NOTE: a delta at one body size does not generalize to another --"
            " report each size on its own, never a blanket speedup."
        )


def print_debug_table(
    label: str, results: dict[int, WitnessSample], concurrencies: list[int]
) -> None:
    print()
    print("=== DEBUG PASS: cache-engagement witnesses ===")
    print(
        "Throughput numbers from this pass are NOT reported and are NOT "
        "comparable to the release pass above -- debug-level logging on "
        "the hot path would distort them. This section is witness counts "
        "only. The harness self-check already confirmed the hit rate "
        "falls materially from the lowest to the highest swept "
        "concurrency; the table below is the actual per-cell evidence "
        "for the ring-sizing question -- does the hit rate DEGRADE as "
        "concurrency rises."
    )
    header = f"{'arm':<14}{'conc':>6}{'created':>9}{'reused':>8}{'hit rate':>10}"
    print(header)
    print("-" * len(header))
    prev_hr: float | None = None
    degraded = False
    for conc in concurrencies:
        w = results[conc]
        hr = w.hit_rate
        hr_s = f"{hr * 100:.1f}%" if hr is not None else "n/a"
        print(f"{label:<14}{conc:>6}{w.created:>9}{w.reused:>8}{hr_s:>10}")
        if hr is not None and prev_hr is not None and hr < prev_hr:
            degraded = True
        if hr is not None:
            prev_hr = hr
    print()
    if degraded:
        print(
            "hit rate DECREASES somewhere in this sweep as concurrency "
            "rises -- the single-slot contention the ring-sizing row "
            "expects. Use these per-conc numbers, not just the "
            "lowest-vs-highest self-check comparison, to size the ring."
        )
    else:
        print(
            "hit rate did NOT decrease anywhere across this per-cell "
            "sweep despite the self-check proving it fell materially "
            "from the lowest to the highest concurrency -- re-check "
            "before using these numbers to size the ring; a single-slot "
            "cache should degrade as concurrency rises."
        )


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--arm-a", required=True, help="path/to/nginx[:label] for arm A")
    ap.add_argument(
        "--arm-b", help="path/to/nginx[:label] for arm B (optional; enables A/B)"
    )
    ap.add_argument(
        "--debug-binary",
        help="path to a --with-debug nginx binary for the SEPARATE debug "
        "pass (cache hit-rate witnesses). If omitted, hit rate is "
        "reported as unmeasured.",
    )
    ap.add_argument(
        "--concurrency",
        default=",".join(str(c) for c in DEFAULT_CONCURRENCY),
        help="comma-separated connection counts to sweep",
    )
    ap.add_argument(
        "--rounds",
        type=int,
        default=DEFAULT_ROUNDS,
        help="interleaved A/B rounds per (concurrency, body size) cell",
    )
    ap.add_argument("--duration", default=DEFAULT_DURATION, help="wrk -d per run")
    ap.add_argument(
        "--workers",
        type=int,
        default=1,
        help="nginx worker_processes (default 1: the TODO rows this "
        "harness gates are about PER-WORKER cache behaviour)",
    )
    ap.add_argument("--base-port", type=int, default=18400)
    ap.add_argument("--json", help="write machine-readable results here")
    args = ap.parse_args()

    if shutil.which("wrk") is None:
        print("error: wrk not found on PATH", file=sys.stderr)
        return 2

    concurrencies = [int(x) for x in args.concurrency.split(",") if x.strip()]

    arms: list[Arm] = []
    for _i, spec in enumerate((args.arm_a, args.arm_b)):
        if spec is None:
            continue
        path, label = parse_arm(spec)
        binary = pathlib.Path(path).resolve()
        if not binary.exists():
            print(f"error: arm binary not found: {binary}", file=sys.stderr)
            return 2
        arms.append(Arm(label=label, binary=binary))
    if len({a.label for a in arms}) != len(arms):
        print("error: arm labels must be distinct", file=sys.stderr)
        return 2

    print(
        f"=== RELEASE PASS: rps/p50/p99/RSS, {args.rounds} interleaved "
        f"round(s), NO cache witnesses in this section ==="
    )
    try:
        samples = run_release_pass(
            arms,
            concurrencies,
            args.rounds,
            args.duration,
            args.workers,
            args.base_port,
        )
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    total_requests = sum(
        s.requests
        for arm in arms
        for conc in concurrencies
        for body in BODY_SIZES
        for s in samples[arm.label][conc][body]
    )
    if total_requests == 0:
        print("error: zero successful requests across the whole sweep", file=sys.stderr)
        return 1

    print_release_table(arms, concurrencies, samples)

    debug_results: dict[int, WitnessSample] = {}
    if args.debug_binary:
        debug_bin = pathlib.Path(args.debug_binary).resolve()
        if not debug_bin.exists():
            print(f"error: debug binary not found: {debug_bin}", file=sys.stderr)
            return 2
        try:
            check_with_debug(debug_bin)
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        debug_arm = Arm(label="debug", binary=debug_bin)
        try:
            debug_results = run_debug_pass(
                debug_arm,
                concurrencies,
                args.duration,
                args.workers,
                args.base_port + len(arms) * 2 + 2,
            )
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print_debug_table(debug_arm.label, debug_results, concurrencies)
    else:
        print()
        print(
            "=== DEBUG PASS: not run (no --debug-binary given) -- cache "
            "hit rate is UNMEASURED, not inferred. ==="
        )

    if args.json:
        out = {
            "meta": {
                "concurrencies": concurrencies,
                "rounds": args.rounds,
                "duration": args.duration,
                "workers": args.workers,
                "arms": [a.label for a in arms],
                "commit": subprocess.run(
                    ["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"],
                    capture_output=True,
                    text=True,
                    check=False,
                ).stdout.strip(),
            },
            "release": {
                arm.label: {
                    str(conc): {
                        body: [
                            dataclasses.asdict(s)
                            for s in samples[arm.label][conc][body]
                        ]
                        for body in BODY_SIZES
                    }
                    for conc in concurrencies
                }
                for arm in arms
            },
            "debug": {
                str(conc): dataclasses.asdict(w) for conc, w in debug_results.items()
            }
            if debug_results
            else None,
        }
        pathlib.Path(args.json).write_text(json.dumps(out, indent=2))
        print(f"wrote {args.json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
