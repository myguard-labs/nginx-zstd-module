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
- It is not a pass/fail gate. Exit non-zero only on a harness error
  (missing wrk/nginx, nginx failed to start, zero successful requests for
  an arm) -- same contract as ci/tools/benchmark.py. A "slow" result is a
  result, not a failure.
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


def write_conf(
    root: pathlib.Path,
    port: int,
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
        root {root}/html;
        default_type application/octet-stream;
        location / {{ }}
    }}
}}
""",
        encoding="utf-8",
    )
    return conf


def make_bodies(root: pathlib.Path) -> None:
    """Realistic ~6:1-compressible HTML-ish bodies, one file per size
    class -- matches the fixture the existing +79% measurement used, not
    incompressible random bytes (which would exercise a different, less
    representative code path in the compressor).
    """
    html = root / "html"
    html.mkdir(exist_ok=True)
    unit = b"<div class='row'><span>item</span><a href='/x'>link text here</a></div>\n"
    for name, size in BODY_SIZES.items():
        reps = size // len(unit) + 1
        (html / name).write_bytes((unit * reps)[:size])


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

    procs: dict[str, tuple[subprocess.Popen, pathlib.Path, int]] = {}
    workdirs: list[pathlib.Path] = []
    try:
        for i, arm in enumerate(arms):
            root = pathlib.Path(tempfile.mkdtemp(prefix=f"ab-bench-{arm.label}-"))
            workdirs.append(root)
            (root / "html").mkdir(exist_ok=True)
            make_bodies(root)
            port = base_port + i
            conf = write_conf(root, port, arm, workers, "warn")
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
        for root in workdirs:
            shutil.rmtree(root, ignore_errors=True)

    return samples


def run_debug_pass(
    arm: Arm,
    conc: int,
    duration: str,
    workers: int,
    base_port: int,
) -> WitnessSample:
    """Separate pass, debug-level logging, only for engagement witnesses.
    Its own throughput is NOT reported -- see module docstring.
    """
    root = pathlib.Path(tempfile.mkdtemp(prefix=f"ab-bench-debug-{arm.label}-"))
    try:
        (root / "html").mkdir(exist_ok=True)
        make_bodies(root)
        port = base_port
        conf = write_conf(root, port, arm, workers, "debug")
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
            # Short, throughput-not-reported run purely to generate
            # witness lines under realistic concurrent load.
            run_wrk(f"http://127.0.0.1:{port}/8kb", conc, duration, min(conc, 4))
            time.sleep(0.3)  # let the debug log flush
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()

        elog = (root / "error.log").read_text("utf-8", "replace")
        created = len(re.findall(re.escape(CREATE_WITNESS), elog))
        reused = len(re.findall(re.escape(REUSE_WITNESS), elog))
        return WitnessSample(created=created, reused=reused)
    finally:
        shutil.rmtree(root, ignore_errors=True)


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


def print_debug_table(results: dict[tuple[str, int], WitnessSample]) -> None:
    print()
    print("=== DEBUG PASS: cache-engagement witnesses ===")
    print(
        "Throughput numbers from this pass are NOT reported and are NOT "
        "comparable to the release pass above -- debug-level logging on "
        "the hot path would distort them. This section is witness counts "
        "only."
    )
    header = f"{'arm':<14}{'conc':>6}{'created':>9}{'reused':>8}{'hit rate':>10}"
    print(header)
    print("-" * len(header))
    for (label, conc), w in results.items():
        hr = f"{w.hit_rate * 100:.1f}%" if w.hit_rate is not None else "n/a"
        print(f"{label:<14}{conc:>6}{w.created:>9}{w.reused:>8}{hr:>10}")


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

    debug_results: dict[tuple[str, int], WitnessSample] = {}
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
        for conc in concurrencies:
            debug_results[(debug_arm.label, conc)] = run_debug_pass(
                debug_arm,
                conc,
                args.duration,
                args.workers,
                args.base_port + len(arms) + 1,
            )
        print_debug_table(debug_results)
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
                f"{label}@{conc}": dataclasses.asdict(w)
                for (label, conc), w in debug_results.items()
            }
            if debug_results
            else None,
        }
        pathlib.Path(args.json).write_text(json.dumps(out, indent=2))
        print(f"wrote {args.json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
