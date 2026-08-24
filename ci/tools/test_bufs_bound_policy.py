#!/usr/bin/env python3
"""Config-load policy: bound the aggregate ``zstd_buffers number size``.

``zstd_buffers`` delegates to nginx core's ``ngx_conf_set_bufs_slot()``,
which rejects only a parse error or either argument being zero -- it never
looks at the PRODUCT. ``ngx_conf_merge_bufs_value()`` (invoked from
``ngx_http_zstd_merge_loc_conf()``) then either keeps an explicit value,
inherits the parent's, or applies this module's own default
(``2 x ZSTD_CStreamOutSize()``); none of those three paths re-validates the
pair either. A typo ("zstd_buffers 100000 100000;" instead of
"100 100k;") or a value inherited from an outer block could therefore
request an overflowing or merely enormous per-response output-chain pool
that nginx would happily commit per concurrent response.

The policy under test
----------------------
  * ``num * size`` overflowing ``size_t`` is a hard config-load error,
    unconditionally -- there is no representable acknowledgement for a
    product that cannot exist.
  * A representable-but-large product (> ``NGX_HTTP_ZSTD_BUFS_ADVISORY_BYTES``,
    8 MB) is a ``[warn]`` naming the total, PER RESPONSE, cross-referencing
    the ``zstd_max_cctx_memory`` advisory for the CCtx half of the budget.
    It never fails the configuration -- a config that loads today keeps
    loading.
  * The check runs once at merge time, which is the single point that
    covers an EXPLICIT value, one INHERITED from an outer block, and the
    module's own DEFAULT alike (all three land in the same ``conf->bufs``
    the filter reads from). The parse-time slot additionally catches an
    overflowing explicit value at the earliest point, but does not repeat
    the advisory -- so a bare explicit large value warns exactly once, not
    twice.

Why this test and not ``ci/t/02-conf-warn.t``: Test::Nginx's error-log
greps can assert a substring appeared, but cannot assert a config-load run
PASSED with the warning present, is REFUSED with a specific message for
overflow, and passed with NO warning at all for the near-boundary/ack
cases -- all as one matrix with an explicit non-zero exit code check. A
signal death (e.g. a bad cast crashing "nginx -t") would still satisfy a
plain string grep; this harness explicitly separates that case out.

Arms
----
1. default zstd_buffers (module default, 2 x stream_out_size)  -> PASS,
   no warning (the ordinary case must stay silent).
2. cap - 1 byte (``zstd_buffers 1 8388607``)                    -> PASS,
   no warning.
3. cap exact (``zstd_buffers 1 8388608``)                       -> PASS,
   no warning (the boundary itself is inclusive of "not advised").
4. cap + 1 byte (``zstd_buffers 1 8388609``)                    -> PASS,
   warning naming ~8388609 bytes.
5. product overflow (``zstd_buffers <huge> <huge>``)            -> REFUSED,
   naming both operands, never a signal death.
6. inherited from an outer (http) block, over the cap           -> PASS,
   warning fires at the location that merges it in (proves inheritance is
   covered, not just the location that wrote the directive).
7. explicit large value fires exactly ONCE, not twice (parse-time slot
   must not duplicate the merge-time advisory).

Arms 1-3 are the controls that keep this test from being vacuous: a build
that warns unconditionally on any zstd_buffers value fails them.
"""

import argparse
import pathlib
import re
import subprocess
import sys
import tempfile

# NGX_HTTP_ZSTD_BUFS_ADVISORY_BYTES in src/ngx_http_zstd_filter_module.c.
ADVISORY_BYTES = 8 * 1024 * 1024

WARN_RE = re.compile(
    r'"zstd_buffers" \((?P<ctx>[^)]+)\) requests (?P<num>\d+) x '
    r"(?P<size>\d+) bytes = ~(?P<total>\d+) bytes"
)
OVERFLOW_RE = re.compile(
    r'"zstd_buffers" \([^)]+\) requests (\d+) buffers of (\d+) bytes each; '
    r"that product overflows"
)


def parse_args():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--nginx-binary", required=True)
    p.add_argument("--filter-module")
    p.add_argument("--port", type=int, default=18140)
    return p.parse_args()


def detect_module(explicit, nginx: pathlib.Path):
    if explicit:
        return pathlib.Path(explicit)
    sib = nginx.parent / "ngx_http_zstd_filter_module.so"
    return sib if sib.exists() else None


def config_test(nginx, module, port, http_directives, srv_directives):
    """Run ``nginx -t``; return (returncode, combined output)."""
    with tempfile.TemporaryDirectory() as td:
        root = pathlib.Path(td)
        (root / "conf").mkdir()
        (root / "logs").mkdir()

        load = f"load_module {module};\n" if module else ""
        (root / "conf" / "nginx.conf").write_text(
            f"{load}"
            "events {}\n"
            "http {\n"
            f"    {http_directives}\n"
            f"    server {{\n"
            f"        listen 127.0.0.1:{port};\n"
            "        zstd on;\n"
            f"        {srv_directives}\n"
            "    }\n"
            "}\n"
        )

        proc = subprocess.run(
            [str(nginx), "-p", str(root), "-c", "conf/nginx.conf", "-t"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        return proc.returncode, proc.stdout + proc.stderr


def check_not_a_signal(name, rc, out):
    if rc < 0:
        return [f"{name}: nginx -t died on signal {-rc}; output: {out.strip()!r}"]
    if rc > 128:
        return [
            (
                f"{name}: nginx -t exited {rc} (128+{rc - 128}), a signal "
                f"death, not a diagnostic; output: {out.strip()!r}"
            )
        ]
    return []


def run_arm(
    nginx,
    module,
    port,
    name,
    http_directives,
    srv_directives,
    want_pass,
    want_warning,
    want_overflow_error=False,
    min_total=None,
    max_warn_count=1,
):
    """One matrix cell. Returns (failures, printable summary)."""
    rc, out = config_test(nginx, module, port, http_directives, srv_directives)
    failures = check_not_a_signal(name, rc, out)

    if want_pass and rc != 0:
        failures.append(
            f"{name}: expected nginx -t to PASS but it exited {rc}. The "
            f"bufs bound policy must never turn a working config into a "
            f"config-load failure; output: {out.strip()!r}"
        )
    if not want_pass and rc == 0:
        failures.append(
            f"{name}: expected nginx -t to be REFUSED but it exited 0; "
            f"output: {out.strip()!r}"
        )

    warns = WARN_RE.findall(out)

    if want_warning and not warns:
        failures.append(
            f"{name}: expected the [warn] advisory naming the aggregate "
            f"buffer total, but it was not emitted; output: {out.strip()!r}"
        )
    if not want_warning and warns:
        failures.append(
            f"{name}: the advisory was emitted but must NOT be. Either "
            f"the threshold is wrong or the boundary is off-by-one; "
            f"output: {out.strip()!r}"
        )
    if warns and len(warns) > max_warn_count:
        failures.append(
            f"{name}: advisory fired {len(warns)} times (want at most "
            f"{max_warn_count}) -- the parse-time slot and the merge-time "
            f"check are double-reporting the same explicit value; output: "
            f"{out.strip()!r}"
        )

    if warns and "[warn]" not in out:
        failures.append(
            f"{name}: matched the advisory text but not at [warn] level; "
            f"output: {out.strip()!r}"
        )

    total = None
    if warns:
        total = int(warns[0][3])
        if total <= ADVISORY_BYTES:
            failures.append(
                f"{name}: advisory fired at {total} bytes, which is <= the "
                f"{ADVISORY_BYTES}-byte threshold. The condition is not "
                f"the documented one."
            )
        if min_total is not None and total < min_total:
            failures.append(
                f"{name}: advisory reports {total} bytes, below the "
                f"expected {min_total}. Computed from the wrong operands."
            )
        if "per response" not in out.lower():
            failures.append(
                f"{name}: advisory does not state the total is PER "
                f"RESPONSE; output: {out.strip()!r}"
            )
        if "zstd_max_cctx_memory" not in out:
            failures.append(
                f"{name}: advisory does not cross-reference the CCtx "
                f'memory advisory ("zstd_max_cctx_memory"); output: '
                f"{out.strip()!r}"
            )

    if want_overflow_error:
        m = OVERFLOW_RE.search(out)
        if m is None:
            failures.append(
                f"{name}: expected the overflow diagnostic naming both "
                f"operands, but it was not found; output: {out.strip()!r}"
            )
        elif "[emerg]" not in out:
            failures.append(
                f"{name}: overflow diagnostic present but not at [emerg] "
                f"level; output: {out.strip()!r}"
            )

    summary = (
        f"  {name:<38} exit {rc} (want {'0' if want_pass else 'non-zero'}), "
        f"warnings {len(warns)} (want {'>=1' if want_warning else '0'})"
        + (f", total {total} bytes" if total is not None else "")
    )
    return failures, summary


def main() -> int:
    args = parse_args()
    nginx = pathlib.Path(args.nginx_binary).resolve()
    if not nginx.exists():
        print(f"FAIL: nginx binary not found: {nginx}", file=sys.stderr)
        return 1

    module = detect_module(args.filter_module, nginx)
    if module is not None:
        module = module.resolve()
        if not module.exists():
            print(f"FAIL: filter module not found: {module}", file=sys.stderr)
            return 1

    huge = 9223372036854775807  # ngx_int_t / int64_t max on a 64-bit build.

    matrix = [
        {
            "name": "1 default bufs",
            "http_directives": "",
            "srv_directives": "",
            "want_pass": True,
            "want_warning": False,
        },
        {
            "name": "2 cap-1 (8388607)",
            "http_directives": "",
            "srv_directives": "zstd_buffers 1 8388607;",
            "want_pass": True,
            "want_warning": False,
        },
        {
            "name": "3 cap exact (8388608)",
            "http_directives": "",
            "srv_directives": "zstd_buffers 1 8388608;",
            "want_pass": True,
            "want_warning": False,
        },
        {
            "name": "4 cap+1 (8388609)",
            "http_directives": "",
            "srv_directives": "zstd_buffers 1 8388609;",
            "want_pass": True,
            "want_warning": True,
            "min_total": 8388609,
            "max_warn_count": 1,
        },
        {
            "name": "5 product overflow",
            "http_directives": "",
            "srv_directives": f"zstd_buffers {huge} {huge};",
            "want_pass": False,
            "want_warning": False,
            "want_overflow_error": True,
        },
        {
            "name": "6 inherited from http block",
            "http_directives": "zstd_buffers 1 8388609;",
            "srv_directives": "",
            "want_pass": True,
            "want_warning": True,
            "min_total": 8388609,
            # Merged twice on this call graph: once into the (unused)
            # http-level location conf, once into the server/location
            # that actually serves -- both are real ngx_conf merges of
            # the SAME inherited value, so 2 is the correct count here,
            # not a duplicate-reporting defect (see arm 7 for that check,
            # which pins the explicit single-location case to exactly 1).
            "max_warn_count": 2,
        },
        {
            "name": "7 explicit large value warns once",
            "http_directives": "",
            "srv_directives": "zstd_buffers 1 16777217;",
            "want_pass": True,
            "want_warning": True,
            "min_total": 16777217,
            "max_warn_count": 1,
        },
    ]

    failures = []
    print("zstd_buffers aggregate bound policy matrix:")
    for i, arm in enumerate(matrix):
        name = arm.pop("name")
        f, summary = run_arm(nginx, module, args.port + i, name, **arm)
        failures += f
        print(summary)

    if failures:
        print("\nFAIL: zstd_buffers bound policy", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print(f"\nOK: zstd_buffers bound policy ({len(matrix)}/{len(matrix)} arms)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
