#!/usr/bin/env python3
"""Drop vendored-nginx results from a CodeQL SARIF file, in place.

CodeQL's `paths`/`paths-ignore` config keys apply only to interpreted
languages, or to a compiled language analyzed without building it. This
project runs a full traced `make` of C/C++, so those keys are inert and
nginx-core findings reach the Security tab on every mainline bump. nginx
is compiled into the binary via --add-module, so it cannot be kept out of
the database either; scoping therefore happens here, after analysis.

Results whose location cannot be determined are kept, never dropped: an
unplaceable finding is a reason to look, not to hide.
"""

import json
import re
import sys

# Vendored nginx is extracted into the workspace as nginx-<version>/.
VENDORED = re.compile(r"^nginx-[0-9]")


def result_uri(result):
    for location in result.get("locations", []):
        uri = (
            location.get("physicalLocation", {}).get("artifactLocation", {}).get("uri")
        )
        if uri:
            return uri
    return None


def filter_sarif(sarif):
    removed = kept = unlocated = 0
    for run in sarif.get("runs", []):
        keep = []
        for result in run.get("results", []):
            uri = result_uri(result)
            if uri is None:
                unlocated += 1
                keep.append(result)
            elif VENDORED.match(uri):
                removed += 1
            else:
                kept += 1
                keep.append(result)
        run["results"] = keep
    return removed, kept, unlocated


def _result(uri):
    """A minimal SARIF result; uri=None models a finding with no location."""
    if uri is None:
        return {"ruleId": "unplaceable", "locations": []}
    return {
        "ruleId": "placed",
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
    }


def selftest():
    """Negative controls for the scoping rule this filter exists to enforce.

    The dangerous failure is not "it dropped too little" -- it is "it dropped
    something it should have kept", because a dropped result never reaches the
    Security tab and nothing reports its absence. So every case below asserts
    a KEPT result too, and the unlocated case is the one that would silently
    hide a real finding if a future edit made `uri is None` fall into the
    vendored branch.
    """
    cases = [
        # label, uris, expected (removed, kept, unlocated)
        ("vendored nginx dropped", ["nginx-1.29.4/src/core/ngx_string.c"], (1, 0, 0)),
        ("module source kept", ["filter/ngx_http_zstd_filter_module.c"], (0, 1, 0)),
        ("unlocated result kept", [None], (0, 0, 1)),
        (
            "mixed run scoped correctly",
            [
                "nginx-1.29.4/src/http/ngx_http.c",
                "nginx-1.28.0/src/core/ngx_cycle.c",
                "filter/ngx_http_zstd_filter_module.c",
                "static/ngx_http_zstd_static_module.c",
                None,
            ],
            (2, 2, 1),
        ),
        # `nginx-` alone must not match: the anchor is `nginx-<digit>`, so a
        # module-owned path that merely starts with the vendor prefix stays.
        ("nginx-like module path kept", ["nginx-helpers/ngx_zstd_util.c"], (0, 1, 0)),
        # Absolute or dot-prefixed paths are NOT vendored-matched by design:
        # the regex is anchored, and over-matching would drop module results.
        ("non-anchored vendored path kept", ["build/nginx-1.29.4/src/x.c"], (0, 1, 0)),
        ("empty run", [], (0, 0, 0)),
    ]
    failed = False
    for label, uris, want in cases:
        sarif = {"runs": [{"results": [_result(u) for u in uris]}]}
        got = filter_sarif(sarif)
        survivors = [r["ruleId"] for r in sarif["runs"][0]["results"]]
        if got != want:
            print(f"FAIL {label}: expected {want}, got {got}", file=sys.stderr)
            failed = True
        elif len(survivors) != want[1] + want[2]:
            print(f"FAIL {label}: survivor count {len(survivors)}", file=sys.stderr)
            failed = True
        else:
            print(f"ok   {label}")

    # Multi-run SARIF: each run is filtered independently and none is dropped.
    sarif = {
        "runs": [
            {"results": [_result("nginx-1.29.4/src/core/ngx_cycle.c")]},
            {"results": [_result("filter/ngx_http_zstd_filter_module.c")]},
        ]
    }
    if filter_sarif(sarif) != (1, 1, 0) or len(sarif["runs"]) != 2:
        print("FAIL multi-run SARIF not filtered per run", file=sys.stderr)
        failed = True
    else:
        print("ok   multi-run SARIF filtered per run")

    # The `runs` key must survive so upload-sarif still sees a valid document.
    sarif = {"version": "2.1.0", "runs": [{"results": []}]}
    filter_sarif(sarif)
    if "runs" not in sarif or "results" not in sarif["runs"][0]:
        print("FAIL filter destroyed SARIF structure", file=sys.stderr)
        failed = True
    else:
        print("ok   SARIF structure preserved")
    return int(failed)


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        return selftest()
    if len(sys.argv) != 2:
        print(
            "usage: filter-codeql-sarif.py <sarif-file> | --selftest",
            file=sys.stderr,
        )
        return 2
    path = sys.argv[1]
    with open(path, encoding="utf-8") as fh:
        sarif = json.load(fh)
    removed, kept, unlocated = filter_sarif(sarif)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh)
    print(f"nginx-core results removed: {removed}")
    print(f"module results kept:        {kept}")
    print(f"unlocated results kept:     {unlocated}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
