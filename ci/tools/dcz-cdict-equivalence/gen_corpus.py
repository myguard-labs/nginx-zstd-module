#!/usr/bin/env python3
"""Generate dict.bin / body.bin for the dcz CDict-vs-refPrefix probes.

The corpus must be realistic text-like data. A degenerate periodic buffer
compresses to a few dozen bytes and hides the refCDict/refPrefix divergence
entirely -- that artifact is what previously made the substitution look
byte-safe at levels 3-19.
"""

import random

WORDS = [
    "<div>",
    "</div>",
    "class=",
    '"container"',
    "user",
    "id",
    "name",
    "value",
    "true",
    "false",
    "null",
    "data",
    "<span>",
    "</span>",
    "href",
    "https://example.com/",
    "item",
    "list",
    "2026",
    "response",
    "header",
    "content",
    "zstd",
    "dictionary",
    "compression",
    "the",
    "and",
    "of",
    "a",
]


def gen(n, seed):
    rnd = random.Random(seed)
    out, length = [], 0
    while length < n:
        w = rnd.choice(WORDS) + rnd.choice([" ", "\n", ""])
        out.append(w)
        length += len(w)
    return "".join(out)[:n].encode()


if __name__ == "__main__":
    # Distinct seeds: the body shares the dictionary's vocabulary and
    # statistics without being a literal copy of it.
    with open("dict.bin", "wb") as f:
        f.write(gen(1 << 20, 7))
    with open("body.bin", "wb") as f:
        f.write(gen(1 << 18, 99))
    print("wrote dict.bin (1 MiB) and body.bin (256 KiB)")
