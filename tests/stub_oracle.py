#!/usr/bin/env python3
"""A pure-Python stand-in for the timing adapter, for tests and CI.

Speaks the same line protocol as oracle/timing.c but computes a *synthetic*
cost model instead of running any cryptography:

    cost_ns = BASE + K * min(two_resp_length, CEILING)      (in range)
    cost_ns = REJECT_NS                                     (above CEILING)

This lets the profiler be tested end-to-end without building the C reference.
The ceiling and slope are chosen per level so tests can assert the profiler
recovers them.

Usage: stub_oracle.py <level>
"""
from __future__ import annotations

import sys

# Layout offsets must match sqvcost.fields (two_resp_length byte position).
TWO_RESP_OFFSET = {1: 65, 3: 97, 5: 129}
CEILING = {1: 126, 3: 192, 5: 253}
BASE_NS = {1: 2_400_000.0, 3: 6_900_000.0, 5: 14_000_000.0}
SLOPE_NS = {1: 10_000.0, 3: 30_000.0, 5: 68_000.0}
REJECT_NS = 5_000.0


def main() -> int:
    level = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    off = TWO_RESP_OFFSET[level]
    ceil = CEILING[level]
    base = BASE_NS[level]
    slope = SLOPE_NS[level]

    for line in sys.stdin:
        parts = line.split()
        if not parts:
            continue
        qid = parts[0]
        if len(parts) < 4:
            print(f"{qid} error_input", flush=True)
            continue
        _id, _pk, _msg, sig = parts
        try:
            sig_bytes = bytes.fromhex(sig) if sig != "-" else b""
        except ValueError:
            print(f"{qid} error_hex", flush=True)
            continue
        v = sig_bytes[off] if len(sig_bytes) > off else 0
        if v <= ceil:
            cost = base + slope * v
            verdict = "accept"
        else:
            cost = REJECT_NS
            verdict = "reject"
        print(f"{qid} {verdict} {cost:.1f}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
