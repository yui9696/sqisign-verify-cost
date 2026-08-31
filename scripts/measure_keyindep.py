#!/usr/bin/env python3
"""Recompute only results/key-independence.json (fast; no full profile).

Same code paths as scripts/measure.py, isolated so the key-independence
metric can be regenerated without the ~15-minute full sweep.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqvcost.adapter import Adapter
from sqvcost.baseline import OPENSSL_VERSION
from sqvcost.fields import layout
from sqvcost.kat import load_kat
from sqvcost.profile import key_independence

KAT_NAME = {1: "PQCsignKAT_353_SQIsign_lvl1.rsp",
            3: "PQCsignKAT_529_SQIsign_lvl3.rsp",
            5: "PQCsignKAT_701_SQIsign_lvl5.rsp"}
ORACLE = {1: "timing_lvl1", 3: "timing_lvl3", 5: "timing_lvl5"}
# Two fixed attacker values per level: one moderate, one near the ceiling.
VALUES = {1: [110, 124], 3: [110, 189], 5: [110, 250]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--oracle-dir", required=True)
    ap.add_argument("--kat-dir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--n", type=int, default=20)
    args = ap.parse_args()

    env = {
        "machine": platform.platform(),
        "python": platform.python_version(),
        "openssl": OPENSSL_VERSION,
        "reference_commit": "dd133d7",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    out = {"_meta": env, "levels": {}}
    for level in (1, 3, 5):
        L = layout(level)
        records = load_kat(os.path.join(args.kat_dir, KAT_NAME[level]),
                           L.signature_bytes, limit=args.n)
        oracle = os.path.join(args.oracle_dir, ORACLE[level])
        with Adapter.from_command(oracle) as ad:
            lvl = {}
            for v in VALUES[level]:
                ki = key_independence(ad, L, records, v)
                lvl[str(v)] = ki
                mc = ki["main_cluster"]
                print(f"[L{level} value={v}] main_cluster n={mc['n']} "
                      f"median={mc.get('median_us')}us "
                      f"spread={mc.get('spread_us')}us "
                      f"({mc.get('spread_pct_of_median')}% of median) ; "
                      f"partial_work n={ki['partial_work']['n']} "
                      f"early_exit n={ki['early_exit']['n']}", flush=True)
            out["levels"][f"L{level}"] = lvl

    with open(os.path.join(args.out, "key-independence.json"), "w") as f:
        json.dump(out, f, indent=2)
    print("DONE", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
