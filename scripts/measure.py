#!/usr/bin/env python3
"""Generate the committed measured results by driving the real timing oracle.

This is the exact run that produced results/*.json in this repository. It uses
the same sqvcost code paths as the CLI. Point --oracle-dir and --kat-dir at a
built reference oracle to reproduce.
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
from sqvcost.baseline import MEASURED_BASELINES, OPENSSL_VERSION, ratios
from sqvcost.fields import layout
from sqvcost.kat import load_kat
from sqvcost.profile import key_independence, profile_level
from sqvcost.report import ascii_curve
from sqvcost.sweep import sweep_byte

KAT_NAME = {1: "PQCsignKAT_353_SQIsign_lvl1.rsp",
            3: "PQCsignKAT_529_SQIsign_lvl3.rsp",
            5: "PQCsignKAT_701_SQIsign_lvl5.rsp"}
ORACLE = {1: "timing_lvl1", 3: "timing_lvl3", 5: "timing_lvl5"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--oracle-dir", required=True)
    ap.add_argument("--kat-dir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--curve-index", type=int, default=0)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    env = {
        "machine": platform.platform(),
        "python": platform.python_version(),
        "openssl": OPENSSL_VERSION,
        "reference_commit": "dd133d7",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    amp = {"_meta": env, "levels": {}}
    curves = {"_meta": env, "levels": {}}
    keyindep = {"_meta": env, "levels": {}}

    for level in (1, 3, 5):
        L = layout(level)
        kat = os.path.join(args.kat_dir, KAT_NAME[level])
        oracle = os.path.join(args.oracle_dir, ORACLE[level])
        records = load_kat(kat, L.signature_bytes, limit=args.n)
        print(f"[L{level}] {len(records)} signatures via {oracle}", flush=True)

        with Adapter.from_command(oracle) as ad:
            def prog(i, n, prof):
                print(f"  [L{level} {i}/{n}] honest={prof.honest_cost_ns/1e3:.0f}us "
                      f"worst(v={prof.worst_value})={prof.worst_cost_ns/1e3:.0f}us "
                      f"own_amp={prof.own_amplification:.3f}x", flush=True)
            lp = profile_level(ad, L, records, progress=prog)
            amp["levels"][f"L{level}"] = lp.to_dict()

            # representative curve
            rec = records[args.curve_index]
            sw = sweep_byte(ad, L, rec.pk_hex, rec.msg_hex, rec.sig_hex, "two_resp_length")
            curves["levels"][f"L{level}"] = {
                "signature_index": args.curve_index,
                "honest_value": sw.honest_value,
                "ceiling_value": sw.ceiling_value(),
                "samples": [
                    {"value": s.value, "accept": s.accept, "cost_ns": round(s.cost_ns, 1)}
                    for s in sw.samples
                ],
            }
            if level == 5:
                curves["levels"]["L5"]["ascii"] = ascii_curve(sw)

            # key independence at two fixed attacker values
            ki = {}
            for v in (124, layout(level).response_length - 3):
                ki[str(v)] = key_independence(ad, L, records, v)
            keyindep["levels"][f"L{level}"] = ki

    # baseline ratios on the measured L1 numbers
    l1 = amp["levels"]["L1"]
    l1_honest_us = l1["honest_us"]["median"]
    l1_worst_us = l1["worst_attacker_us"]["max"]
    amp["baseline_context"] = {
        "openssl": OPENSSL_VERSION,
        "baselines_us": {k: v.verify_us for k, v in MEASURED_BASELINES.items()},
        "l1_honest_us": l1_honest_us,
        "l1_worst_us": l1_worst_us,
        "l1_honest_ratios": ratios(l1_honest_us),
        "l1_worst_ratios": ratios(l1_worst_us),
    }

    with open(os.path.join(args.out, "amplification.json"), "w") as f:
        json.dump(amp, f, indent=2)
    with open(os.path.join(args.out, "two_resp_length-curve.json"), "w") as f:
        json.dump(curves, f, indent=2)
    with open(os.path.join(args.out, "key-independence.json"), "w") as f:
        json.dump(keyindep, f, indent=2)

    # CSV of the L5 curve
    l5 = curves["levels"]["L5"]["samples"]
    with open(os.path.join(args.out, "two_resp_length-curve.csv"), "w") as f:
        f.write("level,value,verdict,cost_ns\n")
        for lvl in (1, 3, 5):
            for s in curves["levels"][f"L{lvl}"]["samples"]:
                f.write(f"{lvl},{s['value']},{'accept' if s['accept'] else 'reject'},{s['cost_ns']}\n")

    print("DONE", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
