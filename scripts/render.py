#!/usr/bin/env python3
"""Render results/amplification.md and fill the README tables from the JSON.

Pure presentation over the committed measured JSON -- runs offline, no adapter.
"""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from sqvcost.baseline import MEASURED_BASELINES  # noqa: E402


def amp_table(levels: dict) -> str:
    rows = [
        "| Level | Honest median (ms) | Attacker worst (ms) | Amp. median | Amp. max | Ceiling |",
        "|-------|--------------------|---------------------|-------------|----------|---------|",
    ]
    for k in ("L1", "L3", "L5"):
        v = levels[k]
        rows.append(
            f"| {k} | {v['honest_us']['median']/1e3:.2f} | {v['worst_attacker_us']['max']/1e3:.2f} "
            f"| {v['amplification_vs_median_honest']['median']:.2f}x "
            f"| {v['amplification_vs_median_honest']['max']:.2f}x "
            f"| {v['ceiling_value']} |"
        )
    return "\n".join(rows)


def baseline_table(bc: dict) -> str:
    hr = bc["l1_honest_ratios"]
    wr = bc["l1_worst_ratios"]
    b = bc["baselines_us"]
    return "\n".join([
        "| Scheme | Verify cost | vs SQIsign L1 |",
        "|--------|-------------|---------------|",
        f"| RSA-2048 verify | {b['rsa2048']:.1f} us | 1x |",
        f"| ECDSA P-256 verify | {b['ecdsap256']:.1f} us | 1x |",
        f"| SQIsign L1 honest | {bc['l1_honest_us']:.0f} us "
        f"| {hr['rsa2048']:.0f}x RSA, {hr['ecdsap256']:.0f}x ECDSA |",
        f"| SQIsign L1 attacker-worst | {bc['l1_worst_us']:.0f} us "
        f"| {wr['rsa2048']:.0f}x RSA, {wr['ecdsap256']:.0f}x ECDSA |",
    ])


def main() -> int:
    amp = json.load(open(os.path.join(ROOT, "results", "amplification.json")))
    curve = json.load(open(os.path.join(ROOT, "results", "two_resp_length-curve.json")))
    ki = json.load(open(os.path.join(ROOT, "results", "key-independence.json")))
    meta = amp["_meta"]
    at = amp_table(amp["levels"])
    bt = baseline_table(amp["baseline_context"])
    l5_ascii = curve["levels"]["L5"].get("ascii", "(no ascii)")

    # ---- amplification.md -------------------------------------------------
    md = [
        "# Measured amplification",
        "",
        f"Machine: `{meta['machine']}`  ",
        f"Reference: SQIsign commit `{meta['reference_commit']}`  ",
        f"OpenSSL: {meta['openssl']}  ",
        f"Generated: {meta['timestamp_utc']} (by `scripts/measure.py`)",
        "",
        "All numbers below were produced by driving the reference verify-timing",
        "adapter on the machine above. This measures a resource-cost property of",
        "a **non-production reference** implementation; it is not a break and not",
        "a secret-dependent side channel. See the repository README.",
        "",
        "## Amplification by level (20 KAT signatures each)",
        "",
        "Attacker-swept byte: `two_resp_length`. Amplification = attacker-worst",
        "cost / median-honest cost.",
        "",
        at,
        "",
        "Amplification rises with the security level. Some individual signatures",
        "show ~1.0x because their honest `two_resp_length` is already near the",
        "ceiling (no headroom) -- see the per-signature arrays in",
        "`amplification.json`.",
        "",
        "## Classical verify baselines (same machine)",
        "",
        bt,
        "",
        "## L5 cost vs `two_resp_length` (representative signature)",
        "",
        "The ramp up to the ceiling, then the free-reject cliff:",
        "",
        "```",
        l5_ascii,
        "```",
        "",
        "## Cost tracks the public value, not the secret key",
        "",
        "At a fixed attacker value, the main cluster of full-work verifications",
        "across 20 distinct keys is tight (spread as a percentage of the median):",
        "",
        "| Level | Fixed value | Main-cluster keys | Median (ms) | Spread | Spread % |",
        "|-------|-------------|-------------------|-------------|--------|----------|",
    ]
    for lvl in ("L1", "L3", "L5"):
        for val, r in ki["levels"][lvl].items():
            mc = r["main_cluster"]
            md.append(
                f"| {lvl} | {val} | {mc['n']} | {mc['median_us']/1e3:.2f} "
                f"| {mc['spread_us']:.0f} us | {mc['spread_pct_of_median']}% |"
            )
    md += [
        "",
        "The tight spread (~1-3%) across distinct keys shows the cost is governed",
        "by the public chosen bytes, not the secret key. A minority of signatures",
        "exit the (now-invalid) computation earlier -- counted as `partial_work`",
        "or `early_exit` in `key-independence.json` -- which is content-driven,",
        "not key-driven.",
        "",
    ]
    with open(os.path.join(ROOT, "results", "amplification.md"), "w") as f:
        f.write("\n".join(md))
    print("wrote results/amplification.md")

    # ---- fill README tables ----------------------------------------------
    readme_path = os.path.join(ROOT, "README.md")
    text = open(readme_path).read()
    text = text.replace("<!-- AMPLIFICATION_TABLE -->", at)
    text = text.replace("<!-- BASELINE_TABLE -->", bt)
    open(readme_path, "w").write(text)
    print("filled README tables")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
