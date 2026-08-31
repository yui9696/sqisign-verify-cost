"""Command-line interface for sqisign-verify-cost.

Subcommands:
  profile   full cost profile for a level (amplification table + per-signature)
  sweep     single-field cost curve (value -> verdict, cost)
  curve     the two_resp_length cost curve as CSV-ready data
  baseline  print / re-measure the RSA & ECDSA verify baselines
"""

from __future__ import annotations

import argparse
import csv
import json
import sys

from . import __version__
from .adapter import Adapter
from .baseline import MEASURED_BASELINES, OPENSSL_VERSION, measure_openssl
from .fields import layout
from .kat import load_kat
from .profile import key_independence, profile_level
from .report import ascii_curve, profile_markdown
from .sweep import sweep_byte


def _eprint(*a: object) -> None:
    print(*a, file=sys.stderr)


def _load_records(kat_path: str, level: int, limit: int | None):
    L = layout(level)
    return load_kat(kat_path, L.signature_bytes, limit=limit), L


def cmd_profile(args: argparse.Namespace) -> int:
    records, L = _load_records(args.kat, args.level, args.limit)
    if not records:
        _eprint("no KAT records loaded")
        return 2

    def progress(i: int, n: int, prof) -> None:
        _eprint(f"  [{i}/{n}] honest={prof.honest_cost_ns/1e3:.0f}us "
                f"worst(v={prof.worst_value})={prof.worst_cost_ns/1e3:.0f}us "
                f"own_amp={prof.own_amplification:.2f}x")

    with Adapter.from_command(args.adapter) as ad:
        lp = profile_level(ad, L, records, field_name=args.field,
                           progress=None if args.quiet else progress)

    if args.json:
        print(json.dumps(lp.to_dict(), indent=2))
    else:
        d = lp.to_dict()
        print(f"Level L{lp.level}  field={lp.field_name}  n={lp.n_signatures}  "
              f"response_length={lp.response_length}")
        print(f"  honest verify (ms):   median={d['honest_us']['median']/1e3:.2f}  "
              f"min={d['honest_us']['min']/1e3:.2f}  max={d['honest_us']['max']/1e3:.2f}")
        print(f"  attacker worst (ms):  median={d['worst_attacker_us']['median']/1e3:.2f}  "
              f"max={d['worst_attacker_us']['max']/1e3:.2f}")
        print(f"  amplification vs median-honest:  median={lp.amp_median:.2f}x  max={lp.amp_max:.2f}x")
        print(f"  amplification vs own-honest:     median={lp.amp_own_median:.2f}x  max={lp.amp_own_max:.2f}x")
        print(f"  ceiling value: {lp.ceiling_value}")
    return 0


def cmd_sweep(args: argparse.Namespace) -> int:
    records, L = _load_records(args.kat, args.level, limit=(args.index + 1))
    if args.index >= len(records):
        _eprint(f"index {args.index} out of range ({len(records)} records)")
        return 2
    rec = records[args.index]
    with Adapter.from_command(args.adapter) as ad:
        sw = sweep_byte(ad, L, rec.pk_hex, rec.msg_hex, rec.sig_hex, args.field)

    if args.json:
        print(json.dumps({
            "level": L.level,
            "field": sw.field_name,
            "honest_value": sw.honest_value,
            "honest_us": round(sw.honest_cost_ns / 1e3, 1),
            "ceiling_value": sw.ceiling_value(),
            "samples": [
                {"value": s.value, "accept": s.accept, "cost_us": round(s.cost_ns / 1e3, 1)}
                for s in sw.samples
            ],
        }, indent=2))
    else:
        print(ascii_curve(sw))
        print(f"honest value={sw.honest_value}  ceiling={sw.ceiling_value()}  "
              f"worst value={sw.worst().value} @ {sw.worst().cost_ns/1e3:.0f}us")
    return 0


def cmd_curve(args: argparse.Namespace) -> int:
    records, L = _load_records(args.kat, args.level, limit=(args.index + 1))
    rec = records[args.index]
    with Adapter.from_command(args.adapter) as ad:
        sw = sweep_byte(ad, L, rec.pk_hex, rec.msg_hex, rec.sig_hex, "two_resp_length")
    w = csv.writer(sys.stdout)
    w.writerow(["value", "verdict", "cost_ns", "cost_us"])
    for s in sw.samples:
        w.writerow([s.value, "accept" if s.accept else "reject",
                    f"{s.cost_ns:.1f}", f"{s.cost_ns/1e3:.1f}"])
    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    if args.measure:
        try:
            base = measure_openssl(seconds=args.seconds)
            note = "measured now via openssl speed"
        except Exception as exc:  # noqa: BLE001
            _eprint(f"openssl measurement failed: {exc}")
            return 2
    else:
        base = MEASURED_BASELINES
        note = f"recorded ({OPENSSL_VERSION})"
    print(f"# classical verify baselines ({note})")
    for name, b in base.items():
        print(f"  {b.name:22s} {b.verify_us:8.1f} us   {b.verify_per_s:12.1f} /s")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sqisign-verify-cost", description=__doc__)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp: argparse.ArgumentParser, need_kat: bool = True) -> None:
        sp.add_argument("--adapter", required=True,
                        help="command that runs the verify-timing adapter")
        sp.add_argument("--level", type=int, required=True, choices=[1, 3, 5])
        if need_kat:
            sp.add_argument("--kat", required=True, help="path to a KAT .rsp file")

    sp = sub.add_parser("profile", help="full cost profile for a level")
    common(sp)
    sp.add_argument("--field", default="two_resp_length")
    sp.add_argument("--limit", type=int, default=20, help="signatures to profile")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--quiet", action="store_true")
    sp.set_defaults(func=cmd_profile)

    sp = sub.add_parser("sweep", help="single-field cost curve for one signature")
    common(sp)
    sp.add_argument("--field", default="two_resp_length")
    sp.add_argument("--index", type=int, default=0, help="KAT record index")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_sweep)

    sp = sub.add_parser("curve", help="two_resp_length cost curve as CSV")
    common(sp)
    sp.add_argument("--index", type=int, default=0)
    sp.set_defaults(func=cmd_curve)

    sp = sub.add_parser("baseline", help="RSA/ECDSA verify baselines for context")
    sp.add_argument("--measure", action="store_true", help="re-run openssl speed now")
    sp.add_argument("--seconds", type=int, default=1)
    sp.set_defaults(func=cmd_baseline)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
