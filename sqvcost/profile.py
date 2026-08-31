"""Full verification-cost profile for one security level.

Given an adapter and a set of honest signatures, this computes:

  * the honest verify-cost distribution,
  * per honest signature, the worst-case attacker cost obtained by sweeping
    ``two_resp_length`` over 0..255,
  * the amplification factors:
      - ``own``    = worst_attacker_cost / this_signature's_honest_cost
      - ``median`` = worst_attacker_cost / median_honest_cost
  * the ceiling value (highest in-range ``two_resp_length``).

Amplification quantifies how much extra CPU an attacker can make a verifier
spend by choosing a public, structural byte -- it is a resource-cost
measurement of the *reference* implementation, not a cryptographic result.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field

from .adapter import Adapter
from .fields import LevelLayout
from .kat import KatRecord
from .sweep import FieldSweep, sweep_byte


@dataclass
class SignatureProfile:
    index: int
    honest_value: int
    honest_cost_ns: float
    worst_value: int
    worst_cost_ns: float
    ceiling_value: int | None

    @property
    def own_amplification(self) -> float:
        return self.worst_cost_ns / self.honest_cost_ns


@dataclass
class LevelProfile:
    level: int
    field_name: str
    response_length: int
    n_signatures: int
    signatures: list[SignatureProfile] = field(default_factory=list)

    # aggregate honest cost
    honest_median_ns: float = 0.0
    honest_min_ns: float = 0.0
    honest_max_ns: float = 0.0

    # aggregate worst-attacker cost
    worst_median_ns: float = 0.0
    worst_max_ns: float = 0.0

    # amplification vs the median honest cost
    amp_median: float = 0.0   # median over signatures of (worst / median_honest)
    amp_max: float = 0.0      # max over signatures of (worst / median_honest)
    # amplification vs each signature's own honest cost
    amp_own_median: float = 0.0
    amp_own_max: float = 0.0

    ceiling_value: int | None = None

    def to_dict(self) -> dict:
        return {
            "level": self.level,
            "field": self.field_name,
            "response_length": self.response_length,
            "n_signatures": self.n_signatures,
            "honest_us": {
                "median": round(self.honest_median_ns / 1e3, 1),
                "min": round(self.honest_min_ns / 1e3, 1),
                "max": round(self.honest_max_ns / 1e3, 1),
            },
            "worst_attacker_us": {
                "median": round(self.worst_median_ns / 1e3, 1),
                "max": round(self.worst_max_ns / 1e3, 1),
            },
            "amplification_vs_median_honest": {
                "median": round(self.amp_median, 3),
                "max": round(self.amp_max, 3),
            },
            "amplification_vs_own_honest": {
                "median": round(self.amp_own_median, 3),
                "max": round(self.amp_own_max, 3),
            },
            "ceiling_value": self.ceiling_value,
            "per_signature": [
                {
                    "index": s.index,
                    "honest_value": s.honest_value,
                    "honest_us": round(s.honest_cost_ns / 1e3, 1),
                    "worst_value": s.worst_value,
                    "worst_us": round(s.worst_cost_ns / 1e3, 1),
                    "own_amplification": round(s.own_amplification, 3),
                    "ceiling_value": s.ceiling_value,
                }
                for s in self.signatures
            ],
        }


def profile_signature(
    adapter: Adapter,
    layout: LevelLayout,
    rec: KatRecord,
    index: int,
    field_name: str = "two_resp_length",
) -> tuple[SignatureProfile, FieldSweep]:
    sweep = sweep_byte(
        adapter, layout, rec.pk_hex, rec.msg_hex, rec.sig_hex, field_name
    )
    worst = sweep.worst()
    prof = SignatureProfile(
        index=index,
        honest_value=sweep.honest_value,
        honest_cost_ns=sweep.honest_cost_ns,
        worst_value=worst.value,
        worst_cost_ns=worst.cost_ns,
        ceiling_value=sweep.ceiling_value(),
    )
    return prof, sweep


def profile_level(
    adapter: Adapter,
    layout: LevelLayout,
    records: list[KatRecord],
    field_name: str = "two_resp_length",
    progress=None,
) -> LevelProfile:
    profs: list[SignatureProfile] = []
    ceilings: list[int] = []
    for i, rec in enumerate(records):
        prof, sweep = profile_signature(adapter, layout, rec, i, field_name)
        profs.append(prof)
        if prof.ceiling_value is not None:
            ceilings.append(prof.ceiling_value)
        if progress is not None:
            progress(i + 1, len(records), prof)

    return summarize(layout, field_name, profs, ceilings)


def summarize(
    layout: LevelLayout,
    field_name: str,
    profs: list[SignatureProfile],
    ceilings: list[int],
) -> LevelProfile:
    honest = [p.honest_cost_ns for p in profs]
    worst = [p.worst_cost_ns for p in profs]
    honest_median = statistics.median(honest)

    amp_vs_median = [p.worst_cost_ns / honest_median for p in profs]
    amp_own = [p.own_amplification for p in profs]

    lp = LevelProfile(
        level=layout.level,
        field_name=field_name,
        response_length=layout.response_length,
        n_signatures=len(profs),
        signatures=profs,
        honest_median_ns=honest_median,
        honest_min_ns=min(honest),
        honest_max_ns=max(honest),
        worst_median_ns=statistics.median(worst),
        worst_max_ns=max(worst),
        amp_median=statistics.median(amp_vs_median),
        amp_max=max(amp_vs_median),
        amp_own_median=statistics.median(amp_own),
        amp_own_max=max(amp_own),
        ceiling_value=statistics.mode(ceilings) if ceilings else None,
    )
    return lp


def key_independence(
    adapter: Adapter,
    layout: LevelLayout,
    records: list[KatRecord],
    value: int,
    field_name: str = "two_resp_length",
    fix_backtracking: int | None = 0,
) -> dict:
    """Measure the cost of a fixed attacker value across distinct keys.

    Each record is a different key pair. To isolate the *key* as the only free
    variable we hold **both** public structural bytes that drive the isogeny
    work equal across every signature:

      * ``two_resp_length`` is set to ``value`` in every signature, and
      * ``backtracking`` is set to ``fix_backtracking`` (default 0).

    The verify.c:253 check is ``pow_dim2_deg_resp = response_length - value -
    backtracking``; fixing both bytes makes that quantity identical for all
    keys, so every signature does the *same* amount of isogeny work. Any
    residual spread in the measured cost is therefore attributable to the
    (secret) key or to timing noise -- not to the structural fields.

    A tight spread means the cost is a function of the public chosen bytes, not
    the secret key: an algorithmic-cost effect, not a secret-dependent side
    channel. (If ``fix_backtracking`` is None each signature keeps its own
    backtracking, which reintroduces a public-field dependence and is reported
    honestly via the in-range/instant-reject split below.)
    """
    fld = layout.field_by_name(field_name)
    bt = layout.field_by_name("backtracking")
    costs: list[dict] = []
    for i, rec in enumerate(records):
        base = bytearray.fromhex(rec.sig_hex)
        base[fld.offset] = value & 0xFF
        if fix_backtracking is not None:
            base[bt.offset] = fix_backtracking & 0xFF
        ans = adapter.query(rec.pk_hex, rec.msg_hex, base.hex(), qid=f"k{i}")
        costs.append(
            {
                "key_index": i,
                "pk_prefix": rec.pk_hex[:16],
                "accept": ans.accept,
                "cost_us": round(ans.cost_ns / 1e3, 3),
            }
        )
    cvals = [c["cost_us"] for c in costs]
    # Classify: an "in-range" key spent real work (cost within a factor of the
    # cohort's max), a "cheap" key exited early (range check, or an internal
    # order/basis check on the now-invalid content). The clusters are far apart,
    # so the split is unambiguous.
    hi = max(cvals)
    threshold = 0.5 * hi
    in_range = [c["cost_us"] for c in costs if c["cost_us"] >= threshold]
    cheap = [c["cost_us"] for c in costs if c["cost_us"] < threshold]

    # The key-independence headline: the MAIN cluster of full-work verifications
    # (costs within 10% of the median in-range cost). A minority of signatures
    # exit the isogeny computation partway (e.g. ~half cost) because their
    # public content triggers an earlier internal return -- that is
    # content-driven, not key-driven, and is reported separately.
    main_cluster: list[float] = []
    off_cluster: list[float] = []
    if in_range:
        med_ir = statistics.median(in_range)
        for c in in_range:
            (main_cluster if abs(c - med_ir) <= 0.10 * med_ir else off_cluster).append(c)

    def stats(vals: list[float]) -> dict:
        if not vals:
            return {"n": 0}
        med = statistics.median(vals)
        spread = max(vals) - min(vals)
        return {
            "n": len(vals),
            "min_us": round(min(vals), 3),
            "max_us": round(max(vals), 3),
            "median_us": round(med, 3),
            "spread_us": round(spread, 3),
            "spread_pct_of_median": round(100 * spread / med, 2) if med else None,
        }

    return {
        "level": layout.level,
        "field": field_name,
        "fixed_value": value,
        "fixed_backtracking": fix_backtracking,
        "n_keys": len(costs),
        # The headline: the main cluster of full-work verifications. A tight
        # spread here is the "cost tracks the public value, not the key" result.
        "main_cluster": stats(main_cluster),
        # Full-work verifications that exited partway (content-driven, e.g. half
        # cost). Empty for most values.
        "partial_work": stats(off_cluster),
        # All full-work verifications (main + partial), threshold >= 0.5*max.
        "in_range": stats(in_range),
        # Keys that exited early/cheaply (range check or internal order check).
        "early_exit": stats(cheap),
        # Overall, for transparency (mixes every cluster).
        "overall_spread_us": round(max(cvals) - min(cvals), 3),
        "per_key": costs,
    }
