"""Sweep a signature field and record the verifier's cost per value.

Given an adapter and a *base* (honest, verifying) signature, these helpers
mutate one structural byte over a range of values and report, for each value,
the verdict and the cost the verifier spent. Nothing is decrypted or forged;
the mutated signatures do not verify (they reject), but the cost is spent
*before* the rejection, which is exactly the resource-exhaustion surface being
measured.
"""

from __future__ import annotations

from dataclasses import dataclass

from .adapter import Adapter, Query
from .fields import LevelLayout


@dataclass(frozen=True)
class Sample:
    """One measured point: field set to ``value`` -> (verdict, cost)."""

    value: int
    accept: bool
    cost_ns: float


@dataclass(frozen=True)
class FieldSweep:
    field_name: str
    honest_value: int
    honest_cost_ns: float
    samples: list[Sample]

    def in_range(self) -> list[Sample]:
        """Samples the verifier did *not* instantly reject.

        A value is "in range" when its cost is a non-trivial fraction of the
        honest cost, i.e. the verifier proceeded past the early length check
        rather than bailing out cheaply. The threshold (half the honest cost)
        is deliberately loose; the instant-reject cliff is orders of magnitude
        below honest cost, so the classification is not sensitive to it.
        """
        thresh = 0.5 * self.honest_cost_ns
        return [s for s in self.samples if s.cost_ns >= thresh]

    def worst(self) -> Sample:
        """The most expensive value the attacker can choose."""
        return max(self.samples, key=lambda s: s.cost_ns)

    def ceiling_value(self) -> int | None:
        """Highest value that is still 'in range' (below the reject cliff)."""
        vals = [s.value for s in self.in_range()]
        return max(vals) if vals else None


def _base_bytes(sig_hex: str) -> bytearray:
    return bytearray.fromhex(sig_hex)


def _with_byte(base: bytearray, offset: int, value: int) -> str:
    b = bytearray(base)
    b[offset] = value & 0xFF
    return b.hex()


def sweep_byte(
    adapter: Adapter,
    layout: LevelLayout,
    pk_hex: str,
    msg_hex: str,
    sig_hex: str,
    field_name: str,
    values: range | list[int] | None = None,
) -> FieldSweep:
    """Sweep a single-byte structural field over ``values`` (default 0..255).

    The honest cost is measured from the unmodified signature.
    """
    fld = layout.field_by_name(field_name)
    if fld.length != 1:
        raise ValueError(f"sweep_byte only handles 1-byte fields, {field_name} is {fld.length}")
    if values is None:
        values = range(256)

    base = _base_bytes(sig_hex)
    honest_value = base[fld.offset]

    # Measure the honest signature.
    honest = adapter.query(pk_hex, msg_hex, sig_hex, qid="honest")

    queries: list[Query] = []
    for v in values:
        queries.append(Query(f"v{v}", pk_hex, msg_hex, _with_byte(base, fld.offset, v)))
    answers = adapter.batch(queries)

    samples = [
        Sample(value=v, accept=a.accept, cost_ns=a.cost_ns)
        for v, a in zip(values, answers)
    ]
    return FieldSweep(
        field_name=field_name,
        honest_value=honest_value,
        honest_cost_ns=honest.cost_ns,
        samples=samples,
    )


def worst_case(
    adapter: Adapter,
    layout: LevelLayout,
    pk_hex: str,
    msg_hex: str,
    sig_hex: str,
    field_name: str = "two_resp_length",
) -> Sample:
    """Find the maximum-cost value for a single structural byte."""
    return sweep_byte(adapter, layout, pk_hex, msg_hex, sig_hex, field_name).worst()
