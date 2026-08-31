"""Sweep + profile logic against the synthetic stub oracle.

The stub models cost = BASE + SLOPE*min(value, CEILING), instant-reject above.
These tests assert the profiler recovers the ceiling and the amplification the
model implies -- no C build required.
"""

import os
import sys

import pytest

from sqvcost.adapter import Adapter
from sqvcost.fields import layout
from sqvcost.kat import KatRecord
from sqvcost.profile import key_independence, profile_level, summarize
from sqvcost.profile import SignatureProfile
from sqvcost.sweep import sweep_byte

STUB = os.path.join(os.path.dirname(__file__), "stub_oracle.py")

# Mirror of the stub's model, for computing expected values.
BASE = {1: 2_400_000.0, 3: 6_900_000.0, 5: 14_000_000.0}
SLOPE = {1: 10_000.0, 3: 30_000.0, 5: 68_000.0}
CEIL = {1: 126, 3: 192, 5: 253}


def stub_cmd(level):
    return [sys.executable, STUB, str(level)]


def make_record(level, honest_value):
    L = layout(level)
    sig = bytearray(L.signature_bytes)
    sig[L.field_by_name("two_resp_length").offset] = honest_value
    return KatRecord(count=0, msg_hex="aa", pk_hex="00" * L.public_key_bytes, sig_hex=sig.hex())


@pytest.mark.parametrize("level", [1, 3, 5])
def test_sweep_recovers_ceiling(level):
    L = layout(level)
    rec = make_record(level, honest_value=1)
    with Adapter.from_command(stub_cmd(level)) as ad:
        sw = sweep_byte(ad, L, rec.pk_hex, rec.msg_hex, rec.sig_hex, "two_resp_length")
    assert sw.ceiling_value() == CEIL[level]
    # worst value is the ceiling (highest in-range)
    assert sw.worst().value == CEIL[level]
    assert sw.worst().cost_ns == pytest.approx(BASE[level] + SLOPE[level] * CEIL[level])


def test_sweep_honest_value_and_cost():
    L = layout(1)
    rec = make_record(1, honest_value=40)
    with Adapter.from_command(stub_cmd(1)) as ad:
        sw = sweep_byte(ad, L, rec.pk_hex, rec.msg_hex, rec.sig_hex, "two_resp_length")
    assert sw.honest_value == 40
    assert sw.honest_cost_ns == pytest.approx(BASE[1] + SLOPE[1] * 40)


def test_profile_amplification_matches_model():
    level = 1
    L = layout(level)
    # honest value 1 -> plenty of headroom to the ceiling
    records = [make_record(level, honest_value=1) for _ in range(5)]
    with Adapter.from_command(stub_cmd(level)) as ad:
        lp = profile_level(ad, L, records)
    honest = BASE[level] + SLOPE[level] * 1
    worst = BASE[level] + SLOPE[level] * CEIL[level]
    assert lp.amp_own_median == pytest.approx(worst / honest, rel=1e-6)
    assert lp.amp_max == pytest.approx(worst / honest, rel=1e-6)
    assert lp.ceiling_value == CEIL[level]


def test_profile_no_headroom_gives_unit_amplification():
    level = 1
    L = layout(level)
    # honest value already at the ceiling -> attacker can't do better
    rec = make_record(level, honest_value=CEIL[level])
    with Adapter.from_command(stub_cmd(level)) as ad:
        lp = profile_level(ad, L, [rec])
    assert lp.amp_own_max == pytest.approx(1.0, abs=1e-9)


def test_key_independence_zero_spread_in_model():
    # The stub cost depends only on the value, not on the (fake) key bytes,
    # so spread must be exactly zero -> demonstrates the metric.
    level = 3
    L = layout(level)
    records = []
    for k in range(10):
        sig = bytearray(L.signature_bytes)
        # vary "key" region (E_aux_A) but not two_resp_length
        sig[0] = k
        sig[L.field_by_name("two_resp_length").offset] = 1
        records.append(KatRecord(0, "aa", "00" * L.public_key_bytes, sig.hex()))
    with Adapter.from_command(stub_cmd(level)) as ad:
        ki = key_independence(ad, L, records, value=120)
    assert ki["n_keys"] == 10
    # value 120 <= ceiling for this level, so all 10 keys are in range and,
    # since the stub cost ignores the key bytes, the spread is exactly zero.
    assert ki["in_range"]["n"] == 10
    assert ki["in_range"]["spread_us"] == pytest.approx(0.0, abs=1e-6)
