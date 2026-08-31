"""Amplification arithmetic on hand-made data (no adapter)."""

import pytest

from sqvcost.fields import layout
from sqvcost.profile import SignatureProfile, summarize


def sp(index, honest, worst, worst_value=126, ceiling=126):
    return SignatureProfile(
        index=index,
        honest_value=1,
        honest_cost_ns=honest,
        worst_value=worst_value,
        worst_cost_ns=worst,
        ceiling_value=ceiling,
    )


def test_own_amplification():
    s = sp(0, honest=2_000_000, worst=3_000_000)
    assert s.own_amplification == pytest.approx(1.5)


def test_summarize_median_and_max():
    L = layout(1)
    profs = [
        sp(0, 2_000_000, 3_000_000),  # own 1.50
        sp(1, 2_000_000, 3_200_000),  # own 1.60
        sp(2, 2_000_000, 2_000_000),  # own 1.00 (no headroom)
    ]
    lp = summarize(L, "two_resp_length", profs, ceilings=[126, 126, 126])
    # median honest = 2_000_000
    assert lp.honest_median_ns == 2_000_000
    # amp vs median: 1.5, 1.6, 1.0 -> median 1.5, max 1.6
    assert lp.amp_median == pytest.approx(1.5)
    assert lp.amp_max == pytest.approx(1.6)
    # own amp: median 1.5, max 1.6
    assert lp.amp_own_median == pytest.approx(1.5)
    assert lp.amp_own_max == pytest.approx(1.6)
    assert lp.ceiling_value == 126


def test_amp_vs_median_differs_from_own_when_honest_costs_vary():
    L = layout(1)
    profs = [
        sp(0, 2_000_000, 4_000_000),  # own 2.0
        sp(1, 4_000_000, 4_000_000),  # own 1.0
    ]
    lp = summarize(L, "two_resp_length", profs, ceilings=[126, 126])
    # median honest = 3_000_000 ; amp vs median = 4/3 for both -> median 1.333
    assert lp.amp_median == pytest.approx(4_000_000 / 3_000_000)
    # own amp median = mean-of-two median = (1.0+2.0)/2 = 1.5
    assert lp.amp_own_median == pytest.approx(1.5)


def test_ceiling_is_mode():
    L = layout(1)
    profs = [sp(i, 2_000_000, 3_000_000) for i in range(3)]
    lp = summarize(L, "two_resp_length", profs, ceilings=[126, 126, 125])
    assert lp.ceiling_value == 126
