"""Rendering helpers."""

from sqvcost.fields import layout
from sqvcost.profile import SignatureProfile, summarize
from sqvcost.report import amplification_table, ascii_curve, baseline_table
from sqvcost.sweep import FieldSweep, Sample


def _profile():
    L = layout(1)
    profs = [
        SignatureProfile(0, 1, 2_000_000, 126, 3_000_000, 126),
        SignatureProfile(1, 1, 2_000_000, 126, 3_100_000, 126),
    ]
    return summarize(L, "two_resp_length", profs, [126, 126])


def test_amplification_table_has_row_per_level():
    t = amplification_table([_profile()])
    assert "| L1 " in t
    assert "1.50x" in t or "1.55x" in t


def test_baseline_table_mentions_rsa_and_ecdsa():
    t = baseline_table(2436, 3658)
    assert "RSA" in t and "ECDSA" in t
    # 2436us / 13.3us ~ 183x RSA -- assert the honest row carries a triple-digit ratio
    assert "x RSA" in t and "183x RSA" in t


def test_ascii_curve_renders():
    samples = [Sample(v, v <= 126, 2_000_000 + 10_000 * min(v, 126)) for v in range(256)]
    sw = FieldSweep("two_resp_length", 1, 2_010_000, samples)
    art = ascii_curve(sw)
    assert "#" in art
    assert "two_resp_length" in art
