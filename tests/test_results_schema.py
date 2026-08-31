"""Pin the schema of the committed measured results.

This does NOT re-measure (CI has no C build). It asserts the shape and basic
sanity of the JSON produced by scripts/measure.py, so a refactor cannot
silently change the result format.
"""

import json
import os

import pytest

RESULTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")


def _load(name):
    path = os.path.join(RESULTS, name)
    if not os.path.exists(path):
        pytest.skip(f"{name} not present (results not generated in this checkout)")
    with open(path) as f:
        return json.load(f)


def test_amplification_schema():
    d = _load("amplification.json")
    assert "_meta" in d and "reference_commit" in d["_meta"]
    assert set(d["levels"]) == {"L1", "L3", "L5"}
    for key, lvl in d["levels"].items():
        for req in ("level", "field", "response_length", "n_signatures",
                    "honest_us", "worst_attacker_us",
                    "amplification_vs_median_honest",
                    "amplification_vs_own_honest",
                    "ceiling_value", "per_signature"):
            assert req in lvl, f"{key} missing {req}"
        assert lvl["field"] == "two_resp_length"
        assert lvl["amplification_vs_median_honest"]["max"] >= 1.0
        # amplification rises with level in the ground-truth measurement
    bc = d["baseline_context"]
    assert "l1_honest_ratios" in bc and "rsa2048" in bc["l1_honest_ratios"]


def test_amplification_increases_with_level():
    d = _load("amplification.json")
    m = {k: v["amplification_vs_median_honest"]["median"] for k, v in d["levels"].items()}
    assert m["L1"] < m["L3"] < m["L5"]


def test_curve_schema():
    d = _load("two_resp_length-curve.json")
    assert set(d["levels"]) == {"L1", "L3", "L5"}
    l5 = d["levels"]["L5"]
    assert l5["ceiling_value"] is not None
    assert len(l5["samples"]) == 256
    assert "ascii" in l5
    # every sample has value/accept/cost
    s = l5["samples"][0]
    assert {"value", "accept", "cost_ns"} <= set(s)


def test_key_independence_schema_and_tightness():
    d = _load("key-independence.json")
    for lvl in ("L1", "L3", "L5"):
        for value_key, ki in d["levels"][lvl].items():
            assert ki["n_keys"] >= 5
            assert "main_cluster" in ki and "early_exit" in ki
            mc = ki["main_cluster"]
            if mc["n"] >= 2:
                # The main cluster of full-work verifications is tight: cost is
                # governed by the public chosen bytes, not the secret key.
                # (Loose bound; wall-clock noise included.)
                assert mc["spread_pct_of_median"] < 10.0
