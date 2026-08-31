"""Adapter protocol parsing and subprocess driving (via the stub oracle)."""

import os
import sys

import pytest

from sqvcost.adapter import Adapter, AdapterError, Query, parse_answer

STUB = os.path.join(os.path.dirname(__file__), "stub_oracle.py")


def stub_cmd(level: int) -> list[str]:
    return [sys.executable, STUB, str(level)]


def test_parse_answer_accept():
    a = parse_answer("q0 accept 2477000.0")
    assert a is not None
    assert a.qid == "q0" and a.accept is True and a.cost_ns == 2477000.0


def test_parse_answer_reject():
    a = parse_answer("v42 reject 5000")
    assert a.accept is False and a.cost_ns == 5000.0


def test_parse_answer_blank():
    assert parse_answer("   ") is None


def test_parse_answer_error_line():
    with pytest.raises(AdapterError):
        parse_answer("q0 error_hex")


def test_parse_answer_bad_verdict():
    with pytest.raises(AdapterError):
        parse_answer("q0 maybe 123")


def test_query_to_line_empty_hex():
    q = Query("id7", "aa", "", "bb")
    assert q.to_line() == "id7 aa - bb"


def test_adapter_single_query():
    L1_off = 65
    sig = bytearray(148)
    sig[L1_off] = 100
    with Adapter.from_command(stub_cmd(1)) as ad:
        ans = ad.query("00" * 65, "aa", sig.hex())
    assert ans.accept is True
    # base 2.4e6 + slope 1e4 * 100
    assert ans.cost_ns == pytest.approx(2_400_000 + 10_000 * 100)


def test_adapter_batch_preserves_input_order():
    with Adapter.from_command(stub_cmd(1)) as ad:
        qs = []
        for v in (10, 200, 50):  # 200 is above ceiling -> reject
            sig = bytearray(148)
            sig[65] = v
            qs.append(Query(f"v{v}", "00" * 65, "aa", sig.hex()))
        answers = ad.batch(qs)
    assert [a.qid for a in answers] == ["v10", "v200", "v50"]
    assert answers[1].accept is False  # 200 > 126


def test_adapter_matches_by_id_not_position():
    # Even though the stub answers in order, the matching logic keys on id.
    with Adapter.from_command(stub_cmd(1)) as ad:
        sig = bytearray(148)
        sig[65] = 5
        a = ad.query("00" * 65, "aa", sig.hex(), qid="custom-id")
    assert a.qid == "custom-id"
