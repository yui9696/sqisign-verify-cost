"""Signature layout offsets and sizes."""

import pytest

from sqvcost.fields import LEVELS, PUBLIC_KEY_BYTES, SIGNATURE_BYTES, layout


@pytest.mark.parametrize("level,sig_bytes", [(1, 148), (3, 224), (5, 292)])
def test_signature_bytes(level, sig_bytes):
    assert SIGNATURE_BYTES[level] == sig_bytes


@pytest.mark.parametrize("level,pk_bytes", [(1, 65), (3, 97), (5, 129)])
def test_public_key_bytes(level, pk_bytes):
    assert PUBLIC_KEY_BYTES[level] == pk_bytes


@pytest.mark.parametrize("level", [1, 3, 5])
def test_fields_are_contiguous_and_sum_to_total(level):
    L = layout(level)
    off = 0
    for f in L.fields:
        assert f.offset == off, f"gap/overlap before {f.name}"
        off += f.length
    assert off == L.signature_bytes


@pytest.mark.parametrize("level,off", [(1, 65), (3, 97), (5, 129)])
def test_two_resp_length_offset(level, off):
    assert layout(level).field_by_name("two_resp_length").offset == off


@pytest.mark.parametrize("level,val", [(1, 126), (3, 192), (5, 253)])
def test_response_length(level, val):
    assert layout(level).response_length == val


def test_structural_fields():
    names = {f.name for f in layout(1).structural_fields}
    assert "two_resp_length" in names
    assert "backtracking" in names
    assert "E_aux_A" not in names  # opaque coordinate, not a control scalar


def test_unknown_level():
    with pytest.raises(ValueError):
        layout(2)


def test_mat_and_chall_sizes():
    # nb = (response_length + 9)//8 ; chall = security_bits//8
    L1 = layout(1)
    assert L1.field_by_name("mat_0_0").length == 16
    assert L1.field_by_name("chall_coeff").length == 16
    L3 = layout(3)
    assert L3.field_by_name("mat_0_0").length == 25
    assert L3.field_by_name("chall_coeff").length == 24
    L5 = layout(5)
    assert L5.field_by_name("mat_0_0").length == 32
    assert L5.field_by_name("chall_coeff").length == 32
