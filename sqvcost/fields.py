"""Per-level SQIsign signature byte layout, as data.

This module encodes the on-the-wire signature layout of the SQIsign reference
implementation (commit dd133d7), taken directly from
``src/verification/ref/lvlx/encode_verification.c`` (``signature_from_bytes``).

Nothing here performs cryptography. It only describes which byte ranges hold
which structural field, so a caller can point at, and vary, a field of a base
signature when driving an external verifier.

Layout produced by ``signature_from_bytes`` / ``signature_to_bytes``::

    E_aux_A            fp2      (2 * fp bytes)
    backtracking       1 byte
    two_resp_length    1 byte
    mat[0][0]          nb bytes    nb = (response_length + 9) // 8
    mat[0][1]          nb bytes
    mat[1][0]          nb bytes
    mat[1][1]          nb bytes
    chall_coeff        security_bits // 8 bytes
    hint_aux           1 byte
    hint_chall         1 byte

The single byte ``two_resp_length`` is the one this project measures: it is
read at verify.c:164 as the length of a 2^r-isogeny chain (a loop bound) and
again at verify.c:287. See docs/mechanism.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Field:
    """One structural region of a signature."""

    name: str
    offset: int
    length: int
    #: True if the region is a length/count/hint scalar that a verifier reads
    #: as control flow (as opposed to opaque coordinate/coefficient bytes).
    structural: bool = False
    note: str = ""

    @property
    def end(self) -> int:
        return self.offset + self.length

    @property
    def byte_range(self) -> range:
        return range(self.offset, self.end)


@dataclass(frozen=True)
class LevelLayout:
    """The complete signature layout for one NIST security level."""

    level: int
    #: NIST parameter set name (prime bitsize) used in KAT filenames.
    param: str
    fp_bytes: int
    security_bits: int
    response_length: int
    signature_bytes: int
    public_key_bytes: int
    fields: list[Field] = field(default_factory=list)

    def field_by_name(self, name: str) -> Field:
        for f in self.fields:
            if f.name == name:
                return f
        raise KeyError(name)

    @property
    def structural_fields(self) -> list[Field]:
        return [f for f in self.fields if f.structural]


def _build_level(
    level: int,
    param: str,
    fp_bytes: int,
    security_bits: int,
    response_length: int,
    public_key_bytes: int,
) -> LevelLayout:
    fp2 = 2 * fp_bytes
    nb = (response_length + 9) // 8
    cc = security_bits // 8

    fields: list[Field] = []
    off = 0

    def add(name: str, length: int, structural: bool = False, note: str = "") -> None:
        nonlocal off
        fields.append(Field(name, off, length, structural, note))
        off += length

    add("E_aux_A", fp2, note="auxiliary curve j-invariant coordinate (Fp2)")
    add("backtracking", 1, structural=True,
        note="subtracted from the dim-2 isogeny length at verify.c:251")
    add("two_resp_length", 1, structural=True,
        note="2^r-isogeny chain length / loop bound at verify.c:164,287")
    add("mat_0_0", nb, note="Bchall_can_to_B_chall matrix entry")
    add("mat_0_1", nb, note="Bchall_can_to_B_chall matrix entry")
    add("mat_1_0", nb, note="Bchall_can_to_B_chall matrix entry")
    add("mat_1_1", nb, note="Bchall_can_to_B_chall matrix entry")
    add("chall_coeff", cc, note="challenge coefficient")
    add("hint_aux", 1, structural=True, note="decompression hint")
    add("hint_chall", 1, structural=True, note="decompression hint")

    layout = LevelLayout(
        level=level,
        param=param,
        fp_bytes=fp_bytes,
        security_bits=security_bits,
        response_length=response_length,
        signature_bytes=off,
        public_key_bytes=public_key_bytes,
        fields=fields,
    )
    return layout


# Values taken from the reference build (commit dd133d7):
#   src/precomp/ref/lvlN/include/encoded_sizes.h : SQIsign_response_length
#   fp_bytes, security_bits, and byte totals cross-checked against the KAT
#   signature/public-key sizes (see NOTICE for file digests).
LEVELS: dict[int, LevelLayout] = {
    1: _build_level(1, "353", fp_bytes=32, security_bits=128,
                    response_length=126, public_key_bytes=65),
    3: _build_level(3, "529", fp_bytes=48, security_bits=192,
                    response_length=192, public_key_bytes=97),
    5: _build_level(5, "701", fp_bytes=64, security_bits=256,
                    response_length=253, public_key_bytes=129),
}

# Signature sizes, kept as a flat table for quick assertions / CLI help.
SIGNATURE_BYTES = {lvl: L.signature_bytes for lvl, L in LEVELS.items()}
PUBLIC_KEY_BYTES = {lvl: L.public_key_bytes for lvl, L in LEVELS.items()}
RESPONSE_LENGTH = {lvl: L.response_length for lvl, L in LEVELS.items()}


def layout(level: int) -> LevelLayout:
    if level not in LEVELS:
        raise ValueError(f"unknown level {level}; expected one of {sorted(LEVELS)}")
    return LEVELS[level]
