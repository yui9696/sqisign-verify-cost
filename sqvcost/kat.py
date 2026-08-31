"""Minimal reader for NIST KAT ``.rsp`` response files.

A record looks like::

    count = 0
    seed = ...
    mlen = 33
    msg = D81C...
    pk  = 07CC...
    sk  = ...
    smlen = 181
    sm  = 8422...

The signed message ``sm`` is ``signature || message``; the signature is the
first ``signature_bytes`` bytes. This reader ships no cryptography -- it only
slices already-generated test vectors.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class KatRecord:
    count: int
    msg_hex: str
    pk_hex: str
    sig_hex: str


_FIELD = re.compile(r"^(\w+)\s*=\s*([0-9A-Fa-f]*)\s*$")


def _records(text: str) -> list[dict[str, str]]:
    recs: list[dict[str, str]] = []
    cur: dict[str, str] = {}
    for line in text.splitlines():
        m = _FIELD.match(line)
        if not m:
            continue
        key, val = m.group(1), m.group(2)
        if key == "count":
            if cur:
                recs.append(cur)
            cur = {}
        cur[key] = val
    if cur:
        recs.append(cur)
    return recs


def load_kat(path: str, signature_bytes: int, limit: int | None = None) -> list[KatRecord]:
    """Load KAT records, slicing ``sm`` into signature + message."""
    text = open(path, encoding="ascii").read()
    out: list[KatRecord] = []
    for r in _records(text):
        if "sm" not in r or "pk" not in r or "msg" not in r:
            continue
        sm = r["sm"]
        sig_hex = sm[: signature_bytes * 2]
        out.append(
            KatRecord(
                count=int(r.get("count", "0")),
                msg_hex=r["msg"],
                pk_hex=r["pk"],
                sig_hex=sig_hex,
            )
        )
        if limit is not None and len(out) >= limit:
            break
    return out
