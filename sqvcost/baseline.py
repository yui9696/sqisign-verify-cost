"""Classical-signature verify baselines for context.

These numbers put the SQIsign verify cost on a familiar scale. They are NOT
fabricated: they are measured with ``openssl speed`` on the same machine and
recorded here, tagged with the OpenSSL version. Re-run :func:`measure_openssl`
to reproduce them, or pass your own measured values.

Context only. A slow verify is a documented property of isogeny signatures
(SQIsign trades signature size for verification work); this is not a defect and
not the subject of the measurement -- it frames the amplification headroom.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class VerifyBaseline:
    name: str
    verify_us: float
    verify_per_s: float


# Measured this session with `openssl speed rsa2048 ecdsap256`.
# OpenSSL 3.6.3 (9 Jun 2026), Apple Silicon (arm64), macOS.
OPENSSL_VERSION = "OpenSSL 3.6.3 9 Jun 2026"

MEASURED_BASELINES: dict[str, VerifyBaseline] = {
    "rsa2048": VerifyBaseline("RSA-2048 verify", verify_us=13.3, verify_per_s=75091.0),
    "ecdsap256": VerifyBaseline("ECDSA P-256 verify", verify_us=48.5, verify_per_s=20621.0),
}


def measure_openssl(seconds: int = 1) -> dict[str, VerifyBaseline]:
    """Run ``openssl speed`` and parse RSA-2048 / ECDSA-P256 verify rates.

    Returns freshly measured baselines. Raises if ``openssl`` is unavailable.
    """
    out: dict[str, VerifyBaseline] = {}

    rsa = subprocess.run(
        ["openssl", "speed", "-seconds", str(seconds), "rsa2048"],
        capture_output=True, text=True, check=True,
    ).stdout
    for line in rsa.splitlines():
        m = re.search(r"rsa\s+2048 bits\s+(\S+)s\s+(\S+)s.*?(\d+\.\d+)\s+(\d+\.\d+)", line)
        if m:
            verify_s = float(m.group(2))
            verify_per_s = float(m.group(4))
            out["rsa2048"] = VerifyBaseline("RSA-2048 verify", verify_s * 1e6, verify_per_s)
            break

    ec = subprocess.run(
        ["openssl", "speed", "-seconds", str(seconds), "ecdsap256"],
        capture_output=True, text=True, check=True,
    ).stdout
    for line in ec.splitlines():
        m = re.search(r"256 bits ecdsa.*?(\d+\.\d+)\s+(\d+\.\d+)\s*$", line)
        if m:
            verify_per_s = float(m.group(2))
            out["ecdsap256"] = VerifyBaseline(
                "ECDSA P-256 verify", 1e6 / verify_per_s, verify_per_s
            )
            break

    return out


def ratios(sqisign_us: float, baselines: dict[str, VerifyBaseline] | None = None) -> dict:
    """Express a SQIsign verify cost as a multiple of each baseline."""
    baselines = baselines or MEASURED_BASELINES
    return {
        name: round(sqisign_us / b.verify_us, 1)
        for name, b in baselines.items()
    }
