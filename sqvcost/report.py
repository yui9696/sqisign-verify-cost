"""Render profiles and sweeps as plain text / Markdown (no plotting deps)."""

from __future__ import annotations

from .baseline import MEASURED_BASELINES, VerifyBaseline, ratios
from .profile import LevelProfile
from .sweep import FieldSweep


def amplification_table(profiles: list[LevelProfile]) -> str:
    """Markdown table: one row per level."""
    rows = [
        "| Level | Honest median (ms) | Attacker worst (ms) | Amplification median | Amplification max | Ceiling value |",
        "|-------|--------------------|---------------------|----------------------|-------------------|---------------|",
    ]
    for p in sorted(profiles, key=lambda x: x.level):
        rows.append(
            f"| L{p.level} "
            f"| {p.honest_median_ns / 1e6:.2f} "
            f"| {p.worst_max_ns / 1e6:.2f} "
            f"| {p.amp_median:.2f}x "
            f"| {p.amp_max:.2f}x "
            f"| {p.ceiling_value} |"
        )
    return "\n".join(rows)


def baseline_table(
    l1_honest_us: float,
    l1_worst_us: float,
    baselines: dict[str, VerifyBaseline] | None = None,
) -> str:
    baselines = baselines or MEASURED_BASELINES
    hon = ratios(l1_honest_us, baselines)
    wor = ratios(l1_worst_us, baselines)
    rows = [
        "| Scheme | Verify cost | vs SQIsign L1 honest | vs SQIsign L1 attacker-worst |",
        "|--------|-------------|----------------------|------------------------------|",
    ]
    for name, b in baselines.items():
        rows.append(
            f"| {b.name} | {b.verify_us:.1f} us | 1x | 1x |"
        )
    rows.append(
        f"| SQIsign L1 honest | {l1_honest_us:.0f} us "
        f"| {hon['rsa2048']:.0f}x RSA / {hon['ecdsap256']:.0f}x ECDSA | -- |"
    )
    rows.append(
        f"| SQIsign L1 attacker-worst | {l1_worst_us:.0f} us "
        f"| -- | {wor['rsa2048']:.0f}x RSA / {wor['ecdsap256']:.0f}x ECDSA |"
    )
    return "\n".join(rows)


def ascii_curve(sweep: FieldSweep, width: int = 56, height: int = 16) -> str:
    """A tiny ASCII scatter of cost (y) vs value (x)."""
    samples = sweep.samples
    if not samples:
        return "(no samples)"
    max_cost = max(s.cost_ns for s in samples)
    max_val = max(s.value for s in samples)
    grid = [[" "] * width for _ in range(height)]
    for s in samples:
        x = int(s.value / max_val * (width - 1)) if max_val else 0
        y = int((1 - s.cost_ns / max_cost) * (height - 1)) if max_cost else height - 1
        grid[y][x] = "#"
    lines = []
    top_ms = max_cost / 1e6
    for r, row in enumerate(grid):
        label = f"{top_ms * (1 - r / (height - 1)):5.1f} |"
        lines.append(label + "".join(row))
    lines.append("      +" + "-" * width)
    lines.append("       0" + " " * (width - 6) + f"{max_val}")
    lines.append(f"       value of {sweep.field_name}  (y axis = verify cost, ms)")
    return "\n".join(lines)


def profile_markdown(
    profiles: list[LevelProfile],
    l1_honest_us: float,
    l1_worst_us: float,
    l5_sweep: FieldSweep | None = None,
) -> str:
    parts = [
        "# SQIsign verification-cost profile",
        "",
        "Measurement of the SQIsign **reference** implementation (commit dd133d7).",
        "This is a resource-cost measurement of a non-production reference, not a",
        "cryptographic break and not a secret-dependent side channel. See README.",
        "",
        "## Amplification by security level",
        "",
        "Attacker-controllable byte swept: `two_resp_length`.",
        "",
        amplification_table(profiles),
        "",
        "## Classical-signature context (same machine)",
        "",
        baseline_table(l1_honest_us, l1_worst_us),
    ]
    if l5_sweep is not None:
        parts += [
            "",
            "## L5 cost vs `two_resp_length` (representative signature)",
            "",
            "```",
            ascii_curve(l5_sweep),
            "```",
        ]
    parts.append("")
    return "\n".join(parts)
