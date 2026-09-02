# sqisign-verify-cost

A **verification-cost / DoS-surface profiler** for [SQIsign](https://sqisign.org),
the NIST round-3 isogeny signature. It measures how much CPU an attacker can
make a *verifier* spend as a function of attacker-controllable signature bytes,
and ships the measured cost-amplification curves.

It is the *cost* counterpart to the author's
[`sqisign-conformance`](https://github.com/yui9696) project (which measures
*correctness*). Like that project, it ships **no cryptography**: it drives an
external verify-timing adapter over a tiny line protocol and does all analysis
in stdlib Python.

> ## What this is, and what it is NOT
>
> - This **is** a measurement of a resource-cost property of the SQIsign
>   **reference** implementation (commit `dd133d7`): a single public,
>   attacker-chosen signature byte (`two_resp_length`) sets an isogeny-chain
>   loop bound, and verification cost scales with it.
> - This is **NOT a vulnerability, a break, an exploit, or an attack on the
>   cryptography.** The math is untouched; no signature is forged and no key is
>   recovered.
> - This is **NOT a secret-leaking side channel.** At a fixed attacker value,
>   the cost across 20 distinct keys forms a tight main cluster (~1–3% spread;
>   see `results/key-independence.json`): the cost is governed by public bytes,
>   not the secret key. It is an algorithmic-complexity / CPU-exhaustion
>   property.
> - The reference implementation is explicitly **not production-ready**
>   (upstream) and **not constant-time** (spec §7). These numbers are properties
>   of that reference on one machine, not of SQIsign-the-scheme or of any
>   optimized/hardened implementation.

## Headline result

Sweeping the `two_resp_length` byte over all 256 values and taking the
most-expensive in-range value gives, per NIST level (20 KAT signatures each,
best-of-5 `CLOCK_MONOTONIC`, one Apple Silicon machine):

| Level | Honest median (ms) | Attacker worst (ms) | Amp. median | Amp. max | Ceiling |
|-------|--------------------|---------------------|-------------|----------|---------|
| L1 | 2.44 | 3.77 | 1.50x | 1.55x | 126 |
| L3 | 7.13 | 13.66 | 1.82x | 1.91x | 192 |
| L5 | 14.60 | 35.36 | 2.17x | 2.42x | 253 |

Amplification **rises with the security level**. A few signatures show ~1.0x
because their honest `two_resp_length` is already near the ceiling (no headroom
for the attacker) — this is reported per-signature, not hidden. The **median**
column is the robust figure; the L5 **max** (2.42x) is inflated by one
signature whose worst-value timing caught wall-clock noise (its neighbours sit
near 2.17x), so treat the max as an upper wall-clock envelope, not a tighter
claim.

For scale, on the same machine (OpenSSL 3.6.3):

| Scheme | Verify cost | vs SQIsign L1 |
|--------|-------------|---------------|
| RSA-2048 verify | 13.3 us | 1x |
| ECDSA P-256 verify | 48.5 us | 1x |
| SQIsign L1 honest | 2440 us | 184x RSA, 50x ECDSA |
| SQIsign L1 attacker-worst | 3773 us | 284x RSA, 78x ECDSA |

SQIsign verify being ~2 orders of magnitude slower than RSA/ECDSA is a known
property of isogeny signatures; this project quantifies the *extra* DoS
headroom on top of that, and confirms the concern raised by Ondřej Surý on
pqc-forum (2026-07-20) that SQIsign verification is "two magnitudes slower than
RSA/ECC … susceptible to CPU-exhaustion attacks."

## The mechanism (one paragraph)

The signature byte `two_resp_length` (offset 65/97/129 at L1/L3/L5) is read at
`src/verification/ref/lvlx/verify.c:164` as the length of a 2^r-isogeny chain
(`ec_eval_small_chain(..., sig->two_resp_length, ...)`) and again at
`verify.c:287` (`two_response_isogeny_verify`). There is an early range check
(`verify.c:253`: `pow_dim2_deg_resp = SQIsign_response_length - two_resp_length
- backtracking; if (pow_dim2_deg_resp < 0) return 0;`), so values above the
per-level `response_length` (126/192/253) are rejected essentially for free —
the **cliff** at the right of every curve. But within `[0, response_length]`,
the cost ramps up with the value, and that residual ramp is the amplification
measured here. Full detail with source citations in
[`docs/mechanism.md`](docs/mechanism.md).

## Install / run

Pure stdlib; Python ≥ 3.11.

```bash
pip install -e ".[dev]"     # dev extra = pytest only
```

The Python side needs an **adapter**: any process speaking
`<id> <pk_hex> <msg_hex> <sig_hex>` → `<id> <accept|reject> <cost_ns>`. A
reference adapter that links the SQIsign reference implementation is in
[`oracle/`](oracle/) (build instructions there — you supply your own reference
checkout; this repo redistributes no cryptographic source).

```bash
# full cost profile for level 1
sqisign-verify-cost profile --adapter ./oracle/timing_lvl1 --level 1 \
    --kat /path/to/PQCsignKAT_353_SQIsign_lvl1.rsp

# the two_resp_length cost curve for one signature (CSV to stdout)
sqisign-verify-cost curve --adapter ./oracle/timing_lvl5 --level 5 \
    --kat /path/to/PQCsignKAT_701_SQIsign_lvl5.rsp --index 0

# single-field sweep with an ASCII plot
sqisign-verify-cost sweep --adapter ./oracle/timing_lvl3 --level 3 \
    --kat /path/to/PQCsignKAT_529_SQIsign_lvl3.rsp --field two_resp_length

# RSA / ECDSA verify baselines for context
sqisign-verify-cost baseline --measure
```

**To profile your own verifier** (an optimized or hardened implementation),
wrap it in the same line protocol and pass it as `--adapter`. Nothing about the
analysis is C-specific.

## Committed results

Everything in [`results/`](results/) was produced by
[`scripts/measure.py`](scripts/measure.py) driving the reference adapter on the
author's machine this session:

- `amplification.json` / `.md` — per-level honest cost, attacker-worst cost,
  amplification (median & max over 20 signatures), ceiling value, baseline ratios.
- `two_resp_length-curve.json` / `.csv` — cost vs value 0..255 for a
  representative signature per level (the ramp then the instant-reject cliff),
  plus an ASCII plot of the L5 curve.
- `key-independence.json` — cost of a fixed attacker value across 20 keys
  (both length bytes held equal), showing cost tracks the public bytes, not the
  key: the main cluster spreads ~1–3%.

## Round 3 closes this by construction

**The byte this project measures no longer exists.**

SQIsign's round-3 release (2026-09-01, `6d01770`, tag `nist-v3`, spec v3.0) removed both
`backtracking` and `two_resp_length` from the signature, along with the entire
`two_response_isogeny_verify` stage. Every isogeny-chain length in round-3 verification is
now a compile-time constant (`CHALLENGE_BITS + EC_EXTRA_TORSION` and `RESPONSE_BITS`);
`protocols_verify` no longer derives any loop bound from signature data at all.

The reason is cryptographic rather than a response to cost: spec v3.0 §1.4(6) shortened
the challenge isogeny to length λ and made the response odd-degree, so challenge and
response can no longer share a common suffix — and those two bytes existed only to
describe that shared suffix. Removing it removed them.

So the amplification curves below are a measurement of round 2, and the surface they
measure is **closed by construction in round 3**, not merely mitigated. The mitigation
suggested in the next section is what the round-3 design does structurally.

Re-measuring the round-3 verifier for any residual input-dependent cost is the obvious
follow-up; the harness carries over unchanged apart from the parameter-set names
(`lvl1/3/5` → `p324_3`/`p500_27`/`p664_17`) and the reversed argument order of
`crypto_sign_verify`.

## Mitigation

Simple and worth stating: a verifier can **bound the work at the honest
maximum** — reject `two_resp_length` larger than an honest signer ever emits,
rather than only rejecting values past `response_length`. The existing check
bounds the *value* (past `response_length` is free-rejected), but the residual
`[0, response_length]` range still permits the measured amplification, because
honest signatures use only small values. Tightening the encoding, or a
work-cap in the verifier, closes the residual ramp.

## Honest limitations

- **One machine** (Apple Silicon / arm64 / macOS); absolute costs and the exact
  slope differ elsewhere. The transferable findings are the ramp-then-cliff
  shape and the rises-with-level trend, not the absolute milliseconds.
- **One implementation**: only the SQIsign **reference** (commit `dd133d7`),
  which is *not production-ready* and *not constant-time*. Optimized/hardened
  implementations may differ.
- **Wall-clock, best-of-5** `CLOCK_MONOTONIC`, not cycle-accurate; subject to
  turbo/thermal/DVFS and scheduler noise. Comparisons are always
  ratio-of-best-of-5, so systematic bias cancels.
- **GMP is not constant-time**, but that is orthogonal here: the varied input is
  a public loop bound, not secret data.
- **Verification only**: nothing is claimed about signing or key generation.
- **Reference KAT signatures** use small honest `two_resp_length`; a deployment
  whose honest signers emit larger values would see less headroom.

See [`docs/method.md`](docs/method.md) for the full method and threats to
validity.

## Prior art and context

- **Ondřej Surý, pqc-forum (2026-07-20)** — raised that SQIsign verification is
  ~two orders of magnitude slower than RSA/ECC and thus susceptible to
  CPU-exhaustion. This project *quantifies* the additional per-field headroom.
- **NIST IR 8610** (Status Report, second round of additional signatures) —
  asks for *constant-time signing* to mitigate side-channel leakage. That is a
  **signing**-side, secret-dependent axis; verification DoS from a public
  structural field is a **distinct axis they did not measure**.
- **SQIsign spec §7** — states plainly the submitted implementations do not run
  in constant time. This project measures a consequence on the *verify* path.
- **ePrint 2025/830, "Simple Power Analysis Attack on SQIsign"** — an SPA
  side-channel on **signing** (physical, secret-leaking). Cited to *contrast*:
  this project is neither physical nor secret-leaking; it is a remote CPU-cost
  measurement driven by public bytes.
- **[`sqisign-conformance`](https://github.com/yui9696)** — the author's
  companion project measuring verifier *correctness* with the same
  drive-an-adapter, ship-no-cryptography design.

## License

MIT © 2026 Moe Tabei. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE)
(upstream attribution, KAT digests). No cryptographic source or key material is
redistributed here.
