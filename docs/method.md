# Method and threats to validity

## What is measured

For each honest, verifying signature from the KAT vectors, we:

1. Measure the verifier's cost on the unmodified signature (the **honest** cost).
2. Sweep the single byte `two_resp_length` over all 256 values, measuring the
   cost the verifier spends for each (the signature no longer verifies once the
   byte is changed — it *rejects* — but the cost is spent before the rejection,
   which is exactly the resource-exhaustion surface).
3. Take the maximum in-range cost as the **attacker-worst** cost.

## Timing

- The bundled adapter (`oracle/timing.c`) times each `sqisign_verify` call with
  `clock_gettime(CLOCK_MONOTONIC)` and reports the **best of 5** repetitions per
  call. Best-of-N suppresses upward noise (scheduler preemption, interrupts);
  it does not correct downward bias, but we only ever compare best-of-5 to
  best-of-5, so systematic bias cancels in the ratio.
- Costs are reported in nanoseconds by the adapter and summarized in
  microseconds / milliseconds.

## Amplification, defined

Two definitions are reported because they answer different questions:

- **`amplification_vs_own_honest`** = `worst_attacker_cost / this_signature's_honest_cost`.
  "How much more can the attacker make *this* signature's verification cost?"
  This is ~1.0 when the honest signature already uses a near-ceiling value
  (no headroom), and it is the honest per-signature figure.

- **`amplification_vs_median_honest`** = `worst_attacker_cost / median_honest_cost`.
  "Relative to a typical honest verification, how expensive is the worst input?"
  This is the more stable summary across a signature set and is the headline
  number in the README.

For each we report the median and the max over the signature set.

## The ceiling

The highest in-range value is recovered per signature (the value just below the
reject cliff) and reported as `ceiling_value`. For the KAT signatures measured
here it equals `response_length` (126 / 192 / 253), consistent with those
signatures having `backtracking = 0`.

## Threats to validity (honest limitations)

- **One machine.** All numbers are from a single Apple Silicon (arm64) macOS
  host. Absolute costs and the exact slope will differ elsewhere; the
  *qualitative* ramp-then-cliff and the rising-with-level trend are the
  transferable findings.
- **One implementation.** Only the SQIsign **reference** implementation
  (commit `dd133d7`) was measured. The reference is explicitly *not
  production-ready* (upstream) and *not constant-time* (spec §7). Optimized or
  hardened implementations may behave differently.
- **Wall-clock, best-of-5.** Not cycle-accurate; subject to turbo/thermal
  scaling, DVFS, and scheduler effects. Best-of-5 mitigates but does not
  eliminate these. Comparisons are always ratio-of-best-of-5.
- **GMP is not constant-time.** The reference uses GMP big integers, which are
  data-dependent in timing. This is orthogonal here because our varied input is
  a public loop bound, not secret data.
- **Verification only.** This project measures verify cost only. It says
  nothing about signing or key generation.
- **Reference KAT signatures.** Honest baselines use the shipped KAT vectors,
  whose `two_resp_length` is small; a deployment whose honest signers emit
  larger values would see less headroom.

## Why this is DoS-surface, not a side channel

At a *fixed* attacker value (both length bytes `two_resp_length` and
`backtracking` held equal so every signature does the same isogeny work), the
cost is measured across 20 distinct key pairs. The main cluster of full-work
verifications spreads only ~1–3% of its median (`results/key-independence.json`),
with no key-dependent trend. A minority of signatures exit the now-invalid
computation earlier (partial or cheap) — that is driven by the public signature
*content*, not the secret key. Because the cost tracks public bytes and not the
secret key, the effect is an algorithmic-complexity / CPU-exhaustion property,
not a secret-leaking timing side channel.

## Reproducing

Build an adapter that speaks the protocol in `sqvcost/adapter.py` (the bundled
`oracle/timing.c` links the reference implementation), then:

```
python scripts/measure.py --oracle-dir <dir> --kat-dir <dir> --out results --n 20
```

or drive it a piece at a time with the CLI (`sqisign-verify-cost profile ...`).
