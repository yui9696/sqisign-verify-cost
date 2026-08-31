# Mechanism

This document records exactly *why* a verifier's CPU cost depends on an
attacker-chosen signature byte, with source citations. All line numbers refer
to the SQIsign reference implementation at commit `dd133d7`.

> This is a description of a resource-cost property of a **non-production
> reference** implementation. It is not a vulnerability report and not a
> cryptographic break. See the README's "What this is and is not" box.

## The byte

A SQIsign signature is decoded field-by-field in
`src/verification/ref/lvlx/encode_verification.c`, function
`signature_from_bytes`:

```
enc = fp2_from_bytes(&sig->E_aux_A, enc);   // E_aux_A  (2*fp bytes)
sig->backtracking     = *enc++;             // 1 byte
sig->two_resp_length  = *enc++;             // 1 byte   <-- this one
... mat[0..3], chall_coeff, hint_aux, hint_chall
```

So `two_resp_length` is a single byte at a fixed offset:

| Level | fp bytes | E_aux_A | `backtracking` off | `two_resp_length` off | signature bytes |
|-------|----------|---------|--------------------|-----------------------|-----------------|
| L1    | 32       | 0..63   | 64                 | **65**                | 148             |
| L3    | 48       | 0..95   | 96                 | **97**                | 224             |
| L5    | 64       | 0..127  | 128                | **129**               | 292             |

`sqvcost/fields.py` encodes this table as data.

## Where the byte is used

In `src/verification/ref/lvlx/verify.c`:

- **verify.c:164** — the byte is the length of a 2^r-isogeny chain:
  ```c
  if (ec_eval_small_chain(E_chall, &ker, sig->two_resp_length, points, 3, false))
      return 0;
  ```
  `ec_eval_small_chain` walks a chain whose length is `two_resp_length`; a
  larger value means more isogeny steps.

- **verify.c:251** — the byte also sets the *complementary* dim-2 isogeny
  length:
  ```c
  int pow_dim2_deg_resp = SQIsign_response_length - (int)sig->two_resp_length
                                                  - (int)sig->backtracking;
  ```

- **verify.c:287** — when non-zero it triggers a second short isogeny:
  ```c
  if (sig->two_resp_length > 0) {
      if (!two_response_isogeny_verify(&E_chall, &B_chall_can, sig, pow_dim2_deg_resp))
          return 0;
  ```

`SQIsign_response_length` is a compile-time constant per level, from
`src/precomp/ref/lvlN/include/encoded_sizes.h`: **126 (L1), 192 (L3), 253 (L5)**.

## The range check (and its limit)

`verify.c` does bound the value, at verify.c:253:

```c
if (pow_dim2_deg_resp < 0)   // == two_resp_length + backtracking > response_length
    return 0;
if (pow_dim2_deg_resp == 1)
    return 0;
```

So any `two_resp_length` above `response_length - backtracking` is rejected
essentially for free (the verifier bails before the expensive isogeny work).
That is the **cliff** you see at the right edge of every measured curve.

**But the check bounds the value, not the work.** Every value *within*
`[0, response_length - backtracking]` is accepted into the isogeny computation,
and the cost grows across that whole range. An honest signer emits a small
`two_resp_length` (the KAT vectors here mostly use 0 or 1); an attacker may set
it anywhere up to the ceiling. The measured net effect is that cost rises
monotonically to the ceiling — that residual ramp is the amplification this
project quantifies.

## Why the cost rises

Two lengths move in opposite directions as `two_resp_length` grows: the small
2^r chain at verify.c:164 gets *longer*, while `pow_dim2_deg_resp` (the dim-2
isogeny) gets *shorter*. Empirically, on the reference implementation and this
machine, the net verify cost increases with the value up to the ceiling (see
`results/two_resp_length-curve.*`). This project measures that net curve; it
does not model the two isogeny costs analytically.

## Not key-dependent

At a fixed `two_resp_length` (and fixed `backtracking`), the main cluster of
full-work verifications is nearly the same across 20 distinct key pairs — ~1–3%
spread (`results/key-independence.json`): the work is a function of the *public*
structural bytes, not of the secret key. Some signatures exit earlier (the
now-invalid content fails an internal order/basis check), which is again
content-driven, not key-driven. That is why this is an algorithmic-complexity /
resource-exhaustion property and **not** a secret-dependent side channel.
