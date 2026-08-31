# Measured amplification

Machine: `Darwin-25.1.0-arm64-arm-64bit-Mach-O`  
Reference: SQIsign commit `dd133d7`  
OpenSSL: OpenSSL 3.6.3 9 Jun 2026  
Generated: 2026-08-31T22:03:47Z (by `scripts/measure.py`)

All numbers below were produced by driving the reference verify-timing
adapter on the machine above. This measures a resource-cost property of
a **non-production reference** implementation; it is not a break and not
a secret-dependent side channel. See the repository README.

## Amplification by level (20 KAT signatures each)

Attacker-swept byte: `two_resp_length`. Amplification = attacker-worst
cost / median-honest cost.

| Level | Honest median (ms) | Attacker worst (ms) | Amp. median | Amp. max | Ceiling |
|-------|--------------------|---------------------|-------------|----------|---------|
| L1 | 2.44 | 3.77 | 1.50x | 1.55x | 126 |
| L3 | 7.13 | 13.66 | 1.82x | 1.91x | 192 |
| L5 | 14.60 | 35.36 | 2.17x | 2.42x | 253 |

Amplification rises with the security level. Some individual signatures
show ~1.0x because their honest `two_resp_length` is already near the
ceiling (no headroom) -- see the per-signature arrays in
`amplification.json`.

## Classical verify baselines (same machine)

| Scheme | Verify cost | vs SQIsign L1 |
|--------|-------------|---------------|
| RSA-2048 verify | 13.3 us | 1x |
| ECDSA P-256 verify | 48.5 us | 1x |
| SQIsign L1 honest | 2440 us | 184x RSA, 50x ECDSA |
| SQIsign L1 attacker-worst | 3773 us | 284x RSA, 78x ECDSA |

## L5 cost vs `two_resp_length` (representative signature)

The ramp up to the ceiling, then the free-reject cliff:

```
 31.7 |                                                    ### 
 29.6 |                                                 ####   
 27.5 |                                               ###      
 25.4 |                                           #####        
 23.3 |                                         ###            
 21.2 |                                     ####               
 19.0 |                                  ####                  
 16.9 |                             ######                     
 14.8 |#                        #####                          
 12.7 |                  #######                               
 10.6 |         ##########                                     
  8.5 |##########                                              
  6.3 |                                                        
  4.2 |                                                        
  2.1 |                                                        
  0.0 |                                                      ##
      +--------------------------------------------------------
       0                                                  255
       value of two_resp_length  (y axis = verify cost, ms)
```

## Cost tracks the public value, not the secret key

At a fixed attacker value, the main cluster of full-work verifications
across 20 distinct keys is tight (spread as a percentage of the median):

| Level | Fixed value | Main-cluster keys | Median (ms) | Spread | Spread % |
|-------|-------------|-------------------|-------------|--------|----------|
| L1 | 110 | 15 | 3.13 | 66 us | 2.11% |
| L1 | 124 | 15 | 3.60 | 60 us | 1.67% |
| L3 | 110 | 11 | 6.68 | 116 us | 1.74% |
| L3 | 189 | 11 | 12.48 | 254 us | 2.04% |
| L5 | 110 | 15 | 11.88 | 158 us | 1.33% |
| L5 | 250 | 15 | 30.44 | 746 us | 2.45% |

The tight spread (~1-3%) across distinct keys shows the cost is governed
by the public chosen bytes, not the secret key. A minority of signatures
exit the (now-invalid) computation earlier -- counted as `partial_work`
or `early_exit` in `key-independence.json` -- which is content-driven,
not key-driven.
