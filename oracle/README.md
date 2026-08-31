# Verify-timing adapter

`timing.c` is a small adapter that links the **SQIsign reference
implementation** and exposes verification cost over a line protocol. It is the
only C in this project, and it vendors **no** cryptography: it `#include`s the
reference's `sig.h` / `api.h` and calls `sqisign_verify`.

## Protocol

- stdin:  `<id> <pk_hex> <msg_hex> <sig_hex>` per line (`-` = empty)
- stdout: `<id> <accept|reject> <best_of_5_ns>` per line

`<id>` is echoed back so answers can be matched regardless of order. The cost
is the best of five `clock_gettime(CLOCK_MONOTONIC)` timings around
`sqisign_verify`.

## Build

You need your own built reference checkout (this repo does not redistribute it):

```
git clone https://github.com/SQIsign/the-sqisign && cd the-sqisign
git checkout dd133d7
cmake -B build -DSQISIGN_BUILD_TYPE=ref && cmake --build build
cd -
./oracle/build.sh /path/to/the-sqisign
```

This produces `oracle/timing_lvl1`, `oracle/timing_lvl3`, `oracle/timing_lvl5`
(git-ignored). Point the CLI's `--adapter` at one of them.

## Substituting your own verifier

Any process that speaks the protocol above works. To profile a *different*
SQIsign implementation (optimized, hardened, another language), wrap its
verifier in the same line protocol and pass it as `--adapter`. The Python side
knows nothing about C.
