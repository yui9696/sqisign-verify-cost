#!/usr/bin/env bash
# Build the SQIsign verify-timing adapter against a local reference checkout.
#
# This links the SQIsign REFERENCE implementation (Apache-2.0, commit dd133d7)
# to produce a small process that speaks the line protocol in
# sqvcost/adapter.py. No cryptographic source is vendored in this repository;
# you must have your own reference checkout built with CMake first:
#
#   git clone https://github.com/SQIsign/the-sqisign && cd the-sqisign
#   git checkout dd133d7
#   cmake -B build -DSQISIGN_BUILD_TYPE=ref && cmake --build build
#
# Then:  ./oracle/build.sh /path/to/the-sqisign
#
# Produces oracle/timing_lvl1, oracle/timing_lvl3, oracle/timing_lvl5.
#
# Notes:
#  * -Wno-macro-redefined works around upstream issue #12 (duplicate macro defs).
#  * Adjust GMP_PREFIX for your platform (Homebrew path shown).
set -euo pipefail

REF="${1:?usage: build.sh /path/to/the-sqisign}"
B="$REF/build/src"
GMP_PREFIX="${GMP_PREFIX:-/opt/homebrew/opt/gmp}"
HERE="$(cd "$(dirname "$0")" && pwd)"

for L in lvl1 lvl3 lvl5; do
  cc -O2 -Wno-macro-redefined \
    -DSQISIGN_VARIANT="$L" -DSQISIGN_BUILD_TYPE_REF \
    -I"$REF/include" -I"$REF/src/nistapi/$L" \
    "$HERE/timing.c" \
    "$B/libsqisign_${L}_nistapi.a" \
    "$B/libsqisign_${L}.a" \
    "$B/verification/ref/$L/libsqisign_verification_${L}.a" \
    "$B/signature/ref/$L/libsqisign_signature_${L}.a" \
    "$B/id2iso/ref/$L/libsqisign_id2iso_${L}.a" \
    "$B/hd/ref/$L/libsqisign_hd_${L}.a" \
    "$B/ec/ref/$L/libsqisign_ec_${L}.a" \
    "$B/gf/ref/$L/libsqisign_gf_${L}.a" \
    "$B/precomp/ref/$L/libsqisign_precomp_${L}.a" \
    "$B/quaternion/ref/generic/libsqisign_quaternion_generic.a" \
    "$B/mp/ref/generic/libsqisign_mp_generic.a" \
    "$B/common/generic/libsqisign_common_sys.a" \
    -I"$GMP_PREFIX/include" -L"$GMP_PREFIX/lib" -lgmp \
    -o "$HERE/timing_$L"
  echo "built oracle/timing_$L"
done
