# Constant-Time Audit — sha3_ada

This document records the source-level audit of secret-dependent
control flow performed in 2026-05.

## Audit scope

A line is flagged **secret-dependent** if the value being branched
on, indexed by, or used as a loop bound depends on the *contents*
of the input data (which may be secret depending on the calling
protocol). Sponge state `Byte_Pos`, `Rate`, and `Squeezing` are
public — they are determined by input *length* (which is itself
public in all callers we audit, including ml_kem and slh_dsa).

## Findings

### All branches are public-dependent

| File:Line | Branch | Why public |
|---|---|---|
| `sha3.adb:104, 157` | `if S.Byte_Pos = S.Rate then permute` | `Byte_Pos` and `Rate` derive only from input *length*, not contents |
| `sha3.adb:123` | `if not S.Squeezing then` | `Squeezing` is a state flag set by `Init` and `Squeeze` |
| `sha3-keccak.adb:8` | `(if Amount = 0 then ...)` (Rotate_Left) | `Amount` is constant per call site (round constants in the lookup table) |

The Keccak-f[1600] permutation itself (`SHA3.Keccak.Permute`) is
pure ARX (xor / rotate / and / not) on the 25-lane state. No data-
dependent control flow.

The Absorb / Squeeze byte-streaming uses index arithmetic over the
sponge rate (a public constant per algorithm). No data-dependent
indexing.

### Conclusion

`sha3_ada` is **constant-time by structure**. No source-level
changes required for constant-time guarantees.

## Plan

Empirical verification via dudect / cycle-counting harness will
still be run as a sanity check, even though the static analysis
predicts no leaks.

## Out of scope

- Cache effects on the round-constants lookup (`RC`) and rho-pi
  permutation tables (`Rho_Pi_Dest`, `Rho_Pi_Rot`). These are read
  with constant indices (the round number, which is the loop
  counter), so cache-based side channels are not applicable.
- Power and EM analysis: software audit cannot cover these.
