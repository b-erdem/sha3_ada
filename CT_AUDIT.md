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

## Cache-CT audit

A cache-side-channel attack reads cache hits/misses to infer which
memory addresses the target accessed. Defeated by ensuring no memory
access is indexed by a value derived from secret data.

Memory access inventory in `sha3-keccak.adb`:

| Access | Index | Secret-derived? |
|---|---|---|
| `RC (Round)` | loop counter | no |
| `Rho_Pi_Dest (I)`, `Rho_Pi_Rot (I)` | loop counter | no |
| `Chi_N1 (I)`, `Chi_N2 (I)` | loop counter | no |
| `B (Rho_Pi_Dest (I))` | constant table indexed by loop counter | no (table content public) |
| `A (I)`, `B (I)` | loop counter | no |

Memory access inventory in `sha3.adb`:

| Access | Index | Secret-derived? |
|---|---|---|
| `S.State (Lane)` (in `XOR_Byte_Into_State`, etc.) | `Pos / 8`, `Pos` from absorb/squeeze byte counter | no — `Pos` derives from input *length* |
| `Data (I)` in absorb | loop counter | no |
| `Result (I)` in squeeze | loop counter | no |

**Verdict**: cache-CT by structure. No secret-data-indexed access.

The lookup tables (`RC`, `Rho_Pi_*`, `Chi_*`) are small (200 bytes
total) and accessed with public loop-counter indices in a fixed
sweep. After the first iteration of a Keccak permutation they fit
entirely in L1 data cache; access timing is constant.

## Empirical cache-CT verification

Not run on macOS. The standard tool is
[cachegrind](https://valgrind.org/docs/manual/cg-manual.html), part
of Valgrind, which works only on Linux. To run:

```bash
docker run --rm -v $PWD:/work ubuntu:latest \
    bash -c "apt-get install -y valgrind libgnat-15 && \
             cd /work && valgrind --tool=cachegrind ./bin/test_sha3"
```

Plus comparing the access trace between two input classes (e.g., via
[cachetap](https://github.com/seec-team/cachetap)).

Since no secret-indexed access exists at the source level, we
expect cachegrind to confirm zero secret-dependent cache effects.
Adding a Linux CI job to run cachegrind on each release tag is on
the v0.2 roadmap.

## Out of scope

- Power and EM analysis: software audit cannot cover these.
