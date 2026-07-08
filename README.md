# sha3_ada

[![CI](https://github.com/b-erdem/sha3_ada/actions/workflows/ci.yml/badge.svg)](https://github.com/b-erdem/sha3_ada/actions/workflows/ci.yml) [![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE) [![SPARK: 159/159 proved](https://img.shields.io/badge/SPARK%20proof-159%2F159%20VCs-brightgreen.svg)](TOOL_QUALIFICATION.md)

A SHA-3 / SHAKE ([FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf))
implementation for Ada 2022, formally verified with
[SPARK](https://www.adacore.com/about-spark).

The Keccak-f[1600] permutation, sponge construction, and public API are
**100% SPARK-proved at level 2** — mathematically guaranteed free of runtime
errors (no buffer overflows, no range violations, no integer overflows, no
uninitialized reads, no non-terminating loops).

## Key properties

- **Formally verified** — 159 proof obligations, 0 unproved, 0 `pragma Assume`
- **FIPS 202 algorithms** — SHA3-256, SHA3-512, SHAKE128, SHAKE256
- **Both APIs** — one-shot (`SHA3_256`, `SHA3_512`, `SHAKE128`, `SHAKE256`) and
  incremental (`Init` / `Absorb` / `Squeeze`)
- **`Always_Terminates`** declared on every public subprogram — verified
- **No heap allocation** — `pragma Pure`, stack-only, suitable for embedded
- **Zero dependencies** — Ada standard library only
- **35 test cases pass** — NIST KAT vectors + Python `hashlib` differential

## Status

| Property | Status |
|---|---|
| Type safety (overflow, range, bounds) | ✅ Proved (SPARK level 2, 159/159 VCs) |
| Termination | ✅ Proved (`Always_Terminates`) |
| Functional correctness vs FIPS 202 | ✅ Tested against NIST KAT + bundled CAVP subset |
| Constant-time execution | ✅ Empirically verified (`SHA3_256`, Welch *t* = -1.20, cache-CT byte-identical) |
| FIPS 140-3 validated | ❌ Not validated |

## Installation

```bash
alr with sha3_ada
```

Or pin to this repository:

```toml
[[depends-on]]
sha3_ada = "~1.0"

[[pins]]
sha3_ada = { url = "https://github.com/b-erdem/sha3_ada" }
```

## Quick start

### One-shot

```ada
with SHA3;

procedure Demo is
   Data   : constant SHA3.Byte_Array (0 .. 4) := [104, 101, 108, 108, 111];  --  "hello"
   Digest : SHA3.Byte_Array_32;
begin
   SHA3.SHA3_256 (Data, Digest);
end Demo;
```

### Incremental

```ada
with SHA3;

procedure Demo is
   S      : SHA3.Sponge_State;
   Output : SHA3.Byte_Array (0 .. 63);
begin
   SHA3.Init (S, Rate => SHA3.SHAKE128_Rate, Domain => SHA3.SHAKE_Domain);
   SHA3.Absorb (S, Some_Input);
   SHA3.Absorb (S, More_Input);   --  any number of Absorb calls
   SHA3.Squeeze (S, Output);
end Demo;
```

## Building & testing

```bash
alr build
cd tests && alr build && ./bin/test_sha3
```

## Formal verification

```bash
alr exec -- gnatprove -P sha3_ada.gpr -j0 --level=1
```

Expected: 159/159 checks proved, 0 unproved, ≤1 second per check.

## License

Apache-2.0. See [LICENSE](LICENSE).
