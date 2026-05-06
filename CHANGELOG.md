# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-05-06

### Added

- **`SHA3.Wipe`** — caller-facing zeroisation helpers
  (`Wipe_Sponge_State`, `Wipe_Byte_Array`). Bodies in a separate
  compilation unit with `Inline => False` so the optimizer cannot
  prove the writes dead at -O2 without LTO. Used by ML-KEM and
  SLH-DSA to clear absorbed-secret-seed bytes before scope end.
- **`cavp/cavp_runner`** — NIST CAVP `.rsp` cross-validation harness
  parsing the standard CAVS-format vector files (ShortMsg, LongMsg,
  VariableOut) for sha3_256 / sha3_512 / shake128 / shake256.
  Smoke-tested against the published empty-message and "abc"
  reference values; the README documents the full CAVP corpus
  fetch.
- **CI workflow** running build + tests + `gnatprove --level=2` on
  every push/PR.
- **`-fstack-usage`** GPR switch + `scripts/stack_summary.sh`. Stack
  budget now documented in SECURITY.md (worst-case ~640 B).

### Changed

- SECURITY.md: documents the `Wipe` helpers and the LTO caveat
  for memory-erasure callers.

## [0.1.0] - 2026-05-06

Initial release.

### Added

- **Keccak-f[1600] permutation** (`SHA3.Keccak.Permute`) with the FIPS 202
  round constants and ρ rotation offsets.
- **Sponge construction** (`Init` / `Absorb` / `Squeeze`) supporting any rate
  in 1 .. 199 bytes, parameterised at runtime via `Init`.
- **One-shot APIs**: `SHA3_256`, `SHA3_512`, `SHAKE128`, `SHAKE256`.
- **`pragma Pure`** — stateless, no global state, no heap allocation.
- **`Always_Terminates => True`** on all public subprograms (verified, not
  asserted).
- **NIST KAT vectors** + Python `hashlib` differential vectors — 35 test
  cases, all pass.
- **SPARK level 1 proof** — 147/147 proof obligations discharged
  (CVC5 91% / Z3 8% / trivial 1%). Zero `pragma Assume`. Zero unproved VCs.

### Status of out-of-scope items

- Constant-time execution: not empirically verified. See
  [SECURITY.md](SECURITY.md).
- FIPS 140-3 validation: not validated.
- SHA3-224 and SHA3-384: not implemented.

[0.1.0]: https://github.com/b-erdem/sha3_ada/releases/tag/v0.1.0
