# Security Policy & Threat Model

## Reporting Vulnerabilities

Report security issues privately via GitHub Security Advisories or email
`baris@erdem.dev`. Do not open public issues for vulnerabilities.

Disclosure SLA: acknowledgement within 7 days, fix or mitigation within 90
days for high-severity issues.

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

## Threat Model

`sha3_ada` is a hash function library. It does not handle keys directly
(SHA-3 / SHAKE are unkeyed primitives), but it is used as a building block
inside keyed protocols (e.g., HMAC-SHA-3, ML-KEM XOF) where its inputs are
derived from secret material.

### What SPARK proves (level 1)

All 147 proof obligations are discharged, guaranteeing **absence of**:

| Class | Coverage |
|---|---|
| Buffer overflows | Array index checks on every Absorb/Squeeze |
| Integer overflows | Arithmetic checks on rate/byte-position math |
| Range violations | Subtype checks on `Sponge_Rate`, indices, domain bytes |
| Uninitialized reads | Flow analysis ensures sponge state is initialized |
| Non-termination | `Always_Terminates => True` aspect verified |

These guarantees hold for **all possible inputs** — not just tested ones.

### Out of scope

The following are **not** protected against by this library:

#### Constant-time execution

Constant-time execution against timing side-channels has **not been
empirically verified**. The implementation follows constant-time discipline by
structure (no branches on input data inside the round function), but:

- Compiler optimisations may introduce data-dependent control flow.
- Cache-based side channels (data-dependent memory access patterns) are not
  analysed.
- Hardware side channels (power, EM) are out of scope.

A constant-time evidence package (ctgrind, dudect, formal CT analysis) is
available under separate engagement. **Do not deploy this library against
adversaries with timing-channel access without that engagement.**

#### FIPS 140-3

This library is **not FIPS 140-3 validated**. CAVP algorithm certification
and CMVP module certification are available under separate engagement.

#### Misuse of the public API

The library does not enforce protocol-level invariants:

- Re-using a `Sponge_State` for two different inputs after Init is allowed by
  the API but produces an incorrect digest.
- Calling `Absorb` after `Squeeze` is rejected by precondition (would fail
  in proof at the call site or at runtime if assertions enabled), but it is
  the caller's responsibility to respect the absorb-then-squeeze ordering.
- The library does not zeroise sponge state on destruction. If your threat
  model requires post-use erasure of intermediate state, do it explicitly.

### Runtime hardening

The library GPR enables:
- `-gnato` — overflow checks (defense-in-depth beyond SPARK proofs)
- `-gnatVa` — validity checks on all parameters

Internal SPARK contracts (`Pre`/`Post`) are **proof-only** and not checked at
runtime. Enable `-gnata` in your application's GPR to enforce public API
preconditions at runtime.

## Known limitations

- **SHA3-224 and SHA3-384 are not implemented.** Only SHA3-256, SHA3-512,
  SHAKE128, SHAKE256 are exposed. Adding the missing variants is mechanical
  but has not been done.
- **No `pragma Inspection_Point` barriers** are placed around secret-dependent
  state. Their addition is part of the constant-time work above.
