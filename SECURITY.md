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

**Static analysis**: see [CT_AUDIT.md](CT_AUDIT.md). All branches in the
public API are public-data-dependent (depend on input *length*, not contents).
Constant-time by structure.

**Empirical verification** with the [ct_harness](../ct_harness) dudect-style
harness on Apple Silicon (Rosetta x86_64, GNAT 14.x at -O2):

| Test | Class A | Class B | Iterations | Welch t | Verdict |
|---|---|---|---|---|---|
| `SHA3_256` | fixed 256 B | random 256 B | 100 000 | -1.20 | PASS (\|t\| < 4.5) |

The mean of 4.74 µs differed by 0.03 % between classes; well within
measurement noise. Re-run on your target platform with
`alr build && bin/ct_sha3 100000`.

**Cache-CT (data-dependent memory access)**: audited statically and
verified empirically. See [CT_AUDIT.md](CT_AUDIT.md).

| Cache level | Class A | Class B | Δ |
|---|---|---|---|
| D1 misses | 30 561 | 30 557 | -4 (0.013 %) |
| LLd misses | 18 080 | 18 080 | **0** |

50 000 iterations of `SHA3_256` per class under cachegrind 3.22 in a
Linux Docker container. Last-level-data cache misses byte-identical
between fixed and random input. **Verdict**: cache-CT.

**Out of scope:**
- Hardware side channels (power, EM).

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
- The library does not zeroise sponge state on destruction *automatically*,
  but `SHA3.Wipe.Wipe_Sponge_State` and `SHA3.Wipe.Wipe_Byte_Array` are
  available for callers who need post-use erasure. Both procedures live in
  a separate compilation unit with `Inline => False`, so the optimizer
  cannot prove the writes dead at -O2 without LTO. Builds using LTO must
  pair with `-fno-builtin-memset` or call `explicit_bzero(3)`.

### Runtime hardening

The library GPR enables:
- `-gnato` — overflow checks (defense-in-depth beyond SPARK proofs)
- `-gnatVa` — validity checks on all parameters
- `-fstack-usage` — emits per-function `.su` files (no runtime cost)
  for use with `scripts/stack_summary.sh`.

Internal SPARK contracts (`Pre`/`Post`) are **proof-only** and not checked at
runtime. Enable `-gnata` in your application's GPR to enforce public API
preconditions at runtime.

### Stack budget

Per-function frame sizes (GNAT 15.2, x86_64 macOS, `-O2`):

| Function | Frame | Notes |
|---|---:|---|
| Permute   | 384 | Keccak-f[1600] permutation, deepest leaf |
| SHAKE128/256, SHA3_256/512 | 256 | one-shot APIs |
| Squeeze   |  96 |                                        |
| Absorb    |  48 |                                        |

Worst-case call chain: any one-shot API → Permute ≈ **640 B**. Run
`scripts/stack_summary.sh .` after `alr build` to regenerate the table.

## Known limitations

- **SHA3-224 and SHA3-384 are not implemented.** Only SHA3-256, SHA3-512,
  SHAKE128, SHAKE256 are exposed. Adding the missing variants is mechanical
  but has not been done.
- **No `pragma Inspection_Point` barriers** are placed around secret-dependent
  state. Their addition is part of the constant-time work above.
