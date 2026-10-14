# Cryptographic Review Guide — The Remote Viewer Network

**You are invited to review this code.** This project is 100% open-source,
zero-corporate, and built on the principle that security comes from sunlight,
not secrecy. If you know elliptic curves, AEADs, or constant-time Rust, your
eyes are welcome here.

## What this is

Hand-written, std-only, zero-dependency implementations of standard
primitives, used by a local-first encrypted communications network:

| File | Primitive | Standard |
|---|---|---|
| `crypto/ed25519.rs` | Ed25519 sign/verify, SHA-512, Curve25519 field arithmetic (5×51-bit limbs) | RFC 8032, FIPS 180-4 |
| `crypto/chacha20poly1305.rs` | ChaCha20-Poly1305 AEAD | RFC 8439 |
| `crypto/pbkdf2.rs` | PBKDF2-HMAC-SHA512 | RFC 8018 |
| `crypto.rs` | Keypair wrapper, secret zeroization, `Debug` redaction | — |
| `transport.rs` | X25519 (RFC 7748), HKDF-SHA512, encrypted channel w/ replay window | RFC 7748, RFC 5869 |

**Status: NOT production-ready.** An internal audit (see
`AUDIT-2026-10-14.md`) found and fixed one HIGH-severity bug. No independent
audit has happened. Do not use this for production value until one does.

## Threat model

- **Adversary:** network eavesdropper, malicious peer, device thief with
  the powered-off phone. Not: nation-state with a $10M side-channel lab
  (we say so openly).
- **Trust boundary:** everything inside the device. The OS CSPRNG
  (`/dev/urandom`) is trusted for entropy; if it fails, key generation
  fails closed rather than falling back to weak entropy.
- **What must hold:** signatures unforgeable without the secret key;
  ciphertexts unreadable and unforgeable without the key; no secret key
  material in logs, errors, or crash dumps; nonces never reused under
  one key.

## How to run the tests

```sh
# Full workspace (offline; everything is std-only)
~/.cargo/bin/cargo test --offline

# Crypto-focused
~/.cargo/bin/cargo test -p trv-core --lib crypto --offline
```

RFC test vectors are embedded: Ed25519 (RFC 8032 §7.1 tests 1–3),
ChaCha20-Poly1305 (RFC 8439 §2.8.2), X25519 (RFC 7748 §6.1), SHA-512
(FIPS 180-4).

## Where to look first (highest risk)

These are the places a subtle bug would hide. Listed in rough order of
consequence:

### 1. Ed25519 field arithmetic — `ed25519.rs` lines ~212–493

5×51-bit limb representation. Highest-risk functions:
- `fe_mul_raw` / `fe_mul` / `fe_sq` — check the carry chain and the
  `19 *` reduction factor handling. A carry bug here corrupts everything
  above it but may still pass test vectors on lucky inputs.
- `fe_inv` (via `fe_pow` with exponent 2²⁵⁵−21) — verify the addition
  chain. Compare against a reference (e.g., `curve25519-dalek`'s
  exponentiation sequence).
- `fe_frombytes` / `fe_tobytes` — canonical-encoding checks. Non-canonical
  encodings must be rejected (malleability).

### 2. Ed25519 scalar arithmetic — `ed25519.rs` lines ~494–647

- `sc_reduce64` / `sc_reduce_limbs` — reduction mod L
  (2²⁵²+27742317777372353535851937790883648493). This is the classic
  place for an off-by-one that passes vectors but breaks on edge scalars.
- `sc_muladd` — used in verification; check against RFC 8032 test 3
  (which exercises a non-trivial `S`).

### 3. Point operations — `ed25519.rs` lines ~649–830

- `ge_frombytes` — must check: canonical encoding, `y² = x² + ...`
  curve membership, and reject the identity point. (The internal audit
  found `verify()` accepted small-order points — fixed by rejecting any
  key with `[8]A == identity`. Check that fix holds under your own
  analysis.)
- `ge_scalarmult_base` / `ge_scalarmult` — comb/window methods; check
  `ge_cmov`/`ge_select` are truly constant-time selections and the
  precomputed base table is correct.
- `sign_inner` — deterministic nonce per RFC 8032 §5.1.6; verify the
  domain separation prefixes.

### 4. X25519 ladder — `transport.rs` `x25519()`

Montgomery ladder reusing the ed25519 field code. Check: scalar clamping
(`e[0] &= 248; e[31] &= 127; e[31] |= 64`), `fe_cmov`-based conditional
swaps (no secret-dependent branches), and the low-order-point rejection
(`is_low_order` via order probe). Cross-check against RFC 7748 §6.1 and
against the all-zero / low-order edge cases in the test module.

### 5. ChaCha20-Poly1305 — `chacha20poly1305.rs`

- Quarter-round: check rotation constants (16, 12, 8, 7) and the exact
  operation order against RFC 8439 §2.1.
- Poly1305 `r` clamping at the byte level; the `s` handling; the final
  tag comparison **must be constant-time** (`ct_eq`-style, no early exit).
- Verify the one-time key comes from counter-0 and the keystream starts
  at counter 1 (RFC 8439 §2.8). Check AAD/ciphertext padding and the
  length-encoding order in the MAC input.

### 6. Protocol layer (if you have time)

- `transport.rs` channel: nonce construction (4-byte session prefix +
  8-byte sequence), replay window marking **after** tag verification,
  per-direction keys.
- `mail.rs` sealed boxes: ephemeral X25519 freshness, HKDF info strings,
  sender-signature verification.
- Nonce discipline at every call site: search for `encrypt(` and confirm
  no nonce is ever reused under one key.

## Known limitations (we're honest about these)

- No independent professional audit has happened.
- Constant-time properties are by construction (no secret-dependent
  branches in field/ladder code) but have **not** been verified with a
  timing-analysis tool. If you can run one, we'd love the results.
- `SecretKey::hex()` exports the seed (by design for issuer tooling, with
  warnings) — review whether the call sites justify it.
- Messaging has per-handshake (not per-message) forward secrecy — a
  design decision, documented in the audit.
- Timestamps are caller-supplied (no trusted on-device clock); replay
  windows are the receiver's responsibility.

## What native assurance already covers

1. **Internal audit** (`AUDIT-2026-10-14.md`): line-by-line review, RFC
   vectors, one real HIGH bug found and fixed (small-order Ed25519 forgery).
2. **Differential testing** (`~/workspace/scratch/crypto-diff/`): our
   outputs cross-checked against Python's `cryptography` library on
   thousands of random inputs — Ed25519 sign/verify, ChaCha20-Poly1305
   encrypt/decrypt (including tampered tags), X25519, SHA-512.
   Latest run: see `last_run.txt` in that directory.
3. **Kani harnesses** (`~/workspace/scratch/crypto-kani/`, when present):
   bounded model checking for panics/overflows on the highest-risk
   functions. See `kani-results.txt` for what was proven.

## How to report findings

Open an issue on the repository with:
- The function and line numbers
- A minimal reproducer (input bytes in hex)
- Whether you believe it's exploitable and how
- Whether existing tests should have caught it (this helps us improve)

If you find a critical vulnerability, please give us a reasonable window
before public disclosure. There is no bug bounty (pre-revenue open-source
project) — only gratitude and credit.

## Ground rules for this codebase

- std only, zero dependencies, zero warnings (`cargo build` must be silent).
- Fail closed: every error path denies rather than permits.
- No `unsafe` except the documented volatile-write zeroization (and even
  that is flagged for review).
- Every fix ships with a regression test that fails on the old code.
