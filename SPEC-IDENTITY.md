# pkvault identity blobs — v1 draft 0.1 (2026-07-16)

> Companion to SPEC.md. Defines the wrapped-identity files in
> `.pkvault/identities/` — how a personal X25519 identity is wrapped
> under passkey-PRF and recovery-code KEKs (PLAN §4.1, the pknotes
> `wrapped_mk` pattern). Blobs are ciphertext-safe: committed to the
> repo so "clone + tap" works on a fresh machine with zero extra steps
> (only the passkey syncs; the blob must travel — PLAN §4.1).

## 1. File: `.pkvault/identities/<label>.wrap`

One file per manifest label. Same global encoding rules as SPEC §0
(UTF-8, LF-only, final LF, canonical padded base64).

```
#! pkvault-identity 1
#! label: daniel
#! recipient: age1…

wrap prf <cred-id-b64> <rp-id> <prf-salt-b64> <nonce-b64> <ct-b64>
wrap recovery <scrypt-salt-b64> <logN> <nonce-b64> <ct-b64>
```

- Version dispatch before layout, as SPEC §2.0 (`pkvault-identity`
  major; unknown → "upgrade required").
- `label` matches the manifest grammar; MUST equal the filename stem.
- `recipient` is the identity's public half under SPEC §2.2 rules —
  and the blob's integrity anchor (§4).
- One blank separator, then ≥ 1 `wrap` lines. Unknown wrap types are
  a per-line "upgrade required" (other wraps remain usable); zero
  usable wraps is a refusal.

## 2. KEKs

All KEKs are 32 bytes and never stored:

- **prf:** the WebAuthn PRF extension output (32 bytes) for
  `prf-salt` under the stored credential, then
  `KEK = HKDF-SHA-256(ikm=prf_output, salt=recipient_pub_32, info="pkvault/kek/prf/v1")`.
  `prf-salt` is 32 random bytes minted per wrap at credential
  registration (the salt must exist before the first evaluation).
  `rp-id` records where the credential lives (PLAN §9 gate 1);
  `cred-id` selects the credential at assertion time.
- **recovery:** printed once at creation, never stored. Format:
  `PKVR-` + 8 groups of 4 Crockford-base32 chars (20 random bytes).
  Normalization before use: uppercase, strip `-` and spaces.
  `KEK = scrypt(normalized_code, salt=scrypt-salt_16, N=2^logN, r=8, p=1, 32)`;
  v1 writes `logN = 15`. Parsers MUST accept 10 ≤ logN ≤ 17 and
  refuse outside that range. The upper bound equals the largest value
  that actually runs under the fixed 256 MiB `maxmem` on the minimum
  supported runtime (Node 18) — scrypt needs ≈128·2^logN·8 bytes, so
  logN 18+ would throw `ERR_CRYPTO_INVALID_SCRYPT_PARAMS`. The accepted
  range must equal the *usable* range; an out-of-range logN (e.g. a
  memory-bomb 30) is refused outright.

## 3. Wrapping

`ct = AES-256-GCM(KEK, nonce_12, identity_scalar_32, AAD)` with

```
AAD = UTF8("pkvault/identity/v1") || 0x00
   || recipient_pub_32
   || UTF8(wrap-type)
```

AAD-binding to the recipient means a ciphertext transplanted into a
blob with a different `#! recipient:` line fails the GCM tag.

## 4. Integrity (self-authenticating, no MAC)

After any successful unwrap, the implementation MUST derive the
X25519 public key from the recovered scalar and require it to equal
the `#! recipient:` line byte-for-byte. The blob authenticates itself
against its own contents; there is no MAC key to manage. What this
does NOT protect: an attacker replacing the entire blob *and* its
recipient with their own — that is a recipient-set change, and the
manifest + vault baseline (SPEC §§2.2, 7) are the authorities that
catch it. The CLI MUST verify blob recipient ∈ manifest on use.

## 5. Recovery semantics (PLAN §4.1)

Recovery re-wraps the identity under a **fresh passkey credential** (the
old one was lost). It does NOT — and cannot — burn the recovery code.
The X25519 scalar IS the identity permanently, so any retained
pre-recovery blob (git history, clones, backups) still unwraps that same
scalar with the same code. The recovery code is therefore **permanent
recovery escrow**: treat it like a root key. Recovery keeps the same
code (re-wrapped under a fresh scrypt salt) rather than pretending a new
code revokes the old.

**True revocation** is identity rotation: run `setup` for a brand-new
scalar and be re-added to every vault (`add`) — the offline,
multi-repository design cannot reach and reseal every vault on the
holder's behalf, so revocation is necessarily a manual, per-vault act.
Docs and CLI MUST describe the code as permanent escrow, never as
"burned."

## 6. Errors

`E_IDENTITY_PARSE`, `E_IDENTITY_VERSION`, `E_IDENTITY_WRAP_VERSION`,
`E_IDENTITY_NO_WRAP`, `E_IDENTITY_KEK` (bad PRF output/code — GCM
failure), `E_IDENTITY_PUB_MISMATCH`, `E_IDENTITY_SCRYPT_PARAM`.
