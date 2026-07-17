# pkvault repository layout & manifest — v1 draft 0.1 (2026-07-15)

> Companion to SPEC.md (v1 wire format, frozen). Defines the committed
> manifest, the `.pkvault/` directory, and the configured-path rules
> that SPEC §8.2 references. Same review bar as SPEC.md.

## 1. Repository layout

```
.pkvault/
  config.toml        committed — configured paths
  recipients.toml    committed — the manifest (§2)
  identities/        committed — wrapped identity blobs (SPEC-IDENTITY.md)
  txn, txn.tmp       NEVER committed — transaction state (SPEC §8.2)
  lock               NEVER committed — mutation lock (SPEC §8.3)
<vault file>         committed — SPEC.md wire format, path from config
```

`init` writes a `.gitignore` inside `.pkvault/` covering `txn`,
`txn.tmp`, and `lock`. Per SPEC §8.2, pkvault refuses to operate while
any of those three is git-tracked or is a symlink.

## 2. `recipients.toml` (the manifest)

A deliberately tiny TOML subset — one unambiguous parse or no parse,
same philosophy as the wire grammar:

- UTF-8, LF-only, final LF required; CR anywhere is a parse error.
- Each line is exactly one of: blank; comment (first non-space byte
  `#`); or `label = "recipient"` — a bare key, ` = `, a double-quoted
  basic string with **no escape sequences**, end of line.
- `label` matches `[a-z0-9-]{1,32}` (SPEC §2.2 grammar). Duplicate
  labels are a parse error.
- `recipient` is a fully valid age X25519 recipient string under SPEC
  §2.2's rules: Bech32-decoded, HRP `age`, 32-byte payload, equal to
  its canonical lowercase re-encoding.
- **Uniqueness is by decoded 32-byte key** across the whole file
  (SPEC §2.2 — the alias-survives-removal attack).
- At least one entry. No tables, arrays, multiline strings, dotted
  keys, or inline comments after values.
- Human ordering is free; the tool writes entries sorted by label.

The canonical `#! recipients:` baseline in the vault header is derived
from this file per SPEC §2.2 at seal time; §7's guard diffs the two.

## 3. `config.toml`

Same TOML subset, keys fixed:

- `vault = "<repo-relative path>"` — required; exactly one in v1
  (PLAN §5). Multi-file later adds keys without breaking this schema.
- `local = "<repo-relative path>"` — optional **personal layer**: a
  second vault sealed to ONE person, gitignored, never committed;
  merged over the team vault at `run`/`get` time (personal wins). A
  present-but-unopenable local vault is someone else's and is ignored
  on read. Exists so per-machine overrides are encrypted at rest
  rather than plaintext (`.local` files defeat the threat model
  otherwise — FRICTION-LOG finding #4).

## 4. Configured-path rules (restates SPEC §8.2 path boundary)

- All configured paths are canonical repository-relative: no absolute
  paths, no `.` / `..` segments, no trailing slash, no backslashes.
- `.pkvault` and every directory from the repository root down to each
  target's parent MUST be a real directory, not a symlink.
- An existing configured target MUST be a regular, non-symlink file;
  a symlink or other file type at a configured target is a refusal.
- Every create/hash/rename/delete operates through these validated
  directories only.

## 5. Errors

Named codes, same style as the wire layer: `E_MANIFEST_PARSE`,
`E_MANIFEST_DUP_LABEL`, `E_MANIFEST_DUP_KEY`, `E_MANIFEST_RECIPIENT`,
`E_MANIFEST_EMPTY`, `E_CONFIG_PARSE`, `E_PATH_BOUNDARY`, `E_TRACKED`,
`E_LOCKED`, `E_LOCK_STALE`, `E_TXN_PENDING`, `E_TXN_MARKER`,
`E_TXN_RECOVERY`.
