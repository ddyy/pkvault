# pkvault file format — v1 draft 0.10 (2026-07-15)

> Status: **v1 WIRE FORMAT FROZEN**; crypto/parser AND transaction
> recovery state machine APPROVED (pass 9). 0.10 carries pass 9's
> three workflow corrections (replacement-write wording, ancestor
> symlink boundary, exact marker grammar) — the reviewer's stated
> gate for full workflow approval. No further crypto or transaction
> redesign is needed (reviewer, pass 9).
> The format is the contract — CLI code is replaceable, bytes in other
> people's repos are not. Every unusual rule traces to a demonstrated
> failure in FRICTION-LOG.md or a decision in PLAN.md §4.

## 0. Global encoding rules

- Files are UTF-8, **LF line endings only**, ending with a final LF.
  A CR byte anywhere is a parse error (before any crypto).
- All **pkvault-owned** base64 (directive values, ENC token fields) is
  RFC 4648 standard alphabet, padded; non-canonical encodings
  rejected. Bytes *inside* the decoded age envelope follow age's own
  format rules.
- "Trailing whitespace" = ASCII space (0x20) and tab (0x09) only.
- All MAC comparisons are **constant-time**.
- "Byte-exact" means byte-exact.

## 1. Design goals (ranked)

1. **Fail safe:** a classification mistake encrypts too much, never
   too little. Corollary (§9): ordinary text editing can never
   declassify a secret.
2. **Tamper-evident within stated limits:** swaps, edits, and
   recipient changes are mechanically detectable (§6); the exclusions
   — member attribution, whole-file rollback — are stated (§6.3).
3. **Reviewable:** names diff in plaintext; unchanged values stay
   byte-stable; ordinary-body comments and ordering are preserved
   verbatim.
4. **age-compatible sealing:** the file key travels as a complete,
   standard age file (§5) — `age -d` alone can recover it.

## 2. File layout

Schematic example — ellipses are intentionally invalid encodings;
real files appear only in fixtures:

```
#! pkvault 1
#! file-id: 3q2+7wEjRkVmTGhK
#! sealed: YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSD…
#! recipients: ci-github=age1qq…, daniel=age1pk…
#! mac: hkYc9PzW0eG1rJq4vXnB8dLmA2sT5uIoP3fRw6yE7cs=

# database — rotate quarterly
DATABASE_URL=ENC[1:kQ3m9v2c8xZa:pF7LkQ9mN2v…]
API_HOST=api.example.com # public
STRIPE_WEBHOOK_SECRET=ENC[1:aB4n7c1d5eFg:qR8sT2uV6wX…]
```

### 2.0 Version dispatch

First line MUST match `#! pkvault <major>`, `<major>` matching
`[1-9][0-9]*`. Dispatch on the major **before** enforcing any
version's layout: unknown major → "upgrade required: file is
pkvault N," never an incidental v1 header error. Below: major 1.

### 2.1 Structure (v1)

```
header      exactly five #! directives, fixed order, byte 0
separator   exactly one blank line
preamble    zero or more canonical annotations (§2.3a)
body        ordinary lines (§2.3b)
```

Missing/duplicate/reordered/unknown directives or a missing separator
are parse errors.

| Directive | Content |
|---|---|
| `#! pkvault 1` | format major (§2.0) |
| `#! file-id:` | base64 of 12 random bytes, minted at adoption, never changed |
| `#! sealed:` | base64 of the **age envelope** (§5) |
| `#! recipients:` | canonical last-seal recipient baseline (§2.2) |
| `#! mac:` | base64 of the 32-byte HMAC (§6) |

### 2.2 Canonical recipients line

`label=recipient` entries joined by `", "`, sorted by label ascending
byte order. Labels match `[a-z0-9-]{1,32}`, unique. **≥ 1 recipient
required.** Each recipient: fully valid age X25519 recipient string —
Bech32-decoded, HRP exactly `age`, 32-byte payload — equal to its
canonical lowercase Bech32 re-encoding byte-for-byte.

**Uniqueness is by decoded 32-byte key**, not string or label — two
labels carrying one key would let a "removed" member keep decrypting
through their alias (fixture N15).

Byte-deterministic across implementations. The committed manifest
(`recipients.toml`: keys = labels, values = recipient strings, same
grammar/canonicalization/uniqueness) gets SPEC-MANIFEST.md (§12.2)
before workflow implementation.

### 2.3a Preamble annotations

Lines whose first bytes are `# pkvault:`. Tool-owned, file-level.
Permitted ONLY in the preamble section (§2.1) — after any ordinary
body line (blank, comment, assignment), a `# pkvault:` line is a
parse error. The preamble MUST be sorted lexicographically (it is a
canonical set, like the recipients line — fixture N17 rejects
unsorted or interspersed annotations). Merges union preambles and
re-sort. The **no-reordering promise (goal 3) applies to the ordinary
body**, not to canonical sections.

### 2.3b Body grammar (wire; the editor form is §9)

Each ordinary body line is exactly one of:

- **Blank line.**
- **Comment** — first byte `#`, not `#!` (parse error), not
  `# pkvault:` (§2.3a).
- **Encrypted assignment** — `NAME=ENC[…]` (§3).
- **Public assignment** — `NAME=value # public`.

Rules, violations rejected with named errors:

- `NAME` matches `[A-Za-z_][A-Za-z0-9_]*` (settled; relaxation is a
  major bump).
- **Names are unique under ASCII case-folding** (`Path` vs `PATH` is
  a duplicate): Windows environment names are case-insensitive, and
  this format promises identical delivery semantics per teammate —
  the same committed vault must not parse on macOS and refuse on
  Windows (fixture N18).
- No quotes, escapes, `export`, leading whitespace, or multiline
  syntax.
- Public values: bytes between `=` and the exact suffix ` # public`.
  Any other trailing `#…` on an assignment is a parse error.
- Empty values legal in both forms.
- Ordinary-body comments and blank lines preserved verbatim, in
  place, MAC-covered; the tool never reorders them.
- **Comment identity (for §8):** each run of comment/blank lines
  belongs to the next assignment below; a run at EOF is the trailer.
- Unmarked plaintext assignments are not valid on the wire (§9 only).

### 2.4 Value domains

- **Encrypted plaintexts:** any **valid UTF-8** except NUL; LF and CR
  permitted. (Env delivery is strings in Node, UTF-16 on Windows;
  the format doesn't pretend otherwise.) **Binary secrets are
  user-base64-encoded before entry.**
- **Public values:** valid UTF-8, no NUL/CR/LF, no `#`, no trailing
  whitespace.
- **Post-decryption validation is normative:** after the GCM tag
  verifies, plaintext MUST validate against this section; violation
  is a named error (fixture N16).

## 3. Value encryption

```
ENC[<v>:<nonce-b64>:<ct-b64>]
```

- `<v>`: inner version matching `[1-9][0-9]*`, currently `1`.
  Unknown inner version → **"upgrade required, value version N"**
  (distinct from "malformed"). With such a token present: targeted
  reads of known values (`get`) proceed; **`run` fails** (cannot
  construct the complete environment); every rewrite (edit/save,
  reseal, rotate) **refuses, file untouched** — a conservative policy
  choice (a same-FK reseal doesn't technically require decrypting the
  unknown token, but partial understanding is not a state we write
  from).
- AES-256-GCM, key = VEK (§4). Nonce = 12 random bytes per
  (re-)encryption; `<nonce-b64>` MUST decode to exactly 12 bytes.
- `<ct-b64>` decodes to `ciphertext || tag`, 16-byte tag appended,
  decoded length ≥ 16.
- **AAD, byte-exact:**

  ```
  AAD = UTF8("pkvault/value/v1") || 0x00
     || file_id                              (12 raw bytes)
     || uint32be(len(NAME))
     || ASCII(NAME)
  ```

  Injective; name binding kills ciphertext swaps, file-id binding
  kills cross-file transplants. AAD is defense-in-depth behind the
  MAC; §11 tests it under valid recomputed MACs.
- Only changed values re-encrypt on save; untouched tokens copy
  byte-identically.

## 4. Keys

FK: 32 random bytes, per file, minted at adoption; a pure root key:

```
VEK     = HKDF-SHA-256(ikm=FK, salt=file_id_raw, info=UTF8("pkvault/vek/v1"))   → 32 bytes
MAC_KEY = HKDF-SHA-256(ikm=FK, salt=file_id_raw, info=UTF8("pkvault/mac/v1"))   → 32 bytes
```

Rotating FK rotates everything. Per-file FKs → independent rotation,
later per-file recipient sets. v1 CLI: one file per repo.

## 5. Sealing — the age envelope

`#! sealed:` is the base64 of a complete, **unarmored binary** age v1
file whose plaintext payload is exactly the 32-byte FK.

**Writer obligations:** seal to every baseline recipient exactly
once, and to no others; emit X25519 stanzas only; never grease.

**Reader validation (strict):**
- the decoded bytes MUST be an unarmored age v1 file;
- **every recipient stanza MUST be type `X25519`** — SSH, plugin,
  grease, and unknown stanza types are REJECTED. An unknown stanza is
  indistinguishable from a real additional recipient type: an
  ssh-ed25519 stanza would hand FK to a key outside the baseline
  while the X25519 count still matched. pkvault reads only envelopes
  pkvault wrote, so strictness costs nothing. (Observed grease in
  Phase 0 captures came from the Rust age crate used by dotenvage —
  rage greases file headers, Go age does not; either way, not our
  writer, so not our reader's problem.)
- X25519 stanza count MUST equal the baseline recipient count — a
  consistency check against smuggled recipients, NOT proof that each
  anonymous stanza matches a particular baseline key (that assurance
  comes from writer obligations + MAC + threat model);
- decrypted payload MUST be exactly 32 bytes.

Envelope regenerates wholesale per seal. Diff-shape promise: a reseal
changes only the `sealed`/`mac` (and `recipients` when the set
changed) lines **within the vault file** — `recipients.toml` changes
too in the repo diff. Body ciphertexts stay byte-stable.

**Rotate (remove):** fresh FK, all values re-encrypted, baseline
rewritten, deliberately noisy; header-only "remove" diffs are flagged
anomalous (N3).

## 6. Integrity

### 6.1 MAC

MAC input = exact file bytes with the bytes beginning at the first
byte of `#! mac:` and continuing through and including that
directive's terminating LF **removed** — no replacement LF or blank
line is inserted (K4 demonstrates the exact resulting bytes).
MAC = HMAC-SHA-256(MAC_KEY, input); constant-time comparison.

### 6.2 Verification order

```
structural parse (dispatch, header, grammar, encodings)
→ unseal FK (strict §5 validation; requires a member identity)
→ verify MAC (hard-fail)
→ interpret / decrypt body (incl. §2.4 post-decryption validation)
```

- **Integrity verification requires membership.**
- **A MAC mismatch is boolean**; line-level reports require a
  separately MAC-verified git ancestor, else generic.
- MAC failure never routes to silent recomputation — only §8 or
  refusal.

### 6.3 Stated limits (README day one)

- **No member attribution** (every member can mint a valid MAC; git
  in v1, signatures in v2).
- **No rollback detection** (replaying manifest + vault to a
  pre-removal commit makes the next legitimate seal re-encrypt
  current secrets to the removed member; mitigations: visible git
  event, v2 seal counter).

## 7. Recipient-change guard (normative behavior)

Before any seal: diff `recipients.toml` against the MAC-verified
baseline. Any delta → interactive confirmation, full strings shown,
additions default NO. Non-interactive contexts refuse to seal.
Baseline updates only on confirmed seal.

## 8. Merge repair protocol

Concurrent edits both rewrite the MAC line (and sometimes the sealed
line — value edits change only the MAC), so plain git normally
reports a **textual conflict** on the header. Clean-but-MAC-invalid
files arise from manual resolution, merge drivers, or naive tooling —
and "accept and recompute" is how malicious edits get laundered.

Inputs are merge stages **base, ours, theirs** (git index stages
1/2/3).

**Preconditions:** the merging member unseals **every** verified
input (refusal names unopenable envelopes). Classification is part of
each variable's record; a declassification from either branch crosses
the §9 confirmation boundary.

1. **Verify each input independently** (full §6.2).
2. **Resolve recipients** three-way vs base: removals win unless
   explicitly reversed; additions default NO; same label + different
   key = remove+add; empty resolved set = refusal.
3. **Resolve FK:** any removal, or inputs not sharing one FK → fresh
   FK, re-encrypt everything; else preserve FK and reuse tokens.
4. **Merge variable records by ASCII-case-folded NAME**, preserving
   the selected record's original spelling; branches introducing
   different spellings of one folded name are a **human conflict**,
   never disjoint additions (fixture F12). Records = value +
   classification + attached comments: disjoint edits compose;
   conflicts (including **delete-vs-modify**) are human choices;
   ordering is a sequence-merge with same-position insertions a human
   choice; preambles union and re-sort; trailer merges as a unit.
5. **Mint the merged file** and update manifest + vault via §8.2
   under the §8.3 lock.

### 8.1 Unverified-merge override — precise boundary

`--accept-unverified-merge` relaxes **MAC authenticity only**. The
accepted input MUST still parse structurally, unseal (§5 strict), and
pass GCM + §2.4 on every value selected into the result. Never
bypasses malformed tokens, failed tags, or missing data. An
unavailable input is only explicitly **discarded**, and recorded.

Normative marker (a preamble annotation, §2.3a):

```
# pkvault: accepted-unverified-merge by <label> on <YYYY-MM-DD> UTC; accepted: <stage>@<oid>[, …]; discarded: <stage>@<oid>[, …]
```

`<stage>` ∈ base/ours/theirs, and stage lists are ordered
**base, ours, theirs**; `<oid>` = exactly `sha1:` + 40 lowercase hex
characters or `sha256:` + 64 lowercase hex characters (the blob's
full git storage object ID, unabbreviated), or `none` when no blob
exists; `discarded:` omitted when empty. The marker
is MAC'd and diff-visible; "permanent" means visible in ordinary git
history — later deletion is itself a reviewable diff event.

### 8.2 Two-file crash consistency

No filesystem gives cross-path transactions. Normative sequence for
any manifest+vault update:

1. Create both replacement temp files **in their target
   directories**, reserved pattern
   (`.pkvault-tmp-<target-basename>-<random>`, where `<random>` is
   exactly 32 lowercase hex characters from 16 cryptographically
   random bytes), each with **`O_CREAT|O_EXCL|O_NOFOLLOW`** — a
   chosen temp path that already exists or is a symlink is a
   **refusal**, not an overwrite. **Write the complete replacement
   bytes to each temp file, and compute (or verify) each `new` hash
   from those exact bytes** — the hash in the marker attests the
   temp's actual contents, never an intention.
2. `fsync` each completed temp file.
3. `fsync` each directory containing a newly created temp file (the
   entries must survive power loss).
4. Create `.pkvault/txn.tmp` with **`O_CREAT|O_EXCL|O_NOFOLLOW`**
   (an existing or symlinked `txn.tmp` is a refusal — see stale
   cleanup below); write the complete marker; `fsync` it.
5. `rename(2)` `.pkvault/txn.tmp` → `.pkvault/txn` (marker
   publication is itself atomic — a crash can never leave a
   partially written marker; an **unpublished** `txn.tmp` is inert
   and carries no recovery obligation).
6. `fsync` the `.pkvault` directory.
7. `rename(2)` the vault, then the manifest; `fsync` each containing
   directory.
8. Remove `.pkvault/txn`; `fsync` its directory.

**Path boundary (applies to every operation in this section):**
configured targets MUST be canonical repository-relative paths.
`O_NOFOLLOW` protects only the final path component, so additionally:
`.pkvault` and **every directory from the repository root down to
each target's parent MUST be a real directory, not a symlink**; all
creation, hashing, renaming, and deletion operate through these
validated directories; a symlinked ancestor, or any path resolving
outside the repository, is a **refusal**. **An existing configured
vault or manifest target MUST be a regular, non-symlink file; an
absent target is permitted only when the marker records
`old: null`; a symlink or any other file type at a configured target
is a refusal** (a rename must never silently replace an
in-repository symlink). (These rules are repeated in
SPEC-MANIFEST.md when the configured vault-path schema is defined.)

**Marker grammar (exact):** UTF-8 JSON, no BOM, no comments;
duplicate keys and unknown fields rejected; maximum size 4096 bytes.
The top-level object contains exactly:

- `txn`: integer `1`
- `hash`: string `"sha256"` (over raw file bytes)
- `files`: array of exactly one vault entry and one manifest entry,
  each containing exactly:
  - `target`: string
  - `temp`: string
  - `old`: `null` (= target absent before) or exactly 64 lowercase
    hex characters
  - `new`: exactly 64 lowercase hex characters

Illustrative shape (elided field values violate the grammar —
elisions are invalid *field values*, not invalid UTF-8; complete
examples live in fixtures):

```json
{"txn":1,"hash":"sha256","files":[
 {"target":".env.pkvault","temp":".pkvault-tmp-.env.pkvault-3f9a…",
  "old":"a1b2…64hex…","new":"c3d4…64hex…"},
 {"target":".pkvault/recipients.toml","temp":".pkvault/.pkvault-tmp-recipients.toml-7e2b…",
  "old":null,"new":"e5f6…64hex…"}]}
```

**The marker is untrusted, repository-controlled input** — a cloned
repo can ship an arbitrary `.pkvault/txn`. Recovery MUST validate
before touching anything. **Schema validation is strict and purely
syntactic** (it never requires any file to exist):

- The document MUST be well-formed JSON with **no duplicate keys**
  (beware: `JSON.parse` silently keeps the last duplicate — use a
  duplicate-rejecting parse or validate the raw text), no unknown
  fields, correct types for every field, `"txn": 1`,
  `"hash": "sha256"`, and **exactly one entry per configured target**
  (v1: exactly two — vault and manifest). Malformed JSON, wrong
  entry count, wrong types → refusal untouched.
- `target` MUST equal one of the configured vault or manifest paths —
  nothing else, ever; no duplicates.
- `temp` MUST lie in the corresponding target's directory and match
  the reserved temp filename pattern — a **path-shape check only**;
  whether the temp exists is NOT part of validation (`target == new`
  with temp absent is the normal success case). The
  regular-file/non-symlink requirement is enforced at the moment a
  branch needs to read or install the temp.
- Absolute-path escapes and `..` traversal are rejected.
- pkvault MUST refuse to operate at all while `.pkvault/txn`,
  `.pkvault/txn.tmp`, or `.pkvault/lock` is tracked by git or is a
  symlink (they are process-local state; a tracked or redirected
  marker is an attack surface, not a transaction).

Recovery (under the §8.3 lock, before any other operation): for each
validated entry, hash the target:

- matches `new` → that rename landed; discard any leftover temp
  (success does not depend on the temp's presence or contents);
- matches `old` (or target absent with `old: null`) → **verify
  `hash(temp) == new` first**, then complete the rename. Temp absent
  or temp hash ≠ `new` → **refuse with instructions** — a temp file
  is repository-adjacent input and is NEVER installed unverified;
- matches **neither** hash → refuse with instructions, never guess.

**Recovery is idempotent and follows the same durability discipline
as the forward path:** each recovery rename is followed by an `fsync`
of the containing directory; the published marker is removed (and its
directory `fsync`ed) **only after every entry is resolved**. A crash
at any point during recovery leaves the marker in place, and re-run
recovery converges — the per-entry hash checks make each step a
no-op or a completion, never a repeat with different effect.

Stale unpublished state (crash before marker publication): a leftover
`txn.tmp`, or temp files matching the reserved pattern with no
published marker, are deleted at next mutation — unlinking only
regular, non-symlink, **untracked** files matching the reserved
pattern in their expected directories. A git-tracked file matching
the reserved temp pattern is a **refusal to operate**, never a
deletion (deleting tracked content on sight is an attack primitive,
not hygiene).

With the listed `fsync` points this is power-loss durable;
implementations that skip them MUST document "process-crash
consistency" instead. (Fixture F7 covers the full crash matrix.)

### 8.3 Repository mutation lock

Every mutation (edit/save, set, add, remove, reseal, rotate, merge
repair, txn recovery) first acquires an exclusive lock —
`.pkvault/lock`, O_CREAT|O_EXCL, containing holder pid + ISO-8601 UTC
timestamp. **Operations that require both the vault and manifest
MUST hold the lock while obtaining their snapshot** — git provides
no snapshot semantics for working-tree reads, and the vault MAC
cannot detect a new-vault/old-manifest pairing. Vault-only reads MAY
remain lock-free (vault replacement is atomic and the vault is
internally MAC-verified). A read that encounters `.pkvault/txn` MUST
refuse, or acquire the lock and complete §8.2 recovery before
continuing. Stale-lock recovery: a lock
whose pid is dead may be broken with an explicit
`pkvault unlock --force`, never automatically. Two concurrent
writers: one proceeds, the other refuses with the holder's pid
(fixture F9).

## 9. Editor representation (`pkvault edit`)

The wire grammar and the editor buffer are **different languages**.
Governing rule: **classification is metadata, never inferred from
buffer text.**

- Classification map comes from the stored, MAC-verified file.
- Secret variables: rest-of-line after `=` is the value, no marker
  parsing.
- Public variables: ` # public` rendered and stripped; **deleting or
  modifying the marker is an editor parse error naming the line.**
- **Editor-incompatible values (containing LF or CR) render as the
  sentinel:**

  ```
  PRIVATE_KEY=<pkvault:multiline; use `pkvault set PRIVATE_KEY`>
  ```

  Unchanged sentinel → token preserved byte-for-byte. Modified
  sentinel → editor parse error. **Sentinel-backed records cannot be
  renamed in-buffer** (rename would silently orphan the multiline
  original and mint a new secret whose literal value is sentinel
  text) — renames use a command. **Deleting a sentinel line deletes
  the variable only via the normal deletion path:** all deletions
  (sentinel or not) are listed in a save-time summary requiring
  confirmation.
- **New names default to secret.**
- **`pkvault set NAME` stdin, byte-exact:** read to EOF, no trimming,
  final LF is part of the value; input MUST be valid UTF-8, no NUL
  (fixture F8). Multiline values enter here; binary is
  user-base64-encoded first.
- **`pkvault public NAME` MUST refuse when the current value is
  outside the public domain** (contains LF/CR, `#`, or trailing
  whitespace) — confirmation cannot make an unrepresentable value
  valid (fixture F11). Declassification is only this command;
  `pkvault secret NAME` needs no confirmation.
- On save: changed values re-encrypt; classification re-applies; wire
  file regenerates per §2.3.

### 9.1 Plaintext-exposure honesty (amends PLAN §5)

- **`pkvault set` (stdin) is the strict path** — no buffer file.
- **`pkvault edit` is documented best-effort:** per-invocation
  private temp dir mode **0700**, buffer **0600**, unlinked
  immediately after the editor exits; stale buffer directories from
  crashed sessions are **best-effort overwritten where supported,
  then deleted** on the next invocation (secure deletion cannot be
  guaranteed on SSDs, CoW filesystems, or snapshots — the README
  says so); editor invoked with history-suppressing hints where
  known (vim `-n -i NONE`).
- No absolute "no disk plaintext" claim appears anywhere.

## 10. Versioning

- `#! pkvault <major>`: byte-incompatible changes; dispatch precedes
  layout (§2.0).
- `ENC[<v>…]`: per-value migration, fail-closed, rewrite-refusal.
- NAME charset + case-fold rule settled; relaxation is a major bump.
- 1.0 = §11 fixtures exist and pass on an implementation.

## 11. Test fixtures (must exist before CLI code)

`fixtures/manifest.json`: per-fixture metadata — test identities,
expected FK, expected plaintexts, expected exact error code.

### 11.1 Known-answer vectors (`fixtures/kat/`)

Cross-checked against a genuinely independent stack (Go stdlib or
Python `cryptography`; Node classic crypto and Web Crypto share
OpenSSL):

- K1. HKDF: (FK, file-id) → VEK, MAC_KEY.
- K2. AAD: (file-id, NAME) → exact bytes.
- K3. AES-256-GCM: (VEK, nonce, plaintext, AAD) → exact token.
- K4. MAC input: small file → exact HMAC input bytes (demonstrating
  the §6.1 line-removal — no replacement LF) and MAC.

### 11.2 Wire fixtures — positive

- W1. `roundtrip.env` — byte-for-byte preservation (ordinary body);
  body beginning with blank lines.
- W2. `add-recipient.diff` — reseal +1: within the vault file, only
  `sealed`/`recipients`/`mac` change; body stable. (The repo diff
  also touches `recipients.toml`.)
- W3. `multiline-secret.env` — ENC plaintext containing LF
  round-trips.

### 11.3 Wire fixtures — negative (MUST fail in the named way)

N1/N2/N4 carry valid recomputed MACs so they reach the GCM layer.

- N1. `aad-name-swap.env` — swapped ciphertexts, MAC valid → GCM
  failures.
- N2. `aad-file-swap.env` — cross-file-id transplant, MAC valid →
  GCM failure.
- N3. `rotate.env` — removed identity cannot unseal new envelope;
  header-only "remove" flagged.
- N4. `bad-tag.env` — corrupted tag, MAC valid → GCM failure.
- N5. `mac-plaintext-tamper.env` — MAC failure; line-named with
  verified ancestor, generic without.
- N6. `mac-recipient-tamper.env` — baseline edited → MAC failure.
- N7. `duplicate-name.env` — parse error.
- N8. `bad-token.env` — missing field / nonce ≠ 12 / ct+tag < 16 /
  zero or leading-zero version → parse errors.
- N9. `future-value-version.env` — `get` of known values succeeds;
  `run` fails; every rewrite refuses, file untouched.
- N10. `crlf.env` / `no-final-newline.env` — parse error before any
  crypto.
- N11. `bad-header/` — directive/separator violations; body `#!`
  line; zero recipients; invalid or mixed-case recipient → parse
  errors.
- N12. `bad-base64.env` — non-canonical base64 in pkvault-owned
  fields → rejected.
- N13. `unmarked-plaintext.env` — parse error.
- N14. `unknown-major.env` — `#! pkvault 9` + non-v1 layout →
  "upgrade required," not a v1 header error.
- N15. `duplicate-recipient-key.env` — two labels, one decoded key →
  rejected.
- N16. `bad-envelope/` — not an age file; armored; **any non-X25519
  stanza (ssh-ed25519, plugin, grease) → rejected**; X25519 count ≠
  baseline (extra AND missing); payload ≠ 32 bytes. Plus
  `bad-plaintext.env` — decrypts to invalid UTF-8 or NUL → §2.4
  error.
- N17. `bad-preamble/` — unsorted annotations; `# pkvault:` line
  after an ordinary body line → parse errors.
- N18. `case-fold-collision.env` — `FOO` and `foo` → parse error.

### 11.4 Workflow fixtures (editor + merge + transactions)

- F1. `edit-classification/` — unmarked new name → encrypted; secret
  value ending ` # public` → stays secret; marker deleted/modified →
  parse error; declassify only via command.
- F2. `edit-sentinel/` — LF and **CR-only** values render as
  sentinel; unchanged → byte-preserved; modified → error.
- F3. `disjoint-merge/` — shared FK, disjoint edits → composed file,
  ciphertext reuse, §8.2 update.
- F4. `rotated-merge/` — removal wins, fresh FK, full re-encrypt,
  removed identity locked out.
- F5. `conflict-merge/` — same-variable conflict AND
  delete-vs-modify → human choices.
- F6. `dirty-merge/` — MAC-invalid input, GCM-valid values → refusal
  without override; with it, exact §8.1 marker in preamble.
  Companion: selected values fail GCM → override **remains
  forbidden**.
- F7. `interrupted-txn/` — the full crash matrix:
  - crash before `txn.tmp` publication → stale temp/`txn.tmp`
    cleaned at next mutation, no recovery obligation;
  - crash after `txn.tmp` fsync, before rename to `txn` → same
    (unpublished marker is inert);
  - crash after publication, before the first target rename →
    recovery completes both from verified temps;
  - crash after the first target rename → recovery completes the
    second;
  - crash after both renames, before marker removal → recovery
    removes the marker, touches nothing else;
  - `target == old` with temp absent → refusal;
  - `target == old` with `hash(temp) != new` → refusal (unverified
    temp never installed);
  - recovery rename followed by power loss before marker removal →
    re-run recovery converges (idempotence);
  - `target == new` with temp absent **passes pre-validation** and
    succeeds;
  - replacement-temp path already exists or is a symlink at forward
    step 1 → refusal;
  - git-tracked file matching the reserved temp pattern → refusal,
    NOT deletion;
  - malformed JSON, duplicate JSON keys, wrong field types, wrong
    entry count → refusal untouched;
  - malicious-marker cases: target outside configured paths,
    symlinked temp at install time, **symlinked ancestor directory
    (incl. `.pkvault` itself)**, `..` traversal, unknown fields,
    duplicate JSON keys, oversized marker, non-hex/wrong-length
    hashes, duplicate targets → rejected untouched; tracked or
    symlinked `.pkvault/txn`, `.pkvault/txn.tmp`, or
    `.pkvault/lock` → refusal to operate.
- F8. `set-stdin/` — final LF preserved byte-exactly; invalid UTF-8
  and NUL refused.
- F9. `two-writers/` — concurrent mutations: one acquires the §8.3
  lock, the other refuses naming the holder.
- F10. `sentinel-rename/` — sentinel-backed record renamed in-buffer
  → refusal.
- F11. `public-refusal/` — `pkvault public` on multiline / `#` /
  trailing-whitespace values → refusal.
- F12. `case-fold-merge/` — concurrent additions of `FOO` and `foo`,
  and divergent case-only renames → human resolution, never disjoint
  additions.

## 12. Open questions (none block wire implementation)

1. Wrapped-identity blob format — SPEC-IDENTITY.md.
2. `recipients.toml` schema — SPEC-MANIFEST.md, before workflow
   implementation.
3. Merge-repair UX copy — implementation-time.
