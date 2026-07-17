# pkvault

**Passkey-encrypted `.env` files for teams.**

Your environment file lives in Git as an authenticated, age-compatible encrypted vault. Human identities unlock through WebAuthn PRF; machine and CI identities can use age secret keys. Adding a recipient reseals the file key, while removing one rotates it and re-encrypts every secret.

## Status

Pre-release (0.1.0) and under active development. The v1 wire format is frozen and the implementation includes setup/recovery ceremonies, the daily-unlock agent, repository identity blobs, recipient workflows, personal layers, and crash-consistent writes. Three-way merge repair is implemented at the format layer; the git merge-driver integration that exposes it on the command line is not yet wired.

## Basic flow

```sh
# Once per person. Defaults to the hosted static ceremony page.
pkvault setup --label daniel

# Initialize a repository using the printed recipient. If the matching wrapped
# blob is in the default pkvault home, init commits it for clone + tap.
pkvault init --label daniel --recipient age1...

# Unlock on first use, then cache in the foreground agent for the configured TTL.
pkvault agent --label daniel
pkvault run -- npm run dev
```

A teammate shares both outputs from `setup`: their public `age1...` recipient and their ciphertext-only `.wrap` file.

```sh
pkvault add sarah age1... --identity sarah.wrap
```

For a deliberate machine/CI recipient without a passkey blob, use `--without-identity-blob`.

## Ceremony origin

The default RP is `https://unlock.pkvault.dev`, a static page with no accounts or backend. Self-hosters select their permanent RP at identity creation or recovery:

```sh
pkvault setup --label daniel --rp-id unlock.example.com
```

The recovery code is independent of the RP and re-wraps the same identity under a new passkey.

### Verifying the hosted ceremony page

The ceremony page is the most trust-sensitive surface (it handles the PRF output
that unwraps your identity), so its bytes are **verifiable, not merely trusted**.
The exact same `web/index.html` shipped in this npm package is what the hosted
origin serves, and its SHA-256 is published in each GitHub Release. Confirm the
live page matches the audited source:

```sh
# <digest> is the SHA-256 published in the GitHub Release for the deployed tag:
node scripts/release-page.mjs check \
  --url https://unlock.pkvault.dev/ --expected-sha256 <digest>
# ✅ VERIFIED — the live page and this source both match the released digest

# or via the npm alias, passing the digest by flag or environment:
npm run verify:page -- --expected-sha256 <digest>
PKVAULT_PAGE_SHA256=<digest> npm run verify:page
```

Verification is against the **release digest**, not the current checkout: the
check passes only when *both* the live page and your local `web/index.html`
equal that digest. That is what makes it meaningful — comparing the live page
only to a moving `main` would either produce false mismatches or hide a drift
where both changed. `node scripts/release-page.mjs hash` prints the local digest
to record when cutting a release.

Deploys are **manual and human-gated** on purpose — there is no auto-deploy from
`main`, so a merge can never publish to the identity-unwrapping origin. Cut a
release, record the page digest in it, then deploy that same commit
(`npx wrangler deploy`). Self-hosters serve their own copy and pin their own
digest the same way.

## Platform support

The daily-unlock agent and the passkey ceremony workflow require POSIX
(macOS, Linux): the agent uses a unix-domain socket with `0600` filesystem
access control, which has no direct Windows equivalent yet. **On Windows,
the agent and passkey flow are unsupported** — use a machine identity via
`PKVAULT_IDENTITY` / `PKVAULT_IDENTITY_FILE` (age secret keys), which work
everywhere. The vault format, `init`, `get`, `run`, `add`/`remove`, and
`export` are cross-platform.

## Durability note

On POSIX systems, transaction files, renames, and containing directories are fsynced and failures are propagated. Node does not expose directory fsync on Windows, so Windows currently provides process-crash consistency but not the same power-loss durability guarantee.

## Editing and plaintext exposure

`pkvault set` (stdin) is the strict path — no plaintext buffer ever hits
disk. `pkvault edit` is best-effort: the decrypted buffer lives in a
per-invocation `0700` temp directory as a `0600` file, is overwritten and
unlinked when the editor exits, and stale directories from a prior
crash are swept on the next `edit`. **Secure deletion cannot be
guaranteed** on SSDs, copy-on-write filesystems, or snapshotting storage;
your editor may also write swap/backup/undo files. For maximum hygiene,
prefer `pkvault set` and configure your editor to disable backups.

## Recovery code

The recovery code printed at `setup` is **permanent recovery escrow**, not
a one-time token. Because your identity's private key never changes, any
retained copy of your committed identity blob (Git history, clones,
backups) remains recoverable with that code forever. `pkvault recover`
re-wraps your identity under a fresh passkey but keeps the same code and
does not revoke it. Treat the code like a root key; true rotation means
running `setup` for a new identity and being re-added to every vault.

## Development

```sh
npm test
```

## License

MIT
