"use strict";
// CLI integration suite: init → set/get/run → add (guard) → remove (rotation +
// checklist + accepted-exposure marker) → status, plus non-interactive refusals
// and interrupted-txn recovery on next mutation. node:test, zero deps.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const cli = require("../src/cli.js");
const fmt = require("../src/format.js");
const age = require("../src/age.js");
const idn = require("../src/identity.js");

const scalarFor = (tag) => crypto.createHash("sha256").update(`pkvault-cli-${tag}`).digest();
const mkId = (tag) => age.keygen(scalarFor(tag));
const A = mkId("A"), B = mkId("B");
const { wrap: bRecoveryWrap } = idn.makeRecoveryWrap({ scalar: scalarFor("B"), pub: age.decodeRecipient(B.recipient) });
const B_BLOB = idn.serializeBlob({ label: "bob", recipient: B.recipient, wraps: [bRecoveryWrap] });
const envA = { PKVAULT_IDENTITY: A.identity };
const envB = { PKVAULT_IDENTITY: B.identity };
const untracked = { isTracked: () => false };

function mkIo({ interactive = true, answer = true } = {}) {
  const lines = [];
  return {
    out: (s) => lines.push(s),
    interactive,
    confirm: () => answer,
    txnOpts: untracked,
    lines,
    text: () => lines.join("\n"),
  };
}

function repo() {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-cli-"));
  fs.writeFileSync(path.join(cwd, ".env"), "# creds\nDATABASE_URL=postgres://x\nAPI_HOST=example.com\n");
  return cwd;
}
function initialized() {
  const cwd = repo();
  const io = mkIo();
  cli.init({ cwd, io, label: "alice", recipient: A.recipient });
  return { cwd, io };
}
function addBob({ cwd, io = mkIo(), ...opts }) {
  const identityBlob = path.join(cwd, "bob.wrap.input");
  fs.writeFileSync(identityBlob, B_BLOB);
  return cli.add({ cwd, io, label: "bob", recipient: B.recipient, env: envA, identityBlob, ...opts });
}
const throwsCode = (fn, code) => assert.throws(fn, (e) => (assert.equal(e.code, code, e.message), true));

test("init adopts .env with everything encrypted; warns about plaintext file", () => {
  const { cwd, io } = initialized();
  const vault = fs.readFileSync(path.join(cwd, ".env.pkvault"), "utf8");
  assert.match(vault, /DATABASE_URL=ENC\[1:/);
  assert.match(vault, /API_HOST=ENC\[1:/, "encrypt-by-default: even the hostname");
  assert.match(vault, /# creds\n/, "comments preserved");
  assert.match(io.text(), /ALL encrypted/);
  assert.match(io.text(), /encrypted\s+DATABASE_URL/);
  assert.match(io.text(), /encrypted\s+API_HOST/);
  assert.match(io.text(), /next steps:/);
  assert.match(io.text(), /pkvault run -- /);
  assert.match(io.text(), /commit \.env\.pkvault and \.pkvault\//);
  assert.ok(fs.existsSync(path.join(cwd, ".pkvault/.gitignore")));
  throwsCode(() => cli.init({ cwd, io, label: "alice", recipient: A.recipient }), "E_ALREADY_INITIALIZED");
});

test("init merges multiple --from files with per-file attribution; last wins duplicates (incl. in-file)", () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-cli-"));
  fs.writeFileSync(path.join(cwd, ".env"), "SHARED=base\nONLY_A=1\n");
  fs.writeFileSync(path.join(cwd, ".env.local"), "SHARED=local\nONLY_B=2\nONLY_B=2b\n");
  // message-aware confirm: accept the .local adoption (this test WANTS the merge),
  // decline the delete prompts
  const io = { ...mkIo(), confirm: (msg) => msg.includes("Adopt anyway") };
  cli.init({ cwd, io, label: "alice", recipient: A.recipient, from: [".env", ".env.local"] });
  assert.match(io.text(), /encrypted\s+ONLY_A\s+\(\.env\)/);
  assert.match(io.text(), /encrypted\s+SHARED\s+\(\.env\.local\)/, "winner attributed to the later file");
  assert.match(io.text(), /DUPLICATE: SHARED in \.env is shadowed by \.env\.local/);
  assert.match(io.text(), /DUPLICATE: ONLY_B in \.env\.local is shadowed by \.env\.local/, "in-file duplicate also resolved");
  // the vault parses (the in-file duplicate bug would have made it unopenable)
  assert.equal(cli.get({ cwd, name: "SHARED", env: envA }), "local");
  assert.equal(cli.get({ cwd, name: "ONLY_B", env: envA }), "2b");
  const vaultText = fs.readFileSync(path.join(cwd, ".env.pkvault"), "utf8");
  assert.match(vaultText, /# ── adopted from \.env ──/);
  // both source files gitignored, both bannered (declined deletion)
  const gi = fs.readFileSync(path.join(cwd, ".gitignore"), "utf8");
  assert.match(gi, /^\.env$/m);
  assert.match(gi, /^\.env\.local$/m);
});

test("init: .local files are personal — declined by default, kept plaintext + gitignored", () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-cli-"));
  fs.writeFileSync(path.join(cwd, ".env"), "TEAM=1\n");
  fs.writeFileSync(path.join(cwd, ".env.local"), "PERSONAL=1\n");
  const io = mkIo({ answer: false }); // decline everything, incl. "Adopt anyway?"
  cli.init({ cwd, io, label: "alice", recipient: A.recipient, from: [".env", ".env.local"] });
  assert.match(io.text(), /skipped \.env\.local — personal overrides stay OUT/);
  throwsCode(() => cli.get({ cwd, name: "PERSONAL", env: envA }), "E_NO_SUCH_NAME");
  assert.equal(cli.get({ cwd, name: "TEAM", env: envA }), "1");
  // still protected from accidental commit, but NOT bannered (not managed)
  assert.match(fs.readFileSync(path.join(cwd, ".gitignore"), "utf8"), /^\.env\.local$/m);
  assert.doesNotMatch(fs.readFileSync(path.join(cwd, ".env.local"), "utf8"), /managed by pkvault/);
});

test("init: .local adoption proceeds loudly when non-interactive (explicitly named)", () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-cli-"));
  fs.writeFileSync(path.join(cwd, ".env.local"), "PERSONAL=1\n");
  const io = mkIo({ interactive: false });
  cli.init({ cwd, io, label: "alice", recipient: A.recipient, from: ".env.local" });
  assert.match(io.text(), /WARNING: adopting \.env\.local \(\.local convention\)/);
  assert.equal(cli.get({ cwd, name: "PERSONAL", env: envA }), "1");
});

test("init warns loudly about lines that did not parse as NAME=value", () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-cli-"));
  fs.writeFileSync(path.join(cwd, ".env"), "GOOD=1\nexport BROKEN LINE\n");
  const io = mkIo();
  cli.init({ cwd, io, label: "alice", recipient: A.recipient });
  assert.match(io.text(), /WARNING: 1 line\(s\) did not parse/);
  assert.match(io.text(), /export BROKEN LINE/);
});

test("init refuses assignment lines with names that cannot exist on the wire", () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-cli-"));
  fs.writeFileSync(path.join(cwd, ".env"), "export FOO=bar\n");
  throwsCode(() => cli.init({ cwd, io: mkIo(), label: "alice", recipient: A.recipient }), "E_BAD_NAME");
  assert.ok(!fs.existsSync(path.join(cwd, ".pkvault/config.toml")), "invalid input leaves no initialized repository");
  assert.ok(!fs.existsSync(path.join(cwd, ".env.pkvault")));
});

test("init refuses a symlinked .pkvault directory", () => {
  const cwd = repo();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-outside-"));
  fs.symlinkSync(outside, path.join(cwd, ".pkvault"));
  throwsCode(() => cli.init({ cwd, io: mkIo(), label: "alice", recipient: A.recipient }), "E_PATH_BOUNDARY");
  assert.ok(!fs.existsSync(path.join(outside, "config.toml")));
});

test("init installs a matching setup blob into the repository", () => {
  const cwd = repo();
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-home-"));
  const { wrap } = idn.makeRecoveryWrap({ scalar: scalarFor("A"), pub: age.decodeRecipient(A.recipient) });
  const bytes = idn.serializeBlob({ label: "alice", recipient: A.recipient, wraps: [wrap] });
  fs.writeFileSync(path.join(home, "alice.wrap"), bytes, { mode: 0o600 });
  cli.init({ cwd, io: mkIo(), label: "alice", recipient: A.recipient, home });
  assert.deepEqual(fs.readFileSync(path.join(cwd, ".pkvault/identities/alice.wrap")), bytes);
});

test("init: gitignore automatic; delete offered (default No → banner; Yes → gone)", () => {
  // decline (default) → plaintext kept, banner stamped, gitignored
  const cwd1 = repo();
  cli.init({ cwd: cwd1, io: mkIo({ answer: false }), label: "alice", recipient: A.recipient });
  assert.match(fs.readFileSync(path.join(cwd1, ".gitignore"), "utf8"), /^\.env$/m);
  const kept = fs.readFileSync(path.join(cwd1, ".env"), "utf8");
  assert.match(kept, /^# managed by pkvault — authoritative copy: \.env\.pkvault/);
  assert.match(kept, /DATABASE_URL=postgres:\/\/x/, "original content intact below the banner");

  // accept → deleted
  const cwd2 = repo();
  cli.init({ cwd: cwd2, io: mkIo({ answer: true }), label: "alice", recipient: A.recipient });
  assert.ok(!fs.existsSync(path.join(cwd2, ".env")));

  // non-interactive → kept with banner (never deletes without a human)
  const cwd3 = repo();
  cli.init({ cwd: cwd3, io: mkIo({ interactive: false }), label: "alice", recipient: A.recipient });
  assert.ok(fs.existsSync(path.join(cwd3, ".env")));
});

test("init without a source env file warns LOUDLY about the empty vault (real dogfood finding)", () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-cli-"));
  const io = mkIo();
  cli.init({ cwd, io, label: "alice", recipient: A.recipient });
  assert.match(io.text(), /WARNING: no \.env found — the vault is EMPTY/);
  assert.match(io.text(), /undo with/);
});

test("get/set round-trip; set takes stdin bytes exactly", () => {
  const { cwd } = initialized();
  assert.equal(cli.get({ cwd, name: "DATABASE_URL", env: envA }), "postgres://x");
  cli.set({ cwd, io: mkIo(), name: "PEM", valueBuf: Buffer.from("line1\nline2\n"), env: envA });
  assert.equal(cli.get({ cwd, name: "PEM", env: envA }), "line1\nline2\n");
});

test("run injects the vault env into the child process only", () => {
  const { cwd } = initialized();
  const status = cli.run({ cwd, env: envA, argv: ["node", "-e", "process.exit(process.env.DATABASE_URL === 'postgres://x' ? 0 : 1)"] });
  assert.equal(status, 0);
  assert.equal(process.env.DATABASE_URL, undefined, "parent env untouched");
});

test("public requires interactive confirmation; declined and non-interactive refuse", () => {
  const { cwd } = initialized();
  throwsCode(() => cli.classify({ cwd, io: mkIo({ interactive: false }), name: "API_HOST", to: "public", env: envA }), "E_GUARD_NONINTERACTIVE");
  throwsCode(() => cli.classify({ cwd, io: mkIo({ answer: false }), name: "API_HOST", to: "public", env: envA }), "E_GUARD_DECLINED");
  cli.classify({ cwd, io: mkIo(), name: "API_HOST", to: "public", env: envA });
  assert.match(fs.readFileSync(path.join(cwd, ".env.pkvault"), "utf8"), /API_HOST=example\.com # public/);
  // secret again needs no confirmation
  cli.classify({ cwd, io: mkIo({ interactive: false }), name: "API_HOST", to: "secret", env: envA });
});

test("add: §7 guard confirms, reseal is header-only, new member can read", () => {
  const { cwd } = initialized();
  const before = fs.readFileSync(path.join(cwd, ".env.pkvault"), "utf8");
  const io = mkIo();
  addBob({ cwd, io });
  const after = fs.readFileSync(path.join(cwd, ".env.pkvault"), "utf8");
  assert.equal(before.split("\n").slice(6).join("\n"), after.split("\n").slice(6).join("\n"), "body byte-stable");
  assert.equal(cli.get({ cwd, name: "DATABASE_URL", env: envB }), "postgres://x");
  assert.match(fs.readFileSync(path.join(cwd, ".pkvault/recipients.toml"), "utf8"), /bob = "age1/);
  assert.deepEqual(fs.readFileSync(path.join(cwd, ".pkvault/identities/bob.wrap")), B_BLOB);
});

test("add validates labels and requires a wrapped blob unless machine identity use is explicit", () => {
  const { cwd } = initialized();
  throwsCode(() => cli.add({ cwd, io: mkIo(), label: "BAD LABEL", recipient: B.recipient, env: envA }), "E_BAD_LABEL");
  throwsCode(() => cli.add({ cwd, io: mkIo(), label: "bob", recipient: B.recipient, env: envA }), "E_IDENTITY_BLOB_REQUIRED");
  const manifest = fs.readFileSync(path.join(cwd, ".pkvault/recipients.toml"), "utf8");
  assert.doesNotMatch(manifest, /bob/);
});

test("add refuses non-interactively (CI identities only ever decrypt)", () => {
  const { cwd } = initialized();
  throwsCode(() => addBob({ cwd, io: mkIo({ interactive: false }) }), "E_GUARD_NONINTERACTIVE");
});

test("remove: rotation locks out the removed member and prints the checklist", () => {
  const { cwd } = initialized();
  addBob({ cwd });
  const io = mkIo();
  cli.remove({ cwd, io, label: "bob", env: envA, date: "2026-07-16" });
  throwsCode(() => cli.get({ cwd, name: "DATABASE_URL", env: envB }), "E_UNSEAL");
  assert.equal(cli.get({ cwd, name: "DATABASE_URL", env: envA }), "postgres://x");
  assert.match(io.text(), /ROTATION CHECKLIST/);
  assert.match(io.text(), /\[ \] DATABASE_URL/);
});

test("remove --accept-exposure records the preamble marker instead of the checklist", () => {
  const { cwd } = initialized();
  addBob({ cwd });
  const io = mkIo();
  cli.remove({ cwd, io, label: "bob", acceptExposure: true, env: envA, date: "2026-07-16" });
  const vault = fs.readFileSync(path.join(cwd, ".env.pkvault"), "utf8");
  assert.match(vault, /# pkvault: accepted-exposure bob on 2026-07-16 UTC/);
  assert.doesNotMatch(io.text(), /ROTATION CHECKLIST/);
  // marker is MAC-covered: the file still opens
  assert.equal(cli.get({ cwd, name: "DATABASE_URL", env: envA }), "postgres://x");
});

test("removing the last recipient refuses", () => {
  const { cwd } = initialized();
  throwsCode(() => cli.remove({ cwd, io: mkIo(), label: "alice", env: envA, date: "2026-07-16" }), "E_BAD_LABEL");
});

test("status reports recipients with fingerprints and verifies integrity", () => {
  const { cwd } = initialized();
  const io = mkIo();
  cli.status({ cwd, io, env: envA });
  assert.match(io.text(), /vault: \.env\.pkvault/);
  assert.match(io.text(), new RegExp(`alice\\s+${cli.fingerprint(A.recipient)}`));
  assert.match(io.text(), /MAC verified/);
});

test("status lists per-name classification without needing an identity", () => {
  const { cwd } = initialized();
  cli.classify({ cwd, io: mkIo(), name: "API_HOST", to: "public", env: envA });
  const io = mkIo();
  cli.status({ cwd, io, env: {} }); // no identity at all
  assert.match(io.text(), /encrypted\s+DATABASE_URL/);
  assert.match(io.text(), /PUBLIC\s+API_HOST = example\.com/);
  assert.match(io.text(), /NOT VERIFIED/, "integrity honestly reported as unverifiable without membership");
});

test("interrupted transaction recovers on the next mutation", () => {
  const { cwd } = initialized();
  // simulate a crash mid-add
  throwsCode(
    () => addBob({ cwd, io: { ...mkIo(), txnOpts: { ...untracked, crashAfter: "rename1" } } }),
    "E_SIMULATED_CRASH"
  );
  assert.ok(fs.existsSync(path.join(cwd, ".pkvault/txn")), "marker left behind");
  // next mutation recovers first, then applies
  cli.set({ cwd, io: mkIo(), name: "NEW", valueBuf: Buffer.from("v"), env: envA });
  assert.ok(!fs.existsSync(path.join(cwd, ".pkvault/txn")), "recovered");
  assert.equal(cli.get({ cwd, name: "DATABASE_URL", env: envB }), "postgres://x", "bob's add was completed by recovery");
  assert.equal(cli.get({ cwd, name: "NEW", env: envA }), "v");
});

test("commands work from a subdirectory (upward root discovery)", () => {
  const { cwd } = initialized();
  const sub = path.join(cwd, "apps/web");
  fs.mkdirSync(sub, { recursive: true });
  assert.equal(cli.get({ cwd: sub, name: "DATABASE_URL", env: envA }), "postgres://x");
  cli.set({ cwd: sub, io: mkIo(), name: "FROM_SUB", valueBuf: Buffer.from("v"), env: envA });
  assert.equal(cli.get({ cwd, name: "FROM_SUB", env: envA }), "v", "mutation landed at the root vault");
});

test("#1 init is resumable: crash after any step, retry completes, .env stays ignored", () => {
  for (const step of ["gitignore", "vault", "manifest", "blob"]) {
    const cwd = repo();
    throwsCode(() => cli.init({ cwd, io: mkIo({ answer: false }), label: "alice", recipient: A.recipient, faultAfter: step }), "E_SIMULATED_CRASH");
    // config.toml (the sentinel) must be ABSENT after any pre-config crash
    assert.ok(!fs.existsSync(path.join(cwd, ".pkvault/config.toml")), `config absent after crash@${step}`);
    // plaintext .env must ALREADY be gitignored (protected first)
    assert.match(fs.readFileSync(path.join(cwd, ".gitignore"), "utf8"), /^\.env$/m, `gitignore after crash@${step}`);
    // retry completes cleanly and the vault is readable
    cli.init({ cwd, io: mkIo({ answer: false }), label: "alice", recipient: A.recipient });
    assert.ok(fs.existsSync(path.join(cwd, ".pkvault/config.toml")));
    assert.equal(cli.get({ cwd, name: "DATABASE_URL", env: envA }), "postgres://x", `resume@${step}`);
  }
});

test("#1 init refuses to overwrite a NON-pkvault file at the vault path", () => {
  const cwd = repo();
  fs.writeFileSync(path.join(cwd, ".env.pkvault"), "i am a user's real file\n");
  throwsCode(() => cli.init({ cwd, io: mkIo(), label: "alice", recipient: A.recipient }), "E_ALREADY_INITIALIZED");
  assert.equal(fs.readFileSync(path.join(cwd, ".env.pkvault"), "utf8"), "i am a user's real file\n", "untouched");
});

test("#1 resume PRESERVES the leftover vault's secrets — never regenerates", () => {
  const cwd = repo();
  fs.writeFileSync(path.join(cwd, ".env"), "SECRET=preserve-me\n");
  throwsCode(() => cli.init({ cwd, io: mkIo({ answer: false }), label: "alice", recipient: A.recipient, faultAfter: "vault" }), "E_SIMULATED_CRASH");
  const leftover = fs.readFileSync(path.join(cwd, ".env.pkvault"));
  // change the source so a naive regenerate would DIFFER (and lose the secret)
  fs.writeFileSync(path.join(cwd, ".env"), "SECRET=CHANGED\nNEW=x\n");
  const io = mkIo({ answer: false });
  cli.init({ cwd, io, label: "alice", recipient: A.recipient });
  assert.match(io.text(), /resumed an interrupted init/);
  assert.equal(cli.get({ cwd, name: "SECRET", env: envA }), "preserve-me", "original secret preserved");
  throwsCode(() => cli.get({ cwd, name: "NEW", env: envA }), "E_NO_SUCH_NAME");
  assert.ok(fs.readFileSync(path.join(cwd, ".env.pkvault")).equals(leftover), "vault bytes byte-identical to leftover");
});

test("#2 init acquires the lock before any state check/generation (serialized)", () => {
  const cwd = repo();
  fs.mkdirSync(path.join(cwd, ".pkvault"), { recursive: true });
  const tx = require("../src/txn.js");
  const held = tx.acquireLock(cwd, { isTracked: () => false });
  try {
    // a concurrent holder blocks init entirely — no preflight overwrite window
    throwsCode(() => cli.init({ cwd, io: mkIo(), label: "alice", recipient: A.recipient }), "E_LOCKED");
  } finally { held.release(); }
  assert.ok(!fs.existsSync(path.join(cwd, ".pkvault/config.toml")), "nothing published while lock was held");
});

test("#1 resume refuses a DIFFERENT identity (label/recipient must match)", () => {
  const cwd = repo();
  fs.writeFileSync(path.join(cwd, ".env"), "SECRET=a\n");
  throwsCode(() => cli.init({ cwd, io: mkIo({ answer: false }), label: "alice", recipient: A.recipient, faultAfter: "vault" }), "E_SIMULATED_CRASH");
  // retry with identity B → must refuse (B could not decrypt the preserved A-vault)
  throwsCode(() => cli.init({ cwd, io: mkIo({ answer: false }), label: "bob", recipient: B.recipient }), "E_RESUME_IDENTITY");
  // changed recipient under same label → also refused
  const other = mkId("other2");
  throwsCode(() => cli.init({ cwd, io: mkIo({ answer: false }), label: "alice", recipient: other.recipient }), "E_RESUME_IDENTITY");
  // correct identity still resumes and decrypts
  cli.init({ cwd, io: mkIo({ answer: false }), label: "alice", recipient: A.recipient });
  assert.equal(cli.get({ cwd, name: "SECRET", env: envA }), "a");
});

test("#1 local-init resume refuses a different identity", () => {
  const { cwd } = initialized();
  fs.writeFileSync(path.join(cwd, ".env.local"), "P=1\n");
  throwsCode(() => cli.localInit({ cwd, io: mkIo(), from: ".env.local", env: envA, faultAfter: "vault" }), "E_SIMULATED_CRASH");
  // retry with identity B → refused (personal vault sealed to A)
  throwsCode(() => cli.localInit({ cwd, io: mkIo(), from: ".env.local", env: envB }), "E_RESUME_IDENTITY");
  cli.localInit({ cwd, io: mkIo(), from: ".env.local", env: envA }); // same identity resumes
});

test("#2 git status 128 inside a worktree fails closed (not read as safe)", () => {
  const cwd = gitRepo();
  fs.writeFileSync(path.join(cwd, ".env"), "A=1\n");
  require("node:child_process").spawnSync("git", ["add", ".env"], { cwd });
  const realGit = require("node:child_process").execSync("command -v git", { encoding: "utf8" }).trim();
  const bin = path.join(cwd, "fakebin128"); fs.mkdirSync(bin);
  // ls-files exits 128 (fatal); everything else delegates to real git
  fs.writeFileSync(path.join(bin, "git"), `#!/bin/sh\ncase "$1" in ls-files) exit 128;; esac\nexec ${realGit} "$@"\n`, { mode: 0o755 });
  const saved = process.env.PATH;
  process.env.PATH = `${bin}:${saved}`;
  try {
    throwsCode(() => cli.init({ cwd, io: mkIo({ answer: false }), label: "alice", recipient: A.recipient }), "E_UNTRACK");
  } finally { process.env.PATH = saved; }
  assert.ok(!fs.existsSync(path.join(cwd, ".pkvault/config.toml")), "no config on 128 probe failure in a worktree");
});

test("#3 init fails closed when the git probe fails inside a worktree", () => {
  const cwd = gitRepo();
  fs.writeFileSync(path.join(cwd, ".env"), "A=1\n");
  require("node:child_process").spawnSync("git", ["add", ".env"], { cwd });
  const emptyBin = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-nogit-"));
  const savedPath = process.env.PATH;
  process.env.PATH = emptyBin; // git now unavailable
  try {
    throwsCode(() => cli.init({ cwd, io: mkIo({ answer: false }), label: "alice", recipient: A.recipient }), "E_UNTRACK");
  } finally { process.env.PATH = savedPath; }
  assert.ok(!fs.existsSync(path.join(cwd, ".pkvault/config.toml")), "no config published on indeterminate git probe");
});

test("#1 a FORGED init-pending marker cannot authorize overwriting a real vault", () => {
  // build a real foreign vault, plant a path-matching marker with a WRONG hash
  const other = mkId("other");
  const foreign = fmt.create({ recipients: [{ label: "x", recipient: other.recipient, key: age.decodeRecipient(other.recipient) }], template: [{ name: "S", value: "theirs" }] });
  const cwd = repo();
  fs.mkdirSync(path.join(cwd, ".pkvault"), { recursive: true });
  fs.writeFileSync(path.join(cwd, ".env.pkvault"), foreign);
  // full-schema marker but WRONG hash → cannot authorize overwrite
  fs.writeFileSync(path.join(cwd, ".pkvault/init-pending"), JSON.stringify({ v: 1, vault: ".env.pkvault", vaultSha256: "0".repeat(64), label: "alice", recipient: A.recipient }) + "\n");
  throwsCode(() => cli.init({ cwd, io: mkIo(), label: "alice", recipient: A.recipient }), "E_ALREADY_INITIALIZED");
  assert.ok(fs.readFileSync(path.join(cwd, ".env.pkvault")).equals(foreign), "foreign vault untouched despite forged marker");
});

test("#1/#4 a symlinked or corrupt init marker is refused as hostile", () => {
  const cwd = repo();
  fs.mkdirSync(path.join(cwd, ".pkvault"), { recursive: true });
  fs.symlinkSync("/etc/hosts", path.join(cwd, ".pkvault/init-pending"));
  throwsCode(() => cli.init({ cwd, io: mkIo(), label: "alice", recipient: A.recipient }), "E_MARKER_HOSTILE");
  fs.unlinkSync(path.join(cwd, ".pkvault/init-pending"));
  fs.writeFileSync(path.join(cwd, ".pkvault/init-pending"), "{not json");
  throwsCode(() => cli.init({ cwd, io: mkIo(), label: "alice", recipient: A.recipient }), "E_MARKER_HOSTILE");
});

test("#4 neither pending marker is visible to git after any init crash point", () => {
  for (const step of ["marker", "gitignore", "vault", "manifest", "blob"]) {
    const cwd = gitRepo();
    fs.writeFileSync(path.join(cwd, ".env"), "A=1\n");
    throwsCode(() => cli.init({ cwd, io: mkIo({ answer: false }), label: "alice", recipient: A.recipient, faultAfter: step }), "E_SIMULATED_CRASH");
    const status = require("node:child_process").spawnSync("git", ["status", "--porcelain", "--ignored"], { cwd, encoding: "utf8" }).stdout;
    // markers appear only as IGNORED (!!), never as untracked (??) or staged
    for (const m of ["init-pending", "local-init-pending"]) {
      const line = status.split("\n").find((l) => l.includes(m));
      if (line) assert.match(line, /^!!/, `${m} must be ignored, not committable, after crash@${step}: "${line}"`);
    }
  }
});

test("#1 init refuses to overwrite a VALID pre-existing vault (no init marker)", () => {
  // build a real, valid vault sealed to a DIFFERENT identity, drop it in a fresh
  // dir, then init — it must NOT be treated as a crashed-init artifact.
  const other = mkId("other");
  const foreign = fmt.create({ recipients: [{ label: "x", recipient: other.recipient, key: age.decodeRecipient(other.recipient) }], template: [{ name: "SECRET", value: "theirs" }] });
  const cwd = repo();
  fs.writeFileSync(path.join(cwd, ".env.pkvault"), foreign);
  throwsCode(() => cli.init({ cwd, io: mkIo(), label: "alice", recipient: A.recipient }), "E_ALREADY_INITIALIZED");
  assert.ok(fs.readFileSync(path.join(cwd, ".env.pkvault")).equals(foreign), "foreign vault untouched");
});

function gitRepo() {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-git-"));
  require("node:child_process").spawnSync("git", ["init", "-q", "."], { cwd });
  require("node:child_process").spawnSync("git", ["config", "user.email", "t@t"], { cwd });
  require("node:child_process").spawnSync("git", ["config", "user.name", "t"], { cwd });
  return cwd;
}
const isStaged = (cwd, f) => require("node:child_process").spawnSync("git", ["ls-files", "--error-unmatch", "--", f], { cwd, stdio: "ignore" }).status === 0;

test("#2 init untracks an already-staged plaintext source", () => {
  const cwd = gitRepo();
  fs.writeFileSync(path.join(cwd, ".env"), "DATABASE_URL=postgres://x\n");
  require("node:child_process").spawnSync("git", ["add", ".env"], { cwd });
  assert.ok(isStaged(cwd, ".env"), "precondition: .env staged");
  const io = mkIo({ answer: false });
  cli.init({ cwd, io, label: "alice", recipient: A.recipient });
  assert.ok(!isStaged(cwd, ".env"), ".env untracked after init");
  assert.match(io.text(), /untracked \.env from git/);
  assert.ok(fs.existsSync(path.join(cwd, ".env")), "working file kept");
});

test("#2 init ABORTS (does not publish) when a tracked source cannot be untracked", () => {
  const cwd = gitRepo();
  fs.writeFileSync(path.join(cwd, ".env"), "DATABASE_URL=postgres://x\n");
  require("node:child_process").spawnSync("git", ["add", ".env"], { cwd });
  // stub: a git wrapper that fails only on `rm` and delegates everything else to
  // the real git — deterministically forces the untrack-failure path.
  const realGit = require("node:child_process").spawnSync("git", ["--exec-path"], { encoding: "utf8" }).status === 0
    ? require("node:child_process").execSync("command -v git", { encoding: "utf8" }).trim() : "git";
  const bin = path.join(cwd, "fakebin"); fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, "git"), `#!/bin/sh\ncase "$1" in rm) exit 3;; esac\nexec ${realGit} "$@"\n`, { mode: 0o755 });
  const io = mkIo({ answer: false });
  const savedPath = process.env.PATH;
  process.env.PATH = `${bin}:${savedPath}`;
  try {
    throwsCode(() => cli.init({ cwd, io, label: "alice", recipient: A.recipient }), "E_UNTRACK");
  } finally { process.env.PATH = savedPath; }
  // init must NOT have published: no config, no vault
  assert.ok(!fs.existsSync(path.join(cwd, ".pkvault/config.toml")), "config not published after untrack failure");
});

test("#2 local-init untracks an already-staged personal source", () => {
  const cwd = gitRepo();
  fs.writeFileSync(path.join(cwd, ".env"), "TEAM=1\n");
  cli.init({ cwd, io: mkIo({ answer: false }), label: "alice", recipient: A.recipient });
  fs.writeFileSync(path.join(cwd, ".env.local"), "PERSONAL=tok\n");
  require("node:child_process").spawnSync("git", ["add", ".env.local"], { cwd });
  cli.localInit({ cwd, io: mkIo(), from: ".env.local", env: envA });
  assert.ok(!isStaged(cwd, ".env.local"), ".env.local untracked");
});

test("#3 local-init is resumable: crash after any step, retry completes", () => {
  for (const step of ["marker", "gitignore", "vault"]) {
    const { cwd } = initialized();
    fs.writeFileSync(path.join(cwd, ".env.local"), "PERSONAL=v\n");
    throwsCode(() => cli.localInit({ cwd, io: mkIo(), from: ".env.local", env: envA, faultAfter: step }), "E_SIMULATED_CRASH");
    // retry completes and the personal value is readable
    cli.localInit({ cwd, io: mkIo(), from: ".env.local", env: envA });
    assert.equal(cli.get({ cwd, name: "PERSONAL", env: envA }), "v", `resume@${step}`);
  }
});

test("#3 init rejects --vault colliding with control files", () => {
  for (const v of [".pkvault/config.toml", ".pkvault/recipients.toml", ".pkvault/.gitignore", ".gitignore", ".pkvault/identities/x.wrap"]) {
    const cwd = repo();
    throwsCode(() => cli.init({ cwd, io: mkIo(), label: "alice", recipient: A.recipient, vault: v }), "E_PATH_RESERVED");
  }
});

test("#2 local-init gitignores its plaintext source", () => {
  const { cwd } = initialized();
  fs.writeFileSync(path.join(cwd, ".env.local"), "PERSONAL=tok\n");
  cli.localInit({ cwd, io: mkIo(), from: ".env.local", env: envA });
  const gi = fs.readFileSync(path.join(cwd, ".gitignore"), "utf8");
  assert.match(gi, /^\.env\.local$/m, "source gitignored");
  assert.match(gi, /^\.env\.local\.pkvault$/m, "personal vault gitignored");
});

test("#5 local-init runs under the lock (refuses when a writer holds it)", () => {
  const { cwd } = initialized();
  const tx = require("../src/txn.js");
  const held = tx.acquireLock(cwd, { isTracked: () => false });
  try {
    throwsCode(() => cli.localInit({ cwd, io: mkIo(), from: null, env: envA }), "E_LOCKED");
  } finally { held.release(); }
});

test("#4 export refuses to overwrite vault / personal / control files", () => {
  const { cwd } = initialized();
  for (const t of [".env.pkvault", ".pkvault/config.toml", ".pkvault/recipients.toml", ".gitignore"]) {
    throwsCode(() => cli.exportPlain({ cwd, io: mkIo(), env: envA, to: t, iWantPlaintextOnDisk: true }), "E_PATH_RESERVED");
  }
  assert.match(fs.readFileSync(path.join(cwd, ".env.pkvault"), "utf8"), /^#! pkvault 1/, "vault still authenticated");
});

test("#7 read commands recover a pending transaction instead of reading torn state", () => {
  const { cwd } = initialized();
  // crash an add after the transaction marker is published but before renames
  throwsCode(
    () => cli.add({ cwd, io: { ...mkIo(), txnOpts: { isTracked: () => false, crashAfter: "marker" } }, label: "bob", recipient: B.recipient, env: envA, allowMissingIdentityBlob: true }),
    "E_SIMULATED_CRASH"
  );
  assert.ok(fs.existsSync(path.join(cwd, ".pkvault/txn")), "transaction pending");
  // a plain read must NOT observe the torn state — it recovers first
  assert.equal(cli.get({ cwd, name: "DATABASE_URL", env: envA }), "postgres://x");
  assert.ok(!fs.existsSync(path.join(cwd, ".pkvault/txn")), "read recovered the pending transaction");
  // and the recovered state is consistent: bob is now a real recipient
  assert.equal(cli.get({ cwd, name: "DATABASE_URL", env: envB }), "postgres://x");
});

test("init discovers sibling env files and proposes them — never auto-adopts", () => {
  const cwd = repo();
  fs.writeFileSync(path.join(cwd, ".env.local"), "LOCAL=1\n");
  fs.writeFileSync(path.join(cwd, ".dev.vars"), "WRANGLER=1\n");
  fs.writeFileSync(path.join(cwd, ".env.example"), "EXAMPLE=\n"); // templates are not secrets
  const io = mkIo();
  cli.init({ cwd, io, label: "alice", recipient: A.recipient });
  assert.match(io.text(), /found but NOT adopted/);
  assert.match(io.text(), /\.env\.local/);
  assert.match(io.text(), /\.dev\.vars/);
  assert.doesNotMatch(io.text(), /\.env\.example/);
  // and truly not adopted:
  throwsCode(() => cli.get({ cwd, name: "LOCAL", env: envA }), "E_NO_SUCH_NAME");
});

test("init refuses traversal in --from", () => {
  const cwd = repo();
  throwsCode(() => cli.init({ cwd, io: mkIo(), label: "alice", recipient: A.recipient, from: "../outside.env" }), "E_PATH_BOUNDARY");
});

test("committed local path traversal is rejected before any outside read", () => {
  const { cwd } = initialized();
  fs.writeFileSync(path.join(cwd, ".pkvault/config.toml"), 'local = "../outside.pkvault"\nvault = ".env.pkvault"\n');
  throwsCode(() => cli.get({ cwd, name: "DATABASE_URL", env: envA }), "E_PATH_BOUNDARY");
});

test("export: stdout free; disk gated behind the honesty flag; multiline refused", () => {
  const { cwd } = initialized();
  const io = mkIo();
  cli.exportPlain({ cwd, io, env: envA });
  assert.match(io.text(), /DATABASE_URL=postgres:\/\/x/);
  assert.match(io.text(), /# creds/, "comments survive the round-trip");
  // disk write without the flag → refusal
  throwsCode(() => cli.exportPlain({ cwd, io: mkIo(), env: envA, to: ".env.out" }), "E_EXPORT_GATED");
  // with the flag → 0600 file whose content round-trips
  cli.exportPlain({ cwd, io: mkIo(), env: envA, to: ".env.out", iWantPlaintextOnDisk: true });
  const out = fs.readFileSync(path.join(cwd, ".env.out"), "utf8");
  assert.match(out, /^DATABASE_URL=postgres:\/\/x$/m);
  assert.equal(fs.statSync(path.join(cwd, ".env.out")).mode & 0o777, 0o600);
  // multiline value → named refusal listing the culprit
  cli.set({ cwd, io: mkIo(), name: "PEM", valueBuf: Buffer.from("a\nb"), env: envA });
  assert.throws(() => cli.exportPlain({ cwd, io: mkIo(), env: envA }), (e) => e.code === "E_EXPORT_MULTILINE" && /PEM/.test(e.message));
});

test("personal layer: encrypted at rest, sealed to self, overrides team in run, invisible to teammates", () => {
  const { cwd } = initialized();
  fs.writeFileSync(path.join(cwd, ".env.local"), "PERSONAL_TOKEN=tok-123\nDATABASE_URL=postgres://my-local-db\n");
  const io = mkIo();
  cli.localInit({ cwd, io, from: ".env.local", env: envA });
  assert.match(io.text(), /sealed to YOU ONLY/);
  // encrypted at rest — no plaintext token in the local vault bytes
  const localBytes = fs.readFileSync(path.join(cwd, ".env.local.pkvault"), "utf8");
  assert.doesNotMatch(localBytes, /tok-123/);
  assert.match(localBytes, /PERSONAL_TOKEN=ENC\[1:/);
  // gitignored
  assert.match(fs.readFileSync(path.join(cwd, ".gitignore"), "utf8"), /^\.env\.local\.pkvault$/m);
  // get: local wins for overridden names, falls through for team names
  assert.equal(cli.get({ cwd, name: "PERSONAL_TOKEN", env: envA }), "tok-123");
  assert.equal(cli.get({ cwd, name: "DATABASE_URL", env: envA }), "postgres://my-local-db", "personal override wins");
  // set --local routes to the personal vault
  cli.set({ cwd, io: mkIo(), name: "PERSONAL_TOKEN", valueBuf: Buffer.from("tok-456"), env: envA, local: true });
  assert.equal(cli.get({ cwd, name: "PERSONAL_TOKEN", env: envA }), "tok-456");
  // teammates can't open the personal layer, and it's not in the team vault
  addBob({ cwd });
  const bScalar = crypto.createHash("sha256").update("pkvault-cli-B").digest();
  assert.throws(() => fmt.open(fs.readFileSync(path.join(cwd, ".env.local.pkvault")), bScalar), (e) => e.code === "E_UNSEAL");
  // bob sees team values only
  assert.equal(cli.get({ cwd, name: "DATABASE_URL", env: envB }), "postgres://x", "no personal layer for bob → team value");
  // status shows the layer
  const st = mkIo();
  cli.status({ cwd, io: st, env: envA });
  assert.match(st.text(), /personal layer: \.env\.local\.pkvault/);
});

test("set asks team-or-personal ONLY for new names when a personal layer exists", () => {
  const { cwd } = initialized();
  cli.localInit({ cwd, io: mkIo(), env: envA });
  const prompts = [];
  const ioAsk = (answer) => ({ ...mkIo(), confirm: (msg) => (prompts.push(msg), answer) });

  // new name, answer y → personal layer, never committed
  cli.set({ cwd, io: ioAsk(true), name: "MY_TOKEN", valueBuf: Buffer.from("t1"), env: envA });
  assert.equal(prompts.length, 1);
  assert.match(prompts[0], /PERSONAL/);
  assert.doesNotMatch(fs.readFileSync(path.join(cwd, ".env.pkvault"), "utf8"), /MY_TOKEN/, "not in the team vault");
  assert.equal(cli.get({ cwd, name: "MY_TOKEN", env: envA }), "t1");

  // new name, answer No → team vault
  cli.set({ cwd, io: ioAsk(false), name: "TEAM_KEY", valueBuf: Buffer.from("t2"), env: envA });
  assert.match(fs.readFileSync(path.join(cwd, ".env.pkvault"), "utf8"), /TEAM_KEY=ENC\[1:/);

  // updates follow the existing home — no prompt either way
  prompts.length = 0;
  cli.set({ cwd, io: ioAsk(true), name: "MY_TOKEN", valueBuf: Buffer.from("t3"), env: envA });
  cli.set({ cwd, io: ioAsk(true), name: "DATABASE_URL", valueBuf: Buffer.from("t4"), env: envA });
  assert.equal(prompts.length, 0, "existing names never prompt");
  assert.equal(cli.get({ cwd, name: "MY_TOKEN", env: envA }), "t3");
  assert.match(fs.readFileSync(path.join(cwd, ".env.pkvault"), "utf8"), /DATABASE_URL=ENC\[1:/);

  // explicit flags skip the prompt; non-interactive defaults to team
  cli.set({ cwd, io: ioAsk(true), name: "FORCED_TEAM", valueBuf: Buffer.from("t5"), env: envA, local: false });
  assert.equal(prompts.length, 0);
  cli.set({ cwd, io: { ...mkIo({ interactive: false }), confirm: () => { throw new Error("must not prompt"); } }, name: "CI_VAR", valueBuf: Buffer.from("t6"), env: envA });
  assert.match(fs.readFileSync(path.join(cwd, ".env.pkvault"), "utf8"), /CI_VAR=ENC\[1:/);
});

test("status rejects a symlinked manifest (no reading outside the repo)", () => {
  const { cwd } = initialized();
  const outside = path.join(os.tmpdir(), `pkvault-outside-${process.pid}.toml`);
  fs.writeFileSync(outside, 'evil = "age1xxx"\n');
  fs.unlinkSync(path.join(cwd, ".pkvault/recipients.toml"));
  fs.symlinkSync(outside, path.join(cwd, ".pkvault/recipients.toml"));
  try {
    throwsCode(() => cli.status({ cwd, io: mkIo(), env: envA }), "E_PATH_BOUNDARY");
  } finally {
    fs.unlinkSync(outside);
  }
});

test("status reads its snapshot UNDER the lock (refuses/waits when a writer holds it)", () => {
  const { cwd } = initialized();
  const tx = require("../src/txn.js");
  // hold the repository mutation lock, then call status → it must fail to acquire
  const held = tx.acquireLock(cwd, { isTracked: () => false });
  try {
    throwsCode(() => cli.status({ cwd, io: mkIo(), env: envA }), "E_LOCKED");
  } finally {
    held.release();
  }
  // once released, status proceeds normally
  const io = mkIo();
  cli.status({ cwd, io, env: envA });
  assert.match(io.text(), /MAC verified/);
});

test("status recovers a pending transaction before reading (no torn snapshot)", () => {
  const { cwd } = initialized();
  // crash a bob-add mid-transaction so the vault is resealed but manifest isn't
  throwsCode(
    () => cli.add({ cwd, io: { ...mkIo(), txnOpts: { isTracked: () => false, crashAfter: "rename1" } }, label: "bob", recipient: B.recipient, env: envA, allowMissingIdentityBlob: true }),
    "E_SIMULATED_CRASH"
  );
  assert.ok(fs.existsSync(path.join(cwd, ".pkvault/txn")), "marker present");
  const io = mkIo();
  cli.status({ cwd, io, env: envA });
  assert.match(io.text(), /recovered a pending transaction/);
  assert.ok(!fs.existsSync(path.join(cwd, ".pkvault/txn")), "recovered");
  // manifest and vault now agree: bob is a recipient AND can decrypt
  assert.match(io.text(), /bob/);
  assert.equal(cli.get({ cwd, name: "DATABASE_URL", env: envB }), "postgres://x");
});

test("edit: injected buffer transform re-encrypts changed values; no-op is a no-op", () => {
  const { cwd } = initialized();
  // change DATABASE_URL via the buffer, leave the rest
  const editBuffer = (text) => text.replace("DATABASE_URL=postgres://x", "DATABASE_URL=postgres://edited");
  const io = mkIo();
  cli.edit({ cwd, io, env: envA, editBuffer });
  assert.match(io.text(), /saved/);
  assert.equal(cli.get({ cwd, name: "DATABASE_URL", env: envA }), "postgres://edited");
  assert.match(fs.readFileSync(path.join(cwd, ".env.pkvault"), "utf8"), /DATABASE_URL=ENC\[1:/, "still encrypted");
  // no-op edit: returning identical text changes nothing
  const io2 = mkIo();
  cli.edit({ cwd, io: io2, env: envA, editBuffer: (t) => t });
  assert.match(io2.text(), /no changes/);
});

test("edit: new unmarked name in the buffer is encrypted; deletions require confirmation", () => {
  const { cwd } = initialized();
  cli.edit({ cwd, io: mkIo(), env: envA, editBuffer: (t) => t + "ADDED=viabuffer\n" });
  const addedLine = fs.readFileSync(path.join(cwd, ".env.pkvault"), "utf8").split("\n").find((l) => l.startsWith("ADDED="));
  assert.match(addedLine, /^ADDED=ENC\[1:/);
  assert.equal(cli.get({ cwd, name: "ADDED", env: envA }), "viabuffer");
  // remove a line, decline the deletion → refusal
  const drop = (t) => t.split("\n").filter((l) => !l.startsWith("DATABASE_URL=")).join("\n");
  throwsCode(() => cli.edit({ cwd, io: mkIo({ answer: false }), env: envA, editBuffer: drop }), "E_EDITOR_DELETION_UNCONFIRMED");
  // confirm → gone
  cli.edit({ cwd, io: mkIo({ answer: true }), env: envA, editBuffer: drop });
  throwsCode(() => cli.get({ cwd, name: "DATABASE_URL", env: envA }), "E_NO_SUCH_NAME");
});

test("set --local without a personal layer → helpful refusal", () => {
  const { cwd } = initialized();
  throwsCode(() => cli.set({ cwd, io: mkIo(), name: "X", valueBuf: Buffer.from("v"), env: envA, local: true }), "E_NO_LOCAL");
});

test("unlock --force resolves the repository root from a subdirectory", () => {
  const { cwd } = initialized();
  const sub = path.join(cwd, "apps/web");
  fs.mkdirSync(sub, { recursive: true });
  fs.writeFileSync(path.join(cwd, ".pkvault/lock"), "999999 stale\n");
  cli.unlockForce({ cwd: sub, io: mkIo() });
  assert.ok(!fs.existsSync(path.join(cwd, ".pkvault/lock")));
});

test("fingerprint is a stable proquint pair", () => {
  const fp = cli.fingerprint(A.recipient);
  assert.match(fp, /^[bdfghjklmnprstvz][aiou][bdfghjklmnprstvz][aiou][bdfghjklmnprstvz]-[bdfghjklmnprstvz][aiou][bdfghjklmnprstvz][aiou][bdfghjklmnprstvz]$/);
  assert.equal(cli.fingerprint(A.recipient), fp);
  assert.notEqual(cli.fingerprint(B.recipient), fp);
});

test("resolveIdentity: env var, file, and failure modes", () => {
  assert.ok(cli.resolveIdentity(envA));
  const f = path.join(os.tmpdir(), `pkvault-id-${process.pid}`);
  fs.writeFileSync(f, `# comment\n${A.identity}\n`);
  assert.ok(cli.resolveIdentity({ PKVAULT_IDENTITY_FILE: f }));
  fs.unlinkSync(f);
  // isolate from any real agent at ~/.config/pkvault (dogfooding is live!)
  const emptyHome = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-nohome-"));
  throwsCode(() => cli.resolveIdentity({ PKVAULT_HOME: emptyHome }), "E_NO_IDENTITY");
  throwsCode(() => cli.resolveIdentity({ PKVAULT_IDENTITY: "garbage" }), "E_NO_IDENTITY");
});
