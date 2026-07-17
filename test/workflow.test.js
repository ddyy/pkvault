"use strict";
// Workflow suite: F7 crash/adversary matrix (SPEC §8.2), F9 locking (§8.3),
// manifest + config parsing (SPEC-MANIFEST). node:test, zero deps.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const txn = require("../src/txn.js");
const manifest = require("../src/manifest.js");

const TARGETS = [".env.pkvault", ".pkvault/recipients.toml"];
const untracked = () => false; // isTracked stub: nothing tracked
const trackedSet = (set) => (root, rel) => set.has(rel);

function repo() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-test-"));
  fs.mkdirSync(path.join(root, ".pkvault"), { recursive: true });
  fs.writeFileSync(path.join(root, ".env.pkvault"), "OLD-VAULT\n");
  fs.writeFileSync(path.join(root, ".pkvault/recipients.toml"), 'a = "old"\n');
  return root;
}
const readTarget = (root, t) => fs.readFileSync(path.join(root, t), "utf8");
const FILES = (v = "NEW-VAULT\n", m = 'a = "new"\n') => [
  { target: ".env.pkvault", bytes: Buffer.from(v) },
  { target: ".pkvault/recipients.toml", bytes: Buffer.from(m) },
];
const commit = (root, opts = {}) => txn.commitTxn(root, FILES(), { isTracked: untracked, ...opts });
const recover = (root, opts = {}) => txn.recover(root, TARGETS, { isTracked: untracked, ...opts });
const assertNew = (root) => {
  assert.equal(readTarget(root, TARGETS[0]), "NEW-VAULT\n");
  assert.equal(readTarget(root, TARGETS[1]), 'a = "new"\n');
  assert.ok(!fs.existsSync(path.join(root, ".pkvault/txn")), "marker must be gone");
};
const throwsCode = (fn, code) => assert.throws(fn, (e) => (assert.equal(e.code, code, e.message), true));

// ---------- happy path ----------
test("F7 happy path replaces both files, no marker left", () => {
  const root = repo();
  commit(root);
  assertNew(root);
});

test("F7 full-write helper handles short writes instead of publishing truncation", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-short-write-"));
  const abs = path.join(root, "out");
  const fd = fs.openSync(abs, "wx");
  const original = fs.writeSync;
  try {
    fs.writeSync = (theFd, bytes, offset, length, position) =>
      original(theFd, bytes, offset, Math.min(length, 3), position);
    txn.writeAllSync(fd, Buffer.from("complete-buffer"));
  } finally {
    fs.writeSync = original;
    fs.closeSync(fd);
  }
  assert.equal(fs.readFileSync(abs, "utf8"), "complete-buffer");
});

// ---------- crash matrix ----------
for (const [stage, expectRecovered, check] of [
  ["temps", false, (root) => { assert.equal(readTarget(root, TARGETS[0]), "OLD-VAULT\n"); }],
  ["marker-tmp", false, (root) => { assert.equal(readTarget(root, TARGETS[0]), "OLD-VAULT\n"); assert.ok(!fs.existsSync(path.join(root, ".pkvault/txn.tmp")), "stale txn.tmp cleaned"); }],
  ["marker", true, assertNew],
  ["rename1", true, assertNew],
  ["rename2", true, assertNew],
]) {
  test(`F7 crash after ${stage} → recovery converges`, () => {
    const root = repo();
    throwsCode(() => commit(root, { crashAfter: stage }), "E_SIMULATED_CRASH");
    const r = recover(root);
    assert.equal(r.recovered, expectRecovered);
    check(root);
    // idempotence: run recovery again, nothing changes
    recover(root);
    check(root);
    // stale temps are gone in all cases
    const leftovers = fs.readdirSync(root).filter((n) => n.startsWith(".pkvault-tmp-"));
    assert.deepEqual(leftovers, []);
  });
}

test("F7 recovery rename then power loss before marker removal → re-run converges", () => {
  const root = repo();
  throwsCode(() => commit(root, { crashAfter: "marker" }), "E_SIMULATED_CRASH");
  // simulate: first recovery completes renames but "crashes" before unlink by
  // restoring the marker afterwards, then recovering again.
  const markerBytes = fs.readFileSync(path.join(root, ".pkvault/txn"));
  recover(root);
  fs.writeFileSync(path.join(root, ".pkvault/txn"), markerBytes); // marker re-appears (pre-removal crash)
  recover(root); // both targets == new → success, marker removed
  assertNew(root);
});

test("F7 target==old with temp absent → refusal", () => {
  const root = repo();
  throwsCode(() => commit(root, { crashAfter: "marker" }), "E_SIMULATED_CRASH");
  for (const n of fs.readdirSync(root)) if (n.startsWith(".pkvault-tmp-")) fs.unlinkSync(path.join(root, n));
  for (const n of fs.readdirSync(path.join(root, ".pkvault"))) if (n.startsWith(".pkvault-tmp-")) fs.unlinkSync(path.join(root, ".pkvault", n));
  throwsCode(() => recover(root), "E_TXN_RECOVERY");
});

test("F7 target==old with temp hash != new → refusal (unverified temp never installed)", () => {
  const root = repo();
  throwsCode(() => commit(root, { crashAfter: "marker" }), "E_SIMULATED_CRASH");
  const temp = fs.readdirSync(root).find((n) => n.startsWith(".pkvault-tmp-"));
  fs.writeFileSync(path.join(root, temp), "CORRUPTED\n");
  throwsCode(() => recover(root), "E_TXN_RECOVERY");
  assert.equal(readTarget(root, TARGETS[0]), "OLD-VAULT\n", "target untouched");
});

test("F7 target matches neither hash → refusal", () => {
  const root = repo();
  throwsCode(() => commit(root, { crashAfter: "marker" }), "E_SIMULATED_CRASH");
  fs.writeFileSync(path.join(root, ".env.pkvault"), "MYSTERY\n");
  throwsCode(() => recover(root), "E_TXN_RECOVERY");
});

test("F7 replacement-temp path pre-planted as symlink → refusal at step 1", () => {
  const root = repo();
  // plant symlinks at plausible temp paths: we can't predict the random suffix,
  // so instead verify the mechanism: creating over an existing path fails (wx).
  // Direct check of the primitive:
  const abs = path.join(root, ".pkvault-tmp-.env.pkvault-" + "0".repeat(32));
  fs.symlinkSync("/etc/hosts", abs);
  assert.throws(() => fs.openSync(abs, "wx"), (e) => e.code === "EEXIST");
});

// ---------- malicious markers ----------
function plantMarker(root, doc) {
  fs.writeFileSync(path.join(root, ".pkvault/txn"), typeof doc === "string" ? doc : JSON.stringify(doc));
}
const E = "E_TXN_MARKER";
const entry = (over = {}) => ({ target: ".env.pkvault", temp: ".pkvault-tmp-.env.pkvault-" + "a".repeat(32), old: null, new: "b".repeat(64), ...over });
const entry2 = (over = {}) => ({ target: ".pkvault/recipients.toml", temp: ".pkvault/.pkvault-tmp-recipients.toml-" + "a".repeat(32), old: null, new: "c".repeat(64), ...over });

for (const [name, doc, code = E] of [
  ["malformed JSON", "{not json", E],
  ["duplicate JSON keys", '{"txn":1,"txn":1,"hash":"sha256","files":[]}', E],
  ["wrong types", { txn: "1", hash: "sha256", files: [entry(), entry2()] }, E],
  ["wrong entry count", { txn: 1, hash: "sha256", files: [entry()] }, E],
  ["unknown top-level field", { txn: 1, hash: "sha256", files: [entry(), entry2()], extra: 1 }, E],
  ["unknown entry field", { txn: 1, hash: "sha256", files: [entry({ note: "hi" }), entry2()] }, E],
  ["target outside configured", { txn: 1, hash: "sha256", files: [entry({ target: ".ssh/authorized_keys", temp: ".ssh/.pkvault-tmp-authorized_keys-" + "a".repeat(32) }), entry2()] }, E],
  ["duplicate targets", { txn: 1, hash: "sha256", files: [entry(), entry()] }, E],
  ["temp outside target dir", { txn: 1, hash: "sha256", files: [entry({ temp: ".pkvault/.pkvault-tmp-.env.pkvault-" + "a".repeat(32) }), entry2()] }, E],
  ["temp not matching pattern", { txn: 1, hash: "sha256", files: [entry({ temp: "evil-name" }), entry2()] }, E],
  ["traversal in temp", { txn: 1, hash: "sha256", files: [entry({ temp: "../.pkvault-tmp-.env.pkvault-" + "a".repeat(32) }), entry2()] }, "E_PATH_BOUNDARY"],
  ["bad old hash", { txn: 1, hash: "sha256", files: [entry({ old: "XYZ" }), entry2()] }, E],
  ["non-hex new hash", { txn: 1, hash: "sha256", files: [entry({ new: "Z".repeat(64) }), entry2()] }, E],
]) {
  test(`F7 malicious marker: ${name} → refusal untouched`, () => {
    const root = repo();
    plantMarker(root, doc);
    throwsCode(() => recover(root), code);
    assert.equal(readTarget(root, TARGETS[0]), "OLD-VAULT\n", "targets untouched");
  });
}

test("F7 oversized marker → refusal", () => {
  const root = repo();
  plantMarker(root, JSON.stringify({ txn: 1, hash: "sha256", files: [] }) + " ".repeat(5000));
  throwsCode(() => recover(root), E);
});

test("F7 tracked .pkvault/txn → refusal to operate", () => {
  const root = repo();
  plantMarker(root, { txn: 1, hash: "sha256", files: [entry(), entry2()] });
  const isTracked = trackedSet(new Set([".pkvault/txn"]));
  throwsCode(() => txn.recover(root, TARGETS, { isTracked }), "E_TRACKED");
  throwsCode(() => txn.commitTxn(root, FILES(), { isTracked }), "E_TRACKED");
});

test("F7 symlinked .pkvault/lock → refusal", () => {
  const root = repo();
  fs.symlinkSync("/tmp/elsewhere", path.join(root, ".pkvault/lock"));
  throwsCode(() => commit(root), "E_TRACKED");
});

test("F7 tracked file matching reserved temp pattern → refusal, not deletion", () => {
  const root = repo();
  const rel = ".pkvault-tmp-.env.pkvault-" + "d".repeat(32);
  fs.writeFileSync(path.join(root, rel), "tracked content");
  throwsCode(() => txn.cleanupStale(root, TARGETS, { isTracked: trackedSet(new Set([rel])) }), "E_TRACKED");
  assert.ok(fs.existsSync(path.join(root, rel)), "tracked file must not be deleted");
});

test("F7 symlinked ancestor directory → refusal", () => {
  const root = repo();
  const real = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-elsewhere-"));
  fs.rmSync(path.join(root, ".pkvault"), { recursive: true });
  fs.symlinkSync(real, path.join(root, ".pkvault"));
  throwsCode(() => txn.validateAncestors(root, ".pkvault/recipients.toml"), "E_PATH_BOUNDARY");
});

// ---------- F9 locking ----------
test("F9 two writers: second refuses naming the holder", () => {
  const root = repo();
  const lock = txn.acquireLock(root, { isTracked: untracked });
  try {
    throwsCode(() => txn.acquireLock(root, { isTracked: untracked }), "E_LOCKED");
  } finally {
    lock.release();
  }
  const again = txn.acquireLock(root, { isTracked: untracked });
  again.release();
});

test("F9 stale lock (dead pid) → E_LOCK_STALE, force unlock recovers", () => {
  const root = repo();
  fs.mkdirSync(path.join(root, ".pkvault"), { recursive: true });
  fs.writeFileSync(path.join(root, ".pkvault/lock"), "999999 2026-07-15T00:00:00Z\n");
  throwsCode(() => txn.acquireLock(root, { isTracked: untracked }), "E_LOCK_STALE");
  txn.forceUnlock(root);
  txn.acquireLock(root, { isTracked: untracked }).release();
});

test("#9 EPERM (process exists, not signalable) → treated LIVE, not stale", () => {
  const root = repo();
  fs.mkdirSync(path.join(root, ".pkvault"), { recursive: true });
  // pid 1 (init/launchd) exists but a normal user cannot signal it → EPERM.
  // The lock must be reported LIVE (E_LOCKED), never auto-declared stale.
  fs.writeFileSync(path.join(root, ".pkvault/lock"), "1 2026-07-16T00:00:00Z\n");
  throwsCode(() => txn.acquireLock(root, { isTracked: untracked }), "E_LOCKED");
  // an unreadable/garbage pid is indeterminate → also LIVE, never stale
  fs.writeFileSync(path.join(root, ".pkvault/lock"), "not-a-pid\n");
  throwsCode(() => txn.acquireLock(root, { isTracked: untracked }), "E_LOCKED");
});

// ---------- manifest / config ----------
const AGE_A = require("../src/age.js").keygen(require("node:crypto").createHash("sha256").update("pkvault-manifest-test").digest()).recipient;
test("manifest: valid file parses, tool serialization is sorted", () => {
  const m = manifest.parseManifest(Buffer.from(`# team\nbob = "${AGE_A}"\n`));
  assert.equal(m.length, 1);
  assert.equal(m[0].label, "bob");
  const out = manifest.serializeManifest(m).toString();
  assert.equal(out, `bob = "${AGE_A}"\n`);
});
for (const [name, text, code] of [
  ["empty", "# nothing\n", "E_MANIFEST_EMPTY"],
  ["duplicate label", `a = "${AGE_A}"\na = "${AGE_A}"\n`, "E_MANIFEST_DUP_LABEL"],
  ["duplicate decoded key", `a = "${AGE_A}"\nb = "${AGE_A}"\n`, "E_MANIFEST_DUP_KEY"],
  ["bad label", `BAD_LABEL = "${AGE_A}"\n`, "E_MANIFEST_PARSE"],
  ["invalid recipient", 'a = "age1notavalidrecipient"\n', "E_MANIFEST_RECIPIENT"],
  ["CR bytes", `a = "${AGE_A}"\r\n`, "E_MANIFEST_PARSE"],
  ["no final LF", `a = "${AGE_A}"`, "E_MANIFEST_PARSE"],
  ["multiline junk", `a = """\nx\n"""\n`, "E_MANIFEST_PARSE"],
]) {
  test(`manifest: ${name} → ${code}`, () => {
    throwsCode(() => manifest.parseManifest(Buffer.from(text)), code);
  });
}
test("config: vault key parses; unknown key refuses", () => {
  assert.deepEqual(manifest.parseConfig(Buffer.from('vault = ".env.pkvault"\n')), { vault: ".env.pkvault" });
  throwsCode(() => manifest.parseConfig(Buffer.from('vault = "x"\nother = "y"\n')), "E_CONFIG_PARSE");
  throwsCode(() => manifest.parseConfig(Buffer.from("# empty\n")), "E_CONFIG_PARSE");
});
