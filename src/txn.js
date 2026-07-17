"use strict";
// SPEC §8.2 two-file crash consistency + §8.3 repository mutation lock.
// The transaction marker is UNTRUSTED repository-controlled input.

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");

class TxnError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.code = code;
  }
}
const err = (code, m) => new TxnError(code, m);

const MARKER_MAX = 4096;
const HEX64 = /^[0-9a-f]{64}$/;
const tmpRe = (base) => new RegExp(`^\\.pkvault-tmp-${base.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}-[0-9a-f]{32}$`);
const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

// --- strict JSON (duplicate keys rejected; objects/arrays/strings/int/null/bool) ---
function strictJsonParse(text) {
  let i = 0;
  const fail = (m) => { throw err("E_TXN_MARKER", `marker JSON: ${m} at ${i}`); };
  const ws = () => { while (" \t\n\r".includes(text[i])) i++; };
  function value() {
    ws();
    const c = text[i];
    if (c === "{") {
      i++;
      const obj = {};
      ws();
      if (text[i] === "}") { i++; return obj; }
      for (;;) {
        ws();
        if (text[i] !== '"') fail("expected key");
        const k = str();
        if (k in obj) fail(`duplicate key "${k}"`);
        ws();
        if (text[i++] !== ":") fail("expected ':'");
        obj[k] = value();
        ws();
        if (text[i] === ",") { i++; continue; }
        if (text[i] === "}") { i++; return obj; }
        fail("expected ',' or '}'");
      }
    }
    if (c === "[") {
      i++;
      const arr = [];
      ws();
      if (text[i] === "]") { i++; return arr; }
      for (;;) {
        arr.push(value());
        ws();
        if (text[i] === ",") { i++; continue; }
        if (text[i] === "]") { i++; return arr; }
        fail("expected ',' or ']'");
      }
    }
    if (c === '"') return str();
    if (text.startsWith("null", i)) { i += 4; return null; }
    if (text.startsWith("true", i)) { i += 4; return true; }
    if (text.startsWith("false", i)) { i += 5; return false; }
    const num = /^-?(0|[1-9][0-9]*)/.exec(text.slice(i));
    if (num) { i += num[0].length; return parseInt(num[0], 10); }
    return fail("unexpected token");
  }
  function str() {
    i++; // opening quote
    let out = "";
    for (;;) {
      const c = text[i++];
      if (c === undefined) fail("unterminated string");
      if (c === '"') return out;
      if (c === "\\") {
        const e = text[i++];
        if (e === '"' || e === "\\" || e === "/") out += e;
        else if (e === "b") out += "\b";
        else if (e === "f") out += "\f";
        else if (e === "n") out += "\n";
        else if (e === "r") out += "\r";
        else if (e === "t") out += "\t";
        else if (e === "u") {
          const hex = text.slice(i, i + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail("bad unicode escape");
          out += String.fromCharCode(parseInt(hex, 16));
          i += 4;
        }
        else fail("bad escape");
      } else {
        if (c.charCodeAt(0) <= 0x1f) fail("unescaped control character");
        out += c;
      }
    }
  }
  const v = value();
  ws();
  if (i !== text.length) fail("trailing bytes");
  return v;
}

// --- path boundary (SPEC §8.2, SPEC-MANIFEST §4) ------------------------------------
function validateRelPath(rel) {
  if (typeof rel !== "string" || rel === "") throw err("E_PATH_BOUNDARY", "empty path");
  if (rel.startsWith("/") || rel.includes("\\") || rel.endsWith("/")) throw err("E_PATH_BOUNDARY", `bad path shape: ${rel}`);
  const segs = rel.split("/");
  if (segs.some((s) => s === "" || s === "." || s === "..")) throw err("E_PATH_BOUNDARY", `traversal in: ${rel}`);
  return segs;
}
function validateAncestors(repoRoot, rel) {
  const segs = validateRelPath(rel);
  let cur = repoRoot;
  for (const seg of segs.slice(0, -1)) {
    cur = path.join(cur, seg);
    let st;
    try { st = fs.lstatSync(cur); } catch { throw err("E_PATH_BOUNDARY", `missing directory: ${cur}`); }
    if (st.isSymbolicLink() || !st.isDirectory()) throw err("E_PATH_BOUNDARY", `not a real directory: ${cur}`);
  }
  return path.join(repoRoot, rel);
}
function checkTargetType(abs) {
  let st;
  try { st = fs.lstatSync(abs); } catch { return "absent"; }
  if (!st.isFile() || st.isSymbolicLink()) throw err("E_PATH_BOUNDARY", `target is not a regular file: ${abs}`);
  return "file";
}
const assertRegularFileOrAbsent = (abs) => { checkTargetType(abs); };

// --- git-tracked check (injectable for tests) ------------------------------------------
function defaultIsTracked(repoRoot, rel) {
  const r = spawnSync("git", ["ls-files", "--error-unmatch", "--", rel], { cwd: repoRoot, stdio: "ignore" });
  return r.status === 0;
}

const PKDIR = ".pkvault";
const localState = ["txn", "txn.tmp", "lock"];
function refuseBadLocalState(repoRoot, isTracked) {
  for (const name of localState) {
    const rel = `${PKDIR}/${name}`;
    const abs = path.join(repoRoot, rel);
    let st = null;
    try { st = fs.lstatSync(abs); } catch {}
    if (st && st.isSymbolicLink()) throw err("E_TRACKED", `${rel} is a symlink`);
    if (isTracked(repoRoot, rel)) throw err("E_TRACKED", `${rel} is tracked by git`);
  }
}

// --- fsync helpers ------------------------------------------------------------------------
function fsyncFile(abs) {
  const fd = fs.openSync(abs, "r");
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function fsyncDir(dirAbs) {
  // Windows does not expose directory fsync through Node. That platform has an
  // explicit process-crash-only durability downgrade; supported POSIX systems
  // propagate failures instead of silently reporting a durable commit.
  if (process.platform === "win32") return false;
  const fd = fs.openSync(dirAbs, "r");
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  return true;
}
function writeAllSync(fd, data) {
  const bytes = Buffer.isBuffer(data) ? data : Buffer.from(data, "utf8");
  let offset = 0;
  while (offset < bytes.length) {
    const written = fs.writeSync(fd, bytes, offset, bytes.length - offset, null);
    if (written <= 0) throw err("E_TXN_WRITE", "write made no progress");
    offset += written;
  }
}
function writeDurableFile(abs, bytes, { mode = 0o600 } = {}) {
  let fd;
  try {
    fd = fs.openSync(abs, "wx", mode);
    writeAllSync(fd, bytes);
    fs.fsyncSync(fd);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

// Atomic single-file replacement through a validated in-repository directory.
function writeFileAtomic(repoRoot, rel, bytes, { mode = 0o600 } = {}) {
  const abs = validateAncestors(repoRoot, rel);
  checkTargetType(abs);
  const tempName = `.pkvault-tmp-${path.basename(rel)}-${crypto.randomBytes(16).toString("hex")}`;
  const tempAbs = path.join(path.dirname(abs), tempName);
  try {
    writeDurableFile(tempAbs, bytes, { mode });
    if (sha256(fs.readFileSync(tempAbs)) !== sha256(Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes, "utf8")))
      throw err("E_TXN_WRITE", `temporary file verification failed: ${tempName}`);
    fsyncDir(path.dirname(tempAbs));
    fs.renameSync(tempAbs, abs);
    fsyncDir(path.dirname(abs));
  } catch (e) {
    try { fs.unlinkSync(tempAbs); } catch {}
    throw e;
  }
}
function removeFileDurable(repoRoot, rel) {
  const abs = validateAncestors(repoRoot, rel);
  const state = checkTargetType(abs);
  if (state === "absent") return false;
  fs.unlinkSync(abs);
  fsyncDir(path.dirname(abs));
  return true;
}

// --- lock (SPEC §8.3) ------------------------------------------------------------------------
function acquireLock(repoRoot, { isTracked = defaultIsTracked } = {}) {
  refuseBadLocalState(repoRoot, isTracked);
  const abs = path.join(repoRoot, PKDIR, "lock");
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  try {
    const fd = fs.openSync(abs, "wx");
    writeAllSync(fd, `${process.pid} ${new Date().toISOString()}\n`);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    return { release: () => { try { fs.unlinkSync(abs); } catch {} } };
  } catch (e) {
    if (e.code !== "EEXIST") throw e;
    let holder = "";
    try { holder = fs.readFileSync(abs, "utf8").trim(); } catch {}
    const pid = parseInt(holder, 10);
    // Only ESRCH proves the holder is gone. EPERM = process exists but owned by
    // another user (shared checkout) → LIVE. Unreadable pid or any other errno →
    // indeterminate → also treat as live. NEVER auto-declare a lock stale unless
    // we have positive proof the process died — a false "stale" invites removal
    // of an active lock.
    let dead = false;
    if (Number.isInteger(pid) && pid > 0) {
      try { process.kill(pid, 0); } catch (e2) { dead = e2.code === "ESRCH"; }
    }
    if (!dead) throw err("E_LOCKED", `another pkvault process holds the lock (${holder || "unreadable"})`);
    throw err("E_LOCK_STALE", `stale lock (${holder || "unreadable"}); run \`pkvault unlock --force\` after confirming no pkvault process is running`);
  }
}
const forceUnlock = (repoRoot) => { try { fs.unlinkSync(path.join(repoRoot, PKDIR, "lock")); } catch {} };

// --- marker schema validation (untrusted input) --------------------------------------------------
function validateMarker(repoRoot, raw, configuredTargets) {
  if (raw.length > MARKER_MAX) throw err("E_TXN_MARKER", `marker exceeds ${MARKER_MAX} bytes`);
  if (raw[0] === 0xef && raw[1] === 0xbb && raw[2] === 0xbf) throw err("E_TXN_MARKER", "BOM present");
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(raw); }
  catch { throw err("E_TXN_MARKER", "marker is not valid UTF-8"); }
  const doc = strictJsonParse(text);
  const keys = Object.keys(doc);
  if (keys.length !== 3 || doc.txn !== 1 || doc.hash !== "sha256" || !Array.isArray(doc.files))
    throw err("E_TXN_MARKER", "bad top-level shape");
  if (doc.files.length !== configuredTargets.length) throw err("E_TXN_MARKER", "wrong entry count");
  const seen = new Set();
  for (const f of doc.files) {
    if (typeof f !== "object" || f === null || Array.isArray(f)) throw err("E_TXN_MARKER", "entry not an object");
    const fk = Object.keys(f);
    if (fk.length !== 4 || typeof f.target !== "string" || typeof f.temp !== "string") throw err("E_TXN_MARKER", "bad entry fields");
    if (!(f.old === null || (typeof f.old === "string" && HEX64.test(f.old)))) throw err("E_TXN_MARKER", "bad old hash");
    if (typeof f.new !== "string" || !HEX64.test(f.new)) throw err("E_TXN_MARKER", "bad new hash");
    if (!configuredTargets.includes(f.target)) throw err("E_TXN_MARKER", `target not configured: ${f.target}`);
    if (seen.has(f.target)) throw err("E_TXN_MARKER", `duplicate target: ${f.target}`);
    seen.add(f.target);
    validateRelPath(f.temp);
    const tdir = path.dirname(f.target), xdir = path.dirname(f.temp);
    if (tdir !== xdir) throw err("E_TXN_MARKER", `temp not in target directory: ${f.temp}`);
    if (!tmpRe(path.basename(f.target)).test(path.basename(f.temp))) throw err("E_TXN_MARKER", `temp does not match reserved pattern: ${f.temp}`);
  }
  return doc;
}

// --- forward path (SPEC §8.2 steps 1–8) -----------------------------------------------------------
// files: [{ target: relPath, bytes: Buffer }] — order = [vault, manifest].
function commitTxn(repoRoot, files, { isTracked = defaultIsTracked, crashAfter = null } = {}) {
  const crash = (stage) => { if (crashAfter === stage) throw err("E_SIMULATED_CRASH", stage); };
  refuseBadLocalState(repoRoot, isTracked);
  const txnAbs = path.join(repoRoot, PKDIR, "txn");
  if (fs.existsSync(txnAbs)) throw err("E_TXN_PENDING", "published transaction marker exists; run recovery first");

  const entries = files.map(({ target, bytes }) => {
    const abs = validateAncestors(repoRoot, target);
    const state = checkTargetType(abs);
    const old = state === "absent" ? null : sha256(fs.readFileSync(abs));
    const tempName = `.pkvault-tmp-${path.basename(target)}-${crypto.randomBytes(16).toString("hex")}`;
    const tempRel = path.dirname(target) === "." ? tempName : `${path.dirname(target)}/${tempName}`;
    return { target, abs, tempRel, bytes, old, new: sha256(bytes) };
  });

  // 1–3: temps with exclusive no-follow creation, write bytes, fsync files + dirs
  for (const e of entries) {
    const tAbs = path.join(repoRoot, e.tempRel);
    writeDurableFile(tAbs, e.bytes); // O_CREAT|O_EXCL (fails on existing path or symlink)
    if (sha256(fs.readFileSync(tAbs)) !== e.new)
      throw err("E_TXN_WRITE", `temporary file verification failed: ${e.tempRel}`);
    fsyncDir(path.dirname(tAbs));
  }
  crash("temps");

  // 4–6: marker via txn.tmp → rename → fsync dir
  const marker = JSON.stringify({ txn: 1, hash: "sha256", files: entries.map((e) => ({ target: e.target, temp: e.tempRel, old: e.old, new: e.new })) });
  if (Buffer.byteLength(marker) > MARKER_MAX) throw err("E_TXN_MARKER", "marker too large");
  const tmpAbs = path.join(repoRoot, PKDIR, "txn.tmp");
  writeDurableFile(tmpAbs, marker);
  crash("marker-tmp");
  fs.renameSync(tmpAbs, txnAbs);
  fsyncDir(path.join(repoRoot, PKDIR));
  crash("marker");

  // 7: renames, in order
  for (let i = 0; i < entries.length; i++) {
    fs.renameSync(path.join(repoRoot, entries[i].tempRel), entries[i].abs);
    fsyncDir(path.dirname(entries[i].abs));
    crash(`rename${i + 1}`);
  }

  // 8: remove marker
  fs.unlinkSync(txnAbs);
  fsyncDir(path.join(repoRoot, PKDIR));
}

// --- recovery (SPEC §8.2) -----------------------------------------------------------------------------
function recover(repoRoot, configuredTargets, { isTracked = defaultIsTracked } = {}) {
  refuseBadLocalState(repoRoot, isTracked);
  const txnAbs = path.join(repoRoot, PKDIR, "txn");
  let st = null;
  try { st = fs.lstatSync(txnAbs); } catch {}
  if (!st) return cleanupStale(repoRoot, configuredTargets, { isTracked });
  if (!st.isFile() || st.isSymbolicLink()) throw err("E_TXN_MARKER", "marker is not a regular file");
  const doc = validateMarker(repoRoot, fs.readFileSync(txnAbs), configuredTargets);

  for (const f of doc.files) {
    const abs = validateAncestors(repoRoot, f.target);
    const tAbs = path.join(repoRoot, f.temp);
    const state = checkTargetType(abs);
    const cur = state === "absent" ? null : sha256(fs.readFileSync(abs));
    if (cur === f.new) {
      // landed — discard leftover temp if present (must be regular non-symlink)
      let ts = null;
      try { ts = fs.lstatSync(tAbs); } catch {}
      if (ts) {
        if (!ts.isFile() || ts.isSymbolicLink()) throw err("E_TXN_RECOVERY", `leftover temp is not a regular file: ${f.temp}`);
        fs.unlinkSync(tAbs);
      }
      continue;
    }
    if (cur === f.old) {
      let ts = null;
      try { ts = fs.lstatSync(tAbs); } catch {}
      if (!ts) throw err("E_TXN_RECOVERY", `temp missing for ${f.target}; cannot complete — restore from git or inspect manually`);
      if (!ts.isFile() || ts.isSymbolicLink()) throw err("E_TXN_RECOVERY", `temp is not a regular file: ${f.temp}`);
      if (sha256(fs.readFileSync(tAbs)) !== f.new) throw err("E_TXN_RECOVERY", `temp content does not match recorded hash for ${f.target}; refusing to install`);
      fs.renameSync(tAbs, abs);
      fsyncDir(path.dirname(abs));
      continue;
    }
    throw err("E_TXN_RECOVERY", `${f.target} matches neither recorded hash; manual inspection required`);
  }
  fs.unlinkSync(txnAbs);
  fsyncDir(path.join(repoRoot, PKDIR));
  return { recovered: true };
}

// stale unpublished state: txn.tmp + orphan temps (no published marker)
function cleanupStale(repoRoot, configuredTargets, { isTracked = defaultIsTracked } = {}) {
  const tmpAbs = path.join(repoRoot, PKDIR, "txn.tmp");
  let ts = null;
  try { ts = fs.lstatSync(tmpAbs); } catch {}
  if (ts) {
    if (!ts.isFile() || ts.isSymbolicLink()) throw err("E_TXN_MARKER", "txn.tmp is not a regular file");
    fs.unlinkSync(tmpAbs);
  }
  for (const target of configuredTargets) {
    const abs = validateAncestors(repoRoot, target);
    const dir = path.dirname(abs);
    const re = tmpRe(path.basename(target));
    for (const name of fs.readdirSync(dir)) {
      if (!re.test(name)) continue;
      const rel = path.dirname(target) === "." ? name : `${path.dirname(target)}/${name}`;
      if (isTracked(repoRoot, rel)) throw err("E_TRACKED", `tracked file matches reserved temp pattern: ${rel}`);
      const st2 = fs.lstatSync(path.join(dir, name));
      if (!st2.isFile() || st2.isSymbolicLink()) throw err("E_TXN_RECOVERY", `reserved-pattern path is not a regular file: ${rel}`);
      fs.unlinkSync(path.join(dir, name));
    }
  }
  return { recovered: false };
}

module.exports = {
  TxnError, strictJsonParse, validateRelPath, validateAncestors,
  assertRegularFileOrAbsent, validateMarker, acquireLock, forceUnlock,
  writeAllSync, writeFileAtomic, removeFileDurable, commitTxn, recover, cleanupStale,
};
