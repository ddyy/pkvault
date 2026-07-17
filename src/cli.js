"use strict";
// pkvault CLI core (PLAN §5). Commands are plain functions with injected io for
// testability; bin wrapper handles argv/TTY. Identity sources today: agent (later),
// PKVAULT_IDENTITY / PKVAULT_IDENTITY_FILE (age secret key — machine/CI path).

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const fmt = require("./format");
const agelib = require("./age");
const manifestlib = require("./manifest");
const txn = require("./txn");
const editorlib = require("./editor");
const bridge = require("./bridge");
const idn = require("./identity");
const unlocklib = require("./unlock");
const os = require("node:os");

class CliError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.code = code;
  }
}
const err = (code, m) => new CliError(code, m);

const CONFIG = ".pkvault/config.toml";
const MANIFEST = ".pkvault/recipients.toml";
const IDENTITIES = ".pkvault/identities";
const NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const LABEL_RE = /^[a-z0-9-]{1,32}$/;

const sha256hex = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

// Is `cwd` inside a git worktree? (walk up for a .git file/dir). Used to decide
// whether a FAILED git probe must fail closed — in a worktree we cannot assume a
// source is untracked just because git errored.
function inGitWorktree(cwd) {
  let d = path.resolve(cwd);
  for (;;) {
    if (fs.existsSync(path.join(d, ".git"))) return true;
    const parent = path.dirname(d);
    if (parent === d) return false;
    d = parent;
  }
}

// Distinguish every outcome of the tracked probe so callers can fail CLOSED on a
// genuine probe failure inside a worktree (never conflate it with "not tracked").
function gitTrackState(cwd, rel) {
  const r = spawnSync("git", ["ls-files", "--error-unmatch", "--", rel], { cwd, stdio: "ignore" });
  if (r.error) return "no-git";       // git binary missing / not executable
  if (r.status === 0) return "tracked";
  if (r.status === 1) return "untracked"; // in a repo, clean no-match
  // status 128 is "not a repo" ONLY outside a worktree; inside one it is a real
  // probe failure (fatal error) and must fail closed, not read as "safe".
  if (r.status === 128) return inGitWorktree(cwd) ? "probe-error" : "not-a-repo";
  return "probe-error";
}

// True only when we can be SURE the path is not tracked. In a git worktree, a
// failed probe is NOT proof of "not tracked" → indeterminate.
function definitelyNotTracked(cwd, rel) {
  const state = gitTrackState(cwd, rel);
  if (state === "untracked" || state === "not-a-repo") return true;
  if (state === "tracked") return false;
  return !inGitWorktree(cwd); // no-git / probe-error: safe only outside a worktree
}

// #2/#3: gitignore alone does not protect an already staged/committed source.
// Untrack it AFTER the ignore rule is durable. Fail CLOSED — a tracked source
// that cannot be removed, OR an indeterminate probe inside a worktree, aborts
// so init/local-init do not publish while plaintext stays committable.
function untrackSource(cwd, rel, io) {
  const state = gitTrackState(cwd, rel);
  if (state === "untracked" || state === "not-a-repo") return; // provably safe
  if (state !== "tracked") { // no-git / probe-error
    if (inGitWorktree(cwd)) throw err("E_UNTRACK", `cannot determine git-tracking of ${rel} (git probe failed inside a worktree); ensure git works, then re-run`);
    return; // not a git repo at all → nothing to untrack
  }
  const rm = spawnSync("git", ["rm", "--cached", "--quiet", "--", rel], { cwd });
  if (rm.error) throw err("E_UNTRACK", `cannot untrack ${rel}: git failed (${rm.error.message}) — run \`git rm --cached -- ${rel}\` then re-run`);
  if (rm.status !== 0) throw err("E_UNTRACK", `git refused to untrack ${rel} (status ${rm.status}) — resolve, then \`git rm --cached -- ${rel}\` and re-run`);
  io.out(`untracked ${rel} from git — was staged/committed in plaintext; working file kept. Rotate values already in history.`);
}

// A process-local pending marker is UNTRUSTED repository-controlled input. Read
// it strictly: regular non-symlink file, not git-tracked, strict JSON, exact
// schema {"v":1,<field>:<path>,"<field>Sha256":<64hex>}. Absent → null. Hostile
// (symlink/tracked/corrupt/wrong-schema) → refuse to operate.
function readPendingMarker(cwd, rel, pathField, extraStringFields = []) {
  const abs = txn.validateAncestors(cwd, rel);
  let st;
  try { st = fs.lstatSync(abs); } catch { return null; }
  if (st.isSymbolicLink() || !st.isFile()) throw err("E_MARKER_HOSTILE", `${rel} is not a regular file`);
  if (!definitelyNotTracked(cwd, rel)) throw err("E_MARKER_HOSTILE", `${rel} is git-tracked or its tracking cannot be determined; process-local state must never be committed`);
  let doc;
  try { doc = txn.strictJsonParse(fs.readFileSync(abs, "utf8")); } catch { throw err("E_MARKER_HOSTILE", `${rel} is not valid marker JSON`); }
  const hashField = `${pathField}Sha256`;
  const expected = ["v", pathField, hashField, ...extraStringFields];
  const keys = Object.keys(doc);
  if (keys.length !== expected.length || keys.some((k) => !expected.includes(k)))
    throw err("E_MARKER_HOSTILE", `${rel} has an invalid schema`);
  if (doc.v !== 1 || typeof doc[pathField] !== "string" || !/^[0-9a-f]{64}$/.test(doc[hashField] ?? ""))
    throw err("E_MARKER_HOSTILE", `${rel} has an invalid schema`);
  for (const f of extraStringFields) if (typeof doc[f] !== "string") throw err("E_MARKER_HOSTILE", `${rel} missing field ${f}`);
  return doc;
}

// A user-supplied file path (--vault, export --to, local vault) MUST NOT collide
// with pkvault's own control files or land inside .pkvault/, or init/export would
// corrupt the repository or overwrite the authenticated vault with plaintext.
const norm = (rel) => rel.replace(/\/+$/, "");
function assertNotReserved(rel, what) {
  const p = norm(rel);
  if (p === CONFIG || p === MANIFEST || p === ".gitignore" || p === `${IDENTITIES}` || p.startsWith(".pkvault/"))
    throw err("E_PATH_RESERVED", `${what} may not be a pkvault control path or live under .pkvault/: ${rel}`);
}

function ensureRealDirectory(abs, { create = false, mode = 0o700 } = {}) {
  let st;
  try { st = fs.lstatSync(abs); }
  catch (e) {
    if (!create || e.code !== "ENOENT") throw e;
    fs.mkdirSync(abs, { mode, recursive: true });
    st = fs.lstatSync(abs);
  }
  if (st.isSymbolicLink() || !st.isDirectory()) throw err("E_PATH_BOUNDARY", `not a real directory: ${abs}`);
}

function readUtf8(abs, what) {
  const bytes = fs.readFileSync(abs);
  try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { throw err("E_PARSE_BODY", `${what} is not valid UTF-8`); }
}

// --- helpers -----------------------------------------------------------------------
// git-style upward discovery: commands work from any subdirectory of the repo
function findRoot(cwd) {
  let d = path.resolve(cwd);
  for (;;) {
    if (fs.existsSync(path.join(d, CONFIG))) return d;
    const parent = path.dirname(d);
    if (parent === d) throw err("E_NOT_INITIALIZED", "no .pkvault/config.toml here or in any parent — run `pkvault init` at the repo root");
    d = parent;
  }
}
function loadConfig(cwd) {
  const root = findRoot(cwd);
  const configAbs = txn.validateAncestors(root, CONFIG);
  txn.assertRegularFileOrAbsent(configAbs);
  const cfg = manifestlib.parseConfig(fs.readFileSync(configAbs));
  // EVERY configured path is validated — shape, in-repo ancestors, and (if
  // present) a regular-non-symlink target — so a committed `local = "../x"`
  // or a symlinked target can never redirect a read/write outside the repo.
  for (const p of [cfg.vault, cfg.local].filter(Boolean)) {
    const abs = txn.validateAncestors(root, p); // throws E_PATH_BOUNDARY on escape/symlinked ancestor
    txn.assertRegularFileOrAbsent(abs);
  }
  return { ...cfg, root };
}
const targets = (cfg) => [cfg.vault, MANIFEST];
function readRepoFile(root, rel) {
  const abs = txn.validateAncestors(root, rel);
  txn.assertRegularFileOrAbsent(abs);
  if (!fs.existsSync(abs)) throw err("E_PATH_BOUNDARY", `configured file is missing: ${rel}`);
  return fs.readFileSync(abs);
}
const loadManifest = (root) => manifestlib.parseManifest(readRepoFile(root, MANIFEST));
const loadVault = (root, cfg) => readRepoFile(root, cfg.vault);

function resolveIdentity(env = process.env) {
  let str = env.PKVAULT_IDENTITY;
  if (!str && env.PKVAULT_IDENTITY_FILE) str = fs.readFileSync(env.PKVAULT_IDENTITY_FILE, "utf8");
  if (str) {
    const m = str.match(/AGE-SECRET-KEY-1[0-9A-Z]+/i);
    const scalar = m && agelib.decodeIdentity(m[0].toUpperCase());
    if (!scalar) throw err("E_NO_IDENTITY", "identity is not a valid age secret key");
    return scalar;
  }
  // agent path: sync commands consult the async socket via a spawned helper.
  // First request of the day blocks here while the agent runs the ceremony.
  const home = env.PKVAULT_HOME ?? defaultHome();
  if (fs.existsSync(path.join(home, "agent.sock"))) {
    const r = spawnSync(process.execPath, [path.join(__dirname, "agent-client.js"), home], { encoding: "utf8", timeout: 180_000 });
    let reply = null;
    try { reply = JSON.parse(r.stdout); } catch {}
    if (reply?.ok) return Buffer.from(reply.scalar, "base64");
    if (reply?.code && reply.code !== "E_AGENT_UNAVAILABLE")
      throw err("E_NO_IDENTITY", `agent: ${reply.message ?? reply.code}`);
  }
  throw err("E_NO_IDENTITY", "no identity available: start `pkvault agent --label <l>` or set PKVAULT_IDENTITY(-_FILE)");
}

// single-file vault update: atomic temp+rename (two-file updates use txn.commitTxn)
function writeVaultAtomic(cwd, cfg, bytes) {
  txn.writeFileAtomic(cwd, cfg.vault, bytes);
}

function withLock(cfg, opts, fn) {
  const lock = txn.acquireLock(cfg.root, opts);
  try {
    txn.recover(cfg.root, targets(cfg), opts); // finish any interrupted transaction first
    return fn();
  } finally {
    lock.release();
  }
}

// SPEC §8.3: a lock-free read that encounters a pending transaction must not
// observe a torn snapshot. Recover it under the lock first (auto-heal); the
// common no-txn case stays lock-free.
function recoverIfPending(cfg, opts = {}) {
  if (fs.existsSync(path.join(cfg.root, ".pkvault", "txn"))) withLock(cfg, opts, () => {});
}

// §7 recipient-change guard: diff manifest against MAC-verified baseline.
function guardRecipients(io, baseline, manifest) {
  const identity = (r) => `${r.label}\0${r.recipient}`;
  const baseSet = new Set(baseline.map(identity));
  const manifestSet = new Set(manifest.map(identity));
  const additions = manifest.filter((r) => !baseSet.has(identity(r)));
  const removals = baseline.filter((r) => !manifestSet.has(identity(r)));
  if (additions.length === 0 && removals.length === 0) return;
  if (!io.interactive) throw err("E_GUARD_NONINTERACTIVE", "recipient set changed; refusing to seal non-interactively (CI identities only ever decrypt)");
  const lines = [
    ...removals.map((r) => `  - ${r.label} ${r.recipient}`),
    ...additions.map((r) => `  + ${r.label} ${r.recipient}`),
  ].join("\n");
  if (!io.confirm(`recipients changed:\n${lines}\nseal to this set? [y/N] `))
    throw err("E_GUARD_DECLINED", "recipient change not confirmed");
}

// proquint fingerprint (PLAN §4.3): 4 bytes of sha256(recipient) → two pronounceable words
function fingerprint(recipient) {
  const con = "bdfghjklmnprstvz", vow = "aiou";
  const h = crypto.createHash("sha256").update(recipient).digest();
  const word = (hi, lo) => {
    const n = (hi << 8) | lo;
    return con[(n >> 12) & 15] + vow[(n >> 10) & 3] + con[(n >> 6) & 15] + vow[(n >> 4) & 3] + con[n & 15];
  };
  return `${word(h[0], h[1])}-${word(h[2], h[3])}`;
}

// --- commands -------------------------------------------------------------------------
function init({ cwd, io, label, recipient, from = ".env", vault = ".env.pkvault", home = defaultHome(), faultAfter = null }) {
  cwd = path.resolve(cwd);
  ensureRealDirectory(cwd);
  const pkdir = path.join(cwd, ".pkvault");
  ensureRealDirectory(pkdir, { create: true });
  ensureRealDirectory(path.join(cwd, IDENTITIES), { create: true });
  // Arg validation (no shared repo state) can precede the lock.
  const key = agelib.decodeRecipient(recipient ?? "");
  if (!key) throw err("E_BAD_RECIPIENT", "init requires a valid age recipient string (from `pkvault setup`, later)");
  if (!LABEL_RE.test(label ?? "")) throw err("E_BAD_LABEL", "init requires --label matching [a-z0-9-]{1,32}");
  txn.validateRelPath(vault);
  assertNotReserved(vault, "--vault");
  const INIT_MARKER = ".pkvault/init-pending";
  const vaultAbs = txn.validateAncestors(cwd, vault);
  const configAbs = txn.validateAncestors(cwd, CONFIG);
  const manifestAbs = txn.validateAncestors(cwd, MANIFEST);
  const personalBlob = blobPath(home, label);
  const recipients = [{ label, recipient, key }];
  const fault = (step) => { if (faultAfter === step) throw err("E_SIMULATED_CRASH", step); };

  // #4: control-file .gitignore before the lock, so lock + markers are never
  // git-visible even on an immediate crash.
  txn.writeFileAtomic(cwd, ".pkvault/.gitignore", "txn\ntxn.tmp\nlock\ninit-pending\nlocal-init-pending\n", { mode: 0o644 });

  let froms = [], skippedLocal = [], template = [], overrides = [], portableBlobBytes = null, resuming = false;
  // #1/#2: EVERYTHING that reads shared state, decides, generates, and writes
  // happens under the lock — no check-then-act window with a concurrent init.
  const lock = txn.acquireLock(cwd, io.txnOpts);
  try {
    txn.assertRegularFileOrAbsent(configAbs);
    if (fs.existsSync(configAbs)) throw err("E_ALREADY_INITIALIZED", ".pkvault/config.toml exists");
    txn.assertRegularFileOrAbsent(vaultAbs);
    txn.assertRegularFileOrAbsent(manifestAbs);
    const marker = readPendingMarker(cwd, INIT_MARKER, "vault", ["label", "recipient"]); // untrusted

    // #1: a leftover vault matching the marker's recorded hash is PRESERVED (its
    // exact bytes — never regenerated). But resume MUST be the SAME identity: the
    // marker records the original label+recipient, the retry must match them, and
    // the preserved vault must actually be sealed to that recipient — otherwise a
    // retry with identity B would publish a manifest B cannot decrypt.
    let vaultBytes = null;
    if (fs.existsSync(vaultAbs)) {
      const existing = fs.readFileSync(vaultAbs);
      const hashOk = marker && marker.vault === vault && marker.vaultSha256 === sha256hex(existing);
      if (!hashOk) throw err("E_ALREADY_INITIALIZED", `${vault} already exists and is not a verified interrupted-init leftover; refusing to overwrite it`);
      if (marker.label !== label || marker.recipient !== recipient)
        throw err("E_RESUME_IDENTITY", `interrupted init used --label ${marker.label} / ${marker.recipient}; retry with the SAME identity, or remove ${vault} and .pkvault/init-pending to start over`);
      const vaultRecips = fmt.parseStructure(existing).recipients;
      if (vaultRecips.length !== 1 || vaultRecips[0].recipient !== recipient)
        throw err("E_RESUME_IDENTITY", `the interrupted vault is not sealed to ${recipient}; retry with the identity that created it`);
      vaultBytes = existing; resuming = true;
    }

    // Determine sources to PROTECT (gitignore + untrack) — done on both fresh and
    // resume paths. On resume the vault is preserved, so sources are NOT re-parsed.
    const fromList = Array.isArray(from) ? from : [from];
    const sourcePaths = new Map();
    for (const f of fromList) { const abs = txn.validateAncestors(cwd, f); txn.assertRegularFileOrAbsent(abs); sourcePaths.set(f, abs); }
    froms = fromList.filter((f) => fs.existsSync(sourcePaths.get(f)));
    froms = froms.filter((f) => {
      if (!/\.local$/.test(path.basename(f))) return true;
      if (io.interactive && io.confirm(`${f} looks like PERSONAL overrides (.local convention). Adopting shares its values with every vault recipient. Adopt anyway? [y/N] `)) return true;
      if (!io.interactive) { io.out(`WARNING: adopting ${f} (.local convention) — its values become TEAM-shared vault content.`); return true; }
      skippedLocal.push(f); return false;
    });

    if (!resuming) {
      const parsedFiles = froms.map((f) => {
        const items = []; let lineNo = 0;
        for (const line of readUtf8(sourcePaths.get(f), f).split("\n")) {
          lineNo++;
          if (line === "") items.push({ blank: true });
          else if (line.startsWith("#")) items.push({ comment: line });
          else {
            const eq = line.indexOf("=");
            if (eq === -1) items.push({ comment: `# pkvault-init: unparsed line preserved: ${line}` });
            else {
              const name = line.slice(0, eq);
              if (!NAME_RE.test(name)) throw err("E_BAD_NAME", `${f}:${lineNo}: invalid variable name ${JSON.stringify(name)}; expected [A-Za-z_][A-Za-z0-9_]*`);
              items.push({ name, value: line.slice(eq + 1) });
            }
          }
        }
        while (items.length && items.at(-1).blank) items.pop();
        return { file: f, items };
      });
      const winner = new Map();
      parsedFiles.forEach(({ file, items }) => items.forEach((it, idx) => {
        if (!it.name) return;
        const folded = it.name.toLowerCase();
        if (winner.has(folded)) overrides.push({ name: it.name, loser: winner.get(folded), winner: { file, idx } });
        winner.set(folded, { file, idx });
      }));
      for (const { file, items } of parsedFiles) {
        if (froms.length > 1) template.push({ comment: `# ── adopted from ${file} ──` });
        items.forEach((it, idx) => {
          if (it.name) { const w = winner.get(it.name.toLowerCase()); if (w.file === file && w.idx === idx) template.push({ ...it, source: file }); }
          else template.push(it);
        });
      }
      vaultBytes = fmt.create({ recipients, template });
    }

    if (fs.existsSync(personalBlob)) {
      const st = fs.lstatSync(personalBlob);
      if (!st.isFile() || st.isSymbolicLink()) throw err("E_IDENTITY_PARSE", `identity blob is not a regular file: ${personalBlob}`);
      portableBlobBytes = fs.readFileSync(personalBlob);
      unlocklib.verifyBlob(portableBlobBytes, { label, recipient });
    }

    // marker records THIS attempt's vault hash + identity (for the NEXT crash).
    txn.writeFileAtomic(cwd, INIT_MARKER, JSON.stringify({ v: 1, vault, vaultSha256: sha256hex(vaultBytes), label, recipient }) + "\n", { mode: 0o600 });
    fault("marker");

    // #2/#3 PROTECT PLAINTEXT: publish the .gitignore update (durable) BEFORE untracking.
    const toIgnore = [...froms, ...skippedLocal];
    if (toIgnore.length) {
      const giPath = txn.validateAncestors(cwd, ".gitignore");
      txn.assertRegularFileOrAbsent(giPath);
      let gi = fs.existsSync(giPath) ? readUtf8(giPath, ".gitignore") : "";
      for (const f of toIgnore) if (!gi.split("\n").includes(f)) { gi += (gi === "" || gi.endsWith("\n") ? "" : "\n") + `${f}\n`; io.out(`added ${f} to .gitignore`); }
      txn.writeFileAtomic(cwd, ".gitignore", gi, { mode: 0o644 });
      fault("gitignore");
      for (const f of toIgnore) untrackSource(cwd, f, io);
    }

    txn.writeFileAtomic(cwd, vault, vaultBytes, { mode: 0o600 }); // preserved bytes on resume
    fault("vault");
    txn.writeFileAtomic(cwd, MANIFEST, manifestlib.serializeManifest(recipients), { mode: 0o644 });
    fault("manifest");
    if (portableBlobBytes) txn.writeFileAtomic(cwd, `${IDENTITIES}/${label}.wrap`, portableBlobBytes, { mode: 0o644 });
    fault("blob");
    txn.writeFileAtomic(cwd, CONFIG, `vault = "${vault}"\n`, { mode: 0o644 }); // LAST — completion sentinel
    try { fs.unlinkSync(txn.validateAncestors(cwd, INIT_MARKER)); } catch {}
  } finally {
    lock.release();
  }

  if (resuming) io.out(`resumed an interrupted init — the existing vault was preserved exactly; source changes since then were NOT re-adopted (use \`pkvault set\`/\`edit\`).`);

  if (portableBlobBytes) io.out(`installed ${IDENTITIES}/${label}.wrap — clone + tap is portable`);
  else io.out(`WARNING: no wrapped identity blob found at ${personalBlob}; this looks like a machine identity, so clone + tap is unavailable.`);

  io.out(`initialized: ${vault} sealed to ${label} (${fingerprint(recipient)})`);
  if (resuming) {
    // vault preserved; sources were gitignored/untracked above but not re-parsed.
  } else if (froms.length === 0) {
    const asked = Array.isArray(from) ? from.join(", ") : from;
    io.out(`WARNING: no ${asked} found — the vault is EMPTY. If your env file lives elsewhere,`);
    io.out(`  undo with \`rm -rf .pkvault ${vault}\` and re-run with --from <path> --vault <path>.pkvault`);
  } else {
    const adopted = template.filter((t) => t.name);
    io.out(`adopted ${adopted.length} value(s) — ALL encrypted (use \`pkvault public NAME\` to opt out per value):`);
    for (const t of adopted) io.out(`  encrypted  ${t.name}${froms.length > 1 ? `  (${t.source})` : ""}`);
    for (const o of overrides)
      io.out(`  DUPLICATE: ${o.name} in ${o.loser.file} is shadowed by ${o.winner.file} (last wins, dotenv convention) — shadowed copy NOT in the vault`);
    const unparsed = template.filter((t) => t.comment?.startsWith("# pkvault-init: unparsed"));
    if (unparsed.length > 0) {
      io.out(`WARNING: ${unparsed.length} line(s) did not parse as NAME=value and were preserved as comments in the vault:`);
      for (const t of unparsed) io.out(`  ${t.comment.replace("# pkvault-init: unparsed line preserved: ", "  ")}`);
      io.out(`  fix them with \`pkvault set NAME\` if they were meant to be values.`);
    }

    for (const f of skippedLocal)
      io.out(`skipped ${f} — personal overrides stay OUT of the shared vault (gitignored above). Encrypt them privately: \`pkvault local-init --from ${f}\``);

    for (const f of froms) {
      const fAbs = path.join(cwd, f);
      // deletion: offered, never automatic — the vault is seconds old and some
      // tools (wrangler) read the file directly. Default No.
      const wantsDelete = io.interactive && io.confirm(`delete ${f} now? Verify decryption first (\`pkvault get\`). [y/N] `);
      if (wantsDelete) {
        fs.unlinkSync(fAbs);
        io.out(`deleted ${f} — the vault now holds the only copy`);
      } else {
        const BANNER = `# managed by pkvault — authoritative copy: ${vault}; edits here do NOT propagate (use \`pkvault set\`)`;
        const plain = readUtf8(fAbs, f);
        if (!plain.startsWith(BANNER)) txn.writeFileAtomic(cwd, f, `${BANNER}\n${plain}`, { mode: 0o600 });
        io.out(`kept ${f} (banner added). Verify with \`pkvault get\`, delete it when confident.`);
      }
      const log = spawnSync("git", ["log", "--oneline", "--", f], { cwd, encoding: "utf8" });
      if (log.status === 0 && log.stdout.trim() !== "")
        io.out(`WARNING: ${f} appears in git history (${log.stdout.trim().split("\n").length} commit(s)). Encrypting already-leaked values is theater — rotate them (PLAN §6).`);
    }
  }

  // discover-and-propose, never auto-adopt: sibling env files may belong in a
  // DIFFERENT vault (prod vs dev recipients — PLAN Phase 4), so we only point.
  const ENVISH = /^(\.env(\..+)?|\.dev\.vars(\..+)?)$/;
  const EXAMPLES = /\.(example|sample|template|dist)$/;
  const candidates = fs.readdirSync(cwd).filter(
    (f) => ENVISH.test(f) && !EXAMPLES.test(f) && !froms.includes(f) && f !== vault && !f.endsWith(".pkvault")
  );
  if (candidates.length > 0) {
    io.out("");
    io.out(`found but NOT adopted (likely plaintext secrets — pkvault never adopts what you didn't name):`);
    for (const f of candidates) io.out(`  ${f}`);
    io.out(`  include one: re-run init with --from, or keep separate vaults per environment (e.g. prod recipients ≠ dev)`);
  }

  io.out("");
  io.out("next steps:");
  io.out(`  pkvault run -- <your dev command>    # decrypted env, this child process only`);
  io.out(`  pkvault get <NAME>                   # verify a value decrypts`);
  io.out(`  pkvault status                       # what's sealed, to whom`);
  io.out(`  pkvault agent --label ${label}       # one tap per day instead of per command`);
  io.out(`  pkvault add <label> <recipient> --identity <label.wrap>  # onboard a teammate`);
  io.out(`hint: package.json → "dev": "pkvault run -- <cmd>" makes it invisible day-to-day`);
  io.out(`commit ${vault} and .pkvault/ — that IS the point.`);
}

// personal layer helpers: cfg.local is an OPTIONAL second vault — gitignored,
// sealed to one person, merged OVER the team vault at read time.
const hasLocal = (cfg) => cfg.local && fs.existsSync(txn.validateAncestors(cfg.root, cfg.local));
const loadLocal = (cfg) => readRepoFile(cfg.root, cfg.local);

function get({ cwd, name, env }) {
  const cfg = loadConfig(cwd);
  recoverIfPending(cfg);
  const scalar = resolveIdentity(env);
  if (hasLocal(cfg)) {
    // a personal layer this identity can't unseal is someone else's — ignore it
    try { return fmt.get(loadLocal(cfg), scalar, name); } catch (e) { if (e.code !== "E_NO_SUCH_NAME" && e.code !== "E_UNSEAL") throw e; }
  }
  return fmt.get(loadVault(cfg.root, cfg), scalar, name);
}

const structuralNames = (bytes) =>
  new Set(fmt.parseStructure(bytes).entries.filter((e) => e.name).map((e) => e.name.toLowerCase()));

// local: true/false = explicit (--local/--team), null = decide.
// Decision order: existing home wins (updates never prompt) → new name with a
// personal layer present prompts (interactive only; the absent-minded
// personal-token-into-committed-team-vault mistake must not be silent) → team.
function set({ cwd, io, name, valueBuf, env, local = null }) {
  const cfg = loadConfig(cwd);
  if (local === null) {
    const inLocal = hasLocal(cfg) && structuralNames(loadLocal(cfg)).has(name.toLowerCase());
    const inTeam = structuralNames(loadVault(cfg.root, cfg)).has(name.toLowerCase());
    if (inLocal) local = true;
    else if (inTeam) local = false;
    else if (hasLocal(cfg) && io.interactive)
      local = io.confirm(`${name} is new — PERSONAL (only you, never committed)? Team vault is the default. [y/N] `);
    else local = false;
  }
  if (local && !hasLocal(cfg)) throw err("E_NO_LOCAL", "no personal layer — run `pkvault local-init` first");
  withLock(cfg, io.txnOpts, () => {
    const bytes = local ? loadLocal(cfg) : loadVault(cfg.root, cfg);
    const out = editorlib.setValue(bytes, resolveIdentity(env), name, valueBuf);
    writeVaultAtomic(cfg.root, { ...cfg, vault: local ? cfg.local : cfg.vault }, out);
  });
  io.out(`set ${name}${local ? " (personal layer — never committed)" : " (team vault)"}`);
}

// $EDITOR flow (SPEC §9). editBuffer(text)→newText is injected so the I/O
// (tempdir hygiene, editor spawn) lives in bin.js and this stays testable.
function edit({ cwd, io, env, local = false, editBuffer }) {
  const cfg = loadConfig(cwd);
  if (local && !hasLocal(cfg)) throw err("E_NO_LOCAL", "no personal layer — run `pkvault local-init` first");
  let changed = false;
  withLock(cfg, io.txnOpts, () => {
    const scalar = resolveIdentity(env);
    const bytes = local ? loadLocal(cfg) : loadVault(cfg.root, cfg);
    const { text } = editorlib.render(bytes, scalar);
    const edited = editBuffer(text);
    if (edited == null || edited === text) return;
    const out = editorlib.save(bytes, scalar, edited, {
      confirmDeletions: (names) =>
        io.interactive && io.confirm(`delete ${names.join(", ")} from the vault? [y/N] `),
    });
    writeVaultAtomic(cfg.root, { ...cfg, vault: local ? cfg.local : cfg.vault }, out);
    changed = true;
  });
  io.out(changed ? `saved${local ? " (personal layer)" : ""}` : "no changes");
}

// create the personal layer: a vault sealed to the CURRENT identity only,
// gitignored, never committed — encrypted at rest, merged over team at run.
function localInit({ cwd, io, from = null, env, localVault = ".env.local.pkvault", faultAfter = null }) {
  const cfg0 = loadConfig(cwd);
  assertNotReserved(localVault, "personal vault");
  if (norm(localVault) === norm(cfg0.vault)) throw err("E_PATH_RESERVED", "personal vault must differ from the team vault");
  const LOCAL_MARKER = ".pkvault/local-init-pending";
  const scalar = resolveIdentity(env);
  const recipient = agelib.encodeRecipient(agelib.publicFromScalar(scalar));
  const recipients = [{ label: "me", recipient, key: agelib.decodeRecipient(recipient) }];
  const lfault = (step) => { if (faultAfter === step) throw err("E_SIMULATED_CRASH", step); };
  // #4: control-file .gitignore before the lock/markers.
  txn.writeFileAtomic(cfg0.root, ".pkvault/.gitignore", "txn\ntxn.tmp\nlock\ninit-pending\nlocal-init-pending\n", { mode: 0o644 });

  let template = [], resuming = false;
  // #1/#2: state checks, generation, and writes all UNDER the lock.
  withLock(cfg0, io.txnOpts, () => {
    const cfg = loadConfig(cfg0.root); // re-read config under the lock (no TOCTOU)
    if (cfg.local) throw err("E_ALREADY_INITIALIZED", `personal layer already configured (${cfg.local})`);
    const localAbs = txn.validateAncestors(cfg.root, localVault);
    txn.assertRegularFileOrAbsent(localAbs);
    const lmarker = readPendingMarker(cfg.root, LOCAL_MARKER, "localVault", ["recipient"]); // untrusted

    // #1: preserve a verified leftover personal vault; refuse anything else — and
    // resume only under the SAME identity (the marker records its recipient and
    // the preserved vault must be sealed to the current one).
    let localBytes = null;
    if (fs.existsSync(localAbs)) {
      const existing = fs.readFileSync(localAbs);
      const hashOk = lmarker && lmarker.localVault === localVault && lmarker.localVaultSha256 === sha256hex(existing);
      if (!hashOk) throw err("E_ALREADY_INITIALIZED", `${localVault} already exists and is not a verified interrupted-local-init leftover; refusing to overwrite it`);
      if (lmarker.recipient !== recipient) throw err("E_RESUME_IDENTITY", `the interrupted local-init used a different identity; retry with the same one, or remove ${localVault} and .pkvault/local-init-pending`);
      const vaultRecips = fmt.parseStructure(existing).recipients;
      if (vaultRecips.length !== 1 || vaultRecips[0].recipient !== recipient)
        throw err("E_RESUME_IDENTITY", `the interrupted personal vault is not sealed to your current identity; retry with the identity that created it`);
      localBytes = existing; resuming = true;
    }

    if (!resuming) {
      if (from) {
        const fromAbs = txn.validateAncestors(cfg.root, from);
        txn.assertRegularFileOrAbsent(fromAbs);
        let lineNo = 0;
        for (const line of readUtf8(fromAbs, from).split("\n")) {
          lineNo++;
          if (line === "") template.push({ blank: true });
          else if (line.startsWith("#")) { if (!line.includes("managed by pkvault")) template.push({ comment: line }); }
          else {
            const eq = line.indexOf("=");
            if (eq !== -1) {
              const name = line.slice(0, eq);
              if (!NAME_RE.test(name)) throw err("E_BAD_NAME", `${from}:${lineNo}: invalid variable name ${JSON.stringify(name)}; expected [A-Za-z_][A-Za-z0-9_]*`);
              template.push({ name, value: line.slice(eq + 1) });
            }
          }
        }
        while (template.length && template.at(-1).blank) template.pop();
      }
      localBytes = fmt.create({ recipients, template });
    }

    txn.writeFileAtomic(cfg.root, LOCAL_MARKER, JSON.stringify({ v: 1, localVault, localVaultSha256: sha256hex(localBytes), recipient }) + "\n", { mode: 0o600 });
    lfault("marker");
    const toIgnore = [localVault, ...(from ? [from] : [])];
    const giPath = txn.validateAncestors(cfg.root, ".gitignore");
    txn.assertRegularFileOrAbsent(giPath);
    let gi = fs.existsSync(giPath) ? readUtf8(giPath, ".gitignore") : "";
    for (const f of toIgnore) if (!gi.split("\n").includes(f)) gi += (gi === "" || gi.endsWith("\n") ? "" : "\n") + `${f}\n`;
    txn.writeFileAtomic(cfg.root, ".gitignore", gi, { mode: 0o644 }); // durable BEFORE untrack (#3)
    lfault("gitignore");
    if (from) untrackSource(cfg.root, from, io);
    txn.writeFileAtomic(cfg.root, localVault, localBytes, { mode: 0o600 }); // preserved on resume
    lfault("vault");
    txn.writeFileAtomic(cfg.root, CONFIG, `local = "${localVault}"\nvault = "${cfg.vault}"\n`, { mode: 0o644 }); // LAST
    try { fs.unlinkSync(txn.validateAncestors(cfg.root, LOCAL_MARKER)); } catch {}
  });
  if (resuming) { io.out(`resumed an interrupted local-init — the existing personal vault was preserved exactly.`); return; }
  if (from) {
    const log = spawnSync("git", ["log", "--oneline", "--", from], { cwd: cfg0.root, encoding: "utf8" });
    if (log.status === 0 && log.stdout.trim() !== "")
      io.out(`WARNING: ${from} appears in git history (${log.stdout.trim().split("\n").length} commit(s)) — encrypting it now does not remove the plaintext already committed; rotate those values.`);
  }

  io.out(`personal layer: ${localVault} — sealed to YOU ONLY (${fingerprint(recipient)}), gitignored, never committed`);
  io.out(`  encrypted at rest like everything else; overrides the team vault in \`pkvault run\``);
  if (from) {
    const adopted = template.filter((t) => t.name);
    io.out(`  adopted ${adopted.length} value(s) from ${from}:`);
    for (const t of adopted) io.out(`    encrypted  ${t.name}`);
    io.out(`  ${from} is still plaintext — delete it once \`pkvault get\` verifies (personal layer has no team to check with).`);
  }
  io.out(`  write to it: pkvault set --local NAME`);
}

function run({ cwd, env, argv }) {
  const cfg = loadConfig(cwd);
  recoverIfPending(cfg);
  const scalar = resolveIdentity(env);
  const vaultEnv = fmt.runEnv(loadVault(cfg.root, cfg), scalar);
  let localEnv = {};
  if (hasLocal(cfg)) {
    try { localEnv = fmt.runEnv(loadLocal(cfg), scalar); } catch (e) { if (e.code !== "E_UNSEAL") throw e; }
  }
  // the child runs where the user is; personal layer wins over team (dotenv semantics)
  const r = spawnSync(argv[0], argv.slice(1), { cwd, env: { ...process.env, ...vaultEnv, ...localEnv }, stdio: "inherit" });
  return r.status ?? 1;
}

function classify({ cwd, io, name, to, env }) {
  const cfg = loadConfig(cwd);
  if (to === "public") {
    if (!io.interactive) throw err("E_GUARD_NONINTERACTIVE", "declassification requires interactive confirmation");
    if (!io.confirm(`declassify ${name}? its value will be committed in PLAINTEXT forever after. [y/N] `))
      throw err("E_GUARD_DECLINED", "declassification not confirmed");
  }
  withLock(cfg, io.txnOpts, () => {
    const out = editorlib.classify(loadVault(cfg.root, cfg), resolveIdentity(env), name, to);
    writeVaultAtomic(cfg.root, cfg, out);
  });
  io.out(`${name} is now ${to}`);
}

// reverse the adoption: plaintext OUT of the vault. stdout by default; a file
// only behind the plan's honesty flag (PLAN §5 non-features).
function exportPlain({ cwd, io, env, to = null, iWantPlaintextOnDisk = false }) {
  const cfg = loadConfig(cwd);
  recoverIfPending(cfg, io.txnOpts);
  const { parsed, values } = fmt.open(loadVault(cfg.root, cfg), resolveIdentity(env));
  const multiline = [...values.entries()].filter(([, v]) => typeof v === "string" && /[\r\n]/.test(v)).map(([k]) => k);
  if (multiline.length > 0)
    throw err("E_EXPORT_MULTILINE", `dotenv lines cannot represent multiline values: ${multiline.join(", ")} — fetch those with \`pkvault get NAME\``);
  const lines = [];
  for (const e of parsed.entries) {
    if (e.type === "blank") lines.push("");
    else if (e.type === "comment") { if (!e.line.startsWith("# pkvault-init:")) lines.push(e.line); }
    else lines.push(`${e.name}=${values.get(e.name)}`);
  }
  const text = lines.join("\n") + "\n";
  if (!to) return io.out(text.trimEnd());
  if (!iWantPlaintextOnDisk)
    throw err("E_EXPORT_GATED", "writing plaintext to disk requires --i-want-plaintext-on-disk (stdout needs no flag)");
  // #4: even with the flag, never overwrite the authenticated vault, the
  // personal vault, or any control file with plaintext.
  assertNotReserved(to, "export --to");
  if (norm(to) === norm(cfg.vault)) throw err("E_PATH_RESERVED", `export --to must not be the team vault (${cfg.vault})`);
  if (cfg.local && norm(to) === norm(cfg.local)) throw err("E_PATH_RESERVED", `export --to must not be the personal vault (${cfg.local})`);
  txn.writeFileAtomic(cfg.root, to, text, { mode: 0o600 });
  io.out(`wrote PLAINTEXT to ${to} (mode 0600). It is on disk now — that was the point of the flag.`);
}

function identityBlobForAdd({ cwd, cfg, label, recipient, identityBlob, home, allowMissingIdentityBlob }) {
  const repoRel = `${IDENTITIES}/${label}.wrap`;
  const repoAbs = txn.validateAncestors(cfg.root, repoRel);
  let source = null;
  if (identityBlob) source = path.resolve(cwd, identityBlob);
  else if (fs.existsSync(repoAbs)) source = repoAbs;
  else {
    const personal = blobPath(home, label);
    if (fs.existsSync(personal)) source = personal;
  }
  if (!source) {
    if (allowMissingIdentityBlob) return { repoRel, bytes: null };
    throw err(
      "E_IDENTITY_BLOB_REQUIRED",
      `adding a passkey identity requires its safe wrapped blob: pkvault add ${label} ${recipient} --identity <${label}.wrap> (machine identities may explicitly use --without-identity-blob)`,
    );
  }
  const st = fs.lstatSync(source);
  if (!st.isFile() || st.isSymbolicLink()) throw err("E_IDENTITY_PARSE", `identity blob is not a regular file: ${source}`);
  const bytes = fs.readFileSync(source);
  unlocklib.verifyBlob(bytes, { label, recipient });
  if (fs.existsSync(repoAbs) && !fs.readFileSync(repoAbs).equals(bytes))
    throw err("E_IDENTITY_PARSE", `${repoRel} already exists with different bytes`);
  return { repoRel, bytes };
}

function add({
  cwd, io, label, recipient, env, identityBlob = null,
  allowMissingIdentityBlob = false, home = defaultHome(),
}) {
  if (!LABEL_RE.test(label ?? "")) throw err("E_BAD_LABEL", "add requires a label matching [a-z0-9-]{1,32}");
  const cfg = loadConfig(cwd);
  const key = agelib.decodeRecipient(recipient ?? "");
  if (!key) throw err("E_BAD_RECIPIENT", "not a valid age recipient string");
  const portable = identityBlobForAdd({ cwd, cfg, label, recipient, identityBlob, home, allowMissingIdentityBlob });
  withLock(cfg, io.txnOpts, () => {
    const scalar = resolveIdentity(env);
    const vault = loadVault(cfg.root, cfg);
    const { parsed } = fmt.open(vault, scalar, { decrypt: false });
    const manifest = loadManifest(cfg.root);
    if (manifest.some((r) => r.label === label)) throw err("E_BAD_LABEL", `label ${label} already exists`);
    if (manifest.some((r) => r.key.equals(key))) throw err("E_BAD_RECIPIENT", "that key is already a recipient under another label");
    const next = [...manifest, { label, recipient, key }];
    guardRecipients(io, parsed.recipients, next);
    const sealed = fmt.reseal(vault, scalar, next);
    // Install first. If the process crashes before the two-file recipient
    // transaction, the result is only a harmless orphan; rerunning add can use it.
    if (portable.bytes && !fs.existsSync(path.join(cfg.root, portable.repoRel)))
      txn.writeFileAtomic(cfg.root, portable.repoRel, portable.bytes, { mode: 0o644 });
    txn.commitTxn(cfg.root, [
      { target: cfg.vault, bytes: sealed },
      { target: MANIFEST, bytes: manifestlib.serializeManifest(next) },
    ], io.txnOpts);
  });
  io.out(`added ${label} (${fingerprint(recipient)}) — reseal complete; commit the vault, manifest${portable.bytes ? ", and identity blob" : ""}`);
}

function remove({ cwd, io, label, acceptExposure = false, env, date }) {
  const cfg = loadConfig(cwd);
  withLock(cfg, io.txnOpts, () => {
    const scalar = resolveIdentity(env);
    const vault = loadVault(cfg.root, cfg);
    const opened = fmt.open(vault, scalar);
    const manifest = loadManifest(cfg.root);
    const target = manifest.find((r) => r.label === label);
    if (!target) throw err("E_BAD_LABEL", `no recipient labeled ${label}`);
    const next = manifest.filter((r) => r !== target);
    if (next.length === 0) throw err("E_BAD_LABEL", "cannot remove the last recipient");
    guardRecipients(io, opened.parsed.recipients, next);
    let rotated = fmt.rotate(vault, scalar, next);
    if (acceptExposure) {
      const p = fmt.parseStructure(rotated);
      const marker = `# pkvault: accepted-exposure ${label} on ${date} UTC`;
      rotated = fmt.serialize({
        fileId: p.fileId,
        fk: fmt.open(rotated, scalar, { decrypt: false }).fk,
        recipients: p.recipients,
        preamble: [...p.preamble, marker].sort(),
        entries: p.entries,
      });
    }
    txn.commitTxn(cfg.root, [
      { target: cfg.vault, bytes: rotated },
      { target: MANIFEST, bytes: manifestlib.serializeManifest(next) },
    ], io.txnOpts);
    txn.removeFileDurable(cfg.root, `${IDENTITIES}/${label}.wrap`);
    const names = [...opened.values.keys()];
    io.out(`removed ${label}: file key rotated; ${label} cannot read FUTURE changes.`);
    if (acceptExposure) io.out(`--accept-exposure recorded in the vault preamble.`);
    else {
      io.out(`ROTATION CHECKLIST — ${label} has SEEN these values; rotate them at their providers:`);
      for (const n of names) io.out(`  [ ] ${n}`);
    }
  });
}

function status({ cwd, io, env }) {
  const cfg = loadConfig(cwd);
  // SPEC §8.3: manifest and vault MUST be captured as ONE snapshot while holding
  // the lock — otherwise a check-then-read race lets a writer publish a
  // transaction between our marker check and our reads, yielding a torn
  // (old-manifest/new-vault) report. Always lock, recover, read both, release.
  // Crypto reporting then runs on the captured bytes (identity ceremony, which
  // can be slow, happens AFTER the lock is dropped).
  const recovered = fs.existsSync(path.join(cfg.root, ".pkvault", "txn")); // before the lock recovers it
  let manifestBytes, vaultBytes;
  withLock(cfg, io.txnOpts, () => {
    // withLock ran recovery before this body; read both files as ONE snapshot,
    // through readRepoFile so a symlinked target (pointing outside the repo) is
    // rejected — validateAncestors alone checks only the parent directories.
    manifestBytes = readRepoFile(cfg.root, MANIFEST);
    vaultBytes = loadVault(cfg.root, cfg);
  });
  if (recovered) io.out("recovered a pending transaction before reading");

  const manifest = manifestlib.parseManifest(manifestBytes);
  io.out(`vault: ${cfg.vault}`);
  if (cfg.local) io.out(`personal layer: ${cfg.local}${hasLocal(cfg) ? "" : " (configured but MISSING on this machine)"} — gitignored, overrides team values in \`run\``);
  io.out(`recipients (${manifest.length}):`);
  for (const r of manifest) io.out(`  ${r.label}  ${fingerprint(r.recipient)}  ${r.recipient}`);
  // per-name classification is structural — visible with no identity, no ceremony
  const structural = fmt.parseStructure(vaultBytes);
  io.out(`values:`);
  for (const e of structural.entries) {
    if (e.type === "secret") io.out(`  encrypted  ${e.name}`);
    if (e.type === "public") io.out(`  PUBLIC     ${e.name} = ${e.value}`);
  }
  try {
    const { parsed } = fmt.open(vaultBytes, resolveIdentity(env), { decrypt: false });
    const future = parsed.entries.filter((e) => e.type === "secret" && e.tok.v !== 1);
    io.out(`integrity: MAC verified; ${parsed.entries.filter((e) => e.type === "secret").length} secret(s), ${parsed.entries.filter((e) => e.type === "public").length} public`);
    for (const e of future) io.out(`WARNING: ${e.name} uses value version ${e.tok.v} — upgrade pkvault to edit this file`);
  } catch (e) {
    io.out(`integrity: NOT VERIFIED (${e.code}: no identity available or verification failed)`);
  }
}

const unlockForce = ({ cwd, io }) => {
  const root = findRoot(cwd);
  txn.forceUnlock(root);
  io.out("lock removed");
};

// --- setup / recover (ceremony-backed, PLAN §4.1 + SPEC-IDENTITY) --------------------
const defaultHome = () => process.env.PKVAULT_HOME ?? path.join(os.homedir(), ".config/pkvault");
const blobPath = (home, label) => path.join(home, `${label}.wrap`);

// --- default label: `--label` optional once the tool can know who you are ------
const defaultLabelPath = (home) => path.join(home, "default-label");
function readDefaultLabel(home) {
  try {
    const l = fs.readFileSync(defaultLabelPath(home), "utf8").trim();
    return LABEL_RE.test(l) ? l : null;
  } catch { return null; }
}
function labelOrDefault(home, label) {
  if (label) {
    if (!LABEL_RE.test(label)) throw err("E_BAD_LABEL", `label must match [a-z0-9-]{1,32}`);
    return label;
  }
  const d = readDefaultLabel(home);
  if (!d) throw err("E_BAD_LABEL", "no --label given and no default saved — pass --label, or set one: `pkvault default <label>`");
  return d;
}
function setDefaultLabel({ io, label, home = defaultHome() }) {
  if (!LABEL_RE.test(label ?? "")) throw err("E_BAD_LABEL", "default requires a label matching [a-z0-9-]{1,32}");
  if (!fs.existsSync(blobPath(home, label))) throw err("E_NO_IDENTITY", `no passkey identity blob at ${blobPath(home, label)} — the default label targets passkey identities from \`pkvault setup\`; machine/CI identities use PKVAULT_IDENTITY and need no default`);
  ensureRealDirectory(home, { create: true });
  txn.writeFileAtomic(home, "default-label", `${label}\n`, { mode: 0o600 });
  io.out(`default label: ${label}`);
}

// default RP for NEW credentials only — every wrap permanently stores the RP it
// was created under, and unlock always follows the stored value (gate 1: the
// choice is per-identity and permanent; this just picks the default for next time).
const HOSTED_RP = "unlock.pkvault.dev";
function readDefaultRpId(home) {
  try {
    const v = fs.readFileSync(path.join(home, "default-rp-id"), "utf8").trim();
    return v || null;
  } catch { return null; }
}
function rpIdOrDefault(home, rpId) {
  const chosen = rpId ?? readDefaultRpId(home) ?? HOSTED_RP;
  bridge.ceremonyOriginForRpId(chosen); // validates shape (throws E_BRIDGE_USAGE)
  return chosen;
}
function setDefaultRpId({ io, rpId, home = defaultHome() }) {
  bridge.ceremonyOriginForRpId(rpId ?? "");
  ensureRealDirectory(home, { create: true });
  txn.writeFileAtomic(home, "default-rp-id", `${rpId}\n`, { mode: 0o600 });
  io.out(`default rp-id for new credentials: ${rpId}${rpId === "localhost" ? " (self-hosted: the CLI serves the ceremony page itself)" : ` (hosted page at https://${rpId})`}`);
}

function ceremonySettings(rpId, bridgeOpts) {
  const ceremonyOrigin = bridgeOpts.ceremonyOrigin ?? bridge.ceremonyOriginForRpId(rpId);
  const expectedRpId = ceremonyOrigin === "local" ? "localhost" : new URL(ceremonyOrigin).hostname;
  return { ceremonyOrigin, expectedRpId };
}

async function setup({ io, label, home = defaultHome(), rpId = null, bridgeOpts = {} }) {
  if (!LABEL_RE.test(label ?? "")) throw err("E_BAD_LABEL", "setup requires --label matching [a-z0-9-]{1,32}");
  rpId = rpIdOrDefault(home, rpId);
  ensureRealDirectory(home, { create: true });
  if (fs.existsSync(blobPath(home, label))) throw err("E_ALREADY_SETUP", `${blobPath(home, label)} exists — one identity per label`);
  const prfSalt = crypto.randomBytes(32);
  const { ceremonyOrigin, expectedRpId } = ceremonySettings(rpId, bridgeOpts);
  io.out("opening the ceremony page — one biometric confirmation…");
  const res = await bridge.startCeremony({ op: "setup", prfSalt, ...bridgeOpts, ceremonyOrigin });
  if (res.rpId !== expectedRpId) throw err("E_IDENTITY_KEK", `ceremony used RP ${res.rpId}; expected ${expectedRpId}`);

  const { scalar, recipient } = idn.mintIdentity();
  const pub = agelib.decodeRecipient(recipient);
  const prfWrap = idn.makePrfWrap({ scalar, pub, credentialId: res.credentialId, rpId: res.rpId, prfOutput: res.prfOutput, prfSalt });
  const { code, wrap: recoveryWrap } = idn.makeRecoveryWrap({ scalar, pub });
  txn.writeFileAtomic(home, `${label}.wrap`, idn.serializeBlob({ label, recipient, wraps: [prfWrap, recoveryWrap] }), { mode: 0o600 });

  io.out("");
  io.out(`identity created for ${label} (passkey RP: ${res.rpId})`);
  io.out(`  recipient (public, share freely):`);
  io.out(`    ${recipient}`);
  io.out(`  fingerprint: ${fingerprint(recipient)}`);
  io.out("");
  io.out(`  RECOVERY CODE — shown ONCE, never stored. Print it, keep it somewhere safe:`);
  io.out(`    ${code}`);
  io.out(`    This is PERMANENT recovery escrow — treat it like a root key. Anyone with`);
  io.out(`    it AND a copy of your committed identity blob can recover this identity. It`);
  io.out(`    cannot be revoked; to truly rotate, run \`pkvault setup\` for a new identity`);
  io.out(`    and get re-added to your vaults.`);
  io.out("");
  io.out(`  wrapped identity blob (safe to share; required for clone + tap):`);
  io.out(`    ${blobPath(home, label)}`);
  io.out(`teammates add you with: pkvault add ${label} ${recipient} --identity ${label}.wrap`);

  // first identity ever → becomes the default; NEVER steals an existing setup's
  // spot (a later test/hosted identity must not silently become "you")
  const otherBlobs = fs.readdirSync(home).filter((f) => f.endsWith(".wrap") && f !== `${label}.wrap`);
  if (!readDefaultLabel(home) && otherBlobs.length === 0) {
    txn.writeFileAtomic(home, "default-label", `${label}\n`, { mode: 0o600 });
    io.out(`saved as your default label — \`--label\` is now optional for agent/recover`);
  } else if (!readDefaultLabel(home)) {
    io.out(`multiple identities exist; set a default with \`pkvault default <label>\``);
  }
  return { recipient };
}

async function recover({ io, label, code, cwd = null, home = defaultHome(), rpId = null, bridgeOpts = {} }) {
  label = labelOrDefault(home, label);
  rpId = rpIdOrDefault(home, rpId);
  let repoRoot = null;
  if (cwd) {
    try { repoRoot = findRoot(cwd); } catch (e) { if (e.code !== "E_NOT_INITIALIZED") throw e; }
  }
  const loaded = unlocklib.loadBlob({ label, home, repoRoot });
  const blob = loaded.blob;
  const originalBlobBytes = fs.readFileSync(loaded.path); // for compare-and-swap after the ceremony
  const prfSalt = crypto.randomBytes(32);
  const { ceremonyOrigin, expectedRpId } = ceremonySettings(rpId, bridgeOpts);
  io.out("recovery re-wraps under a NEW passkey — create one in the ceremony page…");
  const res = await bridge.startCeremony({ op: "setup", prfSalt, ...bridgeOpts, ceremonyOrigin });
  if (res.rpId !== expectedRpId) throw err("E_IDENTITY_KEK", `ceremony used RP ${res.rpId}; expected ${expectedRpId}`);
  const { blob: newBytes } = idn.recoverAndRewrap(blob, code, {
    credentialId: res.credentialId, rpId: res.rpId, prfOutput: res.prfOutput, prfSalt,
  });
  if (repoRoot && loaded.path.startsWith(repoRoot + path.sep)) {
    const rel = path.relative(repoRoot, loaded.path).split(path.sep).join("/");
    // #6 compare-and-swap under the repo lock: recover any pending txn, then
    // verify the on-disk blob is byte-identical to what we loaded before the
    // ceremony. A concurrent remove/re-add/second-recovery would have changed
    // it — refuse rather than overwrite a newer wrap or restore an orphan.
    const repoCfg = loadConfig(repoRoot);
    withLock(repoCfg, {}, () => {
      let current;
      try { current = fs.readFileSync(txn.validateAncestors(repoRoot, rel)); } catch { current = null; }
      if (!current || !current.equals(originalBlobBytes))
        throw err("E_IDENTITY_CONFLICT", `${rel} changed during recovery (concurrent remove/re-add/recovery); re-run \`pkvault recover\``);
      // #4: the manifest must STILL map this label to this identity. A concurrent
      // recipient removal/replacement during the ceremony would leave the blob
      // byte-identical but the manifest pointing elsewhere — refuse to publish an
      // orphaned or superseded identity.
      const entry = loadManifest(repoRoot).find((r) => r.label === blob.label);
      if (!entry || entry.recipient !== blob.recipient)
        throw err("E_IDENTITY_CONFLICT", `manifest no longer maps ${blob.label} to this identity (concurrent remove/replace); resolve, then re-run \`pkvault recover\``);
      txn.writeFileAtomic(repoRoot, rel, newBytes, { mode: 0o644 });
    });
  } else {
    txn.writeFileAtomic(home, `${label}.wrap`, newBytes, { mode: 0o600 });
  }
  // Keep this machine's personal cache synchronized when recovery was driven
  // from a committed repository copy.
  const personal = blobPath(home, label);
  if (loaded.path !== personal && fs.existsSync(personal)) {
    unlocklib.verifyBlob(fs.readFileSync(personal), { label, recipient: blob.recipient });
    txn.writeFileAtomic(home, `${label}.wrap`, newBytes, { mode: 0o600 });
  }
  io.out("");
  io.out(`identity recovered and re-wrapped under your new passkey.`);
  io.out(`  Your recovery code is UNCHANGED and still valid — it is permanent escrow, not`);
  io.out(`  a one-time token. Retained copies of the old blob (git history, clones) remain`);
  io.out(`  recoverable with it; if it may be compromised, rotate: \`pkvault setup\` for a`);
  io.out(`  new identity and get re-added to your vaults.`);
}

// One ceremony → unwrapped scalar (the agent caches this; direct use is per-command).
async function ceremonyUnlock({ label, cwd = null, home = defaultHome(), bridgeOpts = {} }) {
  let repoRoot = null;
  if (cwd) {
    try { repoRoot = findRoot(cwd); } catch (e) { if (e.code !== "E_NOT_INITIALIZED") throw e; }
  }
  const r = await unlocklib.ceremonyUnlock({ label, home, repoRoot, bridgeOpts });
  return r.scalar;
}

module.exports = {
  CliError, findRoot, init, get, set, run, classify, add, remove, status,
  exportPlain, localInit, unlockForce, fingerprint, resolveIdentity,
  setup, recover, ceremonyUnlock, labelOrDefault, setDefaultLabel, readDefaultLabel,
  setDefaultRpId, readDefaultRpId, rpIdOrDefault, edit,
};
