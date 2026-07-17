#!/usr/bin/env node
"use strict";
// Executable wrapper: argv dispatch + TTY io. All logic lives in src/cli.js.
const fs = require("node:fs");
const cli = require("./cli");

// Blocking line read from the controlling terminal. fs.readSync(0) is a trap:
// Node sets TTY stdin non-blocking on macOS, so it throws EAGAIN and a naive
// catch turns every prompt into instant-default (real dogfood bug). /dev/tty
// opens in blocking mode and always means the human, even under redirection.
function readLineTty() {
  let fd = 0, opened = false;
  try { fd = fs.openSync("/dev/tty", "rs"); opened = true; } catch {}
  const buf = Buffer.alloc(1);
  let line = "";
  try {
    for (;;) {
      let n = 0;
      try { n = fs.readSync(fd, buf, 0, 1); } catch (e) {
        if (e.code === "EAGAIN") continue; // non-blocking fd-0 fallback: spin until bytes
        throw e;
      }
      if (n === 0) break;
      const c = buf.toString();
      if (c === "\n") break;
      if (c !== "\r") line += c;
    }
  } finally {
    if (opened) fs.closeSync(fd);
  }
  return line.trim();
}

function makeIo() {
  const interactive = process.stdin.isTTY === true && process.stdout.isTTY === true;
  return {
    out: (s) => process.stdout.write(s + "\n"),
    interactive,
    confirm: (msg) => {
      process.stdout.write(msg);
      return /^y(es)?$/i.test(readLineTty());
    },
    txnOpts: {},
  };
}

function flag(args, name) {
  const i = args.indexOf(name);
  if (i === -1) return null;
  args.splice(i, 1);
  if (args.includes(name)) throw new cli.CliError("E_USAGE", `duplicate flag ${name}`);
  return true;
}
function opt(args, name) {
  const i = args.indexOf(name);
  if (i === -1) return null;
  if (i + 1 >= args.length) throw new cli.CliError("E_USAGE", `${name} requires a value`);
  const v = args[i + 1];
  args.splice(i, 2);
  if (args.includes(name)) throw new cli.CliError("E_USAGE", `duplicate option ${name}`);
  return v;
}
function optAll(args, name) {
  const out = [];
  for (let i = args.indexOf(name); i !== -1; i = args.indexOf(name)) {
    if (i + 1 >= args.length) throw new cli.CliError("E_USAGE", `${name} requires a value`);
    out.push(args[i + 1]);
    args.splice(i, 2);
  }
  return out;
}
// Fail closed after known flags/opts are consumed: reject any leftover dash token
// (unknown/misspelled/duplicate/conflicting flag) AND require exactly `n`
// positional arguments. In a secrets tool, extra or missing args must ERROR.
function end(args, n) {
  const badFlag = args.find((a) => a.startsWith("-") && a !== "-");
  if (badFlag) throw new cli.CliError("E_USAGE", `unknown, misspelled, duplicate, or conflicting flag: ${badFlag}`);
  if (args.length !== n) throw new cli.CliError("E_USAGE", `expected ${n} argument(s), got ${args.length}${args.length ? `: ${args.join(" ")}` : ""}`);
}
const today = () => new Date().toISOString().slice(0, 10);


function promptLine(msg) {
  process.stdout.write(msg);
  return readLineTty();
}

// Best-effort shred: overwrite a regular file with zeros, then unlink. NOT
// guaranteed on SSDs / copy-on-write / snapshotting filesystems (README §9.1).
function shredFile(abs) {
  try {
    const st = fs.lstatSync(abs);
    if (st.isFile() && !st.isSymbolicLink()) {
      const wf = fs.openSync(abs, "r+");
      try { fs.writeSync(wf, Buffer.alloc(st.size, 0)); fs.fsyncSync(wf); } finally { fs.closeSync(wf); }
    }
  } catch {}
  try { fs.unlinkSync(abs); } catch {}
}

// A live process's PID is skipped; only a dead creator's dir is stale.
// EPERM = exists (not ours) → alive; ESRCH → dead.
function pidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; } catch (e) { return e.code === "EPERM"; }
}

// SPEC §9.1 next-invocation cleanup: a crash/kill/power-loss leaves the plaintext
// buffer behind. On the next edit, shred each pkvault-owned edit dir — but ONLY
// when its creator process is provably dead. Every dir carries an `owner` marker
// (PID); a dir whose PID is still alive is a CONCURRENT edit and is left alone
// (deleting it would destroy another invocation's unsaved work). A dir with no
// marker cannot be proven stale, so it is also skipped (fail safe).
function cleanupStaleEditDirs(tmpBase) {
  const path = require("node:path");
  let entries;
  try { entries = fs.readdirSync(tmpBase); } catch { return; }
  const mine = typeof process.getuid === "function" ? process.getuid() : null;
  for (const name of entries) {
    if (!name.startsWith("pkvault-edit-")) continue;
    const dir = path.join(tmpBase, name);
    let st;
    try { st = fs.lstatSync(dir); } catch { continue; }
    if (!st.isDirectory() || st.isSymbolicLink()) continue;
    if (mine !== null && st.uid !== mine) continue; // only our own dirs
    let owner;
    try { owner = parseInt(fs.readFileSync(path.join(dir, "owner"), "utf8").trim(), 10); }
    catch { continue; } // no marker → cannot prove stale → skip
    if (pidAlive(owner)) continue; // concurrent edit in flight — DO NOT touch
    let files;
    try { files = fs.readdirSync(dir); } catch { continue; }
    for (const f of files) shredFile(path.join(dir, f)); // ALL artifacts, incl. swap/backup
    try { fs.rmdirSync(dir); } catch {}
  }
}

// SPEC §9.1: best-effort plaintext hygiene. Per-invocation 0700 tempdir, 0600
// buffer, best-effort overwrite + unlink, history-suppressing editor hints.
function editBufferViaEditor(text) {
  const os = require("node:os"), path = require("node:path"), { spawnSync } = require("node:child_process");
  cleanupStaleEditDirs(os.tmpdir()); // sweep leftovers from any prior crash first
  const editor = process.env.PKVAULT_EDITOR || process.env.VISUAL || process.env.EDITOR || "vi";
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-edit-"));
  fs.chmodSync(dir, 0o700);
  // ownership marker FIRST — a concurrent cleanup that races an unmarked dir
  // skips it (fail safe); once written, our PID being alive protects this dir.
  fs.writeFileSync(path.join(dir, "owner"), `${process.pid}\n`, { mode: 0o600 });
  const file = path.join(dir, "vault.env");
  const fd = fs.openSync(file, "wx", 0o600);
  try { fs.writeSync(fd, text); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  try {
    const [cmd, ...pre] = editor.split(" ");
    const hints = /(^|\/)n?vim?$/.test(cmd) ? ["-n", "-i", "NONE"] : []; // no swap/viminfo
    const r = spawnSync(cmd, [...pre, ...hints, file], { stdio: "inherit" });
    if (r.error) throw new cli.CliError("E_EDIT", `could not launch editor "${editor}": ${r.error.message}`);
    if (r.status !== 0) throw new cli.CliError("E_EDIT", `editor exited with status ${r.status}; leaving the vault unchanged`);
    return fs.readFileSync(file, "utf8");
  } finally {
    for (const f of (() => { try { return fs.readdirSync(dir); } catch { return []; } })())
      shredFile(path.join(dir, f)); // shred buffer AND any editor swap/backup siblings
    try { fs.rmdirSync(dir); } catch {}
  }
}

const USAGE = `pkvault — passkey-encrypted .env files for teams (https://pkvault.dev)

  setup --label <l> [--rp-id <domain>]
                             create your identity: one tap + a printed recovery code
  recover --label <l> [--rp-id <domain>]
                             lost passkey: recovery code + a NEW passkey (the code is
                             permanent escrow — it is NOT revoked, see \`setup\` output)
  agent [--label <l>] [--ttl 12]   one tap per day: first command unlocks, rest are silent
  default [label] [--rp-id <domain|localhost>]
                             set the identity for label-less commands and/or the
                             RP for NEW credentials (hosted page vs self-hosted)
  lock                       drop the agent's cached identity now
  init --label <l> --recipient <age1…> [--from .env]… [--vault .env.pkvault]
                             (repeat --from to merge files; later files win duplicates)
  get <NAME>                 print one decrypted value
  set <NAME> [--local|--team]   encrypt from stdin; new names ask team-or-personal
  local-init [--from .env.local]   personal layer: encrypted, sealed to YOU, gitignored
  run -- <cmd> [args…]       run a command with the decrypted env (child only)
  edit [--local]             decrypt → $EDITOR → re-encrypt (best-effort hygiene; 'set' is strict)
  public <NAME> | secret <NAME>
  add <label> <age1…> --identity <label.wrap>
                             reseal and install the safe wrapped identity blob
  remove <label> [--accept-exposure]
  status
  export [--to <path> --i-want-plaintext-on-disk]   # reverse adoption: stdout free, disk gated
  unlock --force

identity: passkey agent by default; PKVAULT_IDENTITY or PKVAULT_IDENTITY_FILE for machine/CI identities.`;

async function main() {
  const args = process.argv.slice(2);
  const cmd = args.shift();
  const cwd = process.cwd();
  const io = makeIo();
  const env = process.env;
  try {
    switch (cmd) {
      case "agent": {
        const { startAgent } = require("./agent");
        const home0 = process.env.PKVAULT_HOME ?? require("node:path").join(require("node:os").homedir(), ".config/pkvault");
        const labelArg = opt(args, "--label");
        const ttlRaw = opt(args, "--ttl") ?? "12";
        end(args, 0);
        const label = cli.labelOrDefault(home0, labelArg);
        if (!/^\d+(\.\d+)?$/.test(ttlRaw)) throw new cli.CliError("E_USAGE", `--ttl must be a positive number of hours, got ${JSON.stringify(ttlRaw)}`);
        const ttlH = Number(ttlRaw);
        if (!Number.isFinite(ttlH) || ttlH <= 0 || ttlH > 168) throw new cli.CliError("E_USAGE", "--ttl must be > 0 and ≤ 168 hours (one week)");
        await startAgent({
          home: process.env.PKVAULT_HOME ?? require("node:path").join(require("node:os").homedir(), ".config/pkvault"),
          label,
          repoRoot: (() => { try { return cli.findRoot(cwd); } catch { return null; } })(),
          ttlMs: ttlH * 3600 * 1000,
          log: (s) => io.out(`[agent] ${s}`),
        });
        io.out("[agent] running in the foreground — Ctrl-C to stop, `pkvault lock` to drop keys");
        return await new Promise(() => {}); // run until killed
      }
      case "lock": {
        end(args, 0);
        const { agentRequest } = require("./agent");
        const home = process.env.PKVAULT_HOME ?? require("node:path").join(require("node:os").homedir(), ".config/pkvault");
        await agentRequest(home, { op: "lock" });
        return io.out("agent locked");
      }
      case "setup": {
        const label = opt(args, "--label"), rpId = opt(args, "--rp-id");
        end(args, 0);
        return await cli.setup({ io, label, rpId });
      }
      case "recover": {
        const label = opt(args, "--label"), rpId = opt(args, "--rp-id");
        end(args, 0);
        return await cli.recover({ cwd, io, label, code: promptLine("recovery code: "), rpId });
      }
      case "default": {
        const rpId = opt(args, "--rp-id");
        if (args.length > 1 || args.some((a) => a.startsWith("-")))
          throw new cli.CliError("E_USAGE", `default takes at most one label${rpId ? "" : " and/or --rp-id"}: ${args.join(" ")}`);
        const label = args[0] ?? null;
        if (rpId) cli.setDefaultRpId({ io, rpId });
        if (label) cli.setDefaultLabel({ io, label });
        if (!rpId && !label) throw new cli.CliError("E_USAGE", "default needs a label and/or --rp-id <domain|localhost>");
        return;
      }
      case "init": {
        const froms = optAll(args, "--from");
        const label = opt(args, "--label"), recipient = opt(args, "--recipient"), vault = opt(args, "--vault") ?? ".env.pkvault";
        end(args, 0);
        return cli.init({ cwd, io, label, recipient, from: froms.length ? froms : ".env", vault });
      }
      case "get": {
        end(args, 1);
        return process.stdout.write(cli.get({ cwd, name: args[0], env }) + "\n");
      }
      case "set": {
        const local = flag(args, "--local") === true ? true : flag(args, "--team") === true ? false : null;
        end(args, 1); // one NAME positional; any leftover --team/misspelling rejected here
        return cli.set({ cwd, io, name: args[0], valueBuf: fs.readFileSync(0), env, local });
      }
      case "local-init": {
        const from = opt(args, "--from");
        end(args, 0);
        return cli.localInit({ cwd, io, from, env });
      }
      case "run": {
        // everything after `--` is passthrough to the child; do NOT validate it
        const sep = args.indexOf("--");
        if (sep === -1) throw new cli.CliError("E_USAGE", "run needs: pkvault run -- <cmd> [args…]");
        if (sep !== 0) throw new cli.CliError("E_USAGE", `unexpected argument(s) before --: ${args.slice(0, sep).join(" ")}`);
        const argv = args.slice(sep + 1);
        if (argv.length === 0) throw new cli.CliError("E_USAGE", "run needs a command: pkvault run -- <cmd>");
        return process.exit(cli.run({ cwd, env, argv }));
      }
      case "public": {
        end(args, 1);
        return cli.classify({ cwd, io, name: args[0], to: "public", env });
      }
      case "secret": {
        end(args, 1);
        return cli.classify({ cwd, io, name: args[0], to: "secret", env });
      }
      case "add": {
        const identityBlob = opt(args, "--identity");
        const allowMissingIdentityBlob = flag(args, "--without-identity-blob") === true;
        end(args, 2);
        return cli.add({ cwd, io, label: args[0], recipient: args[1], env, identityBlob, allowMissingIdentityBlob });
      }
      case "remove": {
        const acceptExposure = flag(args, "--accept-exposure") === true;
        end(args, 1);
        return cli.remove({ cwd, io, label: args[0], acceptExposure, env, date: today() });
      }
      case "status":
        end(args, 0);
        return cli.status({ cwd, io, env });
      case "export": {
        const to = opt(args, "--to"), iWantPlaintextOnDisk = flag(args, "--i-want-plaintext-on-disk") === true;
        end(args, 0);
        return cli.exportPlain({ cwd, io, env, to, iWantPlaintextOnDisk });
      }
      case "unlock": {
        const force = flag(args, "--force") === true;
        end(args, 0);
        if (force) return cli.unlockForce({ cwd, io });
        throw new cli.CliError("E_USAGE", "unlock requires --force");
      }
      case "edit": {
        const local = flag(args, "--local") === true;
        end(args, 0);
        return cli.edit({ cwd, io, env, local, editBuffer: editBufferViaEditor });
      }
      default:
        process.stdout.write(USAGE + "\n");
        process.exit(cmd === undefined || cmd === "help" || cmd === "--help" ? 0 : 2);
    }
  } catch (e) {
    if (e && e.code && typeof e.code === "string" && e.code.startsWith("E_")) {
      process.stderr.write(`pkvault: ${e.message}\n`);
      process.exit(1);
    }
    throw e;
  }
}
main().catch((e) => {
  process.stderr.write(`pkvault: ${e.message}\n`);
  process.exit(1);
});
