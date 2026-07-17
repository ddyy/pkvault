"use strict";
// pkvault agent (PLAN §4.4): ssh-agent-style daemon. First request of the day
// triggers one ceremony; the unwrapped scalar lives ONLY in this process's
// memory until TTL, sleep, or an explicit lock. Zeroed on lock (best-effort —
// Node memory honesty per SPEC/PLAN; V8 gives no mlock).
//
// v1 trust boundary, stated plainly: the agent returns the scalar to same-uid
// clients over a 0600 unix socket. That is the same *capability* boundary as
// ssh-agent's socket (any same-user process may use the key); V2 hardening
// moves the unseal operation into the agent and never releases the scalar —
// which is also what confirm-mode (PLAN Phase 4) requires.

const net = require("node:net");
const fs = require("node:fs");
const path = require("node:path");

class AgentError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.code = code;
  }
}
const err = (code, m) => new AgentError(code, m);

const sockPath = (home) => path.join(home, "agent.sock");

const POLL_MS = 30_000;
const SLEEP_GAP_MS = 90_000;

// The agent uses a POSIX unix-domain socket with filesystem 0600 access control.
// Windows IPC needs named pipes with a different ACL model — not yet implemented.
// Fail closed with a clear message rather than a confusing low-level error.
const WINDOWS_UNSUPPORTED = "the pkvault agent (and passkey ceremony workflow) is not yet supported on Windows; use a machine identity via PKVAULT_IDENTITY / PKVAULT_IDENTITY_FILE";

function startAgent({ home, label, repoRoot = null, ttlMs = 12 * 3600 * 1000, bridgeOpts = {}, log = () => {}, pollMs = POLL_MS, sleepGapMs = SLEEP_GAP_MS }) {
  if (process.platform === "win32") throw err("E_AGENT_UNSUPPORTED", WINDOWS_UNSUPPORTED);
  // Defense in depth, NOT relying on the CLI wrapper's validation: a non-finite
  // or enormous ttl breaks locking. Too small → never unlocks; non-finite →
  // never expires and toISOString() throws AFTER caching; enormous finite →
  // Date.now()+ttl exceeds the valid Date range and toISOString() throws.
  // Bound to one week (matches the CLI cap).
  const MAX_TTL_MS = 168 * 3600 * 1000;
  if (!Number.isFinite(ttlMs) || ttlMs <= 0 || ttlMs > MAX_TTL_MS)
    throw err("E_AGENT_TTL", `ttlMs must be finite and within (0, ${MAX_TTL_MS}]`);
  const { ceremonyUnlock } = require("./unlock");
  fs.mkdirSync(home, { recursive: true, mode: 0o700 });
  fs.chmodSync(home, 0o700);
  const sock = sockPath(home);

  let scalar = null, recipient = null, expiresAt = 0;
  let lockGeneration = 0;
  let unlockChain = Promise.resolve(); // serialize concurrent unlock requests
  function lock(reason) {
    lockGeneration++;
    expiresAt = 0;
    recipient = null;
    if (scalar) {
      scalar.fill(0);
      scalar = null;
      log(`locked (${reason})`);
    }
  }
  function unlocked() {
    if (scalar && Date.now() > expiresAt) lock("ttl expired");
    return scalar !== null;
  }
  async function ensureUnlocked(requestGeneration) {
    if (requestGeneration !== lockGeneration) throw err("E_AGENT_LOCKED", "request was cancelled by lock");
    if (unlocked()) return;
    const ceremonyGeneration = lockGeneration;
    const r = await ceremonyUnlock({ label, home, repoRoot, bridgeOpts });
    if (ceremonyGeneration !== lockGeneration) {
      r.scalar.fill(0);
      throw err("E_AGENT_LOCKED", "ceremony completed after the agent was locked; result discarded");
    }
    scalar = r.scalar;
    recipient = r.recipient;
    expiresAt = Date.now() + ttlMs;
    log(`unlocked ${label} until ${new Date(expiresAt).toISOString()}`);
  }

  let last = Date.now();
  const timer = setInterval(() => {
    const now = Date.now();
    if (now - last > sleepGapMs) lock("sleep detected");
    else if (scalar && now > expiresAt) lock("ttl expired");
    last = now;
  }, pollMs);
  timer.unref();

  const server = net.createServer((conn) => {
    let buf = "";
    conn.on("data", (d) => {
      buf += d;
      const nl = buf.indexOf("\n");
      if (nl === -1) return;
      const line = buf.slice(0, nl);
      buf = "";
      let msg;
      try { msg = JSON.parse(line); } catch { return conn.end(JSON.stringify({ ok: false, code: "E_AGENT_PROTO" }) + "\n"); }
      handle(msg)
        .then((res) => conn.end(JSON.stringify({ ok: true, ...res }) + "\n"))
        .catch((e) => conn.end(JSON.stringify({ ok: false, code: e.code ?? "E_AGENT", message: e.message }) + "\n"));
    });
  });

  async function handle(msg) {
    switch (msg.op) {
      case "identity":
        {
          const requestGeneration = lockGeneration;
          unlockChain = unlockChain.then(
            () => ensureUnlocked(requestGeneration),
            () => ensureUnlocked(requestGeneration),
          );
        }
        await unlockChain;
        if (!unlocked()) throw err("E_AGENT_LOCKED", "unlock did not complete");
        return { scalar: scalar.toString("base64"), label, recipient };
      case "status":
        return { unlocked: unlocked(), label, expiresAt: unlocked() ? expiresAt : null };
      case "lock":
        lock("requested");
        return {};
      default:
        throw err("E_AGENT_PROTO", `unknown op ${msg.op}`);
    }
  }

  return new Promise((resolve, reject) => {
    const listen = () => server.listen(sock, () => {
      fs.chmodSync(sock, 0o600);
      log(`agent listening on ${sock} (label: ${label}, ttl: ${ttlMs / 3600000}h)`);
      resolve({
        close: () => new Promise((r) => { clearInterval(timer); lock("shutdown"); server.close(() => { try { fs.unlinkSync(sock); } catch {} r(); }); }),
      });
    });
    server.on("error", (e) => {
      if (e.code === "EADDRINUSE") {
        // stale socket? probe it; replace only if dead.
        const probe = net.connect(sock, () => { probe.destroy(); reject(err("E_AGENT_RUNNING", "an agent is already running")); });
        probe.on("error", () => { try { fs.unlinkSync(sock); } catch {} listen(); });
      } else reject(e);
    });
    listen();
  });
}

// async client
function agentRequest(home, msg, { timeoutMs = 180_000 } = {}) {
  if (process.platform === "win32") return Promise.reject(err("E_AGENT_UNSUPPORTED", WINDOWS_UNSUPPORTED));
  return new Promise((resolve, reject) => {
    const conn = net.connect(sockPath(home));
    const timer = setTimeout(() => { conn.destroy(); reject(err("E_AGENT_TIMEOUT", "agent did not answer (ceremony pending?)")); }, timeoutMs);
    let buf = "";
    conn.on("connect", () => conn.write(JSON.stringify(msg) + "\n"));
    conn.on("data", (d) => (buf += d));
    conn.on("end", () => {
      clearTimeout(timer);
      try { resolve(JSON.parse(buf)); } catch { reject(err("E_AGENT_PROTO", "bad agent reply")); }
    });
    conn.on("error", (e) => { clearTimeout(timer); reject(err("E_AGENT_UNAVAILABLE", e.message)); });
  });
}

module.exports = { AgentError, startAgent, agentRequest, sockPath };
