"use strict";
// Agent suite: lazy one-ceremony unlock, caching, TTL, lock, socket hygiene,
// and the full sync-CLI-through-agent path. node:test, zero deps.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const http = require("node:http");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { startAgent, agentRequest } = require("../src/agent.js");
const cli = require("../src/cli.js");
const age = require("../src/age.js");

// simulated authenticator + page (same construction as bridge tests)
const simulatedPrf = (salt) => crypto.createHash("sha256").update(Buffer.concat([Buffer.from("sim-authenticator"), salt])).digest();
const CRED = Buffer.from("agent-sim-credential");
function simulatePage(url) {
  const u = new URL(url);
  const params = new URLSearchParams(u.hash.slice(1));
  const code = params.get("code");
  const port = params.get("port") ?? u.port;
  const cliPub = Buffer.from(params.get("clipub"), "base64url");
  const salt = Buffer.from(params.get("salt"), "base64url");
  const cred = params.get("credid") ? Buffer.from(params.get("credid"), "base64url") : CRED;
  const ecdh = crypto.createECDH("prime256v1");
  ecdh.generateKeys();
  const key = Buffer.from(crypto.hkdfSync("sha256", ecdh.computeSecret(cliPub), Buffer.from(code), Buffer.from("pkvault/bridge/v1"), 32));
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", key, nonce);
  c.setAAD(Buffer.from(code));
  const body = JSON.stringify({ prf: simulatedPrf(salt).toString("base64url"), credentialId: cred.toString("base64url"), rpId: u.hostname });
  const ct = Buffer.concat([c.update(body), c.final(), c.getAuthTag()]);
  const payload = Buffer.concat([ecdh.getPublicKey(), nonce, ct]).toString("base64url");
  http.get(`http://127.0.0.1:${port}/callback?code=${code}&payload=${payload}`, () => {});
}

async function setUpIdentity(home, ceremonies) {
  const bridgeOpts = { openBrowser: (url) => { ceremonies.n++; simulatePage(url); } };
  const { recipient } = await cli.setup({ io: { out: () => {} }, label: "daniel", home, bridgeOpts });
  return { recipient, bridgeOpts };
}

test("agent: first request runs ONE ceremony; later requests are silent; lock forces a new one", async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-agent-"));
  const ceremonies = { n: 0 };
  const { recipient, bridgeOpts } = await setUpIdentity(home, ceremonies);
  assert.equal(ceremonies.n, 1, "setup ceremony");

  const agent = await startAgent({ home, label: "daniel", bridgeOpts });
  try {
    const r1 = await agentRequest(home, { op: "identity" });
    assert.equal(r1.ok, true);
    assert.equal(r1.recipient, recipient);
    assert.equal(ceremonies.n, 2, "one unlock ceremony");
    const r2 = await agentRequest(home, { op: "identity" });
    assert.equal(r2.ok, true);
    assert.equal(ceremonies.n, 2, "cached — no new ceremony");
    assert.equal(age.encodeRecipient(age.publicFromScalar(Buffer.from(r2.scalar, "base64"))), recipient);

    const st = await agentRequest(home, { op: "status" });
    assert.equal(st.unlocked, true);
    await agentRequest(home, { op: "lock" });
    assert.equal((await agentRequest(home, { op: "status" })).unlocked, false);
    await agentRequest(home, { op: "identity" });
    assert.equal(ceremonies.n, 3, "post-lock request re-ceremonies");
  } finally {
    await agent.close();
  }
  assert.ok(!fs.existsSync(path.join(home, "agent.sock")), "socket unlinked on close");
});

test("startAgent enforces its own TTL bound (not just the CLI wrapper)", async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-agent-"));
  const bridgeOpts = { openBrowser: () => {} };
  for (const bad of [0, -1, NaN, Infinity, Number.MAX_VALUE, 200 * 3600 * 1000]) {
    await assert.rejects(async () => startAgent({ home, label: "x", bridgeOpts, ttlMs: bad }), (e) => e.code === "E_AGENT_TTL", `ttlMs=${bad}`);
  }
});

test("agent: ttl expiry forces a new ceremony", async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-agent-"));
  const ceremonies = { n: 0 };
  const { bridgeOpts } = await setUpIdentity(home, ceremonies);
  const agent = await startAgent({ home, label: "daniel", bridgeOpts, ttlMs: 50 });
  try {
    await agentRequest(home, { op: "identity" });
    assert.equal(ceremonies.n, 2);
    await new Promise((r) => setTimeout(r, 80));
    assert.equal((await agentRequest(home, { op: "status" })).unlocked, false, "expired");
    await agentRequest(home, { op: "identity" });
    assert.equal(ceremonies.n, 3, "re-ceremony after ttl");
  } finally {
    await agent.close();
  }
});

test("agent: concurrent first requests share one ceremony", async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-agent-"));
  const ceremonies = { n: 0 };
  const { bridgeOpts } = await setUpIdentity(home, ceremonies);
  const agent = await startAgent({ home, label: "daniel", bridgeOpts });
  try {
    const [a, b, c] = await Promise.all([
      agentRequest(home, { op: "identity" }),
      agentRequest(home, { op: "identity" }),
      agentRequest(home, { op: "identity" }),
    ]);
    assert.ok(a.ok && b.ok && c.ok);
    assert.equal(ceremonies.n, 2, "exactly one unlock ceremony for three concurrent clients");
  } finally {
    await agent.close();
  }
});

test("agent: explicit lock cancels an in-flight ceremony result", async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-agent-"));
  const ceremonies = { n: 0 };
  await setUpIdentity(home, ceremonies);
  let pendingUrl;
  let sawCeremony;
  const opened = new Promise((resolve) => { sawCeremony = resolve; });
  const agent = await startAgent({
    home,
    label: "daniel",
    bridgeOpts: { openBrowser: (url) => { pendingUrl = url; sawCeremony(); } },
  });
  try {
    const identityReply = agentRequest(home, { op: "identity" });
    await opened;
    await agentRequest(home, { op: "lock" });
    simulatePage(pendingUrl);
    const reply = await identityReply;
    assert.equal(reply.ok, false);
    assert.equal(reply.code, "E_AGENT_LOCKED");
    assert.equal((await agentRequest(home, { op: "status" })).unlocked, false);
  } finally {
    await agent.close();
  }
});

test("agent: committed identity blob enables clone + tap without the global blob", async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-agent-"));
  const ceremonies = { n: 0 };
  const { recipient, bridgeOpts } = await setUpIdentity(home, ceremonies);
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-agent-repo-"));
  fs.writeFileSync(path.join(cwd, ".env"), "SECRET=portable\n");
  const io = { out: () => {}, interactive: true, confirm: () => true, txnOpts: { isTracked: () => false } };
  cli.init({ cwd, io, label: "daniel", recipient, home });
  assert.ok(fs.existsSync(path.join(cwd, ".pkvault/identities/daniel.wrap")));
  fs.unlinkSync(path.join(home, "daniel.wrap"));

  const agent = await startAgent({ home, label: "daniel", repoRoot: cwd, bridgeOpts });
  try {
    const reply = await agentRequest(home, { op: "identity" });
    assert.equal(reply.ok, true);
    assert.equal(reply.recipient, recipient);
  } finally {
    await agent.close();
  }
});

test("agent: second agent on the same socket refuses; stale socket is replaced", async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-agent-"));
  const ceremonies = { n: 0 };
  const { bridgeOpts } = await setUpIdentity(home, ceremonies);
  const agent = await startAgent({ home, label: "daniel", bridgeOpts });
  await assert.rejects(startAgent({ home, label: "daniel", bridgeOpts }), (e) => e.code === "E_AGENT_RUNNING");
  await agent.close();
  // stale socket file left behind (simulate crash): create dead socket file
  fs.writeFileSync(path.join(home, "agent.sock"), "");
  const again = await startAgent({ home, label: "daniel", bridgeOpts });
  await again.close();
});

test("end to end: sync CLI commands resolve identity through a real agent process", async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-agent-"));
  const ceremonies = { n: 0 };
  const { recipient } = await setUpIdentity(home, ceremonies);

  // repo sealed to the passkey-backed identity
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-agent-repo-"));
  fs.writeFileSync(path.join(cwd, ".env"), "SECRET_ONE=hello\n");
  const io = { out: () => {}, interactive: true, confirm: () => true, txnOpts: { isTracked: () => false } };
  cli.init({ cwd, io, label: "daniel", recipient, home });

  // the agent must be a SEPARATE process: sync CLI commands block their own
  // event loop while consulting it (production shape; in-process would deadlock)
  const { spawn } = require("node:child_process");
  const child = spawn(process.execPath, [path.join(__dirname, "../scripts/sim-agent.js"), home, "daniel"], { stdio: ["ignore", "pipe", "inherit"] });
  await new Promise((resolve, reject) => {
    child.stdout.on("data", (d) => d.toString().includes("READY") && resolve());
    child.on("exit", (c) => reject(new Error(`sim-agent exited ${c}`)));
    setTimeout(() => reject(new Error("sim-agent never became ready")), 10000).unref();
  });
  const count = () => parseInt(fs.readFileSync(path.join(home, "ceremonies.count"), "utf8"), 10);
  try {
    const env = { PKVAULT_HOME: home }; // no PKVAULT_IDENTITY → agent path
    assert.equal(cli.get({ cwd, name: "SECRET_ONE", env }), "hello");
    assert.equal(count(), 1, "first CLI command triggered the daily ceremony");
    assert.equal(cli.get({ cwd, name: "SECRET_ONE", env }), "hello");
    assert.equal(count(), 1, "second command silent");
  } finally {
    child.kill();
  }
});
