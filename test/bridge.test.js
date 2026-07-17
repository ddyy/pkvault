"use strict";
// Bridge suite: the ceremony transport protocol with a Node-simulated page
// (same ECDH/HKDF/AES-GCM the browser does in WebCrypto), plus setup/recover/
// ceremonyUnlock end-to-end with a simulated authenticator. node:test, zero deps.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const http = require("node:http");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const bridge = require("../src/bridge.js");
const cli = require("../src/cli.js");
const idn = require("../src/identity.js");
const age = require("../src/age.js");

const throwsCodeAsync = (p, code) => assert.rejects(p, (e) => (assert.equal(e.code, code, e.message), true));

// The simulated authenticator: PRF output is a pure function of the salt, like
// a real credential. The simulated page: exactly the WebCrypto construction.
const simulatedPrf = (salt) => crypto.createHash("sha256").update(Buffer.concat([Buffer.from("sim-authenticator"), salt])).digest();
const CRED = Buffer.from("simulated-credential-id-bytes");

function simulatePage(url, { tamper = null, wrongCodeFirst = false, credentialId = CRED, rpId = null } = {}) {
  const u = new URL(url);
  const params = new URLSearchParams(u.hash.slice(1));
  const code = params.get("code");
  const port = params.get("port") ?? u.port;
  const cliPub = Buffer.from(params.get("clipub"), "base64url");
  const salt = Buffer.from(params.get("salt"), "base64url");
  const useCred = params.get("credid") ? Buffer.from(params.get("credid"), "base64url") : credentialId;

  const ecdh = crypto.createECDH("prime256v1");
  ecdh.generateKeys();
  const shared = ecdh.computeSecret(cliPub);
  const key = Buffer.from(crypto.hkdfSync("sha256", shared, Buffer.from(code, "utf8"), Buffer.from("pkvault/bridge/v1", "utf8"), 32));
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", key, nonce);
  c.setAAD(Buffer.from(code, "utf8"));
  const body = JSON.stringify({ prf: simulatedPrf(salt).toString("base64url"), credentialId: useCred.toString("base64url"), rpId: rpId ?? u.hostname });
  const ct = Buffer.concat([c.update(body, "utf8"), c.final(), c.getAuthTag()]);
  let payload = Buffer.concat([ecdh.getPublicKey(), nonce, ct]).toString("base64url");
  if (tamper) payload = payload.slice(0, -4) + (payload.endsWith("AAAA") ? "BBBB" : "AAAA");

  const send = (theCode) => http.get(`http://127.0.0.1:${port}/callback?code=${theCode}&payload=${payload}`, () => {});
  if (wrongCodeFirst) send("0".repeat(32));
  setTimeout(() => send(code), wrongCodeFirst ? 30 : 0);
}

test("bridge: happy path — payload decrypts, salt echoed back", async () => {
  const prfSalt = crypto.randomBytes(32);
  let openedUrl;
  const res = await bridge.startCeremony({ op: "setup", prfSalt, openBrowser: (url) => { openedUrl = url; simulatePage(url); } });
  assert.equal(new URL(openedUrl).origin, "https://unlock.pkvault.dev");
  assert.match(new URLSearchParams(new URL(openedUrl).hash.slice(1)).get("port"), /^[0-9]+$/);
  assert.deepEqual(res.prfOutput, simulatedPrf(prfSalt));
  assert.deepEqual(res.credentialId, CRED);
  assert.equal(res.rpId, "unlock.pkvault.dev");
  assert.deepEqual(res.prfSalt, prfSalt);
});

test("bridge: page cannot claim a different RP ID than the opened origin", async () => {
  await throwsCodeAsync(
    bridge.startCeremony({
      op: "setup",
      prfSalt: crypto.randomBytes(32),
      openBrowser: (url) => simulatePage(url, { rpId: "evil.example" }),
    }),
    "E_BRIDGE_RP_ID",
  );
});

test("bridge: wrong one-time code is rejected without burning the real one", async () => {
  const prfSalt = crypto.randomBytes(32);
  const res = await bridge.startCeremony({ op: "setup", prfSalt, openBrowser: (url) => simulatePage(url, { wrongCodeFirst: true }) });
  assert.deepEqual(res.prfOutput, simulatedPrf(prfSalt));
});

test("bridge: tampered payload → E_BRIDGE_PAYLOAD", async () => {
  await throwsCodeAsync(
    bridge.startCeremony({ op: "setup", prfSalt: crypto.randomBytes(32), openBrowser: (url) => simulatePage(url, { tamper: true }) }),
    "E_BRIDGE_PAYLOAD"
  );
});

test("bridge: timeout → E_BRIDGE_TIMEOUT", async () => {
  await throwsCodeAsync(
    bridge.startCeremony({ op: "setup", prfSalt: crypto.randomBytes(32), timeoutMs: 50, openBrowser: () => {} }),
    "E_BRIDGE_TIMEOUT"
  );
});

test("bridge: unlock op carries the stored credential id into the fragment", async () => {
  const prfSalt = crypto.randomBytes(32);
  let sawCredId = null;
  const res = await bridge.startCeremony({
    op: "unlock", prfSalt, credentialId: CRED,
    openBrowser: (url) => {
      sawCredId = new URLSearchParams(new URL(url).hash.slice(1)).get("credid");
      simulatePage(url);
    },
  });
  assert.equal(sawCredId, CRED.toString("base64url"));
  assert.deepEqual(res.credentialId, CRED);
});

test("bridge: GET / serves the ceremony page", async () => {
  const prfSalt = crypto.randomBytes(32);
  await bridge.startCeremony({
    op: "setup", prfSalt, ceremonyOrigin: "local",
    openBrowser: async (url) => {
      const u = new URL(url);
      const page = await new Promise((res) => http.get(`http://127.0.0.1:${u.port}/`, (r) => {
        let s = "";
        r.on("data", (c) => (s += c));
        r.on("end", () => res(s));
      }));
      assert.match(page, /pkvault ceremony/);
      assert.match(page, /navigator\.credentials/);
      simulatePage(url);
    },
  });
});

// --- setup / recover / ceremonyUnlock end-to-end -------------------------------------
test("setup → blob on disk; ceremonyUnlock and the printed recovery code both unwrap", async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-home-"));
  const io = { out: () => {} };
  const bridgeOpts = { openBrowser: (url) => simulatePage(url) };
  const { recipient } = await cli.setup({ io, label: "daniel", home, bridgeOpts });

  const blob = idn.parseBlob(fs.readFileSync(path.join(home, "daniel.wrap")));
  assert.equal(blob.recipient, recipient);
  // ceremony unlock (the agent's future path): fresh ceremony, same credential
  const scalar = await cli.ceremonyUnlock({ label: "daniel", home, bridgeOpts });
  assert.equal(age.encodeRecipient(age.publicFromScalar(scalar)), recipient);
  // blob is 0600
  assert.equal(fs.statSync(path.join(home, "daniel.wrap")).mode & 0o777, 0o600);
  // duplicate setup refuses
  await throwsCodeAsync(cli.setup({ io, label: "daniel", home, bridgeOpts }), "E_ALREADY_SETUP");
});

test("default label: first setup saves it; later identities never steal it; recover uses it", async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-home-"));
  const lines = [];
  const io = { out: (s) => lines.push(s) };
  const bridgeOpts = { openBrowser: (url) => simulatePage(url), ceremonyOrigin: "local" };
  await cli.setup({ io, label: "daniel", home, bridgeOpts, rpId: "localhost" });
  assert.equal(cli.readDefaultLabel(home), "daniel", "first identity becomes the default");

  await cli.setup({ io, label: "hosted-test", home, bridgeOpts, rpId: "localhost" });
  assert.equal(cli.readDefaultLabel(home), "daniel", "second identity must NOT steal the default");

  // labelOrDefault resolution + explicit override + missing-default error
  assert.equal(cli.labelOrDefault(home, null), "daniel");
  assert.equal(cli.labelOrDefault(home, "hosted-test"), "hosted-test");
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-home-"));
  assert.throws(() => cli.labelOrDefault(empty, null), (e) => e.code === "E_BAD_LABEL");

  // explicit default switch requires an existing blob
  cli.setDefaultLabel({ io, label: "hosted-test", home });
  assert.equal(cli.readDefaultLabel(home), "hosted-test");
  assert.throws(() => cli.setDefaultLabel({ io, label: "ghost", home }), (e) => e.code === "E_NO_IDENTITY");

  // recover with no label uses the default
  const code = lines.filter((l) => l.trim().startsWith("PKVR-")).at(-1).trim();
  await cli.recover({ io, code, home, bridgeOpts, rpId: "localhost" }); // no label → hosted-test
  assert.ok(fs.existsSync(path.join(home, "hosted-test.wrap")));
});

test("default rp-id: saved value governs NEW credentials; explicit flag overrides; bad values refused", async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-home-"));
  const io = { out: () => {} };
  // save localhost as the default RP → setup with NO rpId self-hosts
  cli.setDefaultRpId({ io, rpId: "localhost", home });
  assert.equal(cli.readDefaultRpId(home), "localhost");
  const bridgeOpts = { openBrowser: (url) => simulatePage(url) }; // no explicit ceremonyOrigin
  await cli.setup({ io, label: "selfhosted", home, bridgeOpts });
  const blob = idn.parseBlob(fs.readFileSync(path.join(home, "selfhosted.wrap")));
  assert.equal(blob.wraps.find((w) => w.type === "prf").rpId, "localhost", "wrap bound to the defaulted RP");

  // resolution order: explicit flag > saved default > hosted constant
  assert.equal(cli.rpIdOrDefault(home, "example.com"), "example.com");
  assert.equal(cli.rpIdOrDefault(home, null), "localhost");
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-home-"));
  assert.equal(cli.rpIdOrDefault(empty, null), "unlock.pkvault.dev");

  // invalid values refused at save AND at resolution
  assert.throws(() => cli.setDefaultRpId({ io, rpId: "not a domain!", home }), (e) => e.code === "E_BRIDGE_USAGE");
  fs.writeFileSync(path.join(home, "default-rp-id"), "bad domain!\n");
  assert.throws(() => cli.rpIdOrDefault(home, null), (e) => e.code === "E_BRIDGE_USAGE");
});

test("#6 recover of a REPO blob CAS-guards: concurrent change during ceremony → refusal", async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-home-"));
  const lines = [];
  const io = { out: (s) => lines.push(s), interactive: false, confirm: () => false, txnOpts: { isTracked: () => false } };
  const bridgeOpts = { openBrowser: (url) => simulatePage(url) };
  const { recipient } = await cli.setup({ io, label: "daniel", home, bridgeOpts });
  const oldCode = lines.find((l) => l.trim().startsWith("PKVR-")).trim();

  // init a repo so the committed blob lives at .pkvault/identities/daniel.wrap
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-repo-"));
  fs.writeFileSync(path.join(cwd, ".env"), "A=1\n");
  cli.init({ cwd, io, label: "daniel", recipient, home });
  const repoBlob = path.join(cwd, ".pkvault/identities/daniel.wrap");
  assert.ok(fs.existsSync(repoBlob), "repo blob installed");

  // happy path: recover from the repo blob succeeds (exercises the CAS branch)
  await cli.recover({ cwd, io, label: "daniel", code: oldCode, home, bridgeOpts });
  assert.equal(idn.parseBlob(fs.readFileSync(repoBlob)).recipient, recipient);

  const goodBlob = fs.readFileSync(repoBlob); // valid state to restore between conflict cases

  // conflict A: mutate the on-disk repo blob DURING the ceremony → CAS refuses
  const conflictBlob = { openBrowser: (url) => { fs.appendFileSync(repoBlob, "\n"); simulatePage(url); } };
  await throwsCodeAsync(cli.recover({ cwd, io, label: "daniel", code: oldCode, home, bridgeOpts: conflictBlob }), "E_IDENTITY_CONFLICT");
  fs.writeFileSync(repoBlob, goodBlob); // restore so the next case starts from a valid blob

  // conflict B (#4): replace the manifest recipient for the label DURING the
  // ceremony (blob byte-identical, but manifest no longer maps to us) → refuse
  const other = age.keygen();
  const manifestPath = path.join(cwd, ".pkvault/recipients.toml");
  const conflictManifest = { openBrowser: (url) => { fs.writeFileSync(manifestPath, `daniel = "${other.recipient}"\n`); simulatePage(url); } };
  await throwsCodeAsync(cli.recover({ cwd, io, label: "daniel", code: oldCode, home, bridgeOpts: conflictManifest }), "E_IDENTITY_CONFLICT");
});

test("recover: new passkey; same recovery code stays valid (permanent escrow, not burned)", async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-home-"));
  const lines = [];
  const io = { out: (s) => lines.push(s) };
  const bridgeOpts = { openBrowser: (url) => simulatePage(url) };
  const { recipient } = await cli.setup({ io, label: "daniel", home, bridgeOpts });
  const oldCode = lines.find((l) => l.trim().startsWith("PKVR-")).trim();

  const lines2 = [];
  await cli.recover({ io: { out: (s) => lines2.push(s) }, label: "daniel", code: oldCode, home, bridgeOpts });
  // recover does NOT print a new code; it says the code is unchanged/escrow
  assert.equal(lines2.find((l) => l.trim().startsWith("PKVR-")), undefined, "no fresh code printed");
  assert.ok(lines2.some((l) => /permanent escrow|UNCHANGED/.test(l)), "honest escrow messaging");

  const blob = idn.parseBlob(fs.readFileSync(path.join(home, "daniel.wrap")));
  assert.equal(blob.recipient, recipient, "same identity");
  // the SAME code still opens the re-wrapped blob
  assert.deepEqual(age.encodeRecipient(age.publicFromScalar(idn.unwrapWithRecovery(blob, oldCode))), recipient);
  // and the fresh passkey wrap works via a ceremony
  const scalar = await cli.ceremonyUnlock({ label: "daniel", home, bridgeOpts });
  assert.equal(age.encodeRecipient(age.publicFromScalar(scalar)), recipient);
});
