"use strict";
// Test helper: run a real agent process whose "browser" is the simulated
// authenticator/page. Usage: node sim-agent.js <home> <label>
// Prints READY when listening; increments <home>/ceremonies.count per ceremony.
const crypto = require("node:crypto");
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const { startAgent } = require("../src/agent.js");

const [home, label] = process.argv.slice(2);
const CRED = Buffer.from("agent-sim-credential");
const simulatedPrf = (salt) => crypto.createHash("sha256").update(Buffer.concat([Buffer.from("sim-authenticator"), salt])).digest();

function simulatePage(url) {
  const u = new URL(url);
  const p = new URLSearchParams(u.hash.slice(1));
  const code = p.get("code");
  const port = p.get("port") ?? u.port;
  const cliPub = Buffer.from(p.get("clipub"), "base64url");
  const salt = Buffer.from(p.get("salt"), "base64url");
  const cred = p.get("credid") ? Buffer.from(p.get("credid"), "base64url") : CRED;
  const e = crypto.createECDH("prime256v1");
  e.generateKeys();
  const key = Buffer.from(crypto.hkdfSync("sha256", e.computeSecret(cliPub), Buffer.from(code), Buffer.from("pkvault/bridge/v1"), 32));
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", key, nonce);
  c.setAAD(Buffer.from(code));
  const body = JSON.stringify({ prf: simulatedPrf(salt).toString("base64url"), credentialId: cred.toString("base64url"), rpId: u.hostname });
  const ct = Buffer.concat([c.update(body), c.final(), c.getAuthTag()]);
  const payload = Buffer.concat([e.getPublicKey(), nonce, ct]).toString("base64url");
  http.get(`http://127.0.0.1:${port}/callback?code=${code}&payload=${payload}`, () => {});
}

const counter = path.join(home, "ceremonies.count");
startAgent({
  home, label,
  bridgeOpts: {
    openBrowser: (url) => {
      fs.writeFileSync(counter, String((parseInt(fs.readFileSync(counter, "utf8").trim() || "0", 10) || 0) + 1));
      simulatePage(url);
    },
  },
}).then(() => {
  fs.writeFileSync(counter, "0");
  process.stdout.write("READY\n");
});
