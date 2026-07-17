"use strict";
// Ceremony bridge (PLAN §4.5, SPEC decisions): loopback listener + browser launch.
// The default opens the hosted static page; `ceremonyOrigin: "local"` serves
// the same file from localhost for development. Parameters travel in the URL fragment;
// the PRF output returns ONLY as ciphertext to an ephemeral P-256 key, delivered
// by top-level navigation. One-time code binds the ceremony to this invocation.

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawn } = require("node:child_process");

class BridgeError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.code = code;
  }
}
const err = (code, m) => new BridgeError(code, m);

const b64u = (buf) => Buffer.from(buf).toString("base64url");
// web/index.html is BOTH the locally-served ceremony page and the file deployed
// verbatim to the hosted origin (unlock.pkvault.dev) — one artifact, two RPs.
const PAGE = () => fs.readFileSync(path.join(__dirname, "../web/index.html"));
const DEFAULT_CEREMONY_ORIGIN = "https://unlock.pkvault.dev";

function ceremonyOriginForRpId(rpId) {
  if (rpId === "localhost") return "local";
  if (typeof rpId !== "string" || !/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/.test(rpId) || rpId.includes(".."))
    throw err("E_BRIDGE_USAGE", `invalid rp-id: ${rpId}`);
  return `https://${rpId}`;
}

function defaultOpenBrowser(url) {
  const [cmd, args] = process.platform === "darwin"
    ? ["open", [url]]
    : process.platform === "win32"
      ? ["rundll32.exe", ["url.dll,FileProtocolHandler", url]]
      : ["xdg-open", [url]];
  const child = spawn(cmd, args, { stdio: "ignore", detached: true });
  child.unref();
  return child;
}

function decryptPayload(ecdh, code, payloadB64u) {
  let raw;
  try { raw = Buffer.from(payloadB64u, "base64url"); } catch { throw err("E_BRIDGE_PAYLOAD", "payload not base64url"); }
  if (raw.length < 65 + 12 + 16) throw err("E_BRIDGE_PAYLOAD", "payload too short");
  const pagePub = raw.subarray(0, 65);
  const nonce = raw.subarray(65, 77);
  const ct = raw.subarray(77);
  let shared;
  try { shared = ecdh.computeSecret(pagePub); } catch { throw err("E_BRIDGE_PAYLOAD", "bad ephemeral public key"); }
  const key = Buffer.from(crypto.hkdfSync("sha256", shared, Buffer.from(code, "utf8"), Buffer.from("pkvault/bridge/v1", "utf8"), 32));
  const d = crypto.createDecipheriv("aes-256-gcm", key, nonce);
  d.setAAD(Buffer.from(code, "utf8"));
  d.setAuthTag(ct.subarray(-16));
  let pt;
  try { pt = Buffer.concat([d.update(ct.subarray(0, -16)), d.final()]); } catch { throw err("E_BRIDGE_PAYLOAD", "payload does not decrypt (wrong key or tampered)"); }
  let obj;
  try { obj = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(pt)); }
  catch { throw err("E_BRIDGE_PAYLOAD", "payload is not valid UTF-8 JSON"); }
  const prf = Buffer.from(obj.prf ?? "", "base64url");
  const credentialId = Buffer.from(obj.credentialId ?? "", "base64url");
  if (prf.length !== 32) throw err("E_BRIDGE_PAYLOAD", "PRF output must be 32 bytes");
  if (credentialId.length < 8) throw err("E_BRIDGE_PAYLOAD", "missing credential id");
  if (typeof obj.rpId !== "string" || obj.rpId === "") throw err("E_BRIDGE_PAYLOAD", "missing rpId");
  return { prfOutput: prf, credentialId, rpId: obj.rpId };
}

// startCeremony: resolves { prfOutput, credentialId, rpId, prfSalt } or rejects.
// op: "setup" | "unlock"; unlock requires credentialId + prfSalt from the blob.
function startCeremony({
  op, prfSalt, credentialId = null, timeoutMs = 180000,
  ceremonyOrigin = DEFAULT_CEREMONY_ORIGIN,
  openBrowser = defaultOpenBrowser, log = () => {},
}) {
  if (op !== "setup" && op !== "unlock") throw err("E_BRIDGE_USAGE", "op must be setup|unlock");
  if (!Buffer.isBuffer(prfSalt) || prfSalt.length !== 32) throw err("E_BRIDGE_USAGE", "prfSalt must be 32 bytes");
  if (op === "unlock" && !credentialId) throw err("E_BRIDGE_USAGE", "unlock requires credentialId");

  const code = crypto.randomBytes(16).toString("hex");
  const ecdh = crypto.createECDH("prime256v1");
  ecdh.generateKeys();

  return new Promise((resolve, reject) => {
    let settled = false;
    const server = http.createServer((req, res) => {
      const url = new URL(req.url, "http://localhost");
      if (req.method === "GET" && url.pathname === "/") {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
        return res.end(PAGE());
      }
      if (req.method === "GET" && url.pathname === "/callback") {
        if (settled) { res.writeHead(410).end("ceremony already completed"); return; }
        const gotCode = url.searchParams.get("code") ?? "";
        const codeOk = gotCode.length === code.length && crypto.timingSafeEqual(Buffer.from(gotCode), Buffer.from(code));
        if (!codeOk) {
          log("callback with wrong one-time code rejected");
          res.writeHead(403).end("invalid ceremony code");
          return; // do NOT burn the real code on an attacker's guess
        }
        let result;
        try {
          result = decryptPayload(ecdh, code, url.searchParams.get("payload") ?? "");
          if (result.rpId !== expectedRpId)
            throw err("E_BRIDGE_RP_ID", `ceremony returned rp-id ${result.rpId}; expected ${expectedRpId}`);
        } catch (e) {
          res.writeHead(400).end("payload rejected");
          return finish(() => reject(e));
        }
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        res.end(`<body style="font-family:system-ui;max-width:32rem;margin:4rem auto">
          <h2>✅ pkvault: ceremony complete</h2><p>Return to your terminal. You can close this tab.</p></body>`);
        return finish(() => resolve({ ...result, prfSalt }));
      }
      res.writeHead(404).end();
    });

    const timer = setTimeout(() => finish(() => reject(err("E_BRIDGE_TIMEOUT", `no ceremony completion within ${timeoutMs / 1000}s`))), timeoutMs);
    function finish(fn) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      setImmediate(() => server.close());
      fn();
    }

    let expectedRpId;
    server.listen(0, "127.0.0.1", () => {
      const port = server.address().port;
      const params = new URLSearchParams({ op, code, clipub: b64u(ecdh.getPublicKey()), salt: b64u(prfSalt), port: String(port) });
      if (credentialId) params.set("credid", b64u(credentialId));
      let url;
      if (ceremonyOrigin === "local") {
        expectedRpId = "localhost";
        url = `http://localhost:${port}/#${params.toString()}`;
      } else {
        let origin;
        try { origin = new URL(ceremonyOrigin); }
        catch { return finish(() => reject(err("E_BRIDGE_USAGE", `invalid ceremony origin: ${ceremonyOrigin}`))); }
        if (origin.protocol !== "https:" || origin.username || origin.password || origin.search || origin.hash)
          return finish(() => reject(err("E_BRIDGE_USAGE", "ceremony origin must be an HTTPS URL without credentials, query, or fragment")));
        expectedRpId = origin.hostname;
        url = `${origin.origin}${origin.pathname.replace(/\/$/, "")}/#${params.toString()}`;
      }
      log(`ceremony page: ${url}`);
      try {
        const opened = openBrowser(url);
        if (opened && typeof opened.once === "function")
          opened.once("error", (e) => finish(() => reject(err("E_BRIDGE_BROWSER", `could not open browser: ${e.message}`))));
        if (opened && typeof opened.catch === "function")
          opened.catch((e) => finish(() => reject(err("E_BRIDGE_BROWSER", `could not open browser: ${e.message}`))));
      } catch (e) {
        finish(() => reject(err("E_BRIDGE_BROWSER", `could not open browser: ${e.message}`)));
      }
    });
    server.on("error", (e) => finish(() => reject(err("E_BRIDGE_LISTEN", e.message))));
  });
}

module.exports = {
  BridgeError, DEFAULT_CEREMONY_ORIGIN, ceremonyOriginForRpId,
  startCeremony, decryptPayload,
};
