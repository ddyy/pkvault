"use strict";
// One ceremony → unwrapped identity scalar. Shared by the CLI (per-command
// fallback) and the agent (cached, one tap per day).

const fs = require("node:fs");
const path = require("node:path");
const bridge = require("./bridge");
const idn = require("./identity");
const manifestlib = require("./manifest");
const txn = require("./txn");

const LABEL_RE = /^[a-z0-9-]{1,32}$/;
const MANIFEST = ".pkvault/recipients.toml";

function blobPath(home, label) {
  return path.join(home, `${label}.wrap`);
}

function readRegular(abs) {
  const st = fs.lstatSync(abs);
  if (!st.isFile() || st.isSymbolicLink()) {
    const e = new Error(`E_NO_IDENTITY: identity blob is not a regular file: ${abs}`);
    e.code = "E_NO_IDENTITY";
    throw e;
  }
  return fs.readFileSync(abs);
}

function verifyBlob(bytes, { label, recipient = null, manifest = null } = {}) {
  const blob = idn.parseBlob(bytes);
  if (label && blob.label !== label) {
    const e = new Error(`E_IDENTITY_PARSE: blob label ${blob.label} does not match ${label}`);
    e.code = "E_IDENTITY_PARSE";
    throw e;
  }
  if (recipient && blob.recipient !== recipient) {
    const e = new Error("E_IDENTITY_PUB_MISMATCH: blob recipient does not match requested recipient");
    e.code = "E_IDENTITY_PUB_MISMATCH";
    throw e;
  }
  if (manifest && !manifest.some((r) => r.label === blob.label && r.recipient === blob.recipient)) {
    const e = new Error(`E_IDENTITY_PUB_MISMATCH: ${blob.label}'s blob recipient is not the manifest recipient`);
    e.code = "E_IDENTITY_PUB_MISMATCH";
    throw e;
  }
  return blob;
}

function loadBlob({ label, home, repoRoot = null }) {
  if (!LABEL_RE.test(label ?? "")) {
    const e = new Error("E_NO_IDENTITY: invalid identity label");
    e.code = "E_NO_IDENTITY";
    throw e;
  }
  const candidates = [];
  if (repoRoot) {
    const rel = `.pkvault/identities/${label}.wrap`;
    candidates.push({ path: txn.validateAncestors(repoRoot, rel), repo: true });
  }
  if (home) candidates.push({ path: blobPath(home, label), repo: false });
  const found = candidates.find((p) => fs.existsSync(p.path));
  if (!found) {
    const e = new Error(`E_NO_IDENTITY: no identity blob for ${label} (checked ${candidates.map((p) => p.path).join(", ")})`);
    e.code = "E_NO_IDENTITY";
    throw e;
  }
  let manifest = null;
  if (repoRoot) manifest = manifestlib.parseManifest(readRegular(txn.validateAncestors(repoRoot, MANIFEST)));
  return { path: found.path, blob: verifyBlob(readRegular(found.path), { label, manifest }) };
}

async function ceremonyUnlock({ label, home, repoRoot = null, bridgeOpts = {} }) {
  const { blob } = loadBlob({ label, home, repoRoot });
  const prfWrap = blob.wraps.find((w) => w.type === "prf");
  if (!prfWrap) {
    const e = new Error("E_NO_IDENTITY: blob has no passkey wrap; use `pkvault recover`");
    e.code = "E_NO_IDENTITY";
    throw e;
  }
  const res = await bridge.startCeremony({
    op: "unlock",
    prfSalt: prfWrap.prfSalt,
    credentialId: prfWrap.credentialId,
    ceremonyOrigin: bridge.ceremonyOriginForRpId(prfWrap.rpId),
    ...bridgeOpts,
  });
  if (res.rpId !== prfWrap.rpId) {
    const e = new Error(`E_IDENTITY_KEK: passkey RP ${res.rpId} does not match stored RP ${prfWrap.rpId}`);
    e.code = "E_IDENTITY_KEK";
    throw e;
  }
  return { scalar: idn.unwrapWithPrf(blob, res.credentialId, res.prfOutput), recipient: blob.recipient, label };
}

module.exports = { ceremonyUnlock, blobPath, loadBlob, verifyBlob };
