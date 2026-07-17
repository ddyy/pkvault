"use strict";
// SPEC-IDENTITY v1: wrapped identity blobs (.pkvault/identities/<label>.wrap).
// PRF/recovery KEKs → AES-256-GCM wrap of the X25519 scalar; self-authenticating
// via derive-public-and-compare (no MAC key to manage).

const crypto = require("node:crypto");
const age = require("./age");

class IdentityError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.code = code;
  }
}
const err = (code, m) => new IdentityError(code, m);

const LABEL_RE = /^[a-z0-9-]{1,32}$/;
const RP_ID_RE = /^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/;
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const b64 = (b) => Buffer.from(b).toString("base64");
function unb64(s, what) {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) throw err("E_IDENTITY_PARSE", `non-canonical base64 in ${what}`);
  const buf = Buffer.from(s, "base64");
  if (buf.toString("base64") !== s) throw err("E_IDENTITY_PARSE", `non-canonical base64 in ${what}`);
  return buf;
}

// --- KEKs (SPEC-IDENTITY §2) --------------------------------------------------------
const kekFromPrf = (prfOutput32, recipientPub32) =>
  Buffer.from(crypto.hkdfSync("sha256", prfOutput32, recipientPub32, Buffer.from("pkvault/kek/prf/v1", "utf8"), 32));

// scrypt memory ≈ 128·N·r = 128·2^logN·8 bytes. With MAXMEM = 256 MiB the
// largest USABLE logN is 17 (128 MiB, comfortable headroom); logN 18+ would
// throw ERR_CRYPTO_INVALID_SCRYPT_PARAMS on Node 18. The accepted range must
// equal the usable range — every accepted value must actually run everywhere.
const SCRYPT_MIN_LOGN = 10, SCRYPT_MAX_LOGN = 17, SCRYPT_MAXMEM = 256 * 1024 * 1024;
function kekFromRecovery(code, scryptSalt, logN) {
  if (!Number.isInteger(logN) || logN < SCRYPT_MIN_LOGN || logN > SCRYPT_MAX_LOGN)
    throw err("E_IDENTITY_SCRYPT_PARAM", `logN ${logN} outside ${SCRYPT_MIN_LOGN}..${SCRYPT_MAX_LOGN}`);
  const normalized = code.toUpperCase().replace(/[- ]/g, "");
  return crypto.scryptSync(Buffer.from(normalized, "utf8"), scryptSalt, 32, { N: 2 ** logN, r: 8, p: 1, maxmem: SCRYPT_MAXMEM });
}

function newRecoveryCode() {
  const raw = crypto.randomBytes(20);
  let bits = 0n;
  for (const byte of raw) bits = (bits << 8n) | BigInt(byte);
  let chars = "";
  for (let i = 0; i < 32; i++) {
    chars = CROCKFORD[Number(bits & 31n)] + chars;
    bits >>= 5n;
  }
  return "PKVR-" + chars.match(/.{4}/g).join("-");
}

// --- wrap / unwrap (SPEC-IDENTITY §3–4) -------------------------------------------------
const aad = (recipientPub32, type) =>
  Buffer.concat([Buffer.from("pkvault/identity/v1", "utf8"), Buffer.from([0]), recipientPub32, Buffer.from(type, "utf8")]);

function seal(kek, recipientPub32, type, scalar32) {
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", kek, nonce);
  c.setAAD(aad(recipientPub32, type));
  const ct = Buffer.concat([c.update(scalar32), c.final(), c.getAuthTag()]);
  return { nonce, ct };
}
function openWrap(kek, recipientPub32, type, nonce, ct) {
  const d = crypto.createDecipheriv("aes-256-gcm", kek, nonce);
  d.setAAD(aad(recipientPub32, type));
  d.setAuthTag(ct.subarray(-16));
  let scalar;
  try {
    scalar = Buffer.concat([d.update(ct.subarray(0, -16)), d.final()]);
  } catch {
    throw err("E_IDENTITY_KEK", `${type} wrap did not open (wrong PRF output / recovery code, or tampered blob)`);
  }
  // self-authentication: recovered scalar must reproduce the blob's public half
  if (!age.publicFromScalar(scalar).equals(recipientPub32))
    throw err("E_IDENTITY_PUB_MISMATCH", "recovered identity does not match the blob's recipient");
  return scalar;
}

// --- blob serialization ---------------------------------------------------------------------
function serializeBlob({ label, recipient, wraps }) {
  if (!LABEL_RE.test(label ?? "")) throw err("E_IDENTITY_PARSE", "bad label");
  if (!age.decodeRecipient(recipient ?? "")) throw err("E_IDENTITY_PARSE", "bad recipient");
  if (!Array.isArray(wraps) || wraps.length === 0) throw err("E_IDENTITY_NO_WRAP", "blob contains no wraps");
  const lines = [`#! pkvault-identity 1`, `#! label: ${label}`, `#! recipient: ${recipient}`, ``];
  for (const w of wraps) {
    if (w.type === "prf") {
      if (!RP_ID_RE.test(w.rpId ?? "") || w.rpId.includes("..")) throw err("E_IDENTITY_PARSE", "bad PRF rp-id");
      lines.push(`wrap prf ${b64(w.credentialId)} ${w.rpId} ${b64(w.prfSalt)} ${b64(w.nonce)} ${b64(w.ct)}`);
    }
    else if (w.type === "recovery") lines.push(`wrap recovery ${b64(w.scryptSalt)} ${w.logN} ${b64(w.nonce)} ${b64(w.ct)}`);
    else lines.push(w.raw); // unknown wrap preserved verbatim
  }
  const out = Buffer.from(lines.join("\n") + "\n", "utf8");
  parseBlob(out); // serializer output must satisfy the same strict grammar
  return out;
}

function parseBlob(bytes) {
  if (bytes.includes(0x0d)) throw err("E_IDENTITY_PARSE", "CR byte present");
  if (bytes.length === 0 || bytes[bytes.length - 1] !== 0x0a) throw err("E_IDENTITY_PARSE", "missing final LF");
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { throw err("E_IDENTITY_PARSE", "not valid UTF-8"); }
  const lines = text.split("\n");
  lines.pop();
  const v = /^#! pkvault-identity ([0-9]+)$/.exec(lines[0] ?? "");
  if (!v || !/^[1-9][0-9]*$/.test(v[1])) throw err("E_IDENTITY_PARSE", "first line is not an identity version line");
  if (v[1] !== "1") throw err("E_IDENTITY_VERSION", `upgrade required: blob is pkvault-identity ${v[1]}`);
  const label = (lines[1] ?? "").startsWith("#! label: ") ? lines[1].slice(10) : null;
  const recipient = (lines[2] ?? "").startsWith("#! recipient: ") ? lines[2].slice(14) : null;
  if (!label || !LABEL_RE.test(label)) throw err("E_IDENTITY_PARSE", "bad or missing label");
  const pub = recipient && age.decodeRecipient(recipient);
  if (!pub) throw err("E_IDENTITY_PARSE", "bad or missing recipient");
  if (lines[3] !== "") throw err("E_IDENTITY_PARSE", "missing blank separator");

  const wraps = [];
  for (let i = 4; i < lines.length; i++) {
    const parts = lines[i].split(" ");
    if (parts[0] !== "wrap" || parts.length < 2) throw err("E_IDENTITY_PARSE", `line ${i + 1}: not a wrap line`);
    if (parts[1] === "prf") {
      if (parts.length !== 7) throw err("E_IDENTITY_PARSE", `line ${i + 1}: prf wrap needs 5 fields`);
      if (!RP_ID_RE.test(parts[3]) || parts[3].includes("..")) throw err("E_IDENTITY_PARSE", `line ${i + 1}: bad rp-id`);
      const [credentialId, prfSalt, nonce, ct] = [unb64(parts[2], "cred-id"), unb64(parts[4], "prf-salt"), unb64(parts[5], "nonce"), unb64(parts[6], "ct")];
      if (prfSalt.length !== 32 || nonce.length !== 12 || ct.length < 16) throw err("E_IDENTITY_PARSE", `line ${i + 1}: bad field lengths`);
      wraps.push({ type: "prf", credentialId, rpId: parts[3], prfSalt, nonce, ct });
    } else if (parts[1] === "recovery") {
      if (parts.length !== 6) throw err("E_IDENTITY_PARSE", `line ${i + 1}: recovery wrap needs 4 fields`);
      const logN = /^[1-9][0-9]?$/.test(parts[3]) ? parseInt(parts[3], 10) : NaN;
      if (!Number.isInteger(logN) || logN < SCRYPT_MIN_LOGN || logN > SCRYPT_MAX_LOGN) throw err("E_IDENTITY_SCRYPT_PARAM", `line ${i + 1}: logN outside ${SCRYPT_MIN_LOGN}..${SCRYPT_MAX_LOGN}`);
      const [scryptSalt, nonce, ct] = [unb64(parts[2], "scrypt-salt"), unb64(parts[4], "nonce"), unb64(parts[5], "ct")];
      if (scryptSalt.length !== 16 || nonce.length !== 12 || ct.length < 16) throw err("E_IDENTITY_PARSE", `line ${i + 1}: bad field lengths`);
      wraps.push({ type: "recovery", scryptSalt, logN, nonce, ct });
    } else {
      wraps.push({ type: "unknown", wrapType: parts[1], raw: lines[i] }); // per-line upgrade-required
    }
  }
  if (wraps.length === 0) throw err("E_IDENTITY_NO_WRAP", "blob contains no wraps");
  if (!wraps.some((w) => w.type !== "unknown")) throw err("E_IDENTITY_NO_WRAP", "no usable wraps (all are newer versions — upgrade required)");
  return { label, recipient, pub, wraps };
}

// --- high-level ----------------------------------------------------------------------------------
// Mint a new identity: returns scalar + recipient; caller adds wraps then serializes.
function mintIdentity() {
  const scalar = crypto.randomBytes(32);
  return { scalar, recipient: age.encodeRecipient(age.publicFromScalar(scalar)) };
}

function makePrfWrap({ scalar, pub, credentialId, rpId, prfOutput, prfSalt }) {
  const kek = kekFromPrf(prfOutput, pub);
  const { nonce, ct } = seal(kek, pub, "prf", scalar);
  return { type: "prf", credentialId, rpId, prfSalt, nonce, ct };
}

function recoveryWrapForCode({ scalar, pub, code }) {
  const scryptSalt = crypto.randomBytes(16);
  const logN = 15;
  const kek = kekFromRecovery(code, scryptSalt, logN);
  const { nonce, ct } = seal(kek, pub, "recovery", scalar);
  return { type: "recovery", scryptSalt, logN, nonce, ct };
}
function makeRecoveryWrap({ scalar, pub }) {
  const code = newRecoveryCode();
  return { code, wrap: recoveryWrapForCode({ scalar, pub, code }) };
}

function unwrapWithPrf(blob, credentialId, prfOutput) {
  const w = blob.wraps.find((x) => x.type === "prf" && x.credentialId.equals(credentialId));
  if (!w) throw err("E_IDENTITY_NO_WRAP", "no prf wrap for that credential");
  return openWrap(kekFromPrf(prfOutput, blob.pub), blob.pub, "prf", w.nonce, w.ct);
}

function unwrapWithRecovery(blob, code) {
  const w = blob.wraps.find((x) => x.type === "recovery");
  if (!w) throw err("E_IDENTITY_NO_WRAP", "no recovery wrap in blob");
  return openWrap(kekFromRecovery(code, w.scryptSalt, w.logN), blob.pub, "recovery", w.nonce, w.ct);
}

// SPEC-IDENTITY §5: recovery re-wraps the identity under a FRESH passkey (you
// lost the old one). It does NOT — cannot — burn the recovery code: the X25519
// scalar is the identity forever, so any retained pre-recovery blob (git
// history, clones, backups) still unwraps that same scalar with the same code.
// The code is therefore PERMANENT recovery escrow. The re-wrap keeps the same
// code (fresh scrypt salt) rather than pretending a new one revokes the old.
// True revocation = rotate identity (a fresh `setup`) + be re-added to vaults.
function recoverAndRewrap(blob, code, { credentialId, rpId, prfOutput, prfSalt }) {
  const scalar = unwrapWithRecovery(blob, code); // also verifies the code against THIS blob
  const prfWrap = makePrfWrap({ scalar, pub: blob.pub, credentialId, rpId, prfOutput, prfSalt });
  const recoveryWrap = recoveryWrapForCode({ scalar, pub: blob.pub, code }); // same code, new salt
  const kept = blob.wraps.filter((w) => w.type === "unknown"); // future wraps preserved verbatim
  return {
    blob: serializeBlob({ label: blob.label, recipient: blob.recipient, wraps: [prfWrap, recoveryWrap, ...kept] }),
  };
}

module.exports = {
  IdentityError, mintIdentity, newRecoveryCode, kekFromPrf, kekFromRecovery,
  makePrfWrap, makeRecoveryWrap, recoveryWrapForCode, serializeBlob, parseBlob,
  unwrapWithPrf, unwrapWithRecovery, recoverAndRewrap,
};
