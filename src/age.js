"use strict";
// Minimal age v1 (X25519 recipients only) on node:crypto. Zero deps.
// Writer: never greases, X25519 stanzas only (SPEC §5 writer obligations).
// Reader: strict — any non-X25519 stanza rejects (SPEC §5 reader validation).

const crypto = require("node:crypto");
const bech32 = require("./bech32");

const VERSION_LINE = "age-encryption.org/v1";
// Fixed DER prefixes for raw X25519 key import (RFC 8410 structures).
const PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

const b64 = (buf) => Buffer.from(buf).toString("base64").replace(/=+$/, ""); // age header b64: std, unpadded
function unb64(s) {
  if (!/^[A-Za-z0-9+/]*$/.test(s)) return null;
  const buf = Buffer.from(s, "base64");
  if (b64(buf) !== s) return null; // canonical
  return buf;
}

function privKey(scalar32) {
  return crypto.createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, scalar32]), format: "der", type: "pkcs8" });
}
function pubKey(raw32) {
  return crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw32]), format: "der", type: "spki" });
}
function publicFromScalar(scalar32) {
  const pub = crypto.createPublicKey(privKey(scalar32));
  return pub.export({ format: "der", type: "spki" }).subarray(-32);
}
function x25519(scalar32, theirPub32) {
  return crypto.diffieHellman({ privateKey: privKey(scalar32), publicKey: pubKey(theirPub32) });
}
const hkdf = (ikm, salt, info, len) =>
  Buffer.from(crypto.hkdfSync("sha256", ikm, salt, Buffer.from(info, "utf8"), len));

function chachaSeal(key, nonce, plaintext) {
  const c = crypto.createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  return Buffer.concat([c.update(plaintext), c.final(), c.getAuthTag()]);
}
function chachaOpen(key, nonce, ctAndTag) {
  if (ctAndTag.length < 16) return null;
  const d = crypto.createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  d.setAuthTag(ctAndTag.subarray(-16));
  try {
    return Buffer.concat([d.update(ctAndTag.subarray(0, -16)), d.final()]);
  } catch {
    return null;
  }
}

// --- identity / recipient strings -------------------------------------------
function keygen(scalar32 = crypto.randomBytes(32)) {
  return { scalar: scalar32, recipient: encodeRecipient(publicFromScalar(scalar32)), identity: encodeIdentity(scalar32) };
}
const encodeRecipient = (pub32) => bech32.encode("age", pub32);
const encodeIdentity = (scalar32) => bech32.encode("age-secret-key-", scalar32).toUpperCase();
function decodeRecipient(str) {
  if (str !== str.toLowerCase()) return null; // canonical lowercase required (SPEC §2.2)
  const d = bech32.decode(str);
  if (!d || d.hrp !== "age" || d.data.length !== 32) return null;
  if (bech32.encode("age", d.data) !== str) return null; // canonical re-encoding
  return d.data;
}
function decodeIdentity(str) {
  const d = bech32.decode(str);
  if (!d || d.hrp !== "age-secret-key-" || d.data.length !== 32) return null;
  return d.data;
}

// --- encrypt ------------------------------------------------------------------
function encrypt(payload, recipientPubs /* Buffer32[] */) {
  const fileKey = crypto.randomBytes(16);
  let header = VERSION_LINE + "\n";
  for (const pub of recipientPubs) {
    const eph = crypto.generateKeyPairSync("x25519");
    const ephPub = eph.publicKey.export({ format: "der", type: "spki" }).subarray(-32);
    const ephScalar = eph.privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32);
    const shared = x25519(ephScalar, pub);
    if (shared.every((x) => x === 0)) throw new Error("low-order recipient point");
    const wrapKey = hkdf(shared, Buffer.concat([ephPub, pub]), "age-encryption.org/v1/X25519", 32);
    const body = chachaSeal(wrapKey, Buffer.alloc(12), fileKey); // 32 bytes → one 43-char b64 line (< 64)
    header += `-> X25519 ${b64(ephPub)}\n${b64(body)}\n`;
  }
  header += "---";
  const hmacKey = hkdf(fileKey, Buffer.alloc(0), "header", 32);
  const mac = crypto.createHmac("sha256", hmacKey).update(header).digest();
  header += ` ${b64(mac)}\n`;

  const nonce16 = crypto.randomBytes(16);
  const payloadKey = hkdf(fileKey, nonce16, "payload", 32);
  const chunkNonce = Buffer.alloc(12);
  chunkNonce[11] = 1; // counter 0, last-chunk flag (single chunk; payloads here are 32 bytes)
  const body = chachaSeal(payloadKey, chunkNonce, payload);
  return Buffer.concat([Buffer.from(header, "utf8"), nonce16, body]);
}

// --- parse + strict validation --------------------------------------------------
// Returns { stanzas: [{args, body}], headerNoMac, mac, payload } or throws Error(code).
function parseEnvelope(bytes) {
  const nl = (from) => bytes.indexOf(0x0a, from);
  let pos = nl(0);
  if (pos === -1 || bytes.subarray(0, pos).toString() !== VERSION_LINE) throw new Error("ENVELOPE_NOT_AGE");
  pos += 1;
  const stanzas = [];
  for (;;) {
    let end = nl(pos);
    if (end === -1) throw new Error("ENVELOPE_TRUNCATED");
    const line = bytes.subarray(pos, end).toString();
    if (line.startsWith("--- ") || line === "---") {
      const macB64 = line === "---" ? "" : line.slice(4);
      const mac = unb64(macB64);
      if (!mac || mac.length !== 32) throw new Error("ENVELOPE_BAD_MAC_LINE");
      return { stanzas, headerThroughDashes: bytes.subarray(0, pos).toString() + "---", mac, payload: bytes.subarray(end + 1) };
    }
    if (!line.startsWith("-> ")) throw new Error("ENVELOPE_BAD_STANZA");
    const args = line.slice(3).split(" ");
    pos = end + 1;
    const bodyLines = [];
    for (;;) {
      end = nl(pos);
      if (end === -1) throw new Error("ENVELOPE_TRUNCATED");
      const bl = bytes.subarray(pos, end).toString();
      if (!/^[A-Za-z0-9+/]*$/.test(bl) || bl.length > 64) throw new Error("ENVELOPE_BAD_STANZA");
      bodyLines.push(bl);
      pos = end + 1;
      if (bl.length < 64) break;
    }
    const body = unb64(bodyLines.join(""));
    if (body === null) throw new Error("ENVELOPE_BAD_STANZA");
    stanzas.push({ args, body });
  }
}

// Strict SPEC §5 reader: X25519-only, count == expectedCount, payload exactly 32 bytes.
function decrypt(bytes, identityScalar, expectedCount) {
  const env = parseEnvelope(bytes);
  for (const s of env.stanzas)
    if (s.args[0] !== "X25519") throw new Error("ENVELOPE_FOREIGN_STANZA");
  if (env.stanzas.length !== expectedCount) throw new Error("ENVELOPE_STANZA_COUNT");
  const ourPub = publicFromScalar(identityScalar);
  let fileKey = null;
  for (const s of env.stanzas) {
    if (s.args.length !== 2) throw new Error("ENVELOPE_BAD_STANZA");
    const ephPub = unb64(s.args[1]);
    if (!ephPub || ephPub.length !== 32 || s.body.length !== 32) throw new Error("ENVELOPE_BAD_STANZA");
    const shared = x25519(identityScalar, ephPub);
    if (shared.every((x) => x === 0)) continue;
    const wrapKey = hkdf(shared, Buffer.concat([ephPub, ourPub]), "age-encryption.org/v1/X25519", 32);
    const fk = chachaOpen(wrapKey, Buffer.alloc(12), s.body);
    if (fk) { fileKey = fk; break; }
  }
  if (!fileKey) throw new Error("ENVELOPE_NO_MATCH");
  const hmacKey = hkdf(fileKey, Buffer.alloc(0), "header", 32);
  const mac = crypto.createHmac("sha256", hmacKey).update(env.headerThroughDashes).digest();
  if (!crypto.timingSafeEqual(mac, env.mac)) throw new Error("ENVELOPE_HEADER_MAC");
  if (env.payload.length < 16 + 16) throw new Error("ENVELOPE_TRUNCATED");
  const nonce16 = env.payload.subarray(0, 16);
  const payloadKey = hkdf(fileKey, nonce16, "payload", 32);
  const chunkNonce = Buffer.alloc(12);
  chunkNonce[11] = 1;
  const payload = chachaOpen(payloadKey, chunkNonce, env.payload.subarray(16));
  if (payload === null) throw new Error("ENVELOPE_PAYLOAD");
  if (payload.length !== 32) throw new Error("ENVELOPE_PAYLOAD_LENGTH");
  return payload;
}

module.exports = { keygen, encodeRecipient, encodeIdentity, decodeRecipient, decodeIdentity, publicFromScalar, encrypt, decrypt, parseEnvelope };
