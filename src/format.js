"use strict";
// pkvault v1 wire format (SPEC.md draft 0.10). Zero deps beyond node:crypto.
// Verification order (SPEC §6.2): structural parse → unseal FK → verify MAC → decrypt.

const crypto = require("node:crypto");
const age = require("./age");

// --- errors --------------------------------------------------------------------
class PkvaultError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.code = code;
  }
}
const err = (code, message) => new PkvaultError(code, message);

// --- small helpers ---------------------------------------------------------------
const utf8Ok = (buf) => {
  try { new TextDecoder("utf-8", { fatal: true }).decode(buf); return true; } catch { return false; }
};
function unb64(s, code, what) {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) throw err(code, `non-canonical base64 in ${what}`);
  const buf = Buffer.from(s, "base64");
  if (buf.toString("base64") !== s) throw err(code, `non-canonical base64 in ${what}`);
  return buf;
}
const NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const LABEL_RE = /^[a-z0-9-]{1,32}$/;
const PUBLIC_SUFFIX = " # public";

// --- keys (SPEC §4) ---------------------------------------------------------------
function deriveKeys(fk, fileId) {
  const h = (info) => Buffer.from(crypto.hkdfSync("sha256", fk, fileId, Buffer.from(info, "utf8"), 32));
  return { vek: h("pkvault/vek/v1"), macKey: h("pkvault/mac/v1") };
}

// --- AAD + value tokens (SPEC §3) ---------------------------------------------------
function buildAAD(fileId, name) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(Buffer.byteLength(name, "ascii"));
  return Buffer.concat([Buffer.from("pkvault/value/v1", "utf8"), Buffer.from([0]), fileId, len, Buffer.from(name, "ascii")]);
}

function encryptValue(vek, fileId, name, plaintext /* string */) {
  const pt = Buffer.from(plaintext, "utf8");
  if (pt.includes(0)) throw err("E_PLAINTEXT_DOMAIN", `${name}: NUL not permitted`);
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", vek, nonce);
  c.setAAD(buildAAD(fileId, name));
  const ct = Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
  return `ENC[1:${nonce.toString("base64")}:${ct.toString("base64")}]`;
}

function parseToken(token, name) {
  const m = /^ENC\[([0-9]+):([^:\]]*):([^:\]]*)\]$/.exec(token);
  if (!m) throw err("E_PARSE_TOKEN", `${name}: malformed ENC token`);
  if (!/^[1-9][0-9]*$/.test(m[1])) throw err("E_PARSE_TOKEN", `${name}: bad inner version literal`);
  const v = parseInt(m[1], 10);
  const nonce = unb64(m[2], "E_PARSE_BASE64", `${name} nonce`);
  const ct = unb64(m[3], "E_PARSE_BASE64", `${name} ciphertext`);
  if (nonce.length !== 12) throw err("E_PARSE_TOKEN", `${name}: nonce must decode to 12 bytes`);
  if (ct.length < 16) throw err("E_PARSE_TOKEN", `${name}: ciphertext+tag must be ≥ 16 bytes`);
  return { v, nonce, ct };
}

function decryptValue(vek, fileId, name, tok) {
  if (tok.v !== 1) throw err("E_VALUE_VERSION_UNKNOWN", `${name}: upgrade required, value version ${tok.v}`);
  const d = crypto.createDecipheriv("aes-256-gcm", vek, tok.nonce);
  d.setAAD(buildAAD(fileId, name));
  d.setAuthTag(tok.ct.subarray(-16));
  let pt;
  try {
    pt = Buffer.concat([d.update(tok.ct.subarray(0, -16)), d.final()]);
  } catch {
    throw err("E_GCM", `${name}: decryption failed (tag/AAD)`);
  }
  if (pt.includes(0) || !utf8Ok(pt)) throw err("E_PLAINTEXT_DOMAIN", `${name}: decrypted plaintext violates §2.4`);
  return pt.toString("utf8");
}

// --- recipients line (SPEC §2.2) ------------------------------------------------------
function parseRecipientsLine(line) {
  if (line === "") throw err("E_PARSE_RECIPIENTS", "at least one recipient required");
  const out = [];
  const seenLabels = new Set();
  const seenKeys = new Set();
  for (const entry of line.split(", ")) {
    const eq = entry.indexOf("=");
    if (eq === -1) throw err("E_PARSE_RECIPIENTS", `bad entry: ${entry}`);
    const label = entry.slice(0, eq), recipient = entry.slice(eq + 1);
    if (!LABEL_RE.test(label)) throw err("E_PARSE_RECIPIENTS", `bad label: ${label}`);
    if (seenLabels.has(label)) throw err("E_PARSE_RECIPIENTS", `duplicate label: ${label}`);
    seenLabels.add(label);
    const key = age.decodeRecipient(recipient);
    if (!key) throw err("E_PARSE_RECIPIENTS", `invalid or non-canonical recipient for ${label}`);
    const keyHex = key.toString("hex");
    if (seenKeys.has(keyHex)) throw err("E_PARSE_RECIPIENTS", `duplicate decoded recipient key under ${label}`);
    seenKeys.add(keyHex);
    out.push({ label, recipient, key });
  }
  for (let i = 1; i < out.length; i++)
    if (out[i - 1].label >= out[i].label) throw err("E_PARSE_RECIPIENTS", "labels not in ascending byte order");
  return out;
}
const canonicalRecipientsLine = (recipients) =>
  [...recipients].sort((a, b) => (a.label < b.label ? -1 : 1)).map((r) => `${r.label}=${r.recipient}`).join(", ");

// --- structural parse (SPEC §§2, 6.2 step 1) --------------------------------------------
function parseStructure(bytes) {
  if (bytes.includes(0x0d)) throw err("E_PARSE_CRLF", "CR byte present");
  if (bytes.length === 0 || bytes[bytes.length - 1] !== 0x0a) throw err("E_PARSE_FINAL_LF", "missing final LF");
  if (!utf8Ok(bytes)) throw err("E_PARSE_HEADER", "file is not valid UTF-8");
  const lines = bytes.toString("utf8").split("\n");
  lines.pop(); // final LF → trailing empty element

  // §2.0 version dispatch before v1 layout enforcement
  const v = /^#! pkvault ([0-9]+)$/.exec(lines[0] ?? "");
  if (!v || !/^[1-9][0-9]*$/.test(v[1])) throw err("E_PARSE_HEADER", "first line is not a pkvault version line");
  if (v[1] !== "1") throw err("E_VERSION_UNKNOWN", `upgrade required: file is pkvault ${v[1]}`);

  const expect = (i, prefix) => {
    if (!(lines[i] ?? "").startsWith(prefix)) throw err("E_PARSE_HEADER", `line ${i + 1}: expected "${prefix}"`);
    return lines[i].slice(prefix.length);
  };
  const fileIdB64 = expect(1, "#! file-id: ");
  const sealedB64 = expect(2, "#! sealed: ");
  const recipientsLine = expect(3, "#! recipients: ");
  const macB64 = expect(4, "#! mac: ");
  if (lines[5] !== "") throw err("E_PARSE_HEADER", "missing blank separator line");
  for (let i = 6; i < lines.length; i++)
    if (lines[i].startsWith("#!")) throw err("E_PARSE_BODY", `line ${i + 1}: directive in body`);

  const fileId = unb64(fileIdB64, "E_PARSE_BASE64", "file-id");
  if (fileId.length !== 12) throw err("E_PARSE_HEADER", "file-id must decode to 12 bytes");
  const sealed = unb64(sealedB64, "E_PARSE_BASE64", "sealed");
  const mac = unb64(macB64, "E_PARSE_BASE64", "mac");
  if (mac.length !== 32) throw err("E_PARSE_HEADER", "mac must decode to 32 bytes");
  const recipients = parseRecipientsLine(recipientsLine);

  // body: preamble section then ordinary lines (SPEC §2.3a/b)
  const preamble = [];
  const entries = [];
  const seenNames = new Set(); // case-folded
  let inPreamble = true;
  for (let i = 6; i < lines.length; i++) {
    const line = lines[i], lineNo = i + 1;
    const isAnnotation = line.startsWith("# pkvault:");
    if (isAnnotation) {
      if (!inPreamble) throw err("E_PARSE_PREAMBLE", `line ${lineNo}: annotation after ordinary body`);
      preamble.push(line);
      continue;
    }
    inPreamble = false;
    if (line === "") { entries.push({ type: "blank", line, lineNo }); continue; }
    if (line.startsWith("#")) { entries.push({ type: "comment", line, lineNo }); continue; }
    const eq = line.indexOf("=");
    if (eq === -1) throw err("E_PARSE_BODY", `line ${lineNo}: not an assignment`);
    const name = line.slice(0, eq);
    if (!NAME_RE.test(name)) throw err("E_PARSE_BODY", `line ${lineNo}: bad NAME "${name}"`);
    const folded = name.toLowerCase();
    if (seenNames.has(folded)) throw err("E_PARSE_NAME_DUP", `line ${lineNo}: duplicate name (case-folded): ${name}`);
    seenNames.add(folded);
    const rest = line.slice(eq + 1);
    if (rest.startsWith("ENC[")) {
      const tok = parseToken(rest, name);
      entries.push({ type: "secret", name, token: rest, tok, line, lineNo });
    } else if (rest.endsWith(PUBLIC_SUFFIX)) {
      const value = rest.slice(0, -PUBLIC_SUFFIX.length);
      if (value.includes("#")) throw err("E_PARSE_BODY", `line ${lineNo}: '#' in public value`);
      if (value.includes("\0")) throw err("E_PARSE_BODY", `line ${lineNo}: NUL in public value`); // §2.4 domain applies to every value
      if (/[ \t]$/.test(value)) throw err("E_PARSE_BODY", `line ${lineNo}: trailing whitespace in public value`);
      entries.push({ type: "public", name, value, line, lineNo });
    } else {
      if (rest.includes("#")) throw err("E_PARSE_BODY", `line ${lineNo}: inline comment or malformed marker`);
      throw err("E_PARSE_UNMARKED", `line ${lineNo}: unmarked plaintext assignment`);
    }
  }
  for (let i = 1; i < preamble.length; i++)
    if (preamble[i - 1] >= preamble[i]) throw err("E_PARSE_PREAMBLE", "preamble annotations not a sorted set");

  return { fileId, sealed, recipients, recipientsLine, mac, preamble, entries, lines };
}

// --- MAC (SPEC §6.1) --------------------------------------------------------------------
function macInput(bytes) {
  const s = bytes.toString("utf8");
  const start = s.indexOf("#! mac: ");
  if (start === -1) throw err("E_PARSE_HEADER", "no mac line");
  const end = s.indexOf("\n", start);
  return Buffer.from(s.slice(0, start) + s.slice(end + 1), "utf8");
}
function computeMac(bytes, macKey) {
  return crypto.createHmac("sha256", macKey).update(macInput(bytes)).digest();
}
function verifyMac(bytes, parsed, macKey) {
  if (!crypto.timingSafeEqual(computeMac(bytes, macKey), parsed.mac)) throw err("E_MAC", "file bytes are not authentic");
}

// --- unseal (SPEC §5 strict reader) -------------------------------------------------------
function unsealFK(parsed, identityScalar) {
  let fk;
  try {
    fk = age.decrypt(parsed.sealed, identityScalar, parsed.recipients.length);
  } catch (e) {
    if (e.message === "ENVELOPE_NO_MATCH") throw err("E_UNSEAL", "identity cannot unseal this file");
    throw err("E_ENVELOPE", e.message);
  }
  return fk;
}

// --- serialization ----------------------------------------------------------------------
function serialize({ fileId, fk, recipients, preamble, entries }) {
  if (!Buffer.isBuffer(fileId) || fileId.length !== 12) throw err("E_PARSE_HEADER", "file-id must be 12 bytes");
  if (!Buffer.isBuffer(fk) || fk.length !== 32) throw err("E_ENVELOPE", "file key must be 32 bytes");
  if (!Array.isArray(recipients) || recipients.length === 0) throw err("E_PARSE_RECIPIENTS", "at least one recipient required");
  if (!Array.isArray(preamble) || !Array.isArray(entries)) throw err("E_PARSE_BODY", "preamble and entries must be arrays");

  // Treat serializer inputs as untrusted too. Re-decode recipient strings and
  // use those decoded keys, so a caller cannot pair a displayed recipient with
  // a different encryption key.
  const recipientsLine = canonicalRecipientsLine(recipients);
  const normalizedRecipients = parseRecipientsLine(recipientsLine);
  const sealed = age.encrypt(fk, normalizedRecipients.map((r) => r.key));
  const head =
    `#! pkvault 1\n` +
    `#! file-id: ${fileId.toString("base64")}\n` +
    `#! sealed: ${sealed.toString("base64")}\n` +
    `#! recipients: ${recipientsLine}\n`;
  const body =
    [...preamble].sort().map((l) => l + "\n").join("") +
    entries.map((e) => e.line + "\n").join("");
  const { macKey } = deriveKeys(fk, fileId);
  const noMac = head + `\n` + body;
  // mac input = full file minus mac line → equals head + separator + body exactly
  const mac = crypto.createHmac("sha256", macKey).update(noMac).digest();
  const out = Buffer.from(head + `#! mac: ${mac.toString("base64")}\n` + `\n` + body, "utf8");
  // A serializer must never emit bytes its own structural parser rejects.
  parseStructure(out);
  return out;
}

// --- high-level operations -------------------------------------------------------------------
// Full read pipeline. Returns { parsed, fk, keys, values: Map(name → plaintext|{unknownVersion}) }
function open(bytes, identityScalar, { decrypt = true, dangerouslySkipMac = false } = {}) {
  const parsed = parseStructure(bytes);
  const fk = unsealFK(parsed, identityScalar);
  const keys = deriveKeys(fk, parsed.fileId);
  // dangerouslySkipMac exists ONLY for the SPEC §8.1 unverified-merge override;
  // it relaxes MAC authenticity and nothing else — GCM + §2.4 still apply below.
  if (!dangerouslySkipMac) verifyMac(bytes, parsed, keys.macKey);
  const values = new Map();
  if (decrypt)
    for (const e of parsed.entries) {
      if (e.type === "public") values.set(e.name, e.value);
      if (e.type === "secret") {
        if (e.tok.v !== 1) values.set(e.name, { unknownVersion: e.tok.v });
        else values.set(e.name, decryptValue(keys.vek, parsed.fileId, e.name, e.tok));
      }
    }
  return { parsed, fk, keys, values };
}

// get: targeted read; run: needs the complete environment (SPEC §3).
function get(bytes, identityScalar, name) {
  const { parsed, keys } = open(bytes, identityScalar, { decrypt: false });
  const e = parsed.entries.find((x) => (x.type === "secret" || x.type === "public") && x.name === name);
  if (!e) throw err("E_NO_SUCH_NAME", name);
  if (e.type === "public") return e.value;
  return decryptValue(keys.vek, parsed.fileId, name, e.tok);
}
function runEnv(bytes, identityScalar) {
  const { values } = open(bytes, identityScalar);
  const env = {};
  for (const [k, v] of values) {
    if (typeof v !== "string") throw err("E_VALUE_VERSION_UNKNOWN", `${k}: upgrade required, value version ${v.unknownVersion}`);
    env[k] = v;
  }
  return env;
}

const hasUnknownVersion = (parsed) => parsed.entries.some((e) => e.type === "secret" && e.tok.v !== 1);
function assertRewritable(parsed) {
  if (hasUnknownVersion(parsed))
    throw err("E_VALUE_VERSION_UNKNOWN", "file contains a future value version; rewrite refused, file untouched");
}

// Create a new vault file from template entries: [{comment}|{blank}|{name, value, public?}]
function create({ recipients, template, fileId = crypto.randomBytes(12), fk = crypto.randomBytes(32) }) {
  const { vek } = deriveKeys(fk, fileId);
  const entries = template.map((t) => {
    if (t.comment !== undefined) return { type: "comment", line: t.comment };
    if (t.blank) return { type: "blank", line: "" };
    if (t.public) return { type: "public", name: t.name, line: `${t.name}=${t.value}${PUBLIC_SUFFIX}` };
    return { type: "secret", name: t.name, line: `${t.name}=${encryptValue(vek, fileId, t.name, t.value)}` };
  });
  return serialize({ fileId, fk, recipients, preamble: [], entries });
}

// Save with changed values: untouched ENC tokens copy byte-identically (SPEC §3).
function save(bytes, identityScalar, updates /* Map name → newPlaintext */) {
  const { parsed, fk, keys } = open(bytes, identityScalar, { decrypt: false });
  assertRewritable(parsed);
  const entries = parsed.entries.map((e) => {
    if ((e.type === "secret" || e.type === "public") && updates.has(e.name)) {
      const nv = updates.get(e.name);
      if (e.type === "public") return { ...e, line: `${e.name}=${nv}${PUBLIC_SUFFIX}` };
      return { ...e, line: `${e.name}=${encryptValue(keys.vek, parsed.fileId, e.name, nv)}` };
    }
    return e;
  });
  return serialize({ fileId: parsed.fileId, fk, recipients: parsed.recipients, preamble: parsed.preamble, entries });
}

// Reseal (add recipients): FK unchanged, body byte-stable (SPEC §5).
function reseal(bytes, identityScalar, newRecipients) {
  const { parsed, fk } = open(bytes, identityScalar, { decrypt: false });
  assertRewritable(parsed);
  return serialize({ fileId: parsed.fileId, fk, recipients: newRecipients, preamble: parsed.preamble, entries: parsed.entries });
}

// Rotate (remove recipients): fresh FK, every value re-encrypted (SPEC §5).
function rotate(bytes, identityScalar, newRecipients) {
  const { parsed, values } = open(bytes, identityScalar);
  assertRewritable(parsed);
  const fk = crypto.randomBytes(32);
  const { vek } = deriveKeys(fk, parsed.fileId);
  const entries = parsed.entries.map((e) => {
    if (e.type === "secret")
      return { ...e, line: `${e.name}=${encryptValue(vek, parsed.fileId, e.name, values.get(e.name))}` };
    return e;
  });
  return serialize({ fileId: parsed.fileId, fk, recipients: newRecipients, preamble: parsed.preamble, entries });
}

// N3's anomaly check: a diff that removes a recipient but leaves body bytes unchanged.
function analyzeReseal(oldBytes, newBytes) {
  const bodyOf = (b) => b.toString("utf8").split("\n").slice(6).join("\n");
  const recsOf = (b) => parseStructure(b).recipients.map((r) => r.key.toString("hex"));
  const oldR = recsOf(oldBytes), newR = recsOf(newBytes);
  const removed = oldR.filter((k) => !newR.includes(k));
  const bodyStable = bodyOf(oldBytes) === bodyOf(newBytes);
  return { removed: removed.length > 0, bodyStable, anomalousRemove: removed.length > 0 && bodyStable };
}

module.exports = {
  PkvaultError, deriveKeys, buildAAD, encryptValue, parseToken, decryptValue,
  parseRecipientsLine, canonicalRecipientsLine, parseStructure, macInput, computeMac,
  verifyMac, unsealFK, serialize, open, get, runEnv, create, save, reseal, rotate, analyzeReseal,
  assertRewritable,
};
