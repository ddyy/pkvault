"use strict";
// recipients.toml + config.toml — the tiny TOML subset of SPEC-MANIFEST.md §§2–3.
// One unambiguous parse or no parse.

const age = require("./age");

class ManifestError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.code = code;
  }
}
const err = (code, m) => new ManifestError(code, m);

const LABEL_RE = /^[a-z0-9-]{1,32}$/;
const LINE_RE = /^([A-Za-z0-9_-]+) = "([^"\\]*)"$/;

function parseLines(bytes, codePrefix) {
  if (bytes.includes(0x0d)) throw err(`${codePrefix}_PARSE`, "CR byte present");
  if (bytes.length === 0 || bytes[bytes.length - 1] !== 0x0a) throw err(`${codePrefix}_PARSE`, "missing final LF");
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw err(`${codePrefix}_PARSE`, "not valid UTF-8");
  }
  const out = [];
  const lines = text.split("\n");
  lines.pop();
  lines.forEach((line, i) => {
    if (line === "" || /^\s*#/.test(line)) return;
    const m = LINE_RE.exec(line);
    if (!m) throw err(`${codePrefix}_PARSE`, `line ${i + 1}: not "key = \\"value\\""`);
    out.push({ key: m[1], value: m[2], lineNo: i + 1 });
  });
  return out;
}

function parseManifest(bytes) {
  const entries = parseLines(bytes, "E_MANIFEST");
  if (entries.length === 0) throw err("E_MANIFEST_EMPTY", "at least one recipient required");
  const labels = new Set(), keys = new Set();
  const out = [];
  for (const { key: label, value: recipient, lineNo } of entries) {
    if (!LABEL_RE.test(label)) throw err("E_MANIFEST_PARSE", `line ${lineNo}: bad label "${label}"`);
    if (labels.has(label)) throw err("E_MANIFEST_DUP_LABEL", `line ${lineNo}: duplicate label ${label}`);
    labels.add(label);
    const decoded = age.decodeRecipient(recipient);
    if (!decoded) throw err("E_MANIFEST_RECIPIENT", `line ${lineNo}: invalid or non-canonical recipient for ${label}`);
    const hex = decoded.toString("hex");
    if (keys.has(hex)) throw err("E_MANIFEST_DUP_KEY", `line ${lineNo}: duplicate decoded key under ${label}`);
    keys.add(hex);
    out.push({ label, recipient, key: decoded });
  }
  return out;
}

const serializeManifest = (recipients) =>
  Buffer.from([...recipients].sort((a, b) => (a.label < b.label ? -1 : 1)).map((r) => `${r.label} = "${r.recipient}"\n`).join(""), "utf8");

function parseConfig(bytes) {
  const entries = parseLines(bytes, "E_CONFIG");
  const KEYS = ["vault", "local"]; // local: optional personal-layer vault (gitignored, self-sealed)
  const out = {};
  for (const { key, value, lineNo } of entries) {
    if (!KEYS.includes(key)) throw err("E_CONFIG_PARSE", `line ${lineNo}: unknown key "${key}"`);
    if (key in out) throw err("E_CONFIG_PARSE", `line ${lineNo}: duplicate key "${key}"`);
    out[key] = value;
  }
  if (!out.vault) throw err("E_CONFIG_PARSE", 'missing required key "vault"');
  return out;
}

module.exports = { ManifestError, parseManifest, serializeManifest, parseConfig };
