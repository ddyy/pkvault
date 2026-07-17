"use strict";
// SPEC §9 editor representation. The wire grammar and the editor buffer are
// different languages; classification is METADATA, never inferred from text.
// Preamble annotations are tool-owned and never enter the buffer at all.

const fmt = require("./format");

class EditorError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.code = code;
  }
}
const err = (code, m) => new EditorError(code, m);

const NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const PUBLIC_SUFFIX = " # public";
const sentinelFor = (name) => `<pkvault:multiline; use \`pkvault set ${name}\`>`;
const SENTINEL_PREFIX = "<pkvault:multiline;";
const isEditorIncompatible = (v) => v.includes("\n") || v.includes("\r");
const publicDomainViolation = (v) =>
  v.includes("\n") || v.includes("\r") ? "contains line breaks"
  : v.includes("#") ? "contains '#'"
  : /[ \t]$/.test(v) ? "has trailing whitespace"
  : v.includes("\0") ? "contains NUL"
  : null;

// --- render (open → buffer text + session metadata) ---------------------------------
function render(bytes, identityScalar) {
  const { parsed, fk, values } = fmt.open(bytes, identityScalar);
  for (const [name, v] of values)
    if (typeof v !== "string")
      throw err("E_VALUE_VERSION_UNKNOWN", `${name}: upgrade required, value version ${v.unknownVersion}; edit refused, file untouched`);
  const classification = new Map();
  const tokens = new Map(); // name → original wire line (for byte-exact preservation)
  const linesOut = [];
  for (const e of parsed.entries) {
    if (e.type === "blank" || e.type === "comment") { linesOut.push(e.line); continue; }
    classification.set(e.name, e.type);
    tokens.set(e.name, e.line);
    if (e.type === "public") linesOut.push(`${e.name}=${e.value}${PUBLIC_SUFFIX}`);
    else {
      const v = values.get(e.name);
      linesOut.push(isEditorIncompatible(v) ? `${e.name}=${sentinelFor(e.name)}` : `${e.name}=${v}`);
    }
  }
  return {
    text: linesOut.map((l) => l + "\n").join(""),
    meta: { classification, tokens, values, parsed, fk },
  };
}

// --- parse buffer back (SPEC §9 rules) ---------------------------------------------------
// Returns { entries, deletions } — entries are template items for serialization;
// deletions must be confirmed by the caller before applying.
function parseBuffer(text, meta) {
  if (text.includes("\r")) throw err("E_EDITOR_PARSE", "CR in buffer");
  if (text !== "" && !text.endsWith("\n")) throw err("E_EDITOR_PARSE", "missing final newline");
  const lines = text.split("\n");
  lines.pop();
  const seen = new Set();
  const entries = [];
  lines.forEach((line, i) => {
    const lineNo = i + 1;
    if (line === "") { entries.push({ blank: true }); return; }
    if (line.startsWith("# pkvault:")) throw err("E_EDITOR_PARSE", `line ${lineNo}: pkvault annotations are tool-owned`);
    if (line.startsWith("#!")) throw err("E_EDITOR_PARSE", `line ${lineNo}: directives are not editable`);
    if (line.startsWith("#")) { entries.push({ comment: line }); return; }
    const eq = line.indexOf("=");
    if (eq === -1) throw err("E_EDITOR_PARSE", `line ${lineNo}: not an assignment`);
    const name = line.slice(0, eq);
    if (!NAME_RE.test(name)) throw err("E_EDITOR_PARSE", `line ${lineNo}: bad NAME "${name}"`);
    const folded = name.toLowerCase();
    if (seen.has(folded)) throw err("E_EDITOR_PARSE", `line ${lineNo}: duplicate name (case-folded): ${name}`);
    seen.add(folded);
    const rest = line.slice(eq + 1);
    const known = meta.classification.get(name);

    if (known === "public") {
      // marker must be intact; deleting/modifying it is a parse error, never a
      // classification change or value bytes (SPEC §9).
      if (!rest.endsWith(PUBLIC_SUFFIX))
        throw err("E_EDITOR_MARKER", `line ${lineNo}: '# public' marker on ${name} was removed or modified`);
      const value = rest.slice(0, -PUBLIC_SUFFIX.length);
      const viol = publicDomainViolation(value);
      if (viol) throw err("E_EDITOR_PUBLIC_DOMAIN", `line ${lineNo}: ${name} ${viol}`);
      entries.push({ name, value, public: true });
      return;
    }

    // secret (known) or new (defaults secret): entire rest-of-line is the value —
    // no marker parsing; a value literally ending in " # public" is just bytes.
    if (rest === sentinelFor(name) && known === "secret" && isEditorIncompatible(meta.values.get(name))) {
      entries.push({ name, keepToken: true });
      return;
    }
    if (rest.startsWith(SENTINEL_PREFIX)) {
      // Either a modified sentinel, or a sentinel-backed record renamed in-buffer
      // (the sentinel names its original variable). Both are refusals (F2, F10).
      throw err(
        known === "secret" ? "E_EDITOR_SENTINEL" : "E_EDITOR_SENTINEL_RENAME",
        `line ${lineNo}: ${known === "secret" ? "sentinel was modified" : `sentinel-backed records cannot be renamed in-buffer (${name})`}`
      );
    }
    entries.push({ name, value: rest });
  });

  const deletions = [...meta.classification.keys()].filter((n) => !seen.has(n.toLowerCase()));
  return { entries, deletions };
}

// --- save (render → user edits → new wire bytes) --------------------------------------------
// confirmDeletions: caller-supplied — receives the deletion list, returns true to proceed.
function save(bytes, identityScalar, bufferText, { confirmDeletions = () => false } = {}) {
  const { meta } = render(bytes, identityScalar);
  const { entries, deletions } = parseBuffer(bufferText, meta);
  if (deletions.length > 0 && !confirmDeletions(deletions))
    throw err("E_EDITOR_DELETION_UNCONFIRMED", `deletions not confirmed: ${deletions.join(", ")}`);

  const { vek } = fmt.deriveKeys(meta.fk, meta.parsed.fileId);
  const outEntries = entries.map((t) => {
    if (t.blank) return { type: "blank", line: "" };
    if (t.comment !== undefined) return { type: "comment", line: t.comment };
    if (t.keepToken) return { type: "secret", name: t.name, line: meta.tokens.get(t.name) }; // byte-exact
    if (t.public) return { type: "public", name: t.name, line: `${t.name}=${t.value}${PUBLIC_SUFFIX}` };
    const prev = meta.values.get(t.name);
    if (prev === t.value && meta.classification.get(t.name) === "secret")
      return { type: "secret", name: t.name, line: meta.tokens.get(t.name) }; // unchanged → byte-exact token
    if (t.value.includes("\0")) throw err("E_EDITOR_PARSE", `${t.name}: NUL in value`);
    return { type: "secret", name: t.name, line: `${t.name}=${fmt.encryptValue(vek, meta.parsed.fileId, t.name, t.value)}` };
  });
  return fmt.serialize({
    fileId: meta.parsed.fileId,
    fk: meta.fk,
    recipients: meta.parsed.recipients,
    preamble: meta.parsed.preamble, // tool-owned; passes through untouched
    entries: outEntries,
  });
}

// --- pkvault set (SPEC §9 stdin semantics, byte-exact) -----------------------------------------
function setValue(bytes, identityScalar, name, valueBuf /* Buffer: read-to-EOF, no trimming */) {
  if (!NAME_RE.test(name)) throw err("E_EDITOR_PARSE", `bad NAME "${name}"`);
  if (valueBuf.includes(0)) throw err("E_EDITOR_SET_DOMAIN", "value contains NUL");
  let value;
  try {
    value = new TextDecoder("utf-8", { fatal: true }).decode(valueBuf);
  } catch {
    throw err("E_EDITOR_SET_DOMAIN", "value is not valid UTF-8");
  }
  const { parsed, fk, keys } = fmt.open(bytes, identityScalar, { decrypt: false });
  fmt.assertRewritable(parsed); // SPEC §3: no rewrite while a future value version is present
  const existing = parsed.entries.find((e) => (e.type === "secret" || e.type === "public") && e.name.toLowerCase() === name.toLowerCase());
  if (existing && existing.name !== name) throw err("E_EDITOR_PARSE", `case-fold collision with existing ${existing.name}`);
  if (existing?.type === "public") {
    const viol = publicDomainViolation(value);
    if (viol) throw err("E_EDITOR_PUBLIC_DOMAIN", `${name} is public and the new value ${viol}; run \`pkvault secret ${name}\` first`);
  }
  const line =
    existing?.type === "public"
      ? { type: "public", name, line: `${name}=${value}${PUBLIC_SUFFIX}` }
      : { type: "secret", name, line: `${name}=${fmt.encryptValue(keys.vek, parsed.fileId, name, value)}` };
  const entries = existing
    ? parsed.entries.map((e) => (e === existing ? line : e))
    : [...parsed.entries, line];
  return fmt.serialize({ fileId: parsed.fileId, fk, recipients: parsed.recipients, preamble: parsed.preamble, entries });
}

// --- classification commands (SPEC §9): the ONLY declassification path -------------------------
function classify(bytes, identityScalar, name, to /* 'public' | 'secret' */) {
  const { parsed, fk, keys, values } = fmt.open(bytes, identityScalar);
  fmt.assertRewritable(parsed); // SPEC §3
  const e = parsed.entries.find((x) => (x.type === "secret" || x.type === "public") && x.name === name);
  if (!e) throw err("E_NO_SUCH_NAME", name);
  if (e.type === to) return bytes;
  let line;
  if (to === "public") {
    const v = values.get(name);
    const viol = publicDomainViolation(v);
    if (viol) throw err("E_EDITOR_PUBLIC_DOMAIN", `cannot declassify ${name}: value ${viol}; confirmation cannot make an unrepresentable public value valid`);
    line = { type: "public", name, line: `${name}=${v}${PUBLIC_SUFFIX}` };
  } else {
    line = { type: "secret", name, line: `${name}=${fmt.encryptValue(keys.vek, parsed.fileId, name, values.get(name))}` };
  }
  const entries = parsed.entries.map((x) => (x === e ? line : x));
  return fmt.serialize({ fileId: parsed.fileId, fk, recipients: parsed.recipients, preamble: parsed.preamble, entries });
}

module.exports = { EditorError, render, parseBuffer, save, setValue, classify, sentinelFor };
