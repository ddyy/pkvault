"use strict";
// Editor suite: F1 classification, F2 sentinels, F8 set-stdin, F10 sentinel
// rename, F11 public-refusal (SPEC §§9, 11.4). node:test, zero deps.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fmt = require("../src/format.js");
const age = require("../src/age.js");
const editor = require("../src/editor.js");

const scalar = crypto.createHash("sha256").update("pkvault-editor-test").digest();
const id = age.keygen(scalar);
const rec = { label: "daniel", recipient: id.recipient, key: age.decodeRecipient(id.recipient) };
const PEM = "-----BEGIN KEY-----\nabc\ndef\n-----END KEY-----";

function baseFile() {
  return fmt.create({
    recipients: [rec],
    template: [
      { comment: "# db creds" },
      { name: "DATABASE_URL", value: "postgres://x" },
      { name: "API_HOST", value: "api.example.com", public: true },
      { name: "PRIVATE_KEY", value: PEM },
      { name: "TRICKY", value: "sneaky # public" }, // secret whose VALUE ends in the marker text
    ],
    fileId: Buffer.from("c0c1c2c3c4c5c6c7c8c9cacb", "hex"),
  });
}
const throwsCode = (fn, code) => assert.throws(fn, (e) => (assert.equal(e.code, code, e.message), true));
const lineOf = (bytes, name) => bytes.toString().split("\n").find((l) => l.startsWith(name + "="));

test("render: secrets decrypted, public marked, multiline sentineled, marker-text value raw", () => {
  const { text } = editor.render(baseFile(), scalar);
  assert.match(text, /DATABASE_URL=postgres:\/\/x\n/);
  assert.match(text, /API_HOST=api\.example\.com # public\n/);
  assert.ok(text.includes(`PRIVATE_KEY=${editor.sentinelFor("PRIVATE_KEY")}\n`));
  assert.ok(text.includes("TRICKY=sneaky # public\n"), "secret value rendered raw — no marker semantics on secret lines");
});

test("F1 unmarked new name → encrypted on save (defaults secret, even with marker-ish text)", () => {
  const bytes = baseFile();
  const { text } = editor.render(bytes, scalar);
  const saved = editor.save(bytes, scalar, text + "NEW_ONE=hello # public\n");
  assert.match(lineOf(saved, "NEW_ONE"), /^NEW_ONE=ENC\[1:/, "new names are secret; text never classifies");
  assert.equal(fmt.get(saved, scalar, "NEW_ONE"), "hello # public", "the marker-looking text is value bytes");
});

test("F1 secret value ending ' # public' stays secret through a round-trip", () => {
  const bytes = baseFile();
  const { text } = editor.render(bytes, scalar);
  const saved = editor.save(bytes, scalar, text);
  assert.match(lineOf(saved, "TRICKY"), /^TRICKY=ENC\[1:/);
  assert.equal(fmt.get(saved, scalar, "TRICKY"), "sneaky # public");
});

test("F1 marker deleted or modified on a public entry → editor parse error naming the line", () => {
  const bytes = baseFile();
  const { text } = editor.render(bytes, scalar);
  throwsCode(() => editor.save(bytes, scalar, text.replace("API_HOST=api.example.com # public", "API_HOST=api.example.com")), "E_EDITOR_MARKER");
  throwsCode(() => editor.save(bytes, scalar, text.replace("API_HOST=api.example.com # public", "API_HOST=api.example.com # Public")), "E_EDITOR_MARKER");
});

test("F1 declassification only via classify(): editing text cannot make a secret public", () => {
  const bytes = baseFile();
  const { text } = editor.render(bytes, scalar);
  // user appends ' # public' to a secret line — becomes value bytes, not classification
  const saved = editor.save(bytes, scalar, text.replace("DATABASE_URL=postgres://x", "DATABASE_URL=postgres://x # public"));
  assert.match(lineOf(saved, "DATABASE_URL"), /^DATABASE_URL=ENC\[1:/);
  assert.equal(fmt.get(saved, scalar, "DATABASE_URL"), "postgres://x # public");
});

test("F2 unchanged sentinel preserves the token byte-for-byte", () => {
  const bytes = baseFile();
  const { text } = editor.render(bytes, scalar);
  const before = lineOf(bytes, "PRIVATE_KEY");
  const saved = editor.save(bytes, scalar, text);
  assert.equal(lineOf(saved, "PRIVATE_KEY"), before, "token must be byte-identical");
  assert.equal(fmt.get(saved, scalar, "PRIVATE_KEY"), PEM);
});

test("F2 CR-only value renders as sentinel too", () => {
  const bytes = fmt.create({ recipients: [rec], template: [{ name: "CRV", value: "a\rb" }] });
  const { text } = editor.render(bytes, scalar);
  assert.ok(text.includes(`CRV=${editor.sentinelFor("CRV")}\n`));
});

test("F2 modified sentinel → refusal", () => {
  const bytes = baseFile();
  const { text } = editor.render(bytes, scalar);
  throwsCode(() => editor.save(bytes, scalar, text.replace(editor.sentinelFor("PRIVATE_KEY"), "<pkvault:multiline; hacked>")), "E_EDITOR_SENTINEL");
});

test("F10 sentinel-backed record renamed in-buffer → refusal", () => {
  const bytes = baseFile();
  const { text } = editor.render(bytes, scalar);
  const renamed = text.replace(`PRIVATE_KEY=${editor.sentinelFor("PRIVATE_KEY")}`, `PRIVATE_KEY_V2=${editor.sentinelFor("PRIVATE_KEY")}`);
  throwsCode(() => editor.save(bytes, scalar, renamed), "E_EDITOR_SENTINEL_RENAME");
});

test("deletions require confirmation; sentinel deletion goes through the same path", () => {
  const bytes = baseFile();
  const { text } = editor.render(bytes, scalar);
  const without = text.split("\n").filter((l) => !l.startsWith("PRIVATE_KEY=")).join("\n");
  throwsCode(() => editor.save(bytes, scalar, without), "E_EDITOR_DELETION_UNCONFIRMED");
  let asked = null;
  const saved = editor.save(bytes, scalar, without, { confirmDeletions: (d) => ((asked = d), true) });
  assert.deepEqual(asked, ["PRIVATE_KEY"]);
  assert.equal(lineOf(saved, "PRIVATE_KEY"), undefined);
});

test("F8 set: final LF is part of the value, byte-exact", () => {
  const bytes = baseFile();
  const saved = editor.setValue(bytes, scalar, "WITH_LF", Buffer.from("value\n"));
  assert.equal(fmt.get(saved, scalar, "WITH_LF"), "value\n");
  const saved2 = editor.setValue(bytes, scalar, "NO_LF", Buffer.from("value"));
  assert.equal(fmt.get(saved2, scalar, "NO_LF"), "value");
});

test("F8 set refuses invalid UTF-8 and NUL", () => {
  const bytes = baseFile();
  throwsCode(() => editor.setValue(bytes, scalar, "BAD", Buffer.from([0xff, 0xfe])), "E_EDITOR_SET_DOMAIN");
  throwsCode(() => editor.setValue(bytes, scalar, "BAD", Buffer.from("a\0b")), "E_EDITOR_SET_DOMAIN");
});

test("every editor rewrite refuses while any future value version is present", () => {
  const bytes = baseFile();
  const { parsed, fk } = fmt.open(bytes, scalar, { decrypt: false });
  const entries = parsed.entries.map((e) => e.name === "DATABASE_URL"
    ? { ...e, line: e.line.replace("ENC[1:", "ENC[2:") }
    : e);
  const future = fmt.serialize({ fileId: parsed.fileId, fk, recipients: parsed.recipients, preamble: parsed.preamble, entries });
  throwsCode(() => editor.setValue(future, scalar, "API_HOST", Buffer.from("new.example.com")), "E_VALUE_VERSION_UNKNOWN");
  throwsCode(() => editor.classify(future, scalar, "API_HOST", "secret"), "E_VALUE_VERSION_UNKNOWN");
});

test("F8 set on a public name enforces the public domain and points at reclassification", () => {
  const bytes = baseFile();
  throwsCode(() => editor.setValue(bytes, scalar, "API_HOST", Buffer.from("multi\nline")), "E_EDITOR_PUBLIC_DOMAIN");
  const ok = editor.setValue(bytes, scalar, "API_HOST", Buffer.from("api2.example.com"));
  assert.equal(fmt.get(ok, scalar, "API_HOST"), "api2.example.com");
});

test("F11 pkvault public refuses unrepresentable values (multiline, '#', trailing whitespace)", () => {
  const cases = [
    ["ML", "a\nb"],
    ["HASH", "value#frag"],
    ["TRAIL", "value "],
  ];
  for (const [name, value] of cases) {
    const bytes = fmt.create({ recipients: [rec], template: [{ name, value }] });
    throwsCode(() => editor.classify(bytes, scalar, name, "public"), "E_EDITOR_PUBLIC_DOMAIN");
  }
});

test("F11 classify round-trip: secret → public → secret", () => {
  const bytes = baseFile();
  const pub = editor.classify(bytes, scalar, "DATABASE_URL", "public");
  assert.equal(lineOf(pub, "DATABASE_URL"), "DATABASE_URL=postgres://x # public");
  const sec = editor.classify(pub, scalar, "DATABASE_URL", "secret");
  assert.match(lineOf(sec, "DATABASE_URL"), /^DATABASE_URL=ENC\[1:/);
  assert.equal(fmt.get(sec, scalar, "DATABASE_URL"), "postgres://x");
});

test("editor buffer rejects tool-owned and directive lines", () => {
  const bytes = baseFile();
  const { text } = editor.render(bytes, scalar);
  throwsCode(() => editor.save(bytes, scalar, "# pkvault: injected\n" + text), "E_EDITOR_PARSE");
  throwsCode(() => editor.save(bytes, scalar, "#! pkvault 1\n" + text), "E_EDITOR_PARSE");
});
