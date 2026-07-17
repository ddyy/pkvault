#!/usr/bin/env node
// Generates fixtures/wire/* + fixtures/manifest.json (SPEC 0.10 §§11.2–11.3).
// Deterministic test identities; adversarial fixtures get valid recomputed MACs
// where the spec requires reaching the GCM layer (N1/N2/N4/N9/N16-plaintext).
import { createRequire } from "node:module";
import { writeFileSync, mkdirSync } from "node:fs";
import { createHash, createHmac, createCipheriv } from "node:crypto";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const fmt = require("../src/format.js");
const age = require("../src/age.js");

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dir = join(root, "fixtures/wire");
mkdirSync(dir, { recursive: true });

// deterministic test identities (test keys only)
const scalar = (tag) => createHash("sha256").update(`pkvault-test-${tag}`).digest();
const ID = {};
for (const tag of ["A", "B", "R"]) {
  const s = scalar(tag);
  ID[tag] = { scalar: s, ...age.keygen(s) };
}
const rec = (tag, label) => ({ label, recipient: ID[tag].recipient, key: age.decodeRecipient(ID[tag].recipient) });

const FILE_ID = Buffer.from("a0a1a2a3a4a5a6a7a8a9aaab", "hex");
const FK = Buffer.from("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "hex");

const TEMPLATE = [
  { comment: "# database — rotate quarterly" },
  { name: "DATABASE_URL", value: "postgres://app:hunter2@db.example.com:5432/prod" },
  { blank: true },
  { name: "API_HOST", value: "api.example.com", public: true },
  { name: "JWT_SECRET", value: "jwt-secret-0123456789abcdef" },
];

const manifest = { identities: Object.fromEntries(Object.entries(ID).map(([k, v]) => [k, { scalar: v.scalar.toString("hex"), recipient: v.recipient }])), fixtures: [] };
const put = (name, bytes, entry) => {
  writeFileSync(join(dir, name), bytes);
  manifest.fixtures.push({ file: name, ...entry });
};
// splice a fresh valid MAC into modified bytes (for reach-the-GCM-layer fixtures)
function remac(bytes, fk = FK, fileId = FILE_ID) {
  const { macKey } = fmt.deriveKeys(fk, fileId);
  const mac = createHmac("sha256", macKey).update(fmt.macInput(bytes)).digest();
  return Buffer.from(bytes.toString("utf8").replace(/#! mac: [^\n]*\n/, `#! mac: ${mac.toString("base64")}\n`), "utf8");
}
const swapLine = (bytes, re, replacement) => Buffer.from(bytes.toString("utf8").replace(re, replacement), "utf8");

const base = fmt.create({ recipients: [rec("A", "daniel"), rec("B", "bob")], template: TEMPLATE, fileId: FILE_ID, fk: FK });
const tokenOf = (bytes, name) => new RegExp(`${name}=(ENC\\[[^\\]]*\\])`).exec(bytes.toString())[1];

// ---- W positive -------------------------------------------------------------
put("w1-roundtrip.env", base, {
  id: "W1", op: "roundtrip", identity: "A",
  expect: { values: { DATABASE_URL: "postgres://app:hunter2@db.example.com:5432/prod", API_HOST: "api.example.com", JWT_SECRET: "jwt-secret-0123456789abcdef" } },
});
const w2new = fmt.reseal(base, ID.A.scalar, [rec("A", "daniel"), rec("B", "bob"), rec("R", "sarah")]);
put("w2-add-recipient.env", w2new, { id: "W2", op: "diff-shape", identity: "R", against: "w1-roundtrip.env", expect: { bodyStable: true, newUnseals: true } });
const w3 = fmt.create({ recipients: [rec("A", "daniel")], template: [{ name: "PRIVATE_KEY", value: "-----BEGIN KEY-----\nabc\ndef\n-----END KEY-----" }], fileId: FILE_ID, fk: FK });
put("w3-multiline.env", w3, { id: "W3", op: "get", identity: "A", name: "PRIVATE_KEY", expect: { value: "-----BEGIN KEY-----\nabc\ndef\n-----END KEY-----" } });

// ---- N negative -------------------------------------------------------------
const tokDB = tokenOf(base, "DATABASE_URL"), tokJWT = tokenOf(base, "JWT_SECRET");
let n1 = swapLine(base, `DATABASE_URL=${tokDB}`, `DATABASE_URL=${tokJWT}`);
n1 = swapLine(n1, `JWT_SECRET=${tokJWT}`, `JWT_SECRET=${tokDB}`);
put("n1-aad-name-swap.env", remac(n1), { id: "N1", op: "open", identity: "A", expect: { error: "E_GCM" } });

const otherId = Buffer.from("b0b1b2b3b4b5b6b7b8b9babb", "hex");
const other = fmt.create({ recipients: [rec("A", "daniel"), rec("B", "bob")], template: [{ name: "DATABASE_URL", value: "transplant-me" }], fileId: otherId, fk: FK });
put("n2-aad-file-swap.env", remac(swapLine(base, `DATABASE_URL=${tokDB}`, `DATABASE_URL=${tokenOf(other, "DATABASE_URL")}`)), { id: "N2", op: "open", identity: "A", expect: { error: "E_GCM" } });

const rotated = fmt.rotate(base, ID.A.scalar, [rec("A", "daniel")]); // bob removed
put("n3-rotate.env", rotated, { id: "N3", op: "unseal", identity: "B", expect: { error: "E_UNSEAL" } });
const anomalous = fmt.reseal(base, ID.A.scalar, [rec("A", "daniel")]); // header-only "remove" — WRONG on purpose
put("n3b-anomalous-remove.env", anomalous, { id: "N3b", op: "analyze", identity: "A", against: "w1-roundtrip.env", expect: { anomalousRemove: true } });

const badTag = tokDB.slice(0, -2) + (tokDB.at(-2) === "A" ? "B" : "A") + "]";
put("n4-bad-tag.env", remac(swapLine(base, `DATABASE_URL=${tokDB}`, `DATABASE_URL=${badTag}`)), { id: "N4", op: "open", identity: "A", expect: { error: "E_GCM" } });

put("n5-mac-plaintext-tamper.env", swapLine(base, "API_HOST=api.example.com # public", "API_HOST=attacker.example.com # public"), { id: "N5", op: "open", identity: "A", expect: { error: "E_MAC" } });
put("n6-mac-recipient-tamper.env", swapLine(base, "daniel=", "pwned0="), { id: "N6", op: "open", identity: "A", expect: { error: "E_MAC" } });

put("n7-duplicate-name.env", swapLine(base, `JWT_SECRET=${tokJWT}`, `JWT_SECRET=${tokJWT}\nJWT_SECRET=${tokJWT}`), { id: "N7", op: "open", identity: "A", expect: { error: "E_PARSE_NAME_DUP" } });

const nb = (s) => Buffer.from(s).toString("base64");
const badTokens = [
  ["n8a-missing-field.env", `ENC[1:${nb("0123456789ab")}]`, "E_PARSE_TOKEN"],
  ["n8b-short-nonce.env", `ENC[1:${nb("shortnon")}:${nb("0123456789abcdef0123")}]`, "E_PARSE_TOKEN"],
  ["n8c-short-ct.env", `ENC[1:${nb("0123456789ab")}:${nb("tiny")}]`, "E_PARSE_TOKEN"],
  ["n8d-zero-version.env", `ENC[0:${nb("0123456789ab")}:${nb("0123456789abcdef0123")}]`, "E_PARSE_TOKEN"],
  ["n8e-leading-zero.env", `ENC[01:${nb("0123456789ab")}:${nb("0123456789abcdef0123")}]`, "E_PARSE_TOKEN"],
];
for (const [name, tok, code] of badTokens)
  put(name, swapLine(base, `JWT_SECRET=${tokJWT}`, `JWT_SECRET=${tok}`), { id: "N8", op: "open", identity: "A", expect: { error: code } });

const futureTok = `ENC[9:${nb("0123456789ab")}:${nb("0123456789abcdef0123")}]`;
const n9 = remac(swapLine(base, `JWT_SECRET=${tokJWT}`, `JWT_SECRET=${futureTok}`));
put("n9-future-version.env", n9, { id: "N9", op: "future-version", identity: "A", knownName: "DATABASE_URL", knownValue: "postgres://app:hunter2@db.example.com:5432/prod", expect: { error: "E_VALUE_VERSION_UNKNOWN" } });

put("n10a-crlf.env", Buffer.from(base.toString().replace("\n#! file-id", "\r\n#! file-id")), { id: "N10", op: "open", identity: "A", expect: { error: "E_PARSE_CRLF" } });
put("n10b-no-final-lf.env", base.subarray(0, -1), { id: "N10", op: "open", identity: "A", expect: { error: "E_PARSE_FINAL_LF" } });

const headerCases = [
  ["n11a-missing-directive.env", (s) => s.replace(/#! recipients: [^\n]*\n/, ""), "E_PARSE_HEADER"],
  ["n11b-reordered.env", (s) => s.replace(/(#! file-id: [^\n]*\n)(#! sealed: [^\n]*\n)/, "$2$1"), "E_PARSE_HEADER"],
  ["n11c-unknown-directive.env", (s) => s.replace("#! mac: ", "#! hmac: "), "E_PARSE_HEADER"],
  ["n11d-missing-separator.env", (s) => s.replace(/\n\n/, "\n"), "E_PARSE_HEADER"],
  ["n11e-body-directive.env", (s) => s + "#! rogue: 1\n", "E_PARSE_BODY"],
  ["n11f-zero-recipients.env", (s) => s.replace(/#! recipients: [^\n]*\n/, "#! recipients: \n"), "E_PARSE_RECIPIENTS"],
  ["n11g-mixed-case-recipient.env", (s) => s.replace("bob=age1", "bob=AGE1"), "E_PARSE_RECIPIENTS"],
];
for (const [name, mut, code] of headerCases)
  put(name, Buffer.from(mut(base.toString())), { id: "N11", op: "open", identity: "A", expect: { error: code } });

put("n12-bad-base64.env", swapLine(base, /#! file-id: [^\n]*\n/, `#! file-id: ${FILE_ID.toString("base64").slice(0, -1)}=\n`), { id: "N12", op: "open", identity: "A", expect: { error: "E_PARSE_BASE64" } });
put("n13-unmarked-plaintext.env", swapLine(base, "API_HOST=api.example.com # public", "API_HOST=api.example.com"), { id: "N13", op: "open", identity: "A", expect: { error: "E_PARSE_UNMARKED" } });
put("n14-unknown-major.env", Buffer.from("#! pkvault 9\ntotally different layout\n"), { id: "N14", op: "open", identity: "A", expect: { error: "E_VERSION_UNKNOWN" } });
put("n15-duplicate-recipient-key.env", swapLine(base, /#! recipients: [^\n]*\n/, `#! recipients: alice=${ID.A.recipient}, daniel=${ID.A.recipient}\n`), { id: "N15", op: "open", identity: "A", expect: { error: "E_PARSE_RECIPIENTS" } });

// N16 envelope family
put("n16a-not-age.env", swapLine(base, /#! sealed: [^\n]*\n/, `#! sealed: ${nb("this is not an age file at all")}\n`), { id: "N16", op: "open", identity: "A", expect: { error: "E_ENVELOPE" } });
put("n16b-armored.env", swapLine(base, /#! sealed: [^\n]*\n/, `#! sealed: ${nb("-----BEGIN AGE ENCRYPTED FILE-----\nabc\n-----END AGE ENCRYPTED FILE-----\n")}\n`), { id: "N16", op: "open", identity: "A", expect: { error: "E_ENVELOPE" } });
// foreign stanza: inject an ssh-ed25519 stanza into a real envelope
const realEnv = age.encrypt(FK, [age.decodeRecipient(ID.A.recipient), age.decodeRecipient(ID.B.recipient)]);
const foreign = Buffer.from(realEnv.toString("latin1").replace("---", `-> ssh-ed25519 SkM7lQ ${nb("fakebody").replace(/=+$/, "")}\n${nb("fakewrap").replace(/=+$/, "")}\n---`), "latin1");
put("n16c-foreign-stanza.env", swapLine(base, /#! sealed: [^\n]*\n/, `#! sealed: ${foreign.toString("base64")}\n`), { id: "N16", op: "open", identity: "A", expect: { error: "E_ENVELOPE" } });
// stanza count mismatch: envelope sealed to A+B, baseline lists only A
const n16d = swapLine(base, /#! recipients: [^\n]*\n/, `#! recipients: daniel=${ID.A.recipient}\n`);
put("n16d-count-mismatch.env", n16d, { id: "N16", op: "open", identity: "A", expect: { error: "E_ENVELOPE" } });
// payload length ≠ 32
put("n16e-payload-length.env", swapLine(base, /#! sealed: [^\n]*\n/, `#! sealed: ${age.encrypt(Buffer.alloc(31, 1), [age.decodeRecipient(ID.A.recipient), age.decodeRecipient(ID.B.recipient)]).toString("base64")}\n`), { id: "N16", op: "open", identity: "A", expect: { error: "E_ENVELOPE" } });
// decrypts to invalid UTF-8 → §2.4 post-decryption error (valid MAC, valid GCM)
{
  const { vek } = fmt.deriveKeys(FK, FILE_ID);
  const nonce = Buffer.from("101112131415161718191a1b", "hex");
  const c = createCipheriv("aes-256-gcm", vek, nonce);
  c.setAAD(fmt.buildAAD(FILE_ID, "JWT_SECRET"));
  const ct = Buffer.concat([c.update(Buffer.from([0xff, 0xfe, 0x00, 0x41])), c.final(), c.getAuthTag()]);
  const tok = `ENC[1:${nonce.toString("base64")}:${ct.toString("base64")}]`;
  put("n16f-bad-plaintext.env", remac(swapLine(base, `JWT_SECRET=${tokJWT}`, `JWT_SECRET=${tok}`)), { id: "N16", op: "open", identity: "A", expect: { error: "E_PLAINTEXT_DOMAIN" } });
}

// N17 preamble
const withPreamble = (lines) => Buffer.from(base.toString().replace(/\n\n/, `\n\n${lines}`), "utf8");
put("n17a-unsorted-preamble.env", withPreamble("# pkvault: zzz\n# pkvault: aaa\n"), { id: "N17", op: "open", identity: "A", expect: { error: "E_PARSE_PREAMBLE" } });
put("n17b-late-annotation.env", Buffer.from(base.toString() + "# pkvault: too late\n"), { id: "N17", op: "open", identity: "A", expect: { error: "E_PARSE_PREAMBLE" } });

put("n18-case-fold.env", swapLine(base, `JWT_SECRET=${tokJWT}`, `jwt_secret=${tokJWT}\nJWT_SECRET=${tokJWT}`), { id: "N18", op: "open", identity: "A", expect: { error: "E_PARSE_NAME_DUP" } });

writeFileSync(join(root, "fixtures/manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
console.log(`wrote ${manifest.fixtures.length} fixtures + manifest.json`);
