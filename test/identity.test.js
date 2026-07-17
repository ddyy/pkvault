"use strict";
// Identity-blob suite (SPEC-IDENTITY v1): PRF/recovery wraps, self-authentication,
// recovery-burns-both semantics, parse/version errors. node:test, zero deps.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const age = require("../src/age.js");
const idn = require("../src/identity.js");

const throwsCode = (fn, code) => assert.throws(fn, (e) => (assert.equal(e.code, code, e.message), true));

// deterministic "PRF output" — in production this comes from the authenticator
const prfOut = (tag) => crypto.createHash("sha256").update(`prf-${tag}`).digest();
const CRED = Buffer.from("credential-id-fixed-bytes");

function freshBlob() {
  const { scalar, recipient } = idn.mintIdentity();
  const pub = age.decodeRecipient(recipient);
  const prfSalt = crypto.randomBytes(32);
  const prfWrap = idn.makePrfWrap({ scalar, pub, credentialId: CRED, rpId: "unlock.pkvault.dev", prfOutput: prfOut("one"), prfSalt });
  const { code, wrap: recWrap } = idn.makeRecoveryWrap({ scalar, pub });
  const bytes = idn.serializeBlob({ label: "daniel", recipient, wraps: [prfWrap, recWrap] });
  return { scalar, recipient, pub, code, bytes };
}

test("prf wrap round-trips; wrong PRF output fails as E_IDENTITY_KEK", () => {
  const { scalar, bytes } = freshBlob();
  const blob = idn.parseBlob(bytes);
  assert.deepEqual(idn.unwrapWithPrf(blob, CRED, prfOut("one")), scalar);
  throwsCode(() => idn.unwrapWithPrf(blob, CRED, prfOut("wrong")), "E_IDENTITY_KEK");
  throwsCode(() => idn.unwrapWithPrf(blob, Buffer.from("other-cred"), prfOut("one")), "E_IDENTITY_NO_WRAP");
});

test("recovery wrap round-trips; normalization accepts lowercase/spacing; wrong code fails", () => {
  const { scalar, code, bytes } = freshBlob();
  const blob = idn.parseBlob(bytes);
  assert.deepEqual(idn.unwrapWithRecovery(blob, code), scalar);
  assert.deepEqual(idn.unwrapWithRecovery(blob, code.toLowerCase().replaceAll("-", " ")), scalar, "normalization: case and separators");
  const wrong = code.slice(0, -1) + (code.at(-1) === "A" ? "B" : "A");
  throwsCode(() => idn.unwrapWithRecovery(blob, wrong), "E_IDENTITY_KEK");
});

test("recovery code format: PKVR- + 8 groups of 4 Crockford chars, no ambiguous letters", () => {
  for (let i = 0; i < 5; i++) {
    const code = idn.newRecoveryCode();
    assert.match(code, /^PKVR(-[0-9A-HJKMNP-TV-Z]{4}){8}$/);
    assert.doesNotMatch(code, /[ILOU]/, "Crockford base32 excludes I, L, O, U");
  }
});

test("self-authentication: transplanted ciphertext under a different recipient fails (AAD)", () => {
  const a = freshBlob(), b = freshBlob();
  // splice a's prf wrap line into b's blob (recipient differs → AAD differs)
  const aWrap = a.bytes.toString().split("\n").find((l) => l.startsWith("wrap prf"));
  const swapped = Buffer.from(b.bytes.toString().replace(/^wrap prf .*$/m, aWrap), "utf8");
  const blob = idn.parseBlob(swapped);
  throwsCode(() => idn.unwrapWithPrf(blob, CRED, prfOut("one")), "E_IDENTITY_KEK");
});

test("self-authentication: recipient line swapped wholesale → pub mismatch or KEK failure, never silent", () => {
  const a = freshBlob(), b = freshBlob();
  // full blob body of a, but recipient line replaced with b's → both AAD and
  // derive-and-compare defenses stand between the attacker and a silent success
  const tampered = Buffer.from(a.bytes.toString().replace(a.recipient, b.recipient), "utf8");
  const blob = idn.parseBlob(tampered);
  assert.throws(() => idn.unwrapWithPrf(blob, CRED, prfOut("one")), (e) => ["E_IDENTITY_KEK", "E_IDENTITY_PUB_MISMATCH"].includes(e.code));
});

test("recovery re-wraps under a new passkey; OLD passkey wrap dies on the new blob", () => {
  const { scalar, code, bytes } = freshBlob();
  const blob = idn.parseBlob(bytes);
  const newSalt = crypto.randomBytes(32);
  const { blob: newBytes } = idn.recoverAndRewrap(blob, code, {
    credentialId: Buffer.from("new-credential"), rpId: "unlock.pkvault.dev", prfOutput: prfOut("two"), prfSalt: newSalt,
  });
  const nb = idn.parseBlob(newBytes);
  // same identity, new passkey wrap works
  assert.deepEqual(idn.unwrapWithPrf(nb, Buffer.from("new-credential"), prfOut("two")), scalar);
  // old passkey wrap is gone from the NEW blob
  throwsCode(() => idn.unwrapWithPrf(nb, CRED, prfOut("one")), "E_IDENTITY_NO_WRAP");
});

test("recovery code is PERMANENT escrow, NOT burned — old code opens the new blob AND any retained old blob", () => {
  const { scalar, code, bytes } = freshBlob();
  const blob = idn.parseBlob(bytes);
  const { blob: newBytes } = idn.recoverAndRewrap(blob, code, {
    credentialId: Buffer.from("new-credential"), rpId: "unlock.pkvault.dev", prfOutput: prfOut("two"), prfSalt: crypto.randomBytes(32),
  });
  // same code still opens the re-wrapped blob (not a fresh code)
  assert.deepEqual(idn.unwrapWithRecovery(idn.parseBlob(newBytes), code), scalar);
  // and — the reviewer's point — the RETAINED pre-recovery blob is still fully
  // recoverable with the same code. Recovery cannot revoke escrow.
  assert.deepEqual(idn.unwrapWithRecovery(idn.parseBlob(bytes), code), scalar);
});

test("unknown wrap types are preserved verbatim and skipped; all-unknown is a refusal", () => {
  const { bytes, code } = freshBlob();
  const withFuture = Buffer.from(bytes.toString() + "wrap sphincs+ abc def\n", "utf8");
  const blob = idn.parseBlob(withFuture);
  assert.equal(blob.wraps.filter((w) => w.type === "unknown").length, 1);
  idn.unwrapWithRecovery(blob, code); // usable wraps still work
  const header = bytes.toString().split("\n").slice(0, 3).join("\n");
  const onlyFuture = Buffer.from(header + "\n\nwrap sphincs+ abc def\n", "utf8");
  throwsCode(() => idn.parseBlob(onlyFuture), "E_IDENTITY_NO_WRAP");
});

test("parse errors: version dispatch, scrypt bounds, structure", () => {
  const { bytes } = freshBlob();
  throwsCode(() => idn.parseBlob(Buffer.from("#! pkvault-identity 9\nanything\n")), "E_IDENTITY_VERSION");
  throwsCode(() => idn.parseBlob(Buffer.from(bytes.toString().replace(/^(wrap recovery [^ ]+ )15/m, "$130"), "utf8")), "E_IDENTITY_SCRYPT_PARAM");
  throwsCode(() => idn.parseBlob(Buffer.from(bytes.toString().replace("#! label: daniel\n", ""), "utf8")), "E_IDENTITY_PARSE");
  throwsCode(() => idn.parseBlob(bytes.subarray(0, -1)), "E_IDENTITY_PARSE");
  const invalidUtf8 = Buffer.concat([bytes.subarray(0, -1), Buffer.from([0xff, 0x0a])]);
  throwsCode(() => idn.parseBlob(invalidUtf8), "E_IDENTITY_PARSE");
});

test("#8 every ACCEPTED logN actually runs within maxmem; boundaries reject", () => {
  const salt = Buffer.alloc(16, 7);
  // accepted range 10..17 must all produce a 32-byte KEK (no crash on Node 18)
  for (const n of [10, 11, 15, 16, 17]) {
    const kek = idn.kekFromRecovery("PKVR-BOUNDARY", salt, n);
    assert.equal(kek.length, 32, `logN ${n} must run`);
  }
  // out of range → refused, never attempted
  for (const n of [9, 18, 20, 30, 0, -1, 1.5]) {
    throwsCode(() => idn.kekFromRecovery("PKVR-X", salt, n), "E_IDENTITY_SCRYPT_PARAM");
  }
});
