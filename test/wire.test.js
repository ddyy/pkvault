"use strict";
// Wire-fixture suite (SPEC 0.10 §§11.2–11.3). Runs every fixtures/manifest.json
// entry through the pipeline and asserts the exact expected error code or
// success properties. node:test, zero deps.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const fmt = require("../src/format.js");

const root = path.join(__dirname, "..");
const manifest = JSON.parse(fs.readFileSync(path.join(root, "fixtures/manifest.json"), "utf8"));
const read = (f) => fs.readFileSync(path.join(root, "fixtures/wire", f));
const scalars = Object.fromEntries(Object.entries(manifest.identities).map(([k, v]) => [k, Buffer.from(v.scalar, "hex")]));

const bodyOf = (b) => b.toString("utf8").split("\n").slice(6).join("\n");
const headerLinesChanged = (a, b) => {
  const la = a.toString().split("\n"), lb = b.toString().split("\n");
  return [0, 1, 2, 3, 4].filter((i) => la[i] !== lb[i]);
};

for (const fx of manifest.fixtures) {
  test(`${fx.id} ${fx.file} [${fx.op}]`, () => {
    const bytes = read(fx.file);
    const id = scalars[fx.identity];

    if (fx.expect.error) {
      const run = {
        open: () => fmt.open(bytes, id),
        unseal: () => fmt.open(bytes, id),
        "future-version": () => null, // handled below
      }[fx.op] ?? (() => fmt.open(bytes, id));

      if (fx.op === "future-version") {
        // targeted read of a known value succeeds…
        assert.equal(fmt.get(bytes, id, fx.knownName), fx.knownValue);
        // …run fails, and every rewrite refuses
        assert.throws(() => fmt.runEnv(bytes, id), (e) => e.code === fx.expect.error);
        const { parsed } = fmt.open(bytes, id, { decrypt: false });
        assert.throws(() => fmt.save(bytes, id, new Map([["API_HOST", "x"]])), (e) => e.code === fx.expect.error);
        assert.throws(() => fmt.rotate(bytes, id, parsed.recipients.slice(0, 1)), (e) => e.code === fx.expect.error);
        assert.throws(() => fmt.reseal(bytes, id, parsed.recipients), (e) => e.code === fx.expect.error);
        return;
      }
      assert.throws(run, (e) => {
        assert.equal(e.code, fx.expect.error, `expected ${fx.expect.error}, got ${e.code}: ${e.message}`);
        return true;
      });
      return;
    }

    if (fx.op === "roundtrip") {
      const { values } = fmt.open(bytes, id);
      for (const [k, v] of Object.entries(fx.expect.values)) assert.equal(values.get(k), v);
      // save with no updates: every body byte identical (ENC tokens copied through)
      const saved = fmt.save(bytes, id, new Map());
      assert.equal(bodyOf(saved), bodyOf(bytes), "body must be byte-stable across a no-op save");
      // and the re-sealed file still opens
      const again = fmt.open(saved, id);
      for (const [k, v] of Object.entries(fx.expect.values)) assert.equal(again.values.get(k), v);
    }

    if (fx.op === "diff-shape") {
      const old = read(fx.against);
      assert.equal(bodyOf(bytes), bodyOf(old), "reseal must leave body byte-stable");
      const changed = headerLinesChanged(old, bytes);
      assert.deepEqual(changed, [2, 3, 4], "only sealed/recipients/mac lines may change");
      if (fx.expect.newUnseals) assert.ok(fmt.open(bytes, id).values, "new recipient must unseal the resealed file");
    }

    if (fx.op === "get") assert.equal(fmt.get(bytes, id, fx.name), fx.expect.value);

    if (fx.op === "analyze") {
      const old = read(fx.against);
      const a = fmt.analyzeReseal(old, bytes);
      assert.equal(a.anomalousRemove, fx.expect.anomalousRemove, "header-only remove must be flagged anomalous");
    }
  });
}

test("public values reject NUL on parse and serialization", () => {
  const valid = read("w1-roundtrip.env");
  const nul = Buffer.from(valid.toString("utf8").replace("API_HOST=api.example.com # public", "API_HOST=api\0example.com # public"), "utf8");
  assert.throws(() => fmt.parseStructure(nul), (e) => e.code === "E_PARSE_BODY");

  const parsed = fmt.parseStructure(valid);
  assert.throws(
    () => fmt.create({ recipients: parsed.recipients, template: [{ name: "PUBLIC", value: "a\0b", public: true }] }),
    (e) => e.code === "E_PARSE_BODY",
  );
});

// KAT conformance: the implementation must reproduce the frozen vectors exactly.
test("KAT conformance (K1–K4)", () => {
  const kats = JSON.parse(fs.readFileSync(path.join(root, "fixtures/kat/kats.json"), "utf8"));
  const fk = Buffer.from(kats.inputs.fk, "hex");
  const fileId = Buffer.from(kats.inputs.file_id, "hex");
  const { vek, macKey } = fmt.deriveKeys(fk, fileId);
  assert.equal(vek.toString("hex"), kats.k1.vek);
  assert.equal(macKey.toString("hex"), kats.k1.mac_key);
  assert.equal(fmt.buildAAD(fileId, kats.inputs.name).toString("hex"), kats.k2.aad);
  const tok = fmt.parseToken(kats.k3.token, kats.inputs.name);
  assert.equal(fmt.decryptValue(vek, fileId, kats.inputs.name, tok), kats.inputs.plaintext);
  const fullFile = Buffer.from(kats.k4.full_file, "base64");
  assert.equal(fmt.macInput(fullFile).toString("base64"), kats.k4.mac_input);
  assert.equal(fmt.computeMac(fullFile, macKey).toString("hex"), kats.k4.mac);
});
