"use strict";
// CLI arg-parsing safety (bin.js): fail-closed on unknown/misspelled/conflicting
// flags and invalid --ttl. Exercises the real binary via spawnSync. zero deps.
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const BIN = path.join(__dirname, "../src/bin.js");
const run = (args, input = "") =>
  spawnSync(process.execPath, [BIN, ...args], { input, encoding: "utf8", env: { ...process.env, PKVAULT_HOME: "/nonexistent-pkvault-home" } });

test("editor cleanup does NOT delete a concurrent edit's live buffer (alive PID skipped)", () => {
  const fs = require("node:fs"), os = require("node:os"), path = require("node:path");
  // simulate a CONCURRENT edit dir owned by a live process (this test process)
  const live = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-edit-"));
  fs.writeFileSync(path.join(live, "owner"), `${process.pid}\n`);
  fs.writeFileSync(path.join(live, "vault.env"), "ACTIVE=unsaved-work\n");
  // and a genuinely STALE dir owned by a dead PID
  const stale = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-edit-"));
  fs.writeFileSync(path.join(stale, "owner"), `2147483646\n`); // implausible, dead
  fs.writeFileSync(path.join(stale, "vault.env"), "OLD=leaked\n");
  try {
    // trigger cleanup by running an edit (fake editor is a no-op)
    const S = fs.mkdtempSync(path.join(os.tmpdir(), "pkvault-editrepo-"));
    spawnSync("git", ["init", "-q", "."], { cwd: S });
    const { execFileSync } = require("node:child_process");
    const age = require("../src/age.js");
    const id = age.keygen();
    fs.writeFileSync(path.join(S, "id.txt"), id.identity + "\n");
    fs.writeFileSync(path.join(S, ".env"), "A=1\n");
    const envRun = { ...process.env, PKVAULT_IDENTITY_FILE: path.join(S, "id.txt"), PKVAULT_EDITOR: "true" };
    execFileSync(process.execPath, [BIN, "init", "--label", "m", "--recipient", id.recipient], { cwd: S, env: envRun });
    execFileSync(process.execPath, [BIN, "edit"], { cwd: S, env: envRun });
    // the live edit's buffer MUST survive; the stale one MUST be gone
    assert.ok(fs.existsSync(path.join(live, "vault.env")), "concurrent live edit buffer must NOT be deleted");
    assert.ok(!fs.existsSync(stale), "dead-PID stale dir should be swept");
    fs.rmSync(S, { recursive: true, force: true });
  } finally {
    fs.rmSync(live, { recursive: true, force: true });
    fs.rmSync(stale, { recursive: true, force: true });
  }
});

test("misspelled scope flag is REJECTED, never silently team-scoped", () => {
  const r = run(["edit", "--locla"]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /unknown, misspelled, duplicate, or conflicting flag: --locla/);
});

test("conflicting --local and --team is rejected", () => {
  const r = run(["set", "X", "--local", "--team"], "v");
  assert.equal(r.status, 1);
  assert.match(r.stderr, /conflicting flag/);
});

test("unknown flag on a positional command is rejected", () => {
  const r = run(["get", "NAME", "--oops"]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /--oops/);
});

test("invalid --ttl values are rejected (NaN, Infinity, negative, zero, over-max)", () => {
  for (const bad of ["abc", "Infinity", "-5", "0", "999", "1e3"]) {
    const r = run(["agent", "--label", "x", "--ttl", bad]);
    assert.equal(r.status, 1, `--ttl ${bad} should fail`);
    assert.match(r.stderr, /--ttl/, `--ttl ${bad}`);
  }
});

test("extra positional arguments are rejected", () => {
  for (const argv of [["edit", "unexpected"], ["status", "extra"], ["get", "A", "B"], ["add", "l", "r", "extra"], ["lock", "x"]]) {
    const r = run(argv, "v");
    assert.equal(r.status, 1, argv.join(" "));
    assert.match(r.stderr, /expected \d+ argument|unexpected|E_USAGE/, argv.join(" "));
  }
});

test("missing option value is rejected, never silently defaulted", () => {
  const r = run(["agent", "--label", "x", "--ttl"]); // --ttl has no value
  assert.equal(r.status, 1);
  assert.match(r.stderr, /--ttl requires a value/);
});

test("duplicate options are rejected", () => {
  const r = run(["setup", "--label", "a", "--label", "b"]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /duplicate option --label/);
});

test("lock validates its arguments (was previously unchecked)", () => {
  const r = run(["lock", "--oops"]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /E_USAGE/);
});

test("run passes everything after -- through, rejects args before --", () => {
  assert.match(run(["run", "extra", "--", "echo"]).stderr, /before --/);
  assert.match(run(["run"]).stderr, /run needs/);
});

test("help output contains NO obsolete 'burned recovery code' security claims", () => {
  const help = run(["--help"]).stdout + run([]).stdout;
  assert.doesNotMatch(help, /burns? the (old )?code/i);
  assert.doesNotMatch(help, /burned/i);
  assert.match(help, /permanent escrow/i, "help states the honest escrow model");
});

test("help/usage exits 0; unknown command exits 2", () => {
  assert.equal(run(["--help"]).status, 0);
  assert.equal(run(["frobnicate"]).status, 2);
});
