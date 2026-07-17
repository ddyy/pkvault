#!/usr/bin/env node
// Deploy-time verification for the hosted ceremony page.
//
// The digest that matters is the one PUBLISHED IN THE GITHUB RELEASE for the
// deployed tag — not whatever web/index.html happens to say at the current
// checkout (main can drift ahead of the deploy). So real verification compares
// the live page AND the local source against an explicit expected release digest.
//
//   node scripts/release-page.mjs hash
//       → print the SHA-256 of the local web/index.html (to record in a release)
//
//   node scripts/release-page.mjs check --url <URL> --expected-sha256 <hex> [--timeout-ms <n>]
//       → PASS only if BOTH the live page and the local source equal <hex>.
//         Also reports live-vs-local for information.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const USAGE = `usage:
  release-page.mjs hash
  release-page.mjs check --url <URL> --expected-sha256 <64-hex> [--timeout-ms <n>]`;
function die(msg, code = 2) { process.stderr.write(`${msg}\n${USAGE}\n`); process.exit(code); }

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const localBytes = readFileSync(join(root, "web/index.html"));
const localDigest = createHash("sha256").update(localBytes).digest("hex");

// strict arg parsing: known flags only, no duplicates, values required
const argv = process.argv.slice(2);
const cmd = argv.shift();
function takeOpts(spec) {
  const out = {};
  while (argv.length) {
    const a = argv.shift();
    if (!a.startsWith("--")) die(`unexpected argument: ${a}`);
    if (!(a in spec)) die(`unknown flag: ${a}`);
    if (a in out) die(`duplicate flag: ${a}`);
    if (argv.length === 0 || argv[0].startsWith("--")) die(`${a} requires a value`);
    out[a] = argv.shift();
  }
  return out;
}

if (cmd === "hash") {
  if (argv.length) die(`hash takes no arguments`);
  process.stdout.write(`web/index.html\n  sha256: ${localDigest}\n  bytes:  ${localBytes.length}\n`);
  process.exit(0);
}

if (cmd === "check") {
  const o = takeOpts({ "--url": 1, "--expected-sha256": 1, "--timeout-ms": 1 });
  const url = o["--url"];
  // the release digest may come from the flag OR the PKVAULT_PAGE_SHA256 env var
  // (so `npm run verify:page` works with the digest supplied by environment).
  const expected = o["--expected-sha256"] ?? process.env.PKVAULT_PAGE_SHA256;
  const timeoutMs = o["--timeout-ms"] ? Number(o["--timeout-ms"]) : 15000;
  if (!url) die("check requires --url <URL>");
  if (!expected) die("check requires the release digest: --expected-sha256 <64-hex>, or set PKVAULT_PAGE_SHA256");
  if (!/^[0-9a-f]{64}$/.test(expected)) die("--expected-sha256 must be 64 lowercase hex chars");
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) die("--timeout-ms must be a positive number");

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  let liveBytes;
  try {
    const res = await fetch(url, { signal: ctrl.signal, redirect: "error" });
    if (!res.ok) { process.stderr.write(`fetch ${url} → HTTP ${res.status}\n`); process.exit(3); }
    liveBytes = Buffer.from(await res.arrayBuffer());
  } catch (e) {
    process.stderr.write(`fetch ${url} failed: ${e.name === "AbortError" ? `timed out after ${timeoutMs}ms` : e.message}\n`);
    process.exit(3);
  } finally { clearTimeout(timer); }

  const liveDigest = createHash("sha256").update(liveBytes).digest("hex");
  const liveOk = liveDigest === expected;
  const localOk = localDigest === expected;
  process.stdout.write(
`expected (release): ${expected}
live  (${url}): ${liveDigest}  ${liveOk ? "✅" : "❌"}
local (web/index.html):     ${localDigest}  ${localOk ? "✅" : "❌"}
live == local: ${liveDigest === localDigest ? "yes" : "no"}

${liveOk && localOk
  ? "✅ VERIFIED — the live page and this source both match the released digest"
  : "❌ FAILED — " + (!liveOk ? "the live page does NOT match the released digest" : "the local source does NOT match the released digest")}
`);
  process.exit(liveOk && localOk ? 0 : 1);
}

die(cmd ? `unknown command: ${cmd}` : "no command given");
