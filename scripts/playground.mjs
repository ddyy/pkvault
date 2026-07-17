#!/usr/bin/env node
// Creates ./playground — a disposable sandbox for trying pkvault by hand.
// Regenerable: `npm run playground` resets it. Never committed (.gitignore).
import { execSync } from "node:child_process";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const age = require("../src/age.js");

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dir = join(root, "playground");
rmSync(dir, { recursive: true, force: true });
mkdirSync(dir, { recursive: true });

// sample env files exercising every init behavior: duplicates, unparsed lines,
// sibling discovery, templates
writeFileSync(join(dir, ".env"), `# database credentials
DATABASE_URL=postgres://app:hunter2@db.example.com:5432/prod
API_SECRET_KEY=example-not-a-real-key-000

# plausibly-public config (try: pkvault public API_HOST)
API_HOST=api.example.com
LOG_LEVEL=debug
SHARED=from-dot-env
`);
writeFileSync(join(dir, ".env.local"), `SHARED=from-dot-env-local
export BROKEN LINE
LOCAL_ONLY=1
`);
writeFileSync(join(dir, ".dev.vars"), `WRANGLER_STYLE=1\n`);
writeFileSync(join(dir, ".env.example"), `DATABASE_URL=\nAPI_SECRET_KEY=\n`);
execSync("git init -q .", { cwd: dir });

// a machine identity so everything works without a passkey ceremony;
// delete identity.txt + unset the env var to exercise the agent path instead.
const id = age.keygen();
writeFileSync(join(dir, "identity.txt"), id.identity + "\n", { mode: 0o600 });

console.log(`playground ready at ./playground — try:

  cd playground
  export PKVAULT_IDENTITY_FILE=$PWD/identity.txt
  alias pkvault='node ${root}/src/bin.js'

  pkvault init --label you --recipient ${id.recipient} \\
      --from .env --from .env.local
  # watch for: itemized adoption, the ".local is PERSONAL — adopt anyway?"
  # confirmation (say N: personal overrides don't belong in a TEAM vault;
  # say y to see duplicate shadowing), BROKEN LINE warning, .dev.vars
  # discovery, gitignore, the delete/banner prompt, next steps

  pkvault status
  pkvault get DATABASE_URL
  pkvault public API_HOST            # the declassification ceremony
  printf 'multi\\nline\\n' | pkvault set PEM
  pkvault export                     # reverse it (stdout)
  pkvault run -- env | grep API_

passkey flow instead (real ceremony): unset PKVAULT_IDENTITY_FILE and use your
real recipient from \`pkvault setup\`, with \`pkvault agent --label <you>\` running.

reset anytime: npm run playground`);
