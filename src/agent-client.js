"use strict";
// Tiny sync-bridge: spawned by resolveIdentity so synchronous CLI commands can
// consult the (async, socket-based) agent. Prints the agent's JSON reply.
// Usage: node agent-client.js <home> — request is fixed: {op:"identity"}.
const { agentRequest } = require("./agent");
agentRequest(process.argv[2], { op: "identity" })
  .then((r) => process.stdout.write(JSON.stringify(r)))
  .catch((e) => {
    process.stdout.write(JSON.stringify({ ok: false, code: e.code ?? "E_AGENT", message: e.message }));
    process.exit(0);
  });
