"use strict";
// SPEC §8 merge repair protocol. Inputs are merge stages base/ours/theirs.
// Deterministic library: every human decision arrives via a callback; a needed
// callback that is absent is a refusal, never a heuristic.

const fmt = require("./format");

class MergeError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.code = code;
  }
}
const err = (code, m) => new MergeError(code, m);
const STAGES = ["base", "ours", "theirs"];

// --- record extraction (§2.3 comment identity: runs attach to the next assignment) ---
function toRecords(parsed, values) {
  const recs = new Map(); // folded name → record
  const order = [];
  let pending = [];
  for (const e of parsed.entries) {
    if (e.type === "blank" || e.type === "comment") { pending.push(e.line); continue; }
    const folded = e.name.toLowerCase();
    recs.set(folded, {
      name: e.name, folded, class: e.type,
      value: e.type === "public" ? e.value : values.get(e.name),
      token: e.line, comments: pending,
    });
    order.push(folded);
    pending = [];
  }
  return { recs, order, trailer: pending };
}
const recEq = (a, b) =>
  a.name === b.name && a.class === b.class && a.value === b.value && a.comments.join("\n") === b.comments.join("\n");

// --- input verification (§8 step 1 + §8.1 boundary) --------------------------------------
function verifyInputs(inputs, identityScalar, override) {
  const out = {};
  for (const stage of STAGES) {
    const bytes = inputs[stage];
    if (bytes == null) {
      if (!override?.discarded?.includes(stage))
        throw err("E_MERGE_INPUT_MISSING", `${stage} is unavailable; it can only be explicitly discarded`);
      out[stage] = null;
      continue;
    }
    const skipMac = override?.accepted?.includes(stage) === true;
    let opened;
    try {
      opened = fmt.open(bytes, identityScalar, { dangerouslySkipMac: skipMac });
    } catch (e) {
      if (e.code === "E_MAC" && !skipMac)
        throw err("E_MERGE_INPUT_INVALID", `${stage} fails MAC verification; refuse, or use the unverified-merge override`);
      if (e.code === "E_UNSEAL")
        throw err("E_MERGE_UNSEALABLE", `merging requires unsealing every input; cannot unseal ${stage}`);
      // §8.1: the override relaxes MAC authenticity ONLY — structural, envelope,
      // GCM, and §2.4 failures remain refusals even with the override.
      throw err("E_MERGE_INPUT_INVALID", `${stage}: ${e.message}`);
    }
    for (const [name, v] of opened.values)
      if (typeof v !== "string")
        throw err("E_MERGE_INPUT_INVALID", `${stage}: ${name} has unknown value version ${v.unknownVersion}`);
    out[stage] = { bytes, ...opened, ...toRecords(opened.parsed, opened.values) };
  }
  if (!out.base && !out.ours && !out.theirs) throw err("E_MERGE_INPUT_MISSING", "no inputs left after discards");
  // file-id is part of every value's AAD (SPEC §3). Inputs are three versions of
  // ONE repo file and MUST share a file-id; otherwise token reuse across a shared
  // FK would emit ciphertext that fails its own AAD on the next open.
  const ids = STAGES.map((s) => out[s]?.parsed.fileId).filter(Boolean);
  if (!ids.every((id) => id.equals(ids[0])))
    throw err("E_MERGE_FILE_ID", "merge inputs have different file-ids — not versions of one vault file");
  return out;
}

// --- recipient resolution (§8 step 2) --------------------------------------------------------
function resolveRecipients(v, { confirmRecipientChanges }) {
  const setOf = (stage) => {
    const m = new Map();
    if (v[stage]) for (const r of v[stage].parsed.recipients) m.set(r.key.toString("hex"), r);
    return m;
  };
  const base = setOf("base"), ours = setOf("ours"), theirs = setOf("theirs");
  const removals = [], additions = [];
  for (const [hex, r] of base) {
    if ((v.ours && !ours.has(hex)) || (v.theirs && !theirs.has(hex))) removals.push({ hex, ...pick(r) });
  }
  const addFrom = (m, stage) => {
    for (const [hex, r] of m)
      if (!base.has(hex) && !additions.some((a) => a.hex === hex)) additions.push({ hex, ...pick(r), from: stage });
  };
  addFrom(ours, "ours");
  addFrom(theirs, "theirs");
  function pick(r) { return { label: r.label, recipient: r.recipient, key: r.key }; }

  let decisions = { acceptAdditions: [], reverseRemovals: [] };
  if (removals.length || additions.length) {
    if (!confirmRecipientChanges) throw err("E_MERGE_RECIPIENTS_UNCONFIRMED", "recipient set changed; interactive confirmation required");
    const d = confirmRecipientChanges({ removals: removals.map(({ key, ...x }) => x), additions: additions.map(({ key, ...x }) => x) });
    if (!d) throw err("E_MERGE_RECIPIENTS_UNCONFIRMED", "recipient changes not confirmed");
    decisions = { acceptAdditions: d.acceptAdditions ?? [], reverseRemovals: d.reverseRemovals ?? [] };
  }
  const resolved = new Map();
  for (const [hex, r] of base) {
    const removed = removals.some((x) => x.hex === hex) && !decisions.reverseRemovals.includes(removals.find((x) => x.hex === hex).label);
    if (!removed) resolved.set(hex, pick(r));
  }
  for (const a of additions) if (decisions.acceptAdditions.includes(a.label)) resolved.set(a.hex, { label: a.label, recipient: a.recipient, key: a.key });
  if (resolved.size === 0) throw err("E_MERGE_EMPTY_RECIPIENTS", "resolved recipient set is empty");
  const appliedRemovals = removals.filter((x) => !decisions.reverseRemovals.includes(x.label));
  return { resolved: [...resolved.values()], appliedRemovals };
}

// --- variable record merge (§8 step 4) ----------------------------------------------------------
function mergeRecords(v, cb) {
  const b = v.base ?? { recs: new Map(), order: [], trailer: [] };
  const o = v.ours ?? { recs: new Map(), order: [], trailer: [] };
  const t = v.theirs ?? { recs: new Map(), order: [], trailer: [] };
  const allFolded = new Set([...b.order, ...o.order, ...t.order]);
  const chosen = new Map();

  for (const f of allFolded) {
    const rb = b.recs.get(f) ?? null, ro = o.recs.get(f) ?? null, rt = t.recs.get(f) ?? null;
    const oursChanged = !sameNullable(rb, ro), theirsChanged = !sameNullable(rb, rt);

    if (!oursChanged && !theirsChanged) { if (rb) chosen.set(f, { ...rb, source: "base" }); continue; }
    if (oursChanged && !theirsChanged) { keepOrDelete(f, ro, "ours"); continue; }
    if (!oursChanged && theirsChanged) { keepOrDelete(f, rt, "theirs"); continue; }
    // both changed
    if (sameNullable(ro, rt)) { if (ro) chosen.set(f, { ...ro, source: "ours" }); continue; }
    if (ro === null || rt === null) {
      // delete-vs-modify — a conflict, never silent (§8 step 4)
      const survivor = ro ?? rt;
      if (!cb.resolveDeleteModify) throw err("E_MERGE_CONFLICT", `${survivor.name}: delete-vs-modify conflict`);
      const d = cb.resolveDeleteModify(survivor.name, { survivor: publicView(survivor) });
      if (d === "keep") chosen.set(f, { ...survivor, source: ro ? "ours" : "theirs" });
      else if (d !== "delete") throw err("E_MERGE_CONFLICT", `${survivor.name}: unresolved delete-vs-modify`);
      continue;
    }
    if (ro.name !== rt.name) {
      // divergent spellings of one folded name (F12) — human conflict, never disjoint
      if (!cb.resolveSpelling) throw err("E_MERGE_CONFLICT", `case-fold conflict: ${ro.name} (ours) vs ${rt.name} (theirs)`);
      const winner = cb.resolveSpelling({ ours: publicView(ro), theirs: publicView(rt) });
      if (winner !== "ours" && winner !== "theirs") throw err("E_MERGE_CONFLICT", "unresolved case-fold conflict");
      chosen.set(f, { ...(winner === "ours" ? ro : rt), source: winner });
      continue;
    }
    if (!cb.resolveValueConflict) throw err("E_MERGE_CONFLICT", `${ro.name}: both sides changed`);
    const picked = cb.resolveValueConflict(ro.name, { base: rb ? publicView(rb) : null, ours: publicView(ro), theirs: publicView(rt) });
    if (picked !== "ours" && picked !== "theirs") throw err("E_MERGE_CONFLICT", `${ro.name}: unresolved conflict`);
    chosen.set(f, { ...(picked === "ours" ? ro : rt), source: picked });
  }

  function keepOrDelete(f, r, source) {
    if (r) chosen.set(f, { ...r, source });
    // r === null → deleted on the changed side, unchanged on the other → delete
  }
  function sameNullable(a, c) {
    return a === null || c === null ? a === c : recEq(a, c);
  }
  function publicView(r) { return { name: r.name, class: r.class, value: r.value, comments: r.comments }; }

  // classification changes are part of the record; a declassification from either
  // branch crosses the §9 confirmation boundary.
  for (const [f, rec] of chosen) {
    const rb = b.recs.get(f);
    if (rb && rb.class === "secret" && rec.class === "public") {
      if (!cb.confirmDeclassification || !cb.confirmDeclassification(rec.name))
        throw err("E_MERGE_DECLASS_UNCONFIRMED", `${rec.name} arrives declassified from a branch; explicit confirmation required`);
      const viol = rec.value.includes("\n") || rec.value.includes("\r") || rec.value.includes("#") || /[ \t]$/.test(rec.value);
      if (viol) throw err("E_MERGE_CONFLICT", `${rec.name}: declassified value violates the public domain`);
    }
  }

  // ordering: ours' order is the spine; theirs-only records insert after their
  // predecessor in theirs; a same-anchor concurrent insertion is a human choice.
  const spine = o.order.filter((f) => chosen.has(f));
  const oursSet = new Set(o.order);
  for (const f of t.order) {
    if (!chosen.has(f) || spine.includes(f)) continue;
    const tIdx = t.order.indexOf(f);
    let anchor = -1;
    for (let i = tIdx - 1; i >= 0; i--) {
      const p = spine.indexOf(t.order[i]);
      if (p !== -1) { anchor = p; break; }
    }
    const oursInsertedHere = anchor !== -1 && !b.order.includes(spine[anchor + 1]) && spine[anchor + 1] !== undefined && !new Set(t.order).has(spine[anchor + 1]);
    if (oursInsertedHere) {
      if (!cb.resolveOrdering) throw err("E_MERGE_ORDER", `concurrent insertions at the same position (${f}); human ordering choice required`);
      const order = cb.resolveOrdering({ ours: spine[anchor + 1], theirs: f });
      spine.splice(order === "theirs-first" ? anchor + 1 : anchor + 2, 0, f);
    } else {
      spine.splice(anchor + 1, 0, f);
    }
  }
  // base-only survivors (deleted from ours' order? already filtered by chosen)
  for (const f of chosen.keys()) if (!spine.includes(f)) spine.push(f);

  const trailer = (o.trailer.join("\n") === (v.base?.trailer ?? []).join("\n") ? t.trailer : o.trailer);
  return { spine, chosen, trailer };
}

// --- top level -----------------------------------------------------------------------------------
// inputs: { base, ours, theirs: Buffer|null }; override: { accepted:[stage], discarded:[stage],
// label, date "YYYY-MM-DD", oids: {stage: "sha1:<40hex>"|"sha256:<64hex>"|"none"} }
function merge(inputs, identityScalar, callbacks = {}, override = null) {
  const raw = verifyInputs(inputs, identityScalar, override);
  // A discarded stage contributes NOTHING — it is not an empty file. Substitute
  // base's view (no changes from that side); if base itself was discarded, the
  // surviving stage stands in so the other side's differences read as changes.
  const v = {
    base: raw.base ?? raw.ours ?? raw.theirs,
    ours: raw.ours ?? raw.base ?? raw.theirs,
    theirs: raw.theirs ?? raw.base ?? raw.ours,
  };
  const { resolved, appliedRemovals } = resolveRecipients(v, callbacks);
  const { spine, chosen, trailer } = mergeRecords(v, callbacks);

  // FK resolution (§8 step 3)
  const fks = STAGES.map((s) => v[s]?.fk).filter(Boolean);
  const sameFk = fks.every((f) => f.equals(fks[0]));
  const fkFresh = appliedRemovals.length > 0 || !sameFk;
  const fk = fkFresh ? require("node:crypto").randomBytes(32) : fks[0];
  const ref = v.ours ?? v.theirs ?? v.base;
  const fileId = ref.parsed.fileId;
  const { vek } = fmt.deriveKeys(fk, fileId);

  const entries = [];
  for (const f of spine) {
    const r = chosen.get(f);
    for (const c of r.comments) entries.push({ type: c === "" ? "blank" : "comment", line: c });
    if (r.class === "public") entries.push({ type: "public", name: r.name, line: `${r.name}=${r.value} # public` });
    else if (!fkFresh && v[r.source]?.fk.equals(fk) && r.token.startsWith(`${r.name}=ENC[`))
      entries.push({ type: "secret", name: r.name, line: r.token }); // token reuse, byte-identical
    else entries.push({ type: "secret", name: r.name, line: `${r.name}=${fmt.encryptValue(vek, fileId, r.name, r.value)}` });
  }
  for (const c of trailer) entries.push({ type: c === "" ? "blank" : "comment", line: c });

  // preamble: union of surviving inputs, plus the §8.1 marker when overriding
  const preamble = new Set();
  for (const s of STAGES) if (v[s]) for (const p of v[s].parsed.preamble) preamble.add(p);
  if (override) {
    if (!override.label || !override.date) throw err("E_MERGE_OVERRIDE", "override requires label and date");
    const part = (list) => (list ?? []).map((s) => `${s}@${override.oids?.[s] ?? "none"}`).join(", ");
    let marker = `# pkvault: accepted-unverified-merge by ${override.label} on ${override.date} UTC; accepted: ${part(override.accepted)}`;
    if (override.discarded?.length) marker += `; discarded: ${part(override.discarded)}`;
    preamble.add(marker);
  }

  return fmt.serialize({ fileId, fk, recipients: resolved, preamble: [...preamble].sort(), entries: entries.filter(Boolean) });
}

module.exports = { MergeError, merge };
