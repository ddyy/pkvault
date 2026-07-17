#!/usr/bin/env node
// Generates fixtures/kat/kats.json — known-answer vectors K1–K4 (SPEC §11.1).
// Fixed test keys only; deterministic output. Cross-check: scripts/check-kats.py
import { hkdfSync, createCipheriv, createHmac } from "node:crypto";
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const hex = (b) => Buffer.from(b).toString("hex");

// --- fixed test inputs (never real keys) ------------------------------------
const FK = Buffer.from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex");
const FILE_ID = Buffer.from("a0a1a2a3a4a5a6a7a8a9aaab", "hex"); // 12 bytes
const NAME = "DATABASE_URL";
const NONCE = Buffer.from("101112131415161718191a1b", "hex"); // 12 bytes
const PLAINTEXT = "postgres://app:hunter2@db.example.com:5432/prod";

// --- K1: HKDF-SHA-256(FK, salt=file_id, info) → VEK, MAC_KEY -----------------
const VEK = Buffer.from(hkdfSync("sha256", FK, FILE_ID, Buffer.from("pkvault/vek/v1", "utf8"), 32));
const MAC_KEY = Buffer.from(hkdfSync("sha256", FK, FILE_ID, Buffer.from("pkvault/mac/v1", "utf8"), 32));

// --- K2: AAD = "pkvault/value/v1" || 0x00 || file_id || u32be(len) || NAME ---
function aad(fileId, name) {
  const dom = Buffer.from("pkvault/value/v1", "utf8");
  const len = Buffer.alloc(4);
  len.writeUInt32BE(Buffer.byteLength(name, "ascii"));
  return Buffer.concat([dom, Buffer.from([0]), fileId, len, Buffer.from(name, "ascii")]);
}
const AAD = aad(FILE_ID, NAME);

// --- K3: AES-256-GCM → ENC token ---------------------------------------------
const c = createCipheriv("aes-256-gcm", VEK, NONCE);
c.setAAD(AAD);
const ct = Buffer.concat([c.update(PLAINTEXT, "utf8"), c.final(), c.getAuthTag()]); // ciphertext || tag
const TOKEN = `ENC[1:${NONCE.toString("base64")}:${ct.toString("base64")}]`;

// --- K4: MAC input (file minus the #! mac: line) + HMAC ----------------------
const bodyLines =
  `# comment attached to API_HOST\n` +
  `API_HOST=api.example.com # public\n` +
  `${NAME}=${TOKEN}\n`;
const headNoMac =
  `#! pkvault 1\n` +
  `#! file-id: ${FILE_ID.toString("base64")}\n` +
  `#! sealed: ${Buffer.from("kat-placeholder-not-a-real-envelope").toString("base64")}\n` +
  `#! recipients: daniel=age1kat0000000000000000000000000000000000000000000000000000000000\n`;
const macInput = headNoMac + "\n" + bodyLines; // exact bytes, mac line absent, no replacement LF
const MAC = createHmac("sha256", MAC_KEY).update(macInput).digest();
const fullFile = headNoMac + `#! mac: ${MAC.toString("base64")}\n` + "\n" + bodyLines;

// --- emit ---------------------------------------------------------------------
const kats = {
  note: "pkvault v1 KATs (SPEC 0.10 §11.1). Fixed test keys — never real. K4 sealed/recipients are MAC-construction placeholders, not valid envelope/recipient values.",
  inputs: { fk: hex(FK), file_id: hex(FILE_ID), name: NAME, nonce: hex(NONCE), plaintext: PLAINTEXT },
  k1: { vek: hex(VEK), mac_key: hex(MAC_KEY) },
  k2: { aad: hex(AAD) },
  k3: { ciphertext_and_tag: hex(ct), token: TOKEN },
  k4: { mac_input: Buffer.from(macInput).toString("base64"), mac: hex(MAC), full_file: Buffer.from(fullFile).toString("base64") },
};
mkdirSync(join(root, "fixtures/kat"), { recursive: true });
writeFileSync(join(root, "fixtures/kat/kats.json"), JSON.stringify(kats, null, 2) + "\n");
console.log("K1 VEK      ", hex(VEK));
console.log("K1 MAC_KEY  ", hex(MAC_KEY));
console.log("K2 AAD      ", hex(AAD));
console.log("K3 token    ", TOKEN);
console.log("K4 MAC      ", hex(MAC));
console.log("wrote fixtures/kat/kats.json");
