#!/usr/bin/env python3
"""Independent cross-check of fixtures/kat/kats.json (SPEC 0.10 §11.1).
Recomputes K1-K4 with the `cryptography` package; exits non-zero on mismatch."""
import base64, hmac as hmac_mod, hashlib, json, struct, sys
from pathlib import Path
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

kats = json.loads((Path(__file__).parent.parent / "fixtures/kat/kats.json").read_text())
inp = kats["inputs"]
fk = bytes.fromhex(inp["fk"]); file_id = bytes.fromhex(inp["file_id"])
name = inp["name"]; nonce = bytes.fromhex(inp["nonce"]); pt = inp["plaintext"].encode()

fails = []
def check(label, expected_hex, actual: bytes):
    ok = expected_hex == actual.hex()
    print(f"{'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        fails.append(label); print(f"      expected {expected_hex}\n      actual   {actual.hex()}")

# K1
vek = HKDF(algorithm=SHA256(), length=32, salt=file_id, info=b"pkvault/vek/v1").derive(fk)
mac_key = HKDF(algorithm=SHA256(), length=32, salt=file_id, info=b"pkvault/mac/v1").derive(fk)
check("K1 VEK", kats["k1"]["vek"], vek)
check("K1 MAC_KEY", kats["k1"]["mac_key"], mac_key)

# K2
aad = b"pkvault/value/v1" + b"\x00" + file_id + struct.pack(">I", len(name)) + name.encode("ascii")
check("K2 AAD", kats["k2"]["aad"], aad)

# K3 (AESGCM.encrypt returns ciphertext||tag, same layout as the spec)
ct = AESGCM(vek).encrypt(nonce, pt, aad)
check("K3 ciphertext||tag", kats["k3"]["ciphertext_and_tag"], ct)
token = f"ENC[1:{base64.b64encode(nonce).decode()}:{base64.b64encode(ct).decode()}]"
ok = token == kats["k3"]["token"]
print(f"{'PASS' if ok else 'FAIL'}  K3 token"); fails.append("K3 token") if not ok else None

# K4 — also independently verify mac_input = full_file minus the mac line
mac_input = base64.b64decode(kats["k4"]["mac_input"])
full_file = base64.b64decode(kats["k4"]["full_file"])
lines = full_file.split(b"\n")
reconstructed = b"\n".join(l for l in lines if not l.startswith(b"#! mac:"))
ok = reconstructed == mac_input
print(f"{'PASS' if ok else 'FAIL'}  K4 mac-input construction (line removal, no replacement LF)")
if not ok: fails.append("K4 construction")
mac = hmac_mod.new(mac_key, mac_input, hashlib.sha256).digest()
check("K4 MAC", kats["k4"]["mac"], mac)

print(f"\n{'ALL VECTORS CROSS-CHECKED OK' if not fails else f'{len(fails)} MISMATCH(ES): {fails}'}")
sys.exit(1 if fails else 0)
