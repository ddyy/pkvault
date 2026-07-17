"use strict";
// Minimal Bech32 (BIP-173, checksum constant 1) for age recipient/identity strings.

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function polymod(values) {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GEN[i];
  }
  return chk >>> 0;
}

function hrpExpand(hrp) {
  const out = [];
  for (const c of hrp) out.push(c.charCodeAt(0) >>> 5);
  out.push(0);
  for (const c of hrp) out.push(c.charCodeAt(0) & 31);
  return out;
}

function convertBits(data, from, to, pad) {
  let acc = 0, bits = 0;
  const out = [], maxv = (1 << to) - 1;
  for (const b of data) {
    if (b < 0 || b >>> from) return null;
    acc = (acc << from) | b;
    bits += from;
    while (bits >= to) { bits -= to; out.push((acc >>> bits) & maxv); }
  }
  if (pad) { if (bits) out.push((acc << (to - bits)) & maxv); }
  else if (bits >= from || ((acc << (to - bits)) & maxv)) return null;
  return out;
}

function encode(hrp, data /* Buffer */) {
  const words = convertBits([...data], 8, 5, true);
  const values = [...hrpExpand(hrp), ...words];
  const mod = polymod([...values, 0, 0, 0, 0, 0, 0]) ^ 1;
  const checksum = [];
  for (let i = 0; i < 6; i++) checksum.push((mod >>> (5 * (5 - i))) & 31);
  return hrp + "1" + [...words, ...checksum].map((w) => CHARSET[w]).join("");
}

function decode(str) {
  if (str !== str.toLowerCase() && str !== str.toUpperCase()) return null; // mixed case forbidden
  const s = str.toLowerCase();
  const pos = s.lastIndexOf("1");
  if (pos < 1 || pos + 7 > s.length) return null;
  const hrp = s.slice(0, pos);
  const words = [];
  for (const c of s.slice(pos + 1)) {
    const v = CHARSET.indexOf(c);
    if (v === -1) return null;
    words.push(v);
  }
  if (polymod([...hrpExpand(hrp), ...words]) !== 1) return null;
  const data = convertBits(words.slice(0, -6), 5, 8, false);
  if (data === null) return null;
  return { hrp, data: Buffer.from(data) };
}

module.exports = { encode, decode };
