#!/usr/bin/env node
// Independent Data Integrity verification of a JACS Agreement-v2 VC
// export (P2 Task 004c / FR16, W3C vc-di-ecdsa ecdsa-jcs-2019).
//
// Conformance evidence: the proof is re-verified with the independent
// `canonicalize` RFC 8785 implementation and Node's WebCrypto — no JACS
// code involved. The byte-exact W3C spec-vector KAT lives in the Rust
// unit tests; this script proves real exports verify independently.
//
// Usage:
//   npm install canonicalize
//   jacs agreement-v2 export-vc --agreement agreement.json > vc_export.json
//   jacs agent export-jwks > jwks.json
//   node scripts/smoke/verify_di_vc.mjs vc_export.json jwks.json
//
// Exits 0 and prints DI-VC-VERIFY-OK on success; non-zero otherwise.
//
// Note: this proves the CLASSICAL ES256/P-256 proof only. Trust in the
// signing agent's post-quantum root additionally requires verifying the
// PQ-signed compatibility key binding (jacs agent export-compat-binding).

import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import canonicalize from 'canonicalize';

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58Decode(str) {
  let num = 0n;
  for (const ch of str) {
    const idx = ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error(`invalid base58 char ${ch}`);
    num = num * 58n + BigInt(idx);
  }
  const bytes = [];
  while (num > 0n) {
    bytes.unshift(Number(num & 0xffn));
    num >>= 8n;
  }
  for (const ch of str) {
    if (ch === '1') bytes.unshift(0);
    else break;
  }
  return Uint8Array.from(bytes);
}

const [exportPath, jwksPath] = process.argv.slice(2);
if (!exportPath || !jwksPath) {
  console.error('usage: node verify_di_vc.mjs <vc_export.json> <jwks.json>');
  process.exit(2);
}

const exported = JSON.parse(readFileSync(exportPath, 'utf8'));
const jwks = JSON.parse(readFileSync(jwksPath, 'utf8'));
const vc = exported.vc;
const proof = vc.proof;

if (proof.type !== 'DataIntegrityProof' || proof.cryptosuite !== 'ecdsa-jcs-2019') {
  console.error(`FAIL: unexpected proof type/cryptosuite: ${proof.type}/${proof.cryptosuite}`);
  process.exit(1);
}
if (!proof.verificationMethod.includes('-multikey')) {
  console.error('FAIL: verificationMethod must reference the Multikey entry');
  process.exit(1);
}

// hashData = SHA-256(JCS(proof options)) || SHA-256(JCS(unsecured doc)),
// both recomputed with the independent RFC 8785 implementation.
const { proof: _p, ...unsecured } = vc;
const { proofValue, ...proofOptions } = proof;
const sha256 = (s) => webcrypto.subtle.digest('SHA-256', Buffer.from(s, 'utf8'));
const configHash = new Uint8Array(await sha256(canonicalize(proofOptions)));
const docHash = new Uint8Array(await sha256(canonicalize(unsecured)));
const hashData = new Uint8Array(64);
hashData.set(configHash, 0);
hashData.set(docHash, 32);

if (!proofValue.startsWith('z')) {
  console.error('FAIL: proofValue is not multibase base58btc');
  process.exit(1);
}
const signature = base58Decode(proofValue.slice(1));
if (signature.length !== 64) {
  console.error(`FAIL: expected 64-byte P-256 r||s signature, got ${signature.length}`);
  process.exit(1);
}

const jwk = jwks.keys.find((k) => k.kid === exported.kid);
if (!jwk) {
  console.error(`FAIL: kid ${exported.kid} not present in JWKS`);
  process.exit(1);
}
const key = await webcrypto.subtle.importKey(
  'jwk',
  { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
  { name: 'ECDSA', namedCurve: 'P-256' },
  false,
  ['verify'],
);
const ok = await webcrypto.subtle.verify(
  { name: 'ECDSA', hash: 'SHA-256' },
  key,
  signature,
  hashData,
);
if (!ok) {
  console.error('FAIL: ecdsa-jcs-2019 proof did not verify');
  process.exit(1);
}
console.log(`DI-VC-VERIFY-OK vm=${proof.verificationMethod}`);
