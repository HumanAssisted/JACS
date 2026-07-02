#!/usr/bin/env node
// Stock-JOSE verification of a JACS AP2 merchant-authorization export
// (P2 Task 004b / FR15, UCP AP2-Mandates extension rev 2026-01-23).
//
// This is conformance evidence: it verifies the detached ES256 JWS with
// the standard `jose` library and recomputes the JCS payload with the
// independent `canonicalize` RFC 8785 implementation — no JACS code is
// involved. A self round-trip inside JACS would not prove anything.
//
// Usage:
//   npm install jose canonicalize
//   jacs ap2 export-mandate --input checkout.json > export.json
//   jacs agent export-jwks > jwks.json
//   node scripts/smoke/verify_ap2_jws.mjs export.json jwks.json
//
// Exits 0 and prints AP2-JWS-VERIFY-OK on success; non-zero otherwise.
//
// Note: this proves the CLASSICAL ES256 signature only. Trust in the
// signing agent's post-quantum root additionally requires verifying the
// PQ-signed compatibility key binding (jacs agent export-compat-binding).

import { readFileSync } from 'node:fs';
import { flattenedVerify, importJWK } from 'jose';
import canonicalize from 'canonicalize';

const [exportPath, jwksPath] = process.argv.slice(2);
if (!exportPath || !jwksPath) {
  console.error('usage: node verify_ap2_jws.mjs <export.json> <jwks.json>');
  process.exit(2);
}

const exported = JSON.parse(readFileSync(exportPath, 'utf8'));
const jwks = JSON.parse(readFileSync(jwksPath, 'utf8'));

const detached = exported.detachedJws;
const [protectedHeader, detachedPayload, signature] = detached.split('.');
if (detachedPayload !== '') {
  console.error('FAIL: JWS is not in detached form (<header>..<signature>)');
  process.exit(1);
}

// Signed payload = checkout object EXCLUDING the ap2 field, per the
// AP2-Mandates extension. Recompute JCS independently.
const { ap2, ...payloadObj } = exported.checkout;
const jcs = canonicalize(payloadObj);
const payload = Buffer.from(jcs, 'utf8').toString('base64url');

const header = JSON.parse(Buffer.from(protectedHeader, 'base64url').toString('utf8'));
const headerKeys = Object.keys(header).sort().join(',');
if (headerKeys !== 'alg,kid' || header.alg !== 'ES256') {
  console.error(`FAIL: protected header must be exactly {alg:ES256,kid}, got ${JSON.stringify(header)}`);
  process.exit(1);
}

const jwk = jwks.keys.find((k) => k.kid === header.kid);
if (!jwk) {
  console.error(`FAIL: kid ${header.kid} not present in JWKS`);
  process.exit(1);
}

const key = await importJWK(jwk, 'ES256');
try {
  await flattenedVerify({ protected: protectedHeader, signature, payload }, key);
} catch (err) {
  console.error(`FAIL: signature did not verify: ${err.message}`);
  process.exit(1);
}
console.log(`AP2-JWS-VERIFY-OK kid=${header.kid}`);
