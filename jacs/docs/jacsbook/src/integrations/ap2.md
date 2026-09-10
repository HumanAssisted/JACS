# AP2 (Agent Payments Protocol)

JACS can export the **merchant/business-authorization** artifact of the
UCP AP2-Mandates extension (dated spec revision **2026-01-23**) as a
**detached ES256 JWS**, signed with the agent's `ecosystem_signing`
compatibility key.

Scope is deliberately narrow:

- **Exported role: merchant/business authorization only.** User-side AP2
  Checkout Mandates are SD-JWT-VC and are **not** produced by JACS —
  this is not full AP2 conformance, and the docs do not claim it.
- **Outgoing only.** JACS does not verify incoming AP2 mandates.
- **CLI + binding only.** There is no MCP tool for this export.

## Wire format (pinned)

- Protected header: exactly `{"alg":"ES256","kid":"<compat-key kid>"}` —
  no `typ`, no RFC 7797 `b64:false`, no `crit`.
- Detached compact serialization: `<BASE64URL(header)>..<BASE64URL(signature)>`.
- Signing input: `BASE64URL(header) + "." + BASE64URL(JCS(payload))`,
  where the payload is the checkout object **excluding the `ap2` field**,
  canonicalized per RFC 8785 (JCS).

The exporter validates its input against the named schema
`jacs/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json` and
rejects anything that does not conform — typed input is a schema check,
not a naming convention.

The schema is deliberately open (`additionalProperties: true`) to match
UCP checkout extensibility: extra checkout fields beyond the required
core are signed as-is, so relying parties must not assume JACS validated
anything beyond the schema's required core fields. Operators granting the
`ap2-mandate` scope are authorizing signatures over extensible checkout
payloads.

## Usage

The `ap2-mandate` binding scope is a **content scope**: it is never
auto-issued. Grant it explicitly first (this requires the native root's
signature):

```bash
jacs agent issue-compat-binding \
  --scopes jwks,did,a2a-agent-card,w3c-agent-identity,ap2-mandate

# inline JSON, a file path, or '-' for stdin all work:
jacs ap2 export-mandate --input checkout.json > export.json
cat checkout.json | jacs ap2 export-mandate --input - > export.json
```

The export carries the detached JWS, the checkout with
`ap2.merchant_authorization` filled in, and the binding reference as a
content hash.

## Verification

Any stock JOSE verifier can check the ES256 signature against the
agent's JWKS — see the committed reference verifier:

```bash
jacs agent export-jwks > jwks.json
npm install jose canonicalize
node scripts/smoke/verify_ap2_jws.mjs export.json jwks.json
```

**Classical verification is not native-root trust.** The ES256 check proves
possession of the compatibility key only. To trace the mandate to the
agent's native root, a JACS-aware relying party additionally verifies the
native-root-signed compatibility key binding
(`jacs agent export-compat-binding`) whose content hash the export
references. Native JACS documents are never touched by this export —
signing a mandate does not create or modify any `jacsSignature`.
