/**
 * Method enumeration parity test for the Node.js binding.
 *
 * Validates that all methods listed in
 * binding-core/tests/fixtures/method_parity.json are exposed on the
 * JacsSimpleAgent class, with documented exclusions and camelCase name mappings.
 *
 * This is a *structural* test (method names), not a *behavioral* test.
 * It complements, not duplicates, test_parity.js.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { expect } = require('chai');

const FIXTURE_PATH = path.resolve(
  __dirname,
  '../../binding-core/tests/fixtures/method_parity.json'
);

// Methods that are intentionally Rust-only and not exposed in Node.
const EXCLUDED_FROM_NODE = new Set([
  // inner_ref returns a raw Rust reference; not meaningful across FFI
  'inner_ref',
  // from_agent wraps a Rust SimpleAgent; not callable from JS
  'from_agent',
  // load_with_info is an internal Rust helper; Node uses load() directly
  'load_with_info',
  // Gated on the `a2a` cargo feature, which the default Node build does not
  // enable (jacsnpm default features are attestation + agreements).
  'export_a2a_agent_card_json',
]);

// Rust snake_case method name -> Node camelCase method name mapping.
const NODE_NAME_MAP = {
  'create': 'create',               // static
  'load': 'load',                   // static
  'ephemeral': 'ephemeral',         // static
  'create_with_params': 'createWithParams', // static
  'get_agent_id': 'getAgentId',
  'key_id': 'keyId',
  'is_strict': 'isStrict',
  'config_path': 'configPath',
  'export_agent': 'exportAgent',
  'get_public_key_pem': 'getPublicKeyPem',
  'get_public_key_base64': 'getPublicKeyBase64',
  'diagnostics': 'diagnostics',
  'verify_self': 'verifySelf',
  'verify_json': 'verify',
  'verify_with_key_json': 'verifyWithKey',
  'verify_by_id_json': 'verifyById',
  'sign_message_json': 'signMessage',
  'sign_raw_bytes_base64': 'signRawBytes',
  'sign_file_json': 'signFile',
  'build_auth_header': 'buildAuthHeader',
  'build_request_auth_header': 'buildRequestAuthHeader',
  'canonicalize_json': 'canonicalizeJson',
  'sign_response': 'signResponse',
  'encode_verify_payload': 'encodeVerifyPayload',
  'decode_verify_payload': 'decodeVerifyPayload',
  'extract_document_id': 'extractDocumentId',
  'prepare_signed_event_replay_json': 'prepareSignedEventReplay',
  'unwrap_signed_event': 'unwrapSignedEvent',
  'to_yaml': 'toYaml',
  'from_yaml': 'fromYaml',
  'to_html': 'toHtml',
  'from_html': 'fromHtml',
  'rotate_keys': 'rotateKeys',
  // ES256 compatibility key + exports (P2 Tasks 002 / 003 / 004 / 004b).
  'add_compat_key_json': 'addCompatKey',
  'issue_compat_binding_json': 'issueCompatBinding',
  'export_compatibility_jwks_json': 'exportCompatibilityJwks',
  'export_compatibility_key_binding_json': 'exportCompatibilityKeyBinding',
  'export_ap2_mandate_json': 'exportAp2Mandate',
  'export_w3c_did': 'exportW3cDid',
  'export_w3c_did_document_json': 'exportW3cDidDocument',
  'export_w3c_agent_description_json': 'exportW3cAgentDescription',
  'generate_w3c_well_known_json': 'generateW3cWellKnown',
  'sign_w3c_request_json': 'signW3cRequest',
  'verify_w3c_request_json': 'verifyW3cRequest',
  // Inline text + media (Task 11): NAPI methods on JacsSimpleAgent strip the
  // _json suffix. Short aliases (signText/verifyText) also exist on the class
  // but the parity name is the suffix-stripped name shown here.
  'sign_text_file_json': 'signTextFile',
  'verify_text_file_json': 'verifyTextFile',
  'sign_image_json': 'signImage',
  'verify_image_json': 'verifyImage',
  'extract_media_signature_json': 'extractMediaSignature',
  // Agreement v2 (feature-gated in Rust, exposed by the default Node build).
  'create_agreement_v2_json': 'createAgreementV2',
  'apply_agreement_v2_json': 'applyAgreementV2',
  'sign_agreement_v2_json': 'signAgreementV2',
  'verify_agreement_v2_json': 'verifyAgreementV2',
  'detect_agreement_v2_branch_conflict_json': 'detectAgreementV2BranchConflict',
  'merge_agreement_v2_transcript_branches_json': 'mergeAgreementV2TranscriptBranches',
  'resolve_agreement_v2_branch_conflict_json': 'resolveAgreementV2BranchConflict',
  'export_agreement_v2_as_vc_json': 'exportAgreementV2AsVc',
};

// Static methods (on the class itself, not on instances)
const STATIC_METHODS = new Set(['create', 'load', 'ephemeral', 'createWithParams']);

describe('Node.js method enumeration parity', function () {
  let fixture;
  let JacsSimpleAgent;
  let agent;

  before(function () {
    if (!fs.existsSync(FIXTURE_PATH)) {
      console.log('  Skipping method parity tests - fixture not found');
      this.skip();
      return;
    }
    fixture = JSON.parse(fs.readFileSync(FIXTURE_PATH, 'utf8'));

    try {
      const bindings = require('../index.js');
      JacsSimpleAgent = bindings.JacsSimpleAgent;
      if (!JacsSimpleAgent) {
        this.skip();
        return;
      }
      agent = JacsSimpleAgent.ephemeral('ed25519');
    } catch (e) {
      console.log('  Skipping method parity tests - native binding not available');
      this.skip();
    }
  });

  function parityMethods() {
    const methods = [...fixture.all_methods_flat];
    for (const gated of Object.values(fixture.feature_gated_methods || {})) {
      methods.push(...gated);
    }
    return methods;
  }

  it('all non-excluded methods from fixture exist on JacsSimpleAgent', function () {
    const allMethods = parityMethods();
    const missing = [];

    for (const rustName of allMethods) {
      if (EXCLUDED_FROM_NODE.has(rustName)) continue;

      const nodeName = NODE_NAME_MAP[rustName];
      if (!nodeName) {
        missing.push(`${rustName} (no NODE_NAME_MAP entry)`);
        continue;
      }

      if (STATIC_METHODS.has(nodeName)) {
        // Check on the class itself
        if (typeof JacsSimpleAgent[nodeName] !== 'function') {
          missing.push(`${rustName} -> static ${nodeName}`);
        }
      } else {
        // Check on the instance
        if (typeof agent[nodeName] !== 'function') {
          missing.push(`${rustName} -> ${nodeName}`);
        }
      }
    }

    expect(missing, `Missing methods:\n${missing.join('\n')}`).to.be.empty;
  });

  it('public simple protocol helpers perform a strict roundtrip', function () {
    const legacy = agent.buildAuthHeader();
    expect(legacy).to.match(/^JACS /);
    const body = '{"include_test":false}';
    const header = agent.buildRequestAuthHeader(
      'POST',
      'https://hai.ai/api/v1/agents/hello',
      body,
      'hai.ai'
    );
    expect(header).to.match(/^JACS v2\./);

    const envelope = agent.signResponse('{"type":"connected"}');
    const parsed = JSON.parse(envelope);
    const signerId = parsed.jacsSignature.agentID;
    const verified = JSON.parse(agent.unwrapSignedEvent(
      envelope,
      JSON.stringify({ [signerId]: agent.getPublicKeyPem() })
    ));
    expect(verified.verified).to.equal(true);
    expect(verified.data.type).to.equal('connected');
  });

  it('request auth hashes exact Buffer and Uint8Array body bytes', function () {
    const backing = new Uint8Array([0xaa, 0x10, 0x00, 0xff, 0x20, 0xbb]);
    const bodies = [
      Buffer.from([0x00, 0xff, 0x62, 0x00, 0x79]),
      new Uint8Array([0x80, 0x00, 0xfe, 0x7f]),
      backing.subarray(1, 5),
    ];
    for (const body of bodies) {
      const header = agent.buildRequestAuthHeader(
        'POST',
        'https://hai.ai/api/v1/jobs',
        body,
        'hai.ai',
      );
      const claimsSegment = header.slice('JACS v2.'.length).split('.', 1)[0];
      const claims = JSON.parse(Buffer.from(claimsSegment, 'base64url').toString('utf8'));
      const expected = crypto.createHash('sha256').update(body).digest('base64');
      expect(claims.contentDigest).to.equal(`sha-256=:${expected}:`);
    }
  });

  it('exclusions are all valid fixture methods', function () {
    const allMethods = new Set(parityMethods());
    const invalid = [];
    for (const excluded of EXCLUDED_FROM_NODE) {
      if (!allMethods.has(excluded)) {
        invalid.push(excluded);
      }
    }
    expect(invalid, `EXCLUDED_FROM_NODE contains methods not in fixture: ${invalid}`).to.be.empty;
  });

  it('NODE_NAME_MAP covers all non-excluded methods', function () {
    const allMethods = parityMethods();
    const unmapped = [];
    for (const rustName of allMethods) {
      if (EXCLUDED_FROM_NODE.has(rustName)) continue;
      if (!(rustName in NODE_NAME_MAP)) {
        unmapped.push(rustName);
      }
    }
    expect(unmapped, `Methods without NODE_NAME_MAP entry: ${unmapped}`).to.be.empty;
  });

  it('NODE_NAME_MAP has no stale entries', function () {
    const allMethods = new Set(parityMethods());
    const stale = [];
    for (const rustName of Object.keys(NODE_NAME_MAP)) {
      if (!allMethods.has(rustName)) {
        stale.push(rustName);
      }
    }
    expect(stale, `Stale NODE_NAME_MAP entries: ${stale}`).to.be.empty;
  });

  it('method count matches fixture minus exclusions', function () {
    const expected = parityMethods().length - EXCLUDED_FROM_NODE.size;
    const nodeNameCount = Object.keys(NODE_NAME_MAP).length;
    expect(nodeNameCount).to.equal(expected,
      `NODE_NAME_MAP has ${nodeNameCount} entries but expected ${expected} (${EXCLUDED_FROM_NODE.size} excluded)`
    );
  });
});
