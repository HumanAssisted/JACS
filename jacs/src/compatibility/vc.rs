//! Agreement-v2 → Verifiable Credential export (P2 Task 004c, FR16).
//!
//! Projects an Agreement-v2 JSON document into a schema-pinned VC 2.0
//! credential carrying an `ecdsa-jcs-2019` Data Integrity proof, signed
//! with the ES256 `ecosystem_signing` compatibility key. This is a
//! purpose-built content exporter, not a generic VC issuer: input must
//! be a valid Agreement-v2 document, the cryptosuite is fixed, the
//! `agreement-vc` binding scope gates it (content scopes are NEVER
//! auto-issued), and the native agreement is not mutated.
//!
//! Proof construction pinned to W3C vc-di-ecdsa (Recommendation
//! 2025-05-15), `ecdsa-jcs-2019`:
//!
//! - proof options and document are separately JCS-canonicalized
//!   (RFC 8785); the proof options copy the document's `@context`
//! - signing input = `SHA-256(JCS(proofOptions)) || SHA-256(JCS(document))`
//! - `proofValue` is multibase base58btc (`z…`) over the 64-byte
//!   `r || s` ECDSA P-256 signature
//! - `proof.verificationMethod` references a **Multikey**
//!   (`publicKeyMultibase`) — conformant `ecdsa-jcs-2019` verifiers
//!   reject JWK-typed methods, so this pins the Task 004 Multikey entry
//!   of the DID document
//!
//! This module is compiled only with the `agreements` feature (it
//! references `crate::agreements::v2`). Incoming VC verification is out
//! of P2 scope.

use crate::agent::Agent;
use crate::error::JacsError;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::info;

/// VC 2.0 base context — always FIRST in `@context`.
pub const VC_BASE_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";
/// JACS agreement credential context (an identifier, not a fetched
/// resource — `ecdsa-jcs-2019` requires no JSON-LD processing).
pub const AGREEMENT_VC_CONTEXT: &str = "https://hai.ai/ns/credentials/jacs-agreement/v1";
/// Credential type appended after `VerifiableCredential`.
pub const AGREEMENT_VC_TYPE: &str = "JacsAgreementCredential";
/// The one fixed cryptosuite of this exporter.
pub const CRYPTOSUITE: &str = "ecdsa-jcs-2019";

/// Build an `ecdsa-jcs-2019` DataIntegrityProof over `unsecured_document`
/// per W3C vc-di-ecdsa: the returned proof object includes the document's
/// `@context` (spec step: "set the proof options @context to
/// unsecuredDocument.@context") and the multibase `proofValue`.
/// `pub(crate)` so the KAT unit test can pin exact bytes with the W3C
/// test-vector key.
pub(crate) fn build_ecdsa_jcs_2019_proof(
    private_pkcs8_der: &[u8],
    verification_method: &str,
    created: &str,
    proof_purpose: &str,
    unsecured_document: &Value,
) -> Result<Value, JacsError> {
    let mut proof_config = json!({
        "type": "DataIntegrityProof",
        "cryptosuite": CRYPTOSUITE,
        "created": created,
        "verificationMethod": verification_method,
        "proofPurpose": proof_purpose,
    });
    if let Some(ctx) = unsecured_document.get("@context") {
        proof_config["@context"] = ctx.clone();
    }

    let canonical_config = jacs_core::canonical::canonicalize_json_try(&proof_config)
        .map_err(|e| JacsError::ValidationError(format!("JCS(proofOptions) failed: {e}")))?;
    let canonical_document = jacs_core::canonical::canonicalize_json_try(unsecured_document)
        .map_err(|e| JacsError::ValidationError(format!("JCS(document) failed: {e}")))?;

    // hashData = SHA-256(JCS(proofOptions)) || SHA-256(JCS(document));
    // ECDSA-P256-SHA256 then signs hashData as the message.
    let mut hash_data = Vec::with_capacity(64);
    hash_data.extend_from_slice(&Sha256::digest(canonical_config.as_bytes()));
    hash_data.extend_from_slice(&Sha256::digest(canonical_document.as_bytes()));

    let signature = crate::crypt::es256::sign_es256_jose(private_pkcs8_der, &hash_data)?;
    proof_config["proofValue"] = json!(format!("z{}", bs58::encode(&signature).into_string()));
    Ok(proof_config)
}

/// Export an Agreement-v2 JSON document as a Verifiable Credential with
/// an `ecdsa-jcs-2019` Data Integrity proof.
///
/// Takes Agreement-v2 JSON (never a document id — no storage semantics),
/// requires the `agreement-vc` binding scope (content exports never
/// auto-issue), and leaves the native agreement untouched: the VC is a
/// derived view whose `credentialSubject` embeds the agreement verbatim.
pub fn export_agreement_v2_as_vc(
    agent: &mut Agent,
    key_directory: &str,
    agreement_json: &str,
) -> Result<Value, JacsError> {
    let agreement: Value = serde_json::from_str(agreement_json)
        .map_err(|e| JacsError::ValidationError(format!("agreement input is not JSON: {e}")))?;
    // Typed boundary: a valid Agreement-v2 document, not arbitrary JSON.
    crate::agreements::v2::assert_agreement_v2(&agreement)?;

    // Content scope: require_scope directly — no auto-issue path.
    let binding = super::binding::require_scope(agent, key_directory, "agreement-vc")?;
    let binding_hash = binding["jacsSha256"].as_str().unwrap_or("").to_string();
    let compat = crate::keystore::compat::ecosystem_key_info(key_directory)?;

    // The verification method is the Multikey entry of the agent's DID
    // document (Task 004) — the JWK entry would be rejected by
    // conformant ecdsa-jcs-2019 verifiers.
    let did = crate::w3c::did_wba::export_did_identifier(agent)?;
    let verification_method = format!("{}#{}-multikey", did, compat.kid);

    let created = crate::time_utils::now_rfc3339();
    let agreement_urn = match (
        agreement.get("jacsId").and_then(Value::as_str),
        agreement.get("jacsVersion").and_then(Value::as_str),
    ) {
        (Some(id), Some(version)) => format!("urn:jacs:agreement:{id}:{version}"),
        (Some(id), None) => format!("urn:jacs:agreement:{id}"),
        _ => format!("urn:jacs:agreement:{}", binding_hash),
    };

    let mut vc = json!({
        "@context": [VC_BASE_CONTEXT, AGREEMENT_VC_CONTEXT],
        "type": ["VerifiableCredential", AGREEMENT_VC_TYPE],
        "id": agreement_urn,
        "issuer": did,
        "validFrom": created,
        "credentialSubject": {
            "id": agreement_urn,
            "type": "JacsAgreementV2",
            "jacsAgreementV2": agreement
        }
    });

    // Decrypt the ES256 private key; plaintext PKCS#8 DER lives only in
    // this zeroizing buffer for the duration of the signing call.
    let password = agent.resolve_password()?;
    let encrypted =
        std::fs::read(&compat.private_key_path).map_err(|e| JacsError::FileReadFailed {
            path: compat.private_key_path.clone(),
            reason: e.to_string(),
        })?;
    let private_der =
        crate::crypt::aes_encrypt::decrypt_private_key_secure_with_password(&encrypted, &password)?;
    let proof = build_ecdsa_jcs_2019_proof(
        private_der.as_slice(),
        &verification_method,
        &created,
        "assertionMethod",
        &vc,
    )?;
    vc["proof"] = proof;

    info!(
        event = "ecosystem_export_generated",
        format = "agreement-vc",
        kid = %compat.kid,
        binding_hash = %binding_hash,
        cryptosuite = CRYPTOSUITE,
        "Agreement-v2 exported as VC with ecdsa-jcs-2019 Data Integrity proof"
    );

    Ok(json!({
        "format": "agreement-vc",
        "specSource": "W3C vc-di-ecdsa (Recommendation 2025-05-15), ecdsa-jcs-2019",
        "kid": compat.kid,
        "jacsCompatBindingHash": binding_hash,
        "vc": vc
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// W3C vc-di-ecdsa Recommendation test vectors, appendix
    /// "Representation: ecdsa-jcs-2019 with curve P-256" (Examples 49-59).
    const SPEC_SECRET_MULTIKEY: &str = "z42twTcNeSYcnqg1FLuSFs2bsGH3ZqbRHFmvS9XMsYhjxvHN";
    const SPEC_PUBLIC_MULTIKEY: &str = "zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP";
    const SPEC_VM: &str = "did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP";
    const SPEC_CREATED: &str = "2023-02-24T23:36:38Z";
    /// Example 52: SHA-256 of the canonical credential.
    const SPEC_DOC_HASH_HEX: &str =
        "59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19";
    /// Example 55: SHA-256 of the canonical proof options.
    const SPEC_CONFIG_HASH_HEX: &str =
        "fe5799489119c7fe3c528715e72bd39d2ec6b4ab345978df32e9a9312648ec25";
    /// Example 57: ECDSA signature (r||s hex) over the combined hashes.
    const SPEC_SIGNATURE_HEX: &str = "f15c3b599eb9b3cad05df9d8e8b39a70a86375833b53743c764ac0a88c4457d60707fd7d073e03d906130631d87803f80a9824dc9939632ba92d418181be9d16";
    /// Example 58: the same signature base-58-btc encoded.
    const SPEC_PROOF_VALUE: &str =
        "z5ptCet75SaEgzG4v4zJhbJtfNi74Wv7Fq15hhKouJQQjEPQvPZKaYxcMXAMLPQS2FXrkCWokNJkFVkwxNzZfD5oT";

    fn spec_credential() -> Value {
        json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
            "type": ["VerifiableCredential", "AlumniCredential"],
            "name": "Alumni Credential",
            "description": "A minimum viable example of an Alumni Credential.",
            "issuer": "https://vc.example/issuers/5678",
            "validFrom": "2023-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "did:example:abcdefgh",
                "alumniOf": "The School of Examples"
            }
        })
    }

    fn spec_private_pkcs8_der() -> Vec<u8> {
        use p256::pkcs8::EncodePrivateKey;
        let bytes = bs58::decode(SPEC_SECRET_MULTIKEY.trim_start_matches('z'))
            .into_vec()
            .expect("secret multikey decodes");
        assert_eq!(&bytes[..2], &[0x86, 0x26], "p256 secret multicodec prefix");
        let secret = p256::SecretKey::from_slice(&bytes[2..]).expect("scalar");
        secret.to_pkcs8_der().expect("pkcs8").as_bytes().to_vec()
    }

    fn spec_public_spki_pem() -> String {
        use p256::pkcs8::EncodePublicKey;
        let bytes = bs58::decode(SPEC_PUBLIC_MULTIKEY.trim_start_matches('z'))
            .into_vec()
            .expect("public multikey decodes");
        assert_eq!(&bytes[..2], &[0x80, 0x24], "p256 public multicodec prefix");
        let key = p256::PublicKey::from_sec1_bytes(&bytes[2..]).expect("compressed point");
        key.to_public_key_pem(Default::default()).expect("pem")
    }

    #[test]
    fn ecdsa_jcs_2019_proof_matches_w3c_test_vector() {
        let credential = spec_credential();
        let proof = build_ecdsa_jcs_2019_proof(
            &spec_private_pkcs8_der(),
            SPEC_VM,
            SPEC_CREATED,
            "assertionMethod",
            &credential,
        )
        .expect("build proof");

        // The proof carries the document's @context (spec assembly step).
        assert_eq!(proof["@context"], credential["@context"]);
        assert_eq!(proof["cryptosuite"], "ecdsa-jcs-2019");

        // Both canonicalization hashes match the spec vectors exactly.
        let doc_hash = Sha256::digest(
            jacs_core::canonical::canonicalize_json_try(&credential)
                .unwrap()
                .as_bytes(),
        );
        assert_eq!(hex::encode(doc_hash), SPEC_DOC_HASH_HEX, "document hash");
        let mut config = proof.clone();
        config.as_object_mut().unwrap().remove("proofValue");
        let config_hash = Sha256::digest(
            jacs_core::canonical::canonicalize_json_try(&config)
                .unwrap()
                .as_bytes(),
        );
        assert_eq!(
            hex::encode(config_hash),
            SPEC_CONFIG_HASH_HEX,
            "proof options hash"
        );

        // Byte-exact proofValue: p256 signs per RFC 6979 (deterministic),
        // matching the spec's published signature.
        assert_eq!(
            proof["proofValue"].as_str().unwrap(),
            SPEC_PROOF_VALUE,
            "proofValue drift against the W3C vector"
        );

        // And the spec's own signature verifies through our ES256 verify
        // path over hashData (independent of how it was produced).
        let mut hash_data = Vec::with_capacity(64);
        hash_data.extend_from_slice(&config_hash);
        hash_data.extend_from_slice(&doc_hash);
        let sig = hex::decode(SPEC_SIGNATURE_HEX).unwrap();
        crate::crypt::es256::verify_es256_jose(&spec_public_spki_pem(), &hash_data, &sig)
            .expect("spec signature verifies");

        // b58 sanity: proofValue decodes to the spec signature bytes.
        let decoded = bs58::decode(SPEC_PROOF_VALUE.trim_start_matches('z'))
            .into_vec()
            .unwrap();
        assert_eq!(hex::encode(decoded), SPEC_SIGNATURE_HEX);
    }
}
