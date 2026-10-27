//! JACS extension management for legacy A2A cards and opt-in A2A 1.0 discovery.

use crate::a2a::agent_card::create_extension_descriptor;
use crate::a2a::keys::sign_jws;
use crate::a2a::{AgentCard, AgentCardSignature};
use crate::agent::{Agent, boilerplate::BoilerPlate};
use crate::crypt::supported_verification_algorithms;
use crate::error::JacsError;
use crate::time_utils;
use serde_json::{Value, json};
use tracing::info;

/// Sign an A2A Agent Card using JWS and embed the signature.
///
/// Returns a clone of the AgentCard with the JWS signature appended to
/// its `signatures` field (per A2A v0.4.0).
pub fn sign_agent_card_jws(
    agent_card: &AgentCard,
    private_key: &[u8],
    algorithm: &str,
    key_id: &str,
) -> Result<String, JacsError> {
    // Serialize the agent card to JSON
    let agent_card_json = if matches!(algorithm, "pq2025" | "ML-DSA-87") {
        let mut unsigned = agent_card.clone();
        unsigned.signatures = None;
        jacs_core::canonical::canonicalize_json_try(&serde_json::to_value(unsigned)?)?.into_bytes()
    } else {
        serde_json::to_vec(agent_card)?
    };

    // Sign using JWS
    let jws = sign_jws(&agent_card_json, private_key, algorithm, key_id)?;

    info!("Successfully signed Agent Card with JWS");
    Ok(jws)
}

/// Embed a JWS signature into an AgentCard's `signatures` field (v0.4.0).
///
/// Returns a new AgentCard with the signature appended.
pub fn embed_signature_in_agent_card(
    agent_card: &AgentCard,
    jws_signature: &str,
    key_id: Option<&str>,
) -> AgentCard {
    let mut card = agent_card.clone();
    let sig = AgentCardSignature {
        jws: jws_signature.to_string(),
        key_id: key_id.map(|k| k.to_string()),
    };
    match card.signatures.as_mut() {
        Some(sigs) => sigs.push(sig),
        None => card.signatures = Some(vec![sig]),
    }
    card
}

/// Verify a JWS signature on an A2A Agent Card.
///
/// Checks the first (or specified) JWS signature in the card's `signatures`
/// field against the card's serialized content. The signature is verified by
/// serializing the card *without* signatures, then checking the JWS payload
/// matches and the cryptographic signature is valid.
///
/// # Arguments
///
/// * `agent_card` - The Agent Card to verify (must have at least one signature)
/// * `public_key` - The public key bytes for verification
/// * `algorithm` - The key algorithm (e.g., "ring-Ed25519")
///
/// # Returns
///
/// `Ok(true)` if the signature is valid, or an error describing the failure.
pub fn verify_agent_card_jws(
    agent_card: &AgentCard,
    public_key: &[u8],
    algorithm: &str,
) -> Result<bool, JacsError> {
    use crate::a2a::keys::verify_jws;

    // Get the first signature
    let signatures = agent_card
        .signatures
        .as_ref()
        .ok_or("Agent Card has no signatures")?;

    if signatures.is_empty() {
        return Err("Agent Card signatures array is empty".into());
    }

    let signature = &signatures[0];
    let jws = &signature.jws;

    // The outer A2A keyId and protected JOSE kid must name the same key. A
    // verifier selects the JWKS entry by keyId, so allowing a different or
    // missing protected kid would make key-selection metadata ambiguous.
    use base64::Engine as _;
    let protected_segment = jws
        .split('.')
        .next()
        .ok_or_else(|| JacsError::CryptoError("JWS protected header is missing".to_string()))?;
    let protected_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(protected_segment)
        .map_err(|error| {
            JacsError::CryptoError(format!("Invalid JWS protected header encoding: {error}"))
        })?;
    let protected =
        jacs_core::strict_json::parse_strict_json_slice(&protected_bytes).map_err(|error| {
            JacsError::CryptoError(format!("Invalid JWS protected header: {error}"))
        })?;
    let protected_kid = protected
        .get("kid")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            JacsError::CryptoError("JWS protected header is missing required 'kid'".to_string())
        })?;
    let outer_kid = signature.key_id.as_deref().ok_or_else(|| {
        JacsError::CryptoError("Agent Card signature is missing required keyId".to_string())
    })?;
    if protected_kid != outer_kid {
        return Err(JacsError::CryptoError(format!(
            "Agent Card signature keyId '{}' does not match protected JWS kid '{}'",
            outer_kid, protected_kid
        )));
    }

    // Serialize the card without signatures for comparison. The named ES256
    // exporter signs RFC 8785/JCS bytes; the historical Ed25519 API signed the
    // AgentCard serializer's bytes. Support both contracts explicitly.
    let mut card_without_sig = agent_card.clone();
    card_without_sig.signatures = None;
    let expected_payload = if matches!(
        algorithm,
        "ES256" | "es256" | "ecdsa" | "pq2025" | "ML-DSA-87"
    ) {
        let value = serde_json::to_value(&card_without_sig)?;
        jacs_core::canonical::canonicalize_json_try(&value)
            .map_err(|error| {
                JacsError::ValidationError(format!(
                    "Agent Card JCS canonicalization failed: {error}"
                ))
            })?
            .into_bytes()
    } else {
        serde_json::to_vec(&card_without_sig)?
    };

    // Verify the JWS signature
    let verified_payload = verify_jws(jws, public_key, algorithm)?;

    // Compare payload content
    if verified_payload != expected_payload {
        return Err("JWS payload does not match the Agent Card content".into());
    }

    info!("Successfully verified Agent Card JWS signature");
    Ok(true)
}

/// Generate the .well-known endpoints for A2A integration
pub struct WellKnownEndpoints {
    pub agent_card_path: String,
    pub jwks_path: String,
    pub compat_binding_path: String,
    pub jacs_descriptor_path: String,
    pub jacs_pubkey_path: String,
    pub jacs_extension_path: String,
}

impl Default for WellKnownEndpoints {
    fn default() -> Self {
        Self {
            agent_card_path: "/.well-known/agent-card.json".to_string(),
            jwks_path: "/.well-known/jwks.json".to_string(),
            compat_binding_path: crate::compatibility::exports::A2A_COMPAT_BINDING_PATH.to_string(),
            jacs_descriptor_path: "/.well-known/jacs-agent.json".to_string(),
            jacs_pubkey_path: "/.well-known/jacs-pubkey.json".to_string(),
            jacs_extension_path: "/.well-known/jacs-extension.json".to_string(),
        }
    }
}

/// Legacy caller-supplied-key discovery generator.
///
/// This API previously produced a fresh, unbound Ed25519 identity on every
/// call. It now fails closed because a self-advertised ephemeral key cannot
/// establish the card's JACS identity. Use
/// [`generate_bound_well_known_documents`] so the persisted ES256
/// compatibility key and its native-root-signed binding are published
/// together.
#[deprecated(
    since = "0.11.4",
    note = "use generate_bound_well_known_documents; caller-supplied unbound A2A keys are rejected"
)]
pub fn generate_well_known_documents(
    _agent: &Agent,
    _agent_card: &AgentCard,
    _a2a_public_key: &[u8],
    _a2a_algorithm: &str,
    _jws_signature: &str,
) -> Result<Vec<(String, Value)>, JacsError> {
    Err(JacsError::ValidationError(
        "caller-supplied A2A discovery keys are no longer accepted because they are not bound to \
         the claimed JACS identity; use generate_bound_well_known_documents with the persisted \
         ES256 compatibility key"
            .to_string(),
    ))
}

/// Generate the complete, identity-bound A2A discovery document set.
///
/// The Agent Card is JCS-signed with the persisted ES256 compatibility key;
/// the JWKS publishes that same key; and the same-origin compatibility
/// binding endpoint publishes the current native-root-signed authorization
/// artifact. Repeated calls and processes sharing the identity directory
/// therefore return the same card/JWKS/binding tuple.
pub fn generate_bound_well_known_documents(
    agent: &mut Agent,
    key_directory: &str,
    agent_card: Option<AgentCard>,
) -> Result<Vec<(String, Value)>, JacsError> {
    let signing_algorithm = agent.get_key_algorithm().cloned().ok_or_else(|| {
        JacsError::ValidationError(
            "identity-bound A2A discovery requires the loaded agent's configured signing algorithm"
                .to_string(),
        )
    })?;
    let mut documents = Vec::new();
    let endpoints = WellKnownEndpoints::default();

    // 1. Agent Card signed by the persisted, native-root-bound ES256 key.
    let card = match agent_card {
        Some(card) => card,
        None => crate::a2a::agent_card::export_agent_card(agent)?,
    };
    let expected_agent_id = agent.get_id()?;
    let expected_agent_version = agent.get_version()?;
    let card_agent_id = card
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("jacsId"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            JacsError::ValidationError(
                "identity-bound A2A Agent Card is missing metadata.jacsId".to_string(),
            )
        })?;
    let card_agent_version = card
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("jacsVersion"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            JacsError::ValidationError(
                "identity-bound A2A Agent Card is missing metadata.jacsVersion".to_string(),
            )
        })?;
    if card_agent_id != expected_agent_id
        || card_agent_version != expected_agent_version
        || card.version != expected_agent_version
    {
        return Err(JacsError::ValidationError(format!(
            "identity-bound A2A Agent Card does not match the loaded agent: expected \
             id/version '{expected_agent_id}:{expected_agent_version}', card metadata claims \
             '{card_agent_id}:{card_agent_version}', card.version is '{}'",
            card.version
        )));
    }
    let card_json =
        crate::compatibility::exports::export_a2a_agent_card_from(agent, key_directory, card)?;
    documents.push((endpoints.agent_card_path, card_json));

    // 2. JWKS for the exact same persisted ES256 compatibility key.
    let jwks = crate::compatibility::exports::export_compatibility_jwks(agent, key_directory)?;
    documents.push((endpoints.jwks_path, jwks));

    // 3. Deterministically resolvable native-root-signed binding artifact.
    let binding =
        crate::compatibility::exports::export_compatibility_key_binding(agent, key_directory)?;
    documents.push((endpoints.compat_binding_path, binding));

    // 4. JACS Agent Descriptor
    let jacs_descriptor = create_jacs_agent_descriptor(agent)?;
    documents.push((endpoints.jacs_descriptor_path, jacs_descriptor));

    // 5. JACS Public Key
    let jacs_pubkey_doc = create_jacs_pubkey_document(agent)?;
    documents.push((endpoints.jacs_pubkey_path, jacs_pubkey_doc));

    // 6. JACS Extension Descriptor
    let extension_descriptor = create_extension_descriptor(&signing_algorithm);
    documents.push((endpoints.jacs_extension_path, extension_descriptor));

    Ok(documents)
}

/// Generate discovery with the loaded PQ root by default. ES256 delegation is
/// available only when explicitly selected; a PQ error never triggers fallback.
/// The legacy card model is retained; this does not upgrade its A2A wire version.
pub fn generate_well_known_documents_for_algorithm(
    agent: &mut Agent,
    key_directory: &str,
    agent_card: Option<AgentCard>,
    algorithm: Option<&str>,
) -> Result<Vec<(String, Value)>, JacsError> {
    if algorithm.is_some_and(|a| a.eq_ignore_ascii_case("ES256")) {
        return generate_bound_well_known_documents(agent, key_directory, agent_card);
    }
    if algorithm.is_some_and(|a| !matches!(a, "pq2025" | "ML-DSA-87")) {
        return Err(JacsError::ValidationError(
            "unsupported A2A signing algorithm; select ML-DSA-87 or explicit ES256 compatibility"
                .into(),
        ));
    }
    if agent.get_key_algorithm().map(String::as_str) != Some("pq2025") {
        return Err(JacsError::ValidationError("direct A2A discovery requires a loaded pq2025 root; ES256 compatibility must be explicitly selected".into()));
    }
    use crate::crypt::KeyManager;
    use base64::{
        Engine as _,
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    };

    let mut card = match agent_card {
        Some(card) => card,
        None => crate::a2a::agent_card::export_agent_card(agent)?,
    };
    let id = agent.get_id()?;
    let version = agent.get_version()?;
    let metadata = card
        .metadata
        .as_mut()
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            JacsError::ValidationError("Agent Card metadata must be an object".into())
        })?;
    if metadata.get("jacsId").and_then(Value::as_str) != Some(id.as_str())
        || metadata.get("jacsVersion").and_then(Value::as_str) != Some(version.as_str())
        || card.version != version
    {
        return Err(JacsError::ValidationError(
            "Agent Card does not match the loaded identity and version".into(),
        ));
    }
    // An already signed/delegated projection must not smuggle stale authority.
    if card.signatures.is_some() || metadata.keys().any(|k| k.starts_with("jacsCompat")) {
        return Err(JacsError::ValidationError(
            "direct-root Agent Card must be unsigned and contain no compatibility binding".into(),
        ));
    }
    let public_key = agent.get_public_key()?.clone();
    let jwk = jacs_core::jose::mldsa87_public_jwk(&public_key)?;
    let kid = jwk["kid"]
        .as_str()
        .ok_or_else(|| JacsError::CryptoError("missing root kid".into()))?;
    metadata.insert("jacsRootKid".into(), json!(kid));
    let payload = jacs_core::canonical::canonicalize_json_try(&serde_json::to_value(&card)?)?;
    let input = jacs_core::jose::mldsa87_jws_signing_input(payload.as_bytes(), kid)?;
    // The native custody boundary handles encrypted keys and zeroizing owners.
    let signature = STANDARD.decode(agent.sign_string(&input)?)?;
    let jws = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature));
    jacs_core::jose::verify_mldsa87_jws(&jws, &public_key, Some(kid))?;
    let signed = embed_signature_in_agent_card(&card, &jws, Some(kid));
    let endpoints = WellKnownEndpoints::default();
    let mut descriptor = create_jacs_agent_descriptor(agent)?;
    descriptor["endpoints"]
        .as_object_mut()
        .unwrap()
        .remove("compatibilityBinding");
    let mut extension = create_extension_descriptor("pq2025");
    extension["endpoints"]
        .as_object_mut()
        .unwrap()
        .remove("compatibilityBinding");
    extension["endpoints"]["jwks"]["description"] =
        json!("Retrieve the stable ML-DSA-87 root key used by the Agent Card");
    info!(event = "ecosystem_export_generated", format = "a2a", algorithm = "ML-DSA-87", kid = %kid, "A2A discovery signed directly by the native root");
    Ok(vec![
        (endpoints.agent_card_path, serde_json::to_value(signed)?),
        (endpoints.jwks_path, json!({"keys": [jwk]})),
        (endpoints.jacs_descriptor_path, descriptor),
        (
            endpoints.jacs_pubkey_path,
            create_jacs_pubkey_document(agent)?,
        ),
        (endpoints.jacs_extension_path, extension),
    ])
}

/// Generate discovery for an explicitly described A2A 1.0 JSON-RPC service.
/// Omitting options preserves the legacy card format. This publishes metadata
/// only: the caller must implement the URL, skills and content modes it declares.
pub fn generate_well_known_documents_with_options(
    agent: &mut Agent,
    key_directory: &str,
    legacy_card: Option<AgentCard>,
    algorithm: Option<&str>,
    options_json: Option<&str>,
) -> Result<Vec<(String, Value)>, JacsError> {
    let Some(options_json) = options_json else {
        return generate_well_known_documents_for_algorithm(
            agent,
            key_directory,
            legacy_card,
            algorithm,
        );
    };
    let options: super::v1::DiscoveryOptions = serde_json::from_str(options_json).map_err(|e| {
        JacsError::ValidationError(format!(
            "A2A 1.0 discovery requires protocolVersion, messagingUrl, explicit skills, defaultInputModes and defaultOutputModes: {e}"
        ))
    })?;
    let card = super::v1::project_agent_card_for_discovery(agent, options)?;
    let es256 = algorithm.is_some_and(|value| value.eq_ignore_ascii_case("ES256"));
    if !es256 && algorithm.is_some_and(|value| !matches!(value, "pq2025" | "ML-DSA-87")) {
        return Err(JacsError::ValidationError(
            "unsupported A2A signing algorithm; select ML-DSA-87 or explicit ES256 compatibility"
                .into(),
        ));
    }
    let endpoints = WellKnownEndpoints::default();
    let (signed_card, jwks, binding) = if es256 {
        (
            super::v1::export_agent_card_es256(agent, key_directory, card)?,
            crate::compatibility::exports::export_compatibility_jwks(agent, key_directory)?,
            Some(
                crate::compatibility::exports::export_compatibility_key_binding(
                    agent,
                    key_directory,
                )?,
            ),
        )
    } else {
        (
            super::v1::export_agent_card(agent, key_directory, card)?,
            json!({"keys": [jacs_core::jose::mldsa87_public_jwk(&agent.get_public_key()?)?]}),
            None,
        )
    };
    // A concurrent key/binding lifecycle change must fail closed, rather than
    // publishing a card from one generation alongside another binding or key.
    let root_key = agent.get_public_key()?;
    let id = agent.get_id()?;
    let version = agent.get_version()?;
    if let Some(binding) = &binding {
        super::v1::verify_card_binding(
            &signed_card,
            binding,
            &jwks["keys"][0],
            &id,
            &version,
            &root_key,
        )?;
    } else {
        super::v1::verify_root_card(&signed_card, &jwks["keys"][0], &id, &version, &root_key)?;
    }
    let algorithm = agent.get_key_algorithm().ok_or("missing root algorithm")?;
    let mut descriptor = create_jacs_agent_descriptor(agent)?;
    let mut extension = create_extension_descriptor(algorithm);
    extension["a2aProtocolVersion"] = json!("1.0");
    if !es256 {
        descriptor["endpoints"]
            .as_object_mut()
            .unwrap()
            .remove("compatibilityBinding");
        extension["endpoints"]
            .as_object_mut()
            .unwrap()
            .remove("compatibilityBinding");
        extension["endpoints"]["jwks"]["description"] =
            json!("Retrieve the stable ML-DSA-87 root key used by the Agent Card");
    }
    let mut documents = vec![
        (endpoints.agent_card_path, signed_card),
        (endpoints.jwks_path, jwks),
        (endpoints.jacs_descriptor_path, descriptor),
        (
            endpoints.jacs_pubkey_path,
            create_jacs_pubkey_document(agent)?,
        ),
        (endpoints.jacs_extension_path, extension),
    ];
    if let Some(binding) = binding {
        documents.push((endpoints.compat_binding_path, binding));
    }
    Ok(documents)
}

/// Create JACS agent descriptor document
fn create_jacs_agent_descriptor(agent: &Agent) -> Result<Value, JacsError> {
    let agent_value = agent.get_value().ok_or("Agent value not loaded")?;

    let public_key = agent.get_public_key()?;
    let public_key_hash = crate::crypt::hash::hash_public_key(&public_key);

    let agent_id = agent.get_id()?;
    let agent_version = agent.get_version()?;
    let key_algorithm = agent.get_key_algorithm();

    Ok(json!({
        "jacsVersion": "1.0",
        "agentId": agent_id,
        "agentVersion": agent_version,
        "agentType": agent_value.get("jacsAgentType"),
        "publicKeyHash": public_key_hash,
        "keyAlgorithm": key_algorithm,
        "capabilities": {
            "signing": true,
            "verification": true,
            "verificationAlgorithms": supported_verification_algorithms(),
            "postQuantum": key_algorithm
                .map(|alg| alg.contains("pq2025"))
                .unwrap_or(false),
        },
        "schemas": {
            "agent": "https://jacs.sh/schemas/agent/v1/agent.schema.json",
            "header": "https://jacs.sh/schemas/header/v1/header.schema.json",
            "signature": "https://jacs.sh/schemas/components/signature/v1/signature.schema.json",
        },
        "endpoints": {
            "verify": "/jacs/verify",
            "sign": "/jacs/sign",
            "agent": "/jacs/agent",
            "jwks": "/.well-known/jwks.json",
            "compatibilityBinding": crate::compatibility::exports::A2A_COMPAT_BINDING_PATH,
        }
    }))
}

/// Create JACS public key document
fn create_jacs_pubkey_document(agent: &Agent) -> Result<Value, JacsError> {
    let public_key = agent.get_public_key()?;
    let public_key_b64 = crate::crypt::base64_encode(&public_key);
    let public_key_hash = crate::crypt::hash::hash_public_key(&public_key);

    let agent_id = agent.get_id()?;
    let agent_version = agent.get_version()?;

    Ok(json!({
        "publicKey": public_key_b64,
        "publicKeyHash": public_key_hash,
        "algorithm": agent.get_key_algorithm(),
        "agentId": agent_id,
        "agentVersion": agent_version,
        "timestamp": time_utils::now_rfc3339(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::a2a::JACS_EXTENSION_URI;

    #[test]
    fn test_well_known_endpoints_has_all_six_paths() {
        let endpoints = WellKnownEndpoints::default();
        assert_eq!(endpoints.agent_card_path, "/.well-known/agent-card.json");
        assert_eq!(endpoints.jwks_path, "/.well-known/jwks.json");
        assert_eq!(
            endpoints.compat_binding_path,
            "/.well-known/jacs-compat-binding.json"
        );
        assert_eq!(
            endpoints.jacs_descriptor_path,
            "/.well-known/jacs-agent.json"
        );
        assert_eq!(endpoints.jacs_pubkey_path, "/.well-known/jacs-pubkey.json");
        assert_eq!(
            endpoints.jacs_extension_path,
            "/.well-known/jacs-extension.json"
        );
    }

    #[test]
    fn bound_discovery_rejects_missing_configured_signing_algorithm() {
        let mut agent = crate::get_empty_agent();
        let error = generate_bound_well_known_documents(&mut agent, ".", None)
            .expect_err("an unconfigured algorithm must never be advertised as unknown");
        assert!(
            error.to_string().contains("configured signing algorithm"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn test_well_known_endpoints_all_under_well_known() {
        let endpoints = WellKnownEndpoints::default();
        let paths = [
            &endpoints.agent_card_path,
            &endpoints.jwks_path,
            &endpoints.compat_binding_path,
            &endpoints.jacs_descriptor_path,
            &endpoints.jacs_pubkey_path,
            &endpoints.jacs_extension_path,
        ];
        for path in &paths {
            assert!(
                path.starts_with("/.well-known/"),
                "Path {} should be under /.well-known/",
                path
            );
        }
    }

    #[test]
    fn test_extension_descriptor_via_well_known() {
        // Verify that create_extension_descriptor produces a valid document
        // that would be served at jacs_extension_path
        let descriptor = create_extension_descriptor("pq2025");
        assert_eq!(descriptor["uri"], JACS_EXTENSION_URI);
        assert_eq!(descriptor["name"], "JACS Document Provenance");
        assert!(descriptor["capabilities"].is_object());
        assert!(descriptor["capabilities"]["documentSigning"].is_object());
        assert!(descriptor["capabilities"]["documentVerification"].is_object());
        assert!(descriptor["capabilities"]["postQuantumCrypto"].is_object());
        assert!(descriptor["endpoints"].is_object());
    }

    #[test]
    fn test_embed_signature_in_agent_card() {
        use crate::a2a::{A2A_PROTOCOL_VERSION, AgentCapabilities, AgentInterface};

        let card = AgentCard {
            name: "Test".to_string(),
            description: "Test agent".to_string(),
            version: "1.0".to_string(),
            protocol_versions: vec![A2A_PROTOCOL_VERSION.to_string()],
            supported_interfaces: vec![AgentInterface {
                url: "https://example.com".to_string(),
                protocol_binding: "jsonrpc".to_string(),
                tenant: None,
            }],
            default_input_modes: vec!["text/plain".to_string()],
            default_output_modes: vec!["text/plain".to_string()],
            capabilities: AgentCapabilities {
                streaming: None,
                push_notifications: None,
                extended_agent_card: None,
                extensions: None,
            },
            skills: vec![],
            provider: None,
            documentation_url: None,
            icon_url: None,
            security_schemes: None,
            security: None,
            signatures: None,
            metadata: None,
        };

        let signed = embed_signature_in_agent_card(&card, "fake.jws.signature", Some("key-1"));
        let sigs = signed.signatures.unwrap();
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].jws, "fake.jws.signature");
        assert_eq!(sigs[0].key_id, Some("key-1".to_string()));
    }

    // =========================================================================
    // verify_agent_card_jws tests
    // =========================================================================

    fn make_test_card() -> AgentCard {
        use crate::a2a::{A2A_PROTOCOL_VERSION, AgentCapabilities, AgentInterface};

        AgentCard {
            name: "JWS Test Agent".to_string(),
            description: "Agent for JWS verification tests".to_string(),
            version: "1.0".to_string(),
            protocol_versions: vec![A2A_PROTOCOL_VERSION.to_string()],
            supported_interfaces: vec![AgentInterface {
                url: "https://test.example.com".to_string(),
                protocol_binding: "jsonrpc".to_string(),
                tenant: None,
            }],
            default_input_modes: vec!["text/plain".to_string()],
            default_output_modes: vec!["text/plain".to_string()],
            capabilities: AgentCapabilities {
                streaming: None,
                push_notifications: None,
                extended_agent_card: None,
                extensions: None,
            },
            skills: vec![],
            provider: None,
            documentation_url: None,
            icon_url: None,
            security_schemes: None,
            security: None,
            signatures: None,
            metadata: None,
        }
    }

    #[test]
    fn test_sign_and_verify_agent_card_roundtrip_ed25519() {
        let card = make_test_card();

        // Generate Ed25519 keys
        let (private_key, public_key) =
            crate::crypt::ringwrapper::generate_keys().expect("key gen");

        // Sign the card
        let jws =
            sign_agent_card_jws(&card, &private_key, "ring-Ed25519", "test-key-1").expect("sign");

        // Embed signature
        let signed_card = embed_signature_in_agent_card(&card, &jws, Some("test-key-1"));

        // Verify
        let result =
            verify_agent_card_jws(&signed_card, &public_key, "ring-Ed25519").expect("verify");
        assert!(result);
    }

    #[test]
    fn test_sign_agent_card_ed25519_jwk_keys() {
        let card = make_test_card();
        let keys = crate::a2a::keys::create_jwk_keys(Some("ring-Ed25519"), Some("ring-Ed25519"))
            .expect("Ed25519 A2A key generation should work");
        let jws = sign_agent_card_jws(&card, &keys.a2a_private_key, "ring-Ed25519", "ec-key-1")
            .expect("Ed25519 A2A signing should work");
        let signed_card = embed_signature_in_agent_card(&card, &jws, Some("ec-key-1"));
        let result = verify_agent_card_jws(&signed_card, &keys.a2a_public_key, "ring-Ed25519")
            .expect("Ed25519 A2A verification should work");
        assert!(result);
    }

    #[test]
    fn test_verify_tampered_agent_card_fails() {
        let card = make_test_card();

        // Generate keys and sign
        let (private_key, public_key) =
            crate::crypt::ringwrapper::generate_keys().expect("key gen");
        let jws =
            sign_agent_card_jws(&card, &private_key, "ring-Ed25519", "test-key").expect("sign");

        // Embed signature, then tamper with the card
        let mut signed_card = embed_signature_in_agent_card(&card, &jws, Some("test-key"));
        signed_card.name = "TAMPERED NAME".to_string();

        // Verification should fail (payload mismatch)
        let result = verify_agent_card_jws(&signed_card, &public_key, "ring-Ed25519");
        assert!(result.is_err(), "Tampered card should fail verification");
    }

    #[test]
    fn test_verify_missing_signature_fails() {
        let card = make_test_card(); // No signatures

        let (_private_key, public_key) =
            crate::crypt::ringwrapper::generate_keys().expect("key gen");

        let result = verify_agent_card_jws(&card, &public_key, "ring-Ed25519");
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("no signatures"),
            "Error should mention missing signatures"
        );
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let card = make_test_card();

        // Sign with one key
        let (private_key, _public_key) =
            crate::crypt::ringwrapper::generate_keys().expect("key gen");
        let jws = sign_agent_card_jws(&card, &private_key, "ring-Ed25519", "key-1").expect("sign");
        let signed_card = embed_signature_in_agent_card(&card, &jws, Some("key-1"));

        // Verify with a different key
        let (_private_key2, public_key2) =
            crate::crypt::ringwrapper::generate_keys().expect("key gen 2");

        let result = verify_agent_card_jws(&signed_card, &public_key2, "ring-Ed25519");
        assert!(result.is_err(), "Verification with wrong key should fail");
    }
}
