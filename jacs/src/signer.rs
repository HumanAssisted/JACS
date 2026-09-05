//! Native adapter for the portable restricted signing facade.
//!
//! [`LocalSigningProvider`] keeps the existing encrypted JACS key file as the
//! storage mechanism.  It never returns private-key bytes.  Each signing call
//! resolves the password into a zeroizing temporary, decrypts through
//! `jacs-core`'s existing envelope reader, performs one named operation, and
//! clears the decrypted signer before returning.
//!
//! Existing `Agent::sign_string` / `SimpleAgent::sign_raw_bytes` APIs remain
//! available for source compatibility.  Callers that use the compatibility
//! constructor here receive an explicit
//! `purposeIsolationAssurance=shared_raw_capable`: a method name cannot turn a
//! legacy single key into cryptographic purpose isolation.

use crate::agent::Agent;
use crate::agent::boilerplate::BoilerPlate;
use crate::error::JacsError;
use crate::media_signing::{PreparedMediaV2, prepare_media_v2, prepare_media_v2_with_id};
use chrono::{DateTime, Utc};
use jacs_core::material::{AgentMaterial, UnlockSecret};
use jacs_core::sign::SigningAlgorithm;
use jacs_core::signing::{
    AuthorityClassifiedPreparedDocumentV1, LegacyRawSignature, NativeMessageHeaderV1,
    PreparedDocumentV2, PreparedSigningError, PreparedSigningOutcome, PurposeIsolationAssurance,
    RestrictedSigningProvider, SignatureMetadataV2, SigningKeyScope, SigningPurpose,
};
use jacs_core::signing_context::SigningContextSelectionV1;
use secrecy::{ExposeSecret, SecretBox};
use serde_json::{Value, json};
use zeroize::Zeroizing;

/// Encrypted-file implementation of JACS's named signing operations.
///
/// This value contains only a borrowed `Agent` and public authorization scope.
/// Decrypted material exists solely inside an individual signing method.
pub struct LocalSigningProvider<'a> {
    agent: &'a Agent,
    scope: SigningKeyScope,
}

impl std::fmt::Debug for LocalSigningProvider<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalSigningProvider")
            .field("identity", &self.scope.identity())
            .field("canonical_key_id", &self.scope.canonical_key_id())
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl<'a> LocalSigningProvider<'a> {
    /// Bind an agent to a scope derived from authenticated lifecycle policy.
    pub fn from_scope(agent: &'a Agent, scope: SigningKeyScope) -> Result<Self, JacsError> {
        let public_key = agent.get_public_key()?;
        scope.validate_public_key(&public_key)?;
        if scope.identity() != agent.get_id()? || scope.agent_version() != agent.get_version()? {
            return Err(JacsError::SigningFailed {
                reason: "local signing scope identity/version does not match the loaded agent"
                    .into(),
            });
        }
        let algorithm = native_algorithm(agent)?;
        if scope.algorithm() != algorithm {
            return Err(JacsError::SigningFailed {
                reason: format!(
                    "local signing scope algorithm mismatch: expected {}, got {}",
                    algorithm,
                    scope.algorithm()
                ),
            });
        }
        Ok(Self { agent, scope })
    }

    /// Preserve the current local SDK's combined document/raw key behavior.
    ///
    /// This is intentionally lower assurance.  The same key can sign a named
    /// JACS document and arbitrary compatibility octets, so reports must retain
    /// `shared_raw_capable` until the identity is migrated to separate keys.
    pub fn local_compatibility_combined(agent: &'a Agent) -> Result<Self, JacsError> {
        let public_key = agent.get_public_key()?;
        let scope = SigningKeyScope::from_public_key(
            agent.get_id()?,
            agent.get_version()?,
            native_algorithm(agent)?,
            &public_key,
            [SigningPurpose::Document, SigningPurpose::LegacyRaw],
            PurposeIsolationAssurance::SharedRawCapable,
        )?;
        Self::from_scope(agent, scope)
    }

    pub fn scope(&self) -> &SigningKeyScope {
        &self.scope
    }

    /// Freeze the legacy message-shaped document before an approval ceremony.
    pub fn prepare_message_v2(
        &self,
        content: &Value,
        metadata: SignatureMetadataV2,
    ) -> Result<PreparedDocumentV2, JacsError> {
        Ok(jacs_core::signing::prepare_message_v2(
            &self.scope,
            content,
            metadata,
        )?)
    }

    /// Freeze a native-compatible message using an authoritative operation
    /// UUID as `jacsId`; JACS generates its version/timestamps exactly once.
    pub fn prepare_message_v2_with_id(
        &self,
        content: &Value,
        jacs_id: impl Into<String>,
        metadata: SignatureMetadataV2,
    ) -> Result<PreparedDocumentV2, JacsError> {
        Ok(jacs_core::signing::prepare_message_v2_with_id(
            &self.scope,
            content,
            jacs_id,
            metadata,
        )?)
    }

    /// Deterministic staging-table rehydration with an already-frozen header.
    pub fn prepare_native_message_v2(
        &self,
        content: &Value,
        header: NativeMessageHeaderV1,
        metadata: SignatureMetadataV2,
    ) -> Result<PreparedDocumentV2, JacsError> {
        Ok(jacs_core::signing::prepare_native_message_v2(
            &self.scope,
            content,
            header,
            metadata,
        )?)
    }

    /// Freeze an unchanged generic message signature and attach a separate
    /// registry-selected TP-31 operation classification over its exact input.
    pub fn prepare_authority_classified_native_message_v2(
        &self,
        content: &Value,
        header: NativeMessageHeaderV1,
        metadata: SignatureMetadataV2,
        authority_selection: SigningContextSelectionV1,
    ) -> Result<AuthorityClassifiedPreparedDocumentV1, JacsError> {
        let public_key = self.agent.get_public_key()?;
        let prepared = self.prepare_native_message_v2(content, header, metadata)?;
        Ok(AuthorityClassifiedPreparedDocumentV1::prepare(
            &self.scope,
            &public_key,
            prepared,
            authority_selection,
        )?)
    }

    /// Freeze the native root-level application-artifact shape while keeping
    /// all `$schema`/`jacs*` header fields signer-controlled.
    pub fn prepare_native_artifact_v2(
        &self,
        source: &Value,
        header: NativeMessageHeaderV1,
        metadata: SignatureMetadataV2,
    ) -> Result<PreparedDocumentV2, JacsError> {
        Ok(jacs_core::signing::prepare_native_artifact_v2(
            &self.scope,
            source,
            header,
            metadata,
        )?)
    }

    /// Freeze the native root-level application artifact and attach the
    /// registry-selected TP-31 interpretation of its exact input.
    pub fn prepare_authority_classified_native_artifact_v2(
        &self,
        source: &Value,
        header: NativeMessageHeaderV1,
        metadata: SignatureMetadataV2,
        authority_selection: SigningContextSelectionV1,
    ) -> Result<AuthorityClassifiedPreparedDocumentV1, JacsError> {
        let public_key = self.agent.get_public_key()?;
        let prepared = self.prepare_native_artifact_v2(source, header, metadata)?;
        Ok(AuthorityClassifiedPreparedDocumentV1::prepare(
            &self.scope,
            &public_key,
            prepared,
            authority_selection,
        )?)
    }

    /// Freeze the existing JACS media claim and its exact hardened source
    /// bytes under `SignFileOrMediaManifest/file_media`.
    pub fn prepare_media_v2(
        &self,
        hardened_bytes: &[u8],
        format_hint: Option<&str>,
        robust: bool,
        header: NativeMessageHeaderV1,
        metadata: SignatureMetadataV2,
        authority_selection: SigningContextSelectionV1,
    ) -> Result<PreparedMediaV2, JacsError> {
        let public_key = self.agent.get_public_key()?;
        prepare_media_v2(
            &self.scope,
            &public_key,
            hardened_bytes,
            format_hint,
            robust,
            header,
            metadata,
            authority_selection,
        )
    }

    /// Freeze media with an authoritative operation UUID as its native JACS
    /// document ID; all remaining header values are generated exactly once.
    pub fn prepare_media_v2_with_id(
        &self,
        hardened_bytes: &[u8],
        format_hint: Option<&str>,
        robust: bool,
        operation_id: impl Into<String>,
        metadata: SignatureMetadataV2,
        signing_context: SigningContextSelectionV1,
    ) -> Result<PreparedMediaV2, JacsError> {
        let public_key = self.agent.get_public_key()?;
        prepare_media_v2_with_id(
            &self.scope,
            &public_key,
            hardened_bytes,
            format_hint,
            robust,
            operation_id,
            metadata,
            signing_context,
        )
    }

    /// Freeze a complete unsigned JACS document before an approval ceremony.
    pub fn prepare_document_v2(
        &self,
        document: &Value,
        metadata: SignatureMetadataV2,
    ) -> Result<PreparedDocumentV2, JacsError> {
        Ok(jacs_core::signing::prepare_document_v2(
            &self.scope,
            document,
            metadata,
        )?)
    }

    /// Sign exactly a previously frozen envelope.  UUIDs and timestamps are
    /// not regenerated here.
    pub fn sign_prepared_document(&self, prepared: PreparedDocumentV2) -> Result<Value, JacsError> {
        self.with_one_operation_provider(|provider| {
            provider
                .sign_prepared_document(prepared)
                .map_err(Into::into)
        })
    }

    /// Deadline-bounded frozen signing with conservative private-key-use
    /// classification.  Local keystore setup failures are classified as
    /// `before_key_use`; after primitive dispatch the core provider retains
    /// `key_use_may_have_occurred` even when signing returns an error.
    pub fn sign_prepared_document_before(
        &self,
        prepared: PreparedDocumentV2,
        deadline: DateTime<Utc>,
    ) -> Result<PreparedSigningOutcome, PreparedSigningError> {
        let provider = self.one_operation_provider_typed()?;
        provider.sign_prepared_document_before(prepared, deadline)
    }

    /// Sign an unchanged primary JACS input after rechecking the independently
    /// persisted TP-31 authority-context digest.
    pub fn sign_authority_classified_document_before(
        &self,
        prepared: AuthorityClassifiedPreparedDocumentV1,
        expected_authority_context_digest: &str,
        deadline: DateTime<Utc>,
    ) -> Result<PreparedSigningOutcome, PreparedSigningError> {
        let provider = self.one_operation_provider_typed()?;
        provider.sign_authority_classified_document_before(
            prepared,
            expected_authority_context_digest,
            deadline,
        )
    }

    /// Recheck exact hardened media bytes, then run the same bounded private
    /// key operation used for other prepared envelopes.
    pub fn sign_prepared_media_before(
        &self,
        prepared: PreparedMediaV2,
        hardened_bytes: &[u8],
        expected_authority_context_digest: &str,
        deadline: DateTime<Utc>,
    ) -> Result<PreparedSigningOutcome, PreparedSigningError> {
        let public_key = self.agent.get_public_key().map_err(local_setup_error)?;
        let prepared_document = prepared
            .into_prepared_document(
                &self.scope,
                &public_key,
                hardened_bytes,
                expected_authority_context_digest,
            )
            .map_err(local_setup_error)?;
        let provider = self.one_operation_provider_typed()?;
        provider.sign_prepared_document_before(prepared_document, deadline)
    }

    /// Prepare and sign the compatibility message envelope in one call.
    pub fn sign_message_v2(
        &self,
        content: &Value,
        metadata: SignatureMetadataV2,
    ) -> Result<Value, JacsError> {
        let prepared = self.prepare_message_v2(content, metadata)?;
        self.sign_prepared_document(prepared)
    }

    /// Sign exact compatibility octets without protocol inference.
    pub fn legacy_raw_sign(&self, input: &[u8]) -> Result<LegacyRawSignature, JacsError> {
        self.with_one_operation_provider(|provider| {
            provider.legacy_raw_sign(input).map_err(Into::into)
        })
    }

    fn with_one_operation_provider<T>(
        &self,
        operation: impl FnOnce(RestrictedSigningProvider) -> Result<T, JacsError>,
    ) -> Result<T, JacsError> {
        let material = self.agent_material()?;
        if self.agent.is_ephemeral() {
            let raw_private = self.agent.get_private_key()?.expose_secret().clone();
            let provider = RestrictedSigningProvider::unlock_for_one_operation(
                material,
                UnlockSecret::RawPrivateKey(SecretBox::new(Box::new(raw_private))),
                self.scope.clone(),
            )?;
            operation(provider)
        } else {
            // `Agent::resolve_password` retains source compatibility with the
            // existing keychain/env/config resolution order.  This temporary
            // copy is zeroized at the end of this call, including failures.
            let password = Zeroizing::new(self.agent.resolve_password()?);
            let provider = RestrictedSigningProvider::unlock_for_one_operation(
                material,
                UnlockSecret::Password(password.as_str()),
                self.scope.clone(),
            )?;
            operation(provider)
        }
    }

    fn one_operation_provider_typed(
        &self,
    ) -> Result<RestrictedSigningProvider, PreparedSigningError> {
        let material = self.agent_material().map_err(local_setup_error)?;
        if self.agent.is_ephemeral() {
            let raw_private = self
                .agent
                .get_private_key()
                .map_err(local_setup_error)?
                .expose_secret()
                .clone();
            RestrictedSigningProvider::unlock_for_one_operation(
                material,
                UnlockSecret::RawPrivateKey(SecretBox::new(Box::new(raw_private))),
                self.scope.clone(),
            )
            .map_err(PreparedSigningError::before_key_use)
        } else {
            let password =
                Zeroizing::new(self.agent.resolve_password().map_err(local_setup_error)?);
            RestrictedSigningProvider::unlock_for_one_operation(
                material,
                UnlockSecret::Password(password.as_str()),
                self.scope.clone(),
            )
            .map_err(PreparedSigningError::before_key_use)
        }
    }

    fn agent_material(&self) -> Result<AgentMaterial, JacsError> {
        let encrypted_private_key = if self.agent.is_ephemeral() {
            // The RawPrivateKey unlock arm receives the sole temporary copy in
            // a SecretBox. Do not also place plaintext bytes in AgentMaterial's
            // compatibility ciphertext field.
            Vec::new()
        } else {
            self.agent.get_private_key()?.expose_secret().clone()
        };
        Ok(AgentMaterial {
            // CoreAgent does not consult config while signing; paths and
            // encrypted storage stay owned by the native Agent.
            config: json!({}),
            agent: self
                .agent
                .get_value()
                .cloned()
                .ok_or(JacsError::AgentNotLoaded)?,
            public_key: self.agent.get_public_key()?,
            encrypted_private_key,
            algorithm: native_algorithm(self.agent)?,
        })
    }
}

fn local_setup_error(error: JacsError) -> PreparedSigningError {
    PreparedSigningError::before_key_use(jacs_core::CoreError::MalformedKey(format!(
        "local signing provider setup failed before private-key use: {error}"
    )))
}

fn native_algorithm(agent: &Agent) -> Result<SigningAlgorithm, JacsError> {
    match agent.get_key_algorithm().map(String::as_str) {
        Some("ed25519" | "ring-Ed25519") => Ok(SigningAlgorithm::Ed25519),
        Some("pq2025") => Ok(SigningAlgorithm::Pq2025),
        Some(other) => Err(JacsError::SigningFailed {
            reason: format!("unsupported local signing algorithm '{other}'"),
        }),
        None => Err(JacsError::SigningFailed {
            reason: "loaded agent has no signing algorithm".into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::Agent;

    #[test]
    fn compatibility_provider_reports_shared_raw_capability() {
        let mut agent = Agent::ephemeral("ring-Ed25519").expect("ephemeral agent");
        agent
            .create_agent_and_load(
                r#"{"jacsType":"agent","jacsLevel":"config","name":"local"}"#,
                true,
                Some("ring-Ed25519"),
            )
            .expect("create agent");
        let provider = LocalSigningProvider::local_compatibility_combined(&agent)
            .expect("compatibility provider");
        assert_eq!(
            provider.scope().purpose_isolation_assurance(),
            PurposeIsolationAssurance::SharedRawCapable
        );
    }
}
