//! Prepared, purpose-bound media signing built on the existing `jacs-media`
//! canonicalization rules.
//!
//! Raw image bytes are never placed in the prepared JSON object. Preparation
//! records their exact length and digests, computes the existing canonical
//! media/pixel hashes, and freezes the resulting media claim inside a JACS v2
//! envelope. Final signing rechecks the bytes and consumes that frozen
//! envelope; it does not regenerate identifiers, timestamps, or claim fields.

use crate::crypt::hash::{hash_bytes, hash_bytes_raw};
use crate::error::JacsError;
use base64::Engine as _;
use jacs_core::signing::{
    MediaClaimFormatV1, MediaClaimV1, NativeMessageHeaderV1, PreparedDocumentV2,
    SignatureMetadataV2, SigningKeyScope,
};
use jacs_core::signing_context::{AuthoritySigningClassificationV1, SigningContextSelectionV1};
use serde::{Deserialize, Serialize};

/// Serialized prepared-media profile.
pub const PREPARED_MEDIA_V2_PROFILE: &str = "jacs-prepared-media-v2";
/// Domain for the exact, unmodified hardened media bytes retained by a stage.
pub const PREPARED_MEDIA_BYTES_DIGEST_DOMAIN: &str = "JACS-PREPARED-MEDIA-BYTES-V1";

/// Frozen media claim and its exact source-byte binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PreparedMediaV2 {
    profile: String,
    format: MediaClaimFormatV1,
    robust: bool,
    hardened_byte_length: u64,
    hardened_sha256: String,
    hardened_bytes_digest: String,
    claim: MediaClaimV1,
    prepared_document: PreparedDocumentV2,
    authority_classification: AuthoritySigningClassificationV1,
}

impl PreparedMediaV2 {
    pub fn format(&self) -> MediaClaimFormatV1 {
        self.format
    }

    pub fn robust(&self) -> bool {
        self.robust
    }

    pub fn hardened_byte_length(&self) -> u64 {
        self.hardened_byte_length
    }

    /// Plain lowercase SHA-256, matching the existing media staging field.
    pub fn hardened_sha256(&self) -> &str {
        &self.hardened_sha256
    }

    /// Domain-separated digest of the exact hardened bytes.
    pub fn hardened_bytes_digest(&self) -> &str {
        &self.hardened_bytes_digest
    }

    pub fn claim(&self) -> &MediaClaimV1 {
        &self.claim
    }

    pub fn prepared_document(&self) -> &PreparedDocumentV2 {
        &self.prepared_document
    }

    pub fn authority_classification(&self) -> &AuthoritySigningClassificationV1 {
        &self.authority_classification
    }

    pub fn authority_signing_request_context_digest(&self) -> &str {
        self.authority_classification
            .authority_signing_request_context_digest()
    }

    pub fn signature_input(&self) -> &[u8] {
        self.prepared_document.signature_input()
    }

    pub fn signature_input_digest(&self) -> &str {
        self.prepared_document.signature_input_digest()
    }

    /// Recompute every media hash and the complete frozen JACS signature input.
    pub fn validate(
        &self,
        scope: &SigningKeyScope,
        public_key: &[u8],
        hardened_bytes: &[u8],
    ) -> Result<(), JacsError> {
        if self.profile != PREPARED_MEDIA_V2_PROFILE {
            return Err(JacsError::ValidationError(
                "prepared media profile mismatch".into(),
            ));
        }
        let byte_length = u64::try_from(hardened_bytes.len()).map_err(|_| {
            JacsError::ValidationError("hardened media length does not fit u64".into())
        })?;
        if byte_length != self.hardened_byte_length
            || hash_bytes(hardened_bytes) != self.hardened_sha256
            || jacs_core::identity::digest_bytes(PREPARED_MEDIA_BYTES_DIGEST_DOMAIN, hardened_bytes)
                != self.hardened_bytes_digest
        {
            return Err(JacsError::ValidationError(
                "hardened media bytes no longer match the prepared stage".into(),
            ));
        }

        let expected_public_key_hash = media_public_key_hash(public_key);
        if self.claim.public_key_hash() != expected_public_key_hash {
            return Err(JacsError::ValidationError(
                "prepared media claim public-key hash does not match the signing key".into(),
            ));
        }

        let rebuilt = build_media_claim_v1(
            hardened_bytes,
            media_format_from_claim(self.format),
            self.robust,
            &expected_public_key_hash,
        )?;
        if rebuilt != self.claim {
            return Err(JacsError::ValidationError(
                "prepared media claim no longer matches canonical media bytes".into(),
            ));
        }
        if self.prepared_document.unsigned_envelope().get("content")
            != Some(&self.claim.to_value()?)
        {
            return Err(JacsError::ValidationError(
                "prepared media envelope content does not equal its closed claim".into(),
            ));
        }
        self.prepared_document.validate(scope, public_key)?;
        self.authority_classification.validate_structure(
            scope,
            public_key,
            &self.prepared_document,
        )?;
        if self.prepared_document.operation() != &jacs_core::signing::SigningOperation::SignDocument
            || self.prepared_document.purpose() != &jacs_core::signing::SigningPurpose::Document
            || self.authority_classification.operation()
                != &jacs_core::signing::SigningOperation::SignFileOrMediaManifest
            || self.authority_classification.purpose()
                != &jacs_core::signing::SigningPurpose::FileMedia
        {
            return Err(JacsError::ValidationError(
                "prepared media must retain a generic document primary and a file/media authority classification"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Recompute the exact source/claim/primary-input bindings and require the
    /// independently persisted authority context digest.
    pub fn validate_authorized(
        &self,
        scope: &SigningKeyScope,
        public_key: &[u8],
        hardened_bytes: &[u8],
        expected_authority_context_digest: &str,
    ) -> Result<(), JacsError> {
        self.validate(scope, public_key, hardened_bytes)?;
        self.authority_classification.validate_authorized(
            scope,
            public_key,
            &self.prepared_document,
            expected_authority_context_digest,
        )?;
        Ok(())
    }

    /// Validate exact staged bytes, then yield the one frozen document that a
    /// restricted provider may sign.
    pub fn into_prepared_document(
        self,
        scope: &SigningKeyScope,
        public_key: &[u8],
        hardened_bytes: &[u8],
        expected_authority_context_digest: &str,
    ) -> Result<PreparedDocumentV2, JacsError> {
        self.validate_authorized(
            scope,
            public_key,
            hardened_bytes,
            expected_authority_context_digest,
        )?;
        Ok(self.prepared_document)
    }
}

/// Prepare a purpose-bound media claim from exact hardened bytes.
#[allow(
    clippy::too_many_arguments,
    reason = "public frozen-input adapter keeps each existing authority and media input explicit"
)]
pub fn prepare_media_v2(
    scope: &SigningKeyScope,
    public_key: &[u8],
    hardened_bytes: &[u8],
    format_hint: Option<&str>,
    robust: bool,
    header: NativeMessageHeaderV1,
    signature_metadata: SignatureMetadataV2,
    authority_selection: SigningContextSelectionV1,
) -> Result<PreparedMediaV2, JacsError> {
    scope.validate_public_key(public_key)?;
    let format = resolve_media_format(hardened_bytes, format_hint, "prepared media")?;
    let claim = build_media_claim_v1(
        hardened_bytes,
        format,
        robust,
        &media_public_key_hash(public_key),
    )?;
    let prepared_document =
        jacs_core::signing::prepare_media_claim_v2(scope, &claim, header, signature_metadata)?;
    let authority_classification = AuthoritySigningClassificationV1::build_for_prepared_document(
        scope,
        public_key,
        &prepared_document,
        authority_selection,
    )?;
    let hardened_byte_length = u64::try_from(hardened_bytes.len())
        .map_err(|_| JacsError::ValidationError("hardened media length does not fit u64".into()))?;
    Ok(PreparedMediaV2 {
        profile: PREPARED_MEDIA_V2_PROFILE.into(),
        format: media_format_to_claim(format),
        robust,
        hardened_byte_length,
        hardened_sha256: hash_bytes(hardened_bytes),
        hardened_bytes_digest: jacs_core::identity::digest_bytes(
            PREPARED_MEDIA_BYTES_DIGEST_DOMAIN,
            hardened_bytes,
        ),
        claim,
        prepared_document,
        authority_classification,
    })
}

/// Prepare media whose native document ID is the authoritative operation UUID.
///
/// JACS generates the remaining native header values exactly once and returns
/// them inside the serialized prepared object. Persistence rehydration should
/// keep using [`prepare_media_v2`] with an explicitly stored header.
#[allow(
    clippy::too_many_arguments,
    reason = "public operation-ID adapter mirrors the explicit frozen-input preparation contract"
)]
pub fn prepare_media_v2_with_id(
    scope: &SigningKeyScope,
    public_key: &[u8],
    hardened_bytes: &[u8],
    format_hint: Option<&str>,
    robust: bool,
    operation_id: impl Into<String>,
    signature_metadata: SignatureMetadataV2,
    authority_selection: SigningContextSelectionV1,
) -> Result<PreparedMediaV2, JacsError> {
    prepare_media_v2(
        scope,
        public_key,
        hardened_bytes,
        format_hint,
        robust,
        NativeMessageHeaderV1::now_with_id(operation_id)?,
        signature_metadata,
        authority_selection,
    )
}

/// Build the exact existing v1 media claim from `jacs-media` canonical hashes.
pub fn build_media_claim_v1(
    bytes: &[u8],
    format: jacs_media::MediaFormat,
    robust: bool,
    public_key_hash: &str,
) -> Result<MediaClaimV1, JacsError> {
    let content_hash = if robust {
        jacs_media::canonical_hash_robust_with_format(format, bytes).map_err(media_to_jacs_error)?
    } else {
        jacs_media::canonical_hash_with_format(format, bytes).map_err(media_to_jacs_error)?
    };
    let content_hash = base64url_no_pad(&content_hash);
    let claim_format = media_format_to_claim(format);
    if robust {
        let pixel_hash =
            jacs_media::pixel_hash_pre_lsb(format, bytes).map_err(media_to_jacs_error)?;
        Ok(MediaClaimV1::robust(
            claim_format,
            content_hash,
            public_key_hash,
            format!("sha256-b64url:{}", base64url_no_pad(&pixel_hash)),
        )?)
    } else {
        Ok(MediaClaimV1::standard(
            claim_format,
            content_hash,
            public_key_hash,
        )?)
    }
}

/// Existing media public-key commitment: normalized PEM, SHA-256, base64url.
pub fn media_public_key_hash(public_key: &[u8]) -> String {
    let normalized = crate::crypt::normalize_public_key_pem(public_key);
    format!(
        "sha256-b64url:{}",
        base64url_no_pad(&hash_bytes_raw(normalized.as_bytes()))
    )
}

pub(crate) fn resolve_media_format(
    bytes: &[u8],
    format_hint: Option<&str>,
    subject: &str,
) -> Result<jacs_media::MediaFormat, JacsError> {
    match format_hint {
        Some(hint) => match hint.to_ascii_lowercase().as_str() {
            "png" => Ok(jacs_media::MediaFormat::Png),
            "jpeg" | "jpg" => Ok(jacs_media::MediaFormat::Jpeg),
            "webp" => Ok(jacs_media::MediaFormat::WebP),
            other => Err(JacsError::ValidationError(format!(
                "unknown format hint '{other}' for {subject} (expected png|jpeg|webp)"
            ))),
        },
        None => jacs_media::detect_format(bytes)
            .map_err(|_| JacsError::ValidationError(format!("unsupported format for {subject}"))),
    }
}

pub(crate) fn media_to_jacs_error(error: jacs_media::MediaError) -> JacsError {
    use jacs_media::MediaError;
    match error {
        MediaError::PayloadTooLarge { limit, actual } => JacsError::ValidationError(format!(
            "image signature payload exceeds format limit: actual {actual} > pixel capacity / chunk limit {limit}"
        )),
        MediaError::Unsupported(message) => {
            JacsError::ValidationError(format!("media unsupported: {message}"))
        }
        MediaError::UnsupportedFormat => {
            JacsError::ValidationError("unsupported media format".into())
        }
        MediaError::Parse(message) => {
            JacsError::ValidationError(format!("media parse error: {message}"))
        }
        MediaError::Encode(message) => {
            JacsError::ValidationError(format!("media encode error: {message}"))
        }
    }
}

fn media_format_to_claim(format: jacs_media::MediaFormat) -> MediaClaimFormatV1 {
    match format {
        jacs_media::MediaFormat::Png => MediaClaimFormatV1::Png,
        jacs_media::MediaFormat::Jpeg => MediaClaimFormatV1::Jpeg,
        jacs_media::MediaFormat::WebP => MediaClaimFormatV1::Webp,
    }
}

fn media_format_from_claim(format: MediaClaimFormatV1) -> jacs_media::MediaFormat {
    match format {
        MediaClaimFormatV1::Png => jacs_media::MediaFormat::Png,
        MediaClaimFormatV1::Jpeg => jacs_media::MediaFormat::Jpeg,
        MediaClaimFormatV1::Webp => jacs_media::MediaFormat::WebP,
    }
}

fn base64url_no_pad(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jacs_core::identity::digest_bytes;
    use jacs_core::sign::{DetachedSigner, Ed25519DalekSigner, SigningAlgorithm};
    use jacs_core::signing::{PurposeIsolationAssurance, SigningOperation, SigningPurpose};
    use jacs_core::signing_context::{
        SigningContextSelectionV1, SigningOperationContextV1, local_document_v2_profile_entry,
    };
    use jacs_core::verification_registry::{
        ContextRuleId, ProfileKind, SecurityProfileEntry, SignatureFamilyId, WireRuleId,
    };

    #[test]
    fn media_claim_rejects_robust_webp_before_signing() {
        let error = MediaClaimV1::robust(
            MediaClaimFormatV1::Webp,
            base64url_no_pad(&[0_u8; 32]),
            format!("sha256-b64url:{}", base64url_no_pad(&[1_u8; 32])),
            format!("sha256-b64url:{}", base64url_no_pad(&[2_u8; 32])),
        )
        .expect_err("robust WebP is not supported by the existing wire");
        assert!(error.to_string().contains("inconsistent"));
    }

    #[test]
    fn prepared_media_binds_exact_bytes_operation_id_and_public_key() {
        let signer = Ed25519DalekSigner::generate().expect("test signer");
        let public_key = signer.public_key();
        let authority_entry = SecurityProfileEntry {
            profile_id: "hai-app-artifact-media-create-v1".into(),
            profile_kind: ProfileKind::BuiltIn,
            operation: SigningOperation::SignFileOrMediaManifest,
            purpose: SigningPurpose::FileMedia,
            signature_family_id: SignatureFamilyId::AuthorityReceiptV1,
            wire_rule_id: WireRuleId::AuthorityBackedExactReceiptV1,
            context_rule_id: ContextRuleId::HaiExactReceiptV1,
            allowed_algorithms: vec![SigningAlgorithm::Ed25519.as_str().into()],
            schema_id: None,
            schema_bundle_digest: None,
            conformance_fixture_digest: digest_bytes(
                "JACS-CONFORMANCE-FIXTURE-V1",
                b"prepared-media-authority-test-fixture",
            ),
        };
        let document_entry =
            local_document_v2_profile_entry(SigningAlgorithm::Ed25519).expect("document profile");
        let scope = SigningKeyScope::from_public_key_with_profile_entries(
            "agent-1",
            "version-1",
            SigningAlgorithm::Ed25519,
            public_key,
            &[document_entry, authority_entry.clone()],
            PurposeIsolationAssurance::ClosedMultiPurposeSharedKey,
        )
        .expect("media scope");
        let preauthorization_request_digest = digest_bytes(
            "JACS-HAI-PREAUTHORIZATION-REQUEST-V1",
            b"prepared-media-test-request",
        );
        let authority_selection = SigningContextSelectionV1::new(
            authority_entry,
            SigningOperationContextV1::HaiExactReceiptV1 {
                preauthorization_request_digest,
            },
            None,
            Vec::new(),
        )
        .expect("authority selection");
        let operation_id = "00000000-0000-4000-8000-000000000123";
        let bytes = include_bytes!("../tests/fixtures/provenance/unsigned.png");
        let prepared = prepare_media_v2_with_id(
            &scope,
            public_key,
            bytes,
            Some("png"),
            false,
            operation_id,
            SignatureMetadataV2 {
                date: "2026-09-04T12:00:00Z".into(),
                iat: 1_788_523_200,
                jti: "prepared-media-1".into(),
            },
            authority_selection,
        )
        .expect("prepare media");

        assert_eq!(
            prepared.prepared_document().operation().to_string(),
            "SignDocument"
        );
        assert_eq!(
            prepared.prepared_document().purpose(),
            &SigningPurpose::Document
        );
        assert_eq!(
            prepared.authority_classification().operation(),
            &SigningOperation::SignFileOrMediaManifest
        );
        assert_eq!(
            prepared.prepared_document().unsigned_envelope()["jacsId"],
            operation_id
        );
        prepared
            .validate(&scope, public_key, bytes)
            .expect("exact prepared media validates");
        let authority_context_digest = prepared
            .authority_signing_request_context_digest()
            .to_owned();
        prepared
            .validate_authorized(&scope, public_key, bytes, &authority_context_digest)
            .expect("independently repeated authority digest validates");
        let wrong_authority_context = digest_bytes(
            "JACS-SIGNING-REQUEST-CONTEXT-V1",
            b"different-authority-context",
        );
        assert!(
            prepared
                .validate_authorized(&scope, public_key, bytes, &wrong_authority_context)
                .is_err()
        );

        let mut changed = bytes.to_vec();
        let final_index = changed.len() - 1;
        changed[final_index] ^= 1;
        assert!(prepared.validate(&scope, public_key, &changed).is_err());

        let other_signer = Ed25519DalekSigner::generate().expect("other signer");
        assert!(
            prepared
                .validate(&scope, other_signer.public_key(), bytes)
                .is_err()
        );
    }
}
