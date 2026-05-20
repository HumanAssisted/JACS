use super::transport::SignedEmailTransport;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationMode {
    Strict,
    Degraded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmailVerificationStatus {
    Verified,
    PartiallyVerified,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmailVerificationReason {
    MissingInlineJacsEnvelope,
    MissingSignedLogo,
    LogoSignatureExtractFailed,
    LogoSignatureMismatch,
    ReservedMarkerInUserInput,
    HtmlInTextBody,
    HtmlEquivalenceFailed,
    CanonicalPreimageHashMismatch,
    AgentSignatureInvalid,
    HaiCountersignatureInvalid,
    AttachmentJacsVerified,
    ServerValidationRejected,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignedEmailVerificationResult {
    pub status: EmailVerificationStatus,
    pub transport: SignedEmailTransport,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<EmailVerificationReason>,
}

impl VerificationMode {
    pub fn non_crypto_transport_failure_status(self) -> EmailVerificationStatus {
        match self {
            Self::Strict => EmailVerificationStatus::Failed,
            Self::Degraded => EmailVerificationStatus::PartiallyVerified,
        }
    }
}

impl SignedEmailVerificationResult {
    pub fn verified(transport: SignedEmailTransport) -> Self {
        Self {
            status: EmailVerificationStatus::Verified,
            transport,
            reasons: Vec::new(),
        }
    }

    pub fn failed(transport: SignedEmailTransport, reason: EmailVerificationReason) -> Self {
        Self {
            status: EmailVerificationStatus::Failed,
            transport,
            reasons: vec![reason],
        }
    }

    pub fn non_crypto_transport_failure(
        mode: VerificationMode,
        transport: SignedEmailTransport,
        reason: EmailVerificationReason,
    ) -> Self {
        Self {
            status: mode.non_crypto_transport_failure_status(),
            transport,
            reasons: vec![reason],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_and_degraded_modes_map_missing_logo_differently() {
        let strict = SignedEmailVerificationResult::non_crypto_transport_failure(
            VerificationMode::Strict,
            SignedEmailTransport::HtmlInline,
            EmailVerificationReason::MissingSignedLogo,
        );
        let degraded = SignedEmailVerificationResult::non_crypto_transport_failure(
            VerificationMode::Degraded,
            SignedEmailTransport::HtmlInline,
            EmailVerificationReason::MissingSignedLogo,
        );

        assert_eq!(strict.status, EmailVerificationStatus::Failed);
        assert_eq!(degraded.status, EmailVerificationStatus::PartiallyVerified);
    }

    #[test]
    fn verification_reason_serializes_stably() {
        let value = serde_json::to_value(EmailVerificationReason::LogoSignatureMismatch).unwrap();

        assert_eq!(value, serde_json::json!("logo_signature_mismatch"));
    }

    #[test]
    fn all_required_verification_reasons_serialize_stably() {
        let reasons = [
            (
                EmailVerificationReason::MissingInlineJacsEnvelope,
                "missing_inline_jacs_envelope",
            ),
            (
                EmailVerificationReason::MissingSignedLogo,
                "missing_signed_logo",
            ),
            (
                EmailVerificationReason::LogoSignatureExtractFailed,
                "logo_signature_extract_failed",
            ),
            (
                EmailVerificationReason::LogoSignatureMismatch,
                "logo_signature_mismatch",
            ),
            (
                EmailVerificationReason::ReservedMarkerInUserInput,
                "reserved_marker_in_user_input",
            ),
            (EmailVerificationReason::HtmlInTextBody, "html_in_text_body"),
            (
                EmailVerificationReason::HtmlEquivalenceFailed,
                "html_equivalence_failed",
            ),
            (
                EmailVerificationReason::CanonicalPreimageHashMismatch,
                "canonical_preimage_hash_mismatch",
            ),
            (
                EmailVerificationReason::AgentSignatureInvalid,
                "agent_signature_invalid",
            ),
            (
                EmailVerificationReason::HaiCountersignatureInvalid,
                "hai_countersignature_invalid",
            ),
            (
                EmailVerificationReason::AttachmentJacsVerified,
                "attachment_jacs_verified",
            ),
            (
                EmailVerificationReason::ServerValidationRejected,
                "server_validation_rejected",
            ),
        ];

        for (reason, expected) in reasons {
            assert_eq!(serde_json::to_value(reason).unwrap(), expected);
        }
    }

    #[test]
    fn verification_status_serializes_stably() {
        let value = serde_json::to_value(EmailVerificationStatus::PartiallyVerified).unwrap();

        assert_eq!(value, serde_json::json!("partially_verified"));
    }
}
