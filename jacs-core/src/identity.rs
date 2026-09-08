//! Closed portable identity vocabulary and domain-separated cryptographic inputs.
//! These types describe evidence; decoding them never establishes trust.

use crate::{CoreError, canonical::canonicalize_json_try};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub(crate) fn invalid(message: impl Into<String>) -> CoreError {
    CoreError::MalformedDocument(message.into())
}

/// Normalize only the explicitly supported legacy algorithm spellings.
pub fn canonical_algorithm(algorithm: &str) -> Result<&'static str, CoreError> {
    match algorithm {
        "ed25519" | "Ed25519" | "ring-Ed25519" => Ok("ed25519"),
        "pq2025" | "ML-DSA-87" => Ok("pq2025"),
        "es256" | "ES256" => Ok("es256"),
        _ => Err(CoreError::UnsupportedAlgorithm(algorithm.into())),
    }
}

/// Strict base64url without padding or noncanonical trailing bits.
pub fn decode_binary(value: &str) -> Result<Vec<u8>, CoreError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| invalid(error.to_string()))?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(invalid("noncanonical base64url encoding"));
    }
    Ok(bytes)
}

pub fn encode_binary(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(value)
}

/// TP-07 ID over canonical algorithm and exact canonical key bytes.
pub fn canonical_key_id(algorithm: &str, public_key: &[u8]) -> Result<String, CoreError> {
    let algorithm = canonical_algorithm(algorithm)?;
    match algorithm {
        "ed25519" => {
            let bytes: &[u8; 32] = public_key.try_into().map_err(|_| {
                CoreError::MalformedKey("Ed25519 requires 32 canonical bytes".into())
            })?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(bytes)
                .map_err(|error| CoreError::MalformedKey(error.to_string()))?;
            if key.is_weak() || key.as_bytes() != bytes {
                return Err(CoreError::MalformedKey("invalid Ed25519 point".into()));
            }
        }
        "pq2025" => {
            use fips204::traits::SerDes;
            let bytes: [u8; 2592] = public_key.try_into().map_err(|_| {
                CoreError::MalformedKey("ML-DSA-87 requires 2592 canonical bytes".into())
            })?;
            fips204::ml_dsa_87::PublicKey::try_from_bytes(bytes)
                .map_err(|error| CoreError::MalformedKey(error.to_string()))?;
        }
        "es256" => {
            if public_key.len() != 65 || public_key[0] != 4 {
                return Err(CoreError::MalformedKey(
                    "ES256 requires a 65-byte uncompressed SEC1 point".into(),
                ));
            }
            p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|error| CoreError::MalformedKey(error.to_string()))?;
        }
        _ => unreachable!(),
    }
    let mut hasher = Sha256::new();
    hasher.update(b"JACS-KEY-ID-V1\0");
    hasher.update(algorithm.as_bytes());
    hasher.update([0]);
    hasher.update(public_key);
    Ok(format!(
        "jacs-key-v1:{algorithm}:{}",
        URL_SAFE_NO_PAD.encode(hasher.finalize())
    ))
}

/// TP-10 D: canonicalize a JSON value once, then domain-separate its digest.
pub fn digest_json(label: &str, value: &Value) -> Result<String, CoreError> {
    Ok(digest_bytes(
        label,
        canonicalize_json_try(value)?.as_bytes(),
    ))
}

/// TP-10 B: exact bytes, without parsing or JSON canonicalization.
pub fn digest_bytes(label: &str, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.update([0]);
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

pub fn validate_digest(digest: &str) -> Result<(), CoreError> {
    let hex = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| invalid("digest requires sha256: prefix"))?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(
            "digest requires 64 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}

/// TP-05 constructor. The protocol-specific caller removes only its defined
/// signature value slots, retaining complete signer descriptors.
pub fn new_profile_signature_input(
    domain: &str,
    profile: &str,
    envelope: &Value,
) -> Result<Vec<u8>, CoreError> {
    if domain.is_empty() || profile.is_empty() || !domain.is_ascii() || !profile.is_ascii() {
        return Err(invalid(
            "signature domain and profile must be nonempty ASCII literals",
        ));
    }
    if envelope
        .get("profile")
        .is_some_and(|value| value.as_str() != Some(profile))
    {
        return Err(invalid(
            "signed profile differs from the selected signature profile",
        ));
    }
    let canonical = canonicalize_json_try(envelope)?;
    let mut result = Vec::new();
    result.extend_from_slice(
        &u32::try_from(domain.len())
            .map_err(|_| invalid("domain too long"))?
            .to_be_bytes(),
    );
    result.extend_from_slice(domain.as_bytes());
    result.extend_from_slice(
        &u32::try_from(profile.len())
            .map_err(|_| invalid("profile too long"))?
            .to_be_bytes(),
    );
    result.extend_from_slice(profile.as_bytes());
    result.extend_from_slice(&(canonical.len() as u64).to_be_bytes());
    result.extend_from_slice(canonical.as_bytes());
    Ok(result)
}

/// Strict TP-07 verifier shared by new portable control-plane profiles.
pub fn verify_signature(
    algorithm: &str,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CoreError> {
    canonical_key_id(algorithm, public_key)?;
    match canonical_algorithm(algorithm)? {
        "ed25519" => {
            let key = ed25519_dalek::VerifyingKey::from_bytes(
                public_key
                    .try_into()
                    .map_err(|_| invalid("Ed25519 public key length"))?,
            )
            .map_err(|error| CoreError::MalformedKey(error.to_string()))?;
            let signature = ed25519_dalek::Signature::from_slice(signature)
                .map_err(|error| CoreError::SignatureInvalid(error.to_string()))?;
            key.verify_strict(message, &signature)
                .map_err(|error| CoreError::SignatureInvalid(error.to_string()))
        }
        "pq2025" => crate::sign::Pq2025Signer::verify(public_key, message, signature),
        "es256" => {
            use p256::ecdsa::signature::Verifier;
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|error| CoreError::MalformedKey(error.to_string()))?;
            let signature = p256::ecdsa::Signature::from_slice(signature)
                .map_err(|error| CoreError::SignatureInvalid(error.to_string()))?;
            if signature.normalize_s().is_some() {
                return Err(CoreError::SignatureInvalid(
                    "ES256 requires low-S signature".into(),
                ));
            }
            key.verify(message, &signature)
                .map_err(|error| CoreError::SignatureInvalid(error.to_string()))
        }
        _ => unreachable!(),
    }
}

/// UTC second with the exact `jacs-time-v1` wire grammar.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct JacsTime(String);

impl JacsTime {
    pub fn parse(value: &str) -> Result<Self, CoreError> {
        let bytes = value.as_bytes();
        if bytes.len() != 20
            || bytes[4] != b'-'
            || bytes[7] != b'-'
            || bytes[10] != b'T'
            || bytes[13] != b':'
            || bytes[16] != b':'
            || bytes[19] != b'Z'
            || bytes.iter().enumerate().any(|(index, byte)| {
                ![4, 7, 10, 13, 16, 19].contains(&index) && !byte.is_ascii_digit()
            })
            || &value[..4] == "0000"
            || &value[17..19] > "59"
        {
            return Err(invalid("invalid jacs-time-v1 timestamp"));
        }
        chrono::DateTime::parse_from_rfc3339(value)
            .map_err(|_| invalid("invalid jacs-time-v1 calendar date"))?;
        Ok(Self(value.into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn from_unix_seconds(seconds: i64) -> Result<Self, CoreError> {
        let value = chrono::DateTime::from_timestamp(seconds, 0)
            .ok_or_else(|| invalid("UTC second out of range"))?;
        Self::parse(&value.format("%Y-%m-%dT%H:%M:%SZ").to_string())
    }
    pub fn unix_seconds(&self) -> i64 {
        // Construction and deserialization validate the exact grammar.
        chrono::DateTime::parse_from_rfc3339(&self.0)
            .expect("validated timestamp")
            .timestamp()
    }
}
impl std::fmt::Display for JacsTime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}
impl<'de> Deserialize<'de> for JacsTime {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapProfile {
    PinnedSigningCredentialV1,
    ManagedControlPlaneV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum AuthorityAnchor {
    Authority {
        authority_service_id: String,
        bootstrap_profile: BootstrapProfile,
        bootstrap_credential_id: String,
        bootstrap_record_digest: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum IdentityAnchor {
    Portable {
        jacs_id: String,
        genesis_manifest_digest: String,
        genesis_root_canonical_key_id: String,
    },
    AuthorityBacked {
        authority_anchor: AuthorityAnchor,
        authority_enrollment_handle: String,
        authenticated_initial_record_digest: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum StatusAuthority {
    LocalOwnerStore {
        canonical_store_id: String,
        owner_id: String,
        bootstrap_digest: String,
    },
    PortableRootStatus {
        identity_anchor: IdentityAnchor,
    },
    AuthorityBackedStatus {
        authority_anchor: AuthorityAnchor,
        authority_enrollment_handle: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum TrustStoreAnchor {
    LocalTrustStore {
        local_owner_store: StatusAuthority,
    },
    AuthorityTrustStore {
        authority_anchor: AuthorityAnchor,
        trust_store_enrollment_handle: String,
        trust_store_bootstrap_record_digest: String,
    },
}

pub use crate::signing::SigningPurpose as KeyPurpose;

pub fn validate_legacy_lookup(
    identity: &str,
    version: &str,
    lookup: &str,
) -> Result<(), CoreError> {
    for value in [identity, version] {
        let parsed = uuid::Uuid::parse_str(value)
            .map_err(|_| invalid("legacy identity/version must be canonical UUID text"))?;
        if parsed.hyphenated().to_string() != value {
            return Err(invalid("legacy UUID is not lowercase hyphenated text"));
        }
    }
    if lookup != format!("{identity}:{version}") {
        return Err(invalid("legacy lookup does not match identity and version"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DetachedSigner;
    #[test]
    fn identity_domains_and_canonical_key_encoding_are_stable() {
        let key = crate::ed25519_signer_for_tests();
        let id = canonical_key_id("ed25519", key.public_key()).expect("canonical key");
        assert_eq!(
            id,
            canonical_key_id("ring-Ed25519", key.public_key()).expect("legacy spelling")
        );
        assert!(canonical_key_id("pq2025", key.public_key()).is_err());
        assert_ne!(
            digest_bytes("FIRST", b"same"),
            digest_bytes("SECOND", b"same")
        );
        let value = serde_json::json!({"b":2,"a":1});
        assert_eq!(
            digest_json("VALUE", &value).unwrap(),
            digest_bytes("VALUE", b"{\"a\":1,\"b\":2}")
        );
        let message = new_profile_signature_input(
            "JACS-KEY-EVENT-V1",
            "jacs-identity-v1",
            &serde_json::json!({"profile":"jacs-identity-v1"}),
        )
        .unwrap();
        let signature = key.sign(&message).unwrap();
        verify_signature("ed25519", key.public_key(), &message, &signature).unwrap();
    }
    #[test]
    fn timestamps_have_one_encoding_and_checked_calendar_dates() {
        for value in [
            "0001-01-01T00:00:00Z",
            "1969-12-31T23:59:59Z",
            "2000-02-29T00:00:00Z",
            "9999-12-31T23:59:59Z",
        ] {
            JacsTime::parse(value).unwrap();
        }
        assert_eq!(
            JacsTime::parse("1969-12-31T23:59:59Z")
                .unwrap()
                .unix_seconds(),
            -1
        );
        for value in [
            "0000-01-01T00:00:00Z",
            "2026-02-29T00:00:00Z",
            "2026-01-01T00:00:60Z",
            "2026-01-01T00:00:00+00:00",
            "2026-01-01T00:00:00.0Z",
        ] {
            assert!(JacsTime::parse(value).is_err());
        }
    }
}
