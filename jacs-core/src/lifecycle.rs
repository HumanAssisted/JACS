//! Deterministic portable identity transitions. This module verifies signed
//! history; the selected owner/authority store supplies authenticated acceptance
//! time and commits the resulting state. No input here enrolls an identity.

use crate::CoreError;
use crate::identity::{self, IdentityAnchor, JacsTime, KeyPurpose, invalid};
use crate::signing::SigningOperation;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

mod reducer;
mod status;
pub use status::{
    AuthorityScope, StatusCheckpointPayload, validate_status_checkpoint,
    verify_portable_status_checkpoint,
};

fn nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(deserializer)
}

fn present_nullable<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatus {
    Active,
    Retired,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCategory {
    SuspectedCompromise,
    ConfirmedCompromise,
    KeyLoss,
    AdministrativeWithdrawal,
    Superseded,
    PolicyViolation,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationSemantics {
    DenyAll,
    DenyAtOrAfter,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Retirement {
    pub declared_at: JacsTime,
    pub reason_category: ReasonCategory,
    pub lifecycle_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Revocation {
    pub reason_category: ReasonCategory,
    pub semantics: RevocationSemantics,
    #[serde(deserialize_with = "nullable")]
    pub cutoff: Option<JacsTime>,
    #[serde(deserialize_with = "nullable")]
    pub cutoff_evidence: Option<String>,
    pub lifecycle_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegacyBinding {
    pub jacs_version: String,
    pub signer_lookup_id: String,
    pub legacy_hash_profile: String,
    #[serde(deserialize_with = "nullable")]
    pub legacy_public_key_material: Option<String>,
    pub public_key_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyRecord {
    pub key_id: String,
    pub algorithm: String,
    pub public_key: String,
    pub purposes: Vec<KeyPurpose>,
    pub legacy_bindings: Vec<LegacyBinding>,
    pub status: KeyStatus,
    pub not_before: JacsTime,
    #[serde(deserialize_with = "nullable")]
    pub not_after: Option<JacsTime>,
    #[serde(
        default,
        deserialize_with = "present_nullable",
        skip_serializing_if = "Option::is_none"
    )]
    pub retirement: Option<Option<Retirement>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation: Option<Revocation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoveryAuthority {
    pub key_id: String,
    pub algorithm: String,
    pub public_key: String,
    pub status: KeyStatus,
    pub not_before: JacsTime,
    #[serde(deserialize_with = "nullable")]
    pub not_after: Option<JacsTime>,
    pub threshold_weight: u64,
    #[serde(
        default,
        deserialize_with = "present_nullable",
        skip_serializing_if = "Option::is_none"
    )]
    pub retirement: Option<Option<Retirement>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation: Option<Revocation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CurrentBinding {
    pub operation: SigningOperation,
    pub purpose: KeyPurpose,
    pub signature_profile: String,
    pub canonical_key_id: String,
    #[serde(deserialize_with = "nullable")]
    pub jacs_version: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub signer_lookup_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BindingReplacement {
    pub old: CurrentBinding,
    pub new: CurrentBinding,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusTransitionMode {
    NotApplicable,
    Normal,
    RootEmergency,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusBootstrapMode {
    NotApplicable,
    RootBootstrap,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetCollection {
    Operational,
    HistoricalRoot,
    Recovery,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "body",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum RecoveryChange {
    AddAuthority {
        authority: RecoveryAuthority,
    },
    RetireAuthority {
        key_id: String,
        retired_at: JacsTime,
        reason_category: ReasonCategory,
    },
    RevokeAuthority {
        key_id: String,
        reason_category: ReasonCategory,
        semantics: RevocationSemantics,
        #[serde(deserialize_with = "nullable")]
        cutoff: Option<JacsTime>,
        #[serde(deserialize_with = "nullable")]
        cutoff_evidence: Option<String>,
    },
    SetAuthorityWeight {
        key_id: String,
        old_weight: u64,
        new_weight: u64,
    },
    SetRecoveryThreshold {
        #[serde(deserialize_with = "nullable")]
        old_threshold: Option<u64>,
        #[serde(deserialize_with = "nullable")]
        new_threshold: Option<u64>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "body",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum LifecycleEvent {
    Genesis {},
    AuthorizeOperationalKey {
        key: KeyRecord,
        status_bootstrap_mode: StatusBootstrapMode,
        #[serde(deserialize_with = "nullable")]
        new_current_binding: Option<CurrentBinding>,
    },
    BindLegacyVersion {
        key_id: String,
        prior_key_record_digest: String,
        jacs_version: String,
        signer_lookup_id: String,
        legacy_hash_profile: String,
        #[serde(deserialize_with = "nullable")]
        legacy_public_key_material: Option<String>,
        public_key_hash: String,
    },
    UpdateCurrentBindings {
        prior_current_bindings_digest: String,
        new_current_bindings: Vec<CurrentBinding>,
        status_transition_mode: StatusTransitionMode,
    },
    RotateOperationalKey {
        old_key_id: String,
        old_key_record_digest: String,
        new_key: KeyRecord,
        retired_at: JacsTime,
        reason_category: ReasonCategory,
        binding_replacements: Vec<BindingReplacement>,
        status_transition_mode: StatusTransitionMode,
    },
    RetireOperationalKey {
        key_id: String,
        prior_key_record_digest: String,
        retired_at: JacsTime,
        reason_category: ReasonCategory,
        removed_current_bindings: Vec<CurrentBinding>,
    },
    RevokeOperationalKey {
        key_id: String,
        prior_key_record_digest: String,
        reason_category: ReasonCategory,
        semantics: RevocationSemantics,
        removed_current_bindings: Vec<CurrentBinding>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cutoff: Option<JacsTime>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cutoff_evidence: Option<String>,
    },
    StrengthenRevocation {
        target_collection: TargetCollection,
        key_id: String,
        prior_key_record_digest: String,
        strengthened_key_record: Value,
        prior_semantics: RevocationSemantics,
        new_semantics: RevocationSemantics,
    },
    ConstrainRootPurposes {
        root_key_id: String,
        prior_root_key_record_digest: String,
        old_purposes: Vec<KeyPurpose>,
        new_purposes: Vec<KeyPurpose>,
        removed_at: JacsTime,
        removed_current_bindings: Vec<CurrentBinding>,
    },
    RotateRoot {
        old_root_key_id: String,
        old_root_key_record_digest: String,
        retired_old_root: KeyRecord,
        new_root: KeyRecord,
        retired_at: JacsTime,
        reason_category: ReasonCategory,
        binding_replacements: Vec<BindingReplacement>,
    },
    RevokeHistoricalRoot {
        historical_root_key_id: String,
        prior_historical_root_record_digest: String,
        revoked_historical_root: KeyRecord,
        reason_category: ReasonCategory,
        semantics: RevocationSemantics,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cutoff: Option<JacsTime>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cutoff_evidence: Option<String>,
    },
    ChangeRecoveryAuthorities {
        previous_recovery_set_digest: String,
        new_recovery_authorities: Vec<RecoveryAuthority>,
        #[serde(deserialize_with = "nullable")]
        new_recovery_threshold: Option<u64>,
        changes: Vec<RecoveryChange>,
    },
    ResolveFork {
        base_manifest_digest: String,
        selected_child_digest: String,
        rejected_child_digests: Vec<String>,
        selected_state_digest: String,
    },
    CompromiseRecovery {
        base_manifest_digest: String,
        revoked_root_key_id: String,
        revoked_root_key_record_digest: String,
        revoked_old_root: KeyRecord,
        reason_category: ReasonCategory,
        revocation_semantics: RevocationSemantics,
        new_root: KeyRecord,
        new_recovery_authorities: Vec<RecoveryAuthority>,
        #[serde(deserialize_with = "nullable")]
        new_recovery_threshold: Option<u64>,
        recovery_changes: Vec<RecoveryChange>,
        binding_replacements: Vec<BindingReplacement>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        superseded_child_digests: Option<Vec<String>>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifecycleSignature {
    pub key_id: String,
    pub algorithm: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityManifest {
    pub profile: String,
    pub independent_compromise_recovery: bool,
    pub identity: String,
    pub sequence: u64,
    #[serde(deserialize_with = "nullable")]
    pub previous_manifest: Option<String>,
    pub identity_root: KeyRecord,
    pub recovery_authorities: Vec<RecoveryAuthority>,
    #[serde(deserialize_with = "nullable")]
    pub recovery_threshold: Option<u64>,
    pub keys: Vec<KeyRecord>,
    pub current_bindings: Vec<CurrentBinding>,
    pub issued_at: JacsTime,
    pub event: LifecycleEvent,
    pub signatures: Vec<LifecycleSignature>,
}

fn value<T: Serialize>(input: &T) -> Result<Value, CoreError> {
    serde_json::to_value(input).map_err(|error| invalid(error.to_string()))
}
fn hash<T: Serialize>(label: &str, input: &T) -> Result<String, CoreError> {
    identity::digest_json(label, &value(input)?)
}

impl IdentityManifest {
    pub fn parse(input: &str) -> Result<Self, CoreError> {
        let raw = crate::strict_json::parse_strict_json(input)?;
        let manifest: Self =
            serde_json::from_value(raw.clone()).map_err(|error| invalid(error.to_string()))?;
        if value(&manifest)? != raw {
            return Err(invalid("manifest has noncanonical field presence"));
        }
        Ok(manifest)
    }
    pub fn digest(&self) -> Result<String, CoreError> {
        hash("JACS-MANIFEST-DIGEST-V1", self)
    }
    pub fn state_digest(&self) -> Result<String, CoreError> {
        identity::digest_json("JACS-IDENTITY-STATE-DIGEST-V1", &self.state_value())
    }
    fn state_value(&self) -> Value {
        json!({"identity":self.identity,"profile":self.profile,"identityRoot":self.identity_root,
        "recoveryAuthorities":self.recovery_authorities,"recoveryThreshold":self.recovery_threshold,
        "independentCompromiseRecovery":self.independent_compromise_recovery,"keys":self.keys,"currentBindings":self.current_bindings})
    }
    pub fn signature_input(&self) -> Result<Vec<u8>, CoreError> {
        let mut envelope = value(self)?;
        for signature in envelope["signatures"]
            .as_array_mut()
            .ok_or_else(|| invalid("signature array"))?
        {
            signature
                .as_object_mut()
                .ok_or_else(|| invalid("signature descriptor"))?
                .remove("value");
        }
        identity::new_profile_signature_input("JACS-KEY-EVENT-V1", "jacs-identity-v1", &envelope)
    }
}

impl KeyRecord {
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, CoreError> {
        identity::decode_binary(&self.public_key)
    }
    pub fn digest(&self) -> Result<String, CoreError> {
        hash("JACS-KEY-RECORD-DIGEST-V1", self)
    }
    pub fn eligible_at(&self, at: &JacsTime) -> bool {
        self.status == KeyStatus::Active
            && &self.not_before <= at
            && self.not_after.as_ref().is_none_or(|end| at < end)
    }
}

/// Checked history with no trust/enrollment constructor. The acceptance store
/// must authenticate evaluation times and commit this result before a policy
/// verifier uses it as authority.
#[derive(Debug, Clone)]
pub struct StructuralLifecycleState {
    anchor: IdentityAnchor,
    manifest: IdentityManifest,
    digest: String,
    seen_keys: BTreeSet<String>,
    historical_roots: BTreeMap<String, KeyRecord>,
    binding_history: BTreeMap<String, String>,
    evaluation_times: BTreeMap<String, JacsTime>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityProfileMode {
    Separated,
    LocalCompatibilityCombined,
    LocalCompatibilityBoundPair,
}

#[derive(Debug, Clone)]
pub struct LifecyclePolicy {
    pub profile_mode: IdentityProfileMode,
    pub require_portable_status: bool,
    /// Exact operation/profile/purpose combinations selected by the caller's
    /// authenticated registry; candidate manifests cannot extend this list.
    pub allowed_bindings: Vec<(SigningOperation, String, KeyPurpose)>,
}

impl StructuralLifecycleState {
    pub fn anchor(&self) -> &IdentityAnchor {
        &self.anchor
    }
    pub fn manifest(&self) -> &IdentityManifest {
        &self.manifest
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn evaluation_time(&self, digest: &str) -> Option<&JacsTime> {
        self.evaluation_times.get(digest)
    }

    pub fn recovery_threshold_currently_satisfiable(&self, at: &JacsTime) -> bool {
        let Some(threshold) = self.manifest.recovery_threshold else {
            return false;
        };
        self.manifest
            .recovery_authorities
            .iter()
            .filter(|authority| {
                authority.status == KeyStatus::Active
                    && &authority.not_before <= at
                    && authority.not_after.as_ref().is_none_or(|end| at < end)
            })
            .try_fold(0_u64, |sum, authority| {
                sum.checked_add(authority.threshold_weight)
            })
            .is_some_and(|sum| sum >= threshold)
    }
    pub fn resolve_current(
        &self,
        operation: &SigningOperation,
        profile: &str,
        purpose: &KeyPurpose,
        at: &JacsTime,
    ) -> Result<&KeyRecord, CoreError> {
        let binding = self
            .manifest
            .current_bindings
            .iter()
            .find(|binding| &binding.operation == operation && binding.signature_profile == profile)
            .ok_or_else(|| invalid("no current authorized operation/profile binding"))?;
        if &binding.purpose != purpose {
            return Err(invalid("binding purpose mismatch"));
        }
        let key = find_key(&self.manifest, &binding.canonical_key_id)
            .ok_or_else(|| invalid("binding key unavailable"))?;
        if !key.eligible_at(at) || !key.purposes.contains(purpose) {
            return Err(invalid(
                "selected key is not active, time-valid, and purpose-authorized",
            ));
        }
        Ok(key)
    }
}

fn find_key<'a>(manifest: &'a IdentityManifest, id: &str) -> Option<&'a KeyRecord> {
    if manifest.identity_root.key_id == id {
        Some(&manifest.identity_root)
    } else {
        manifest.keys.iter().find(|key| key.key_id == id)
    }
}

fn ordered_unique<T: Ord>(items: impl IntoIterator<Item = T>, what: &str) -> Result<(), CoreError> {
    let items: Vec<_> = items.into_iter().collect();
    if items.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid(format!("{what} must be sorted and unique")));
    }
    Ok(())
}

fn binding_order(binding: &CurrentBinding) -> (String, String, String, String, String, String) {
    (
        binding.operation.to_wire().into_owned(),
        binding.signature_profile.clone(),
        binding.purpose.to_wire().into_owned(),
        binding.canonical_key_id.clone(),
        binding.jacs_version.clone().unwrap_or_default(),
        binding.signer_lookup_id.clone().unwrap_or_default(),
    )
}

fn legacy_order(binding: &LegacyBinding) -> (String, String, String, String, String) {
    (
        binding.jacs_version.clone(),
        binding.signer_lookup_id.clone(),
        binding.legacy_hash_profile.clone(),
        binding
            .legacy_public_key_material
            .clone()
            .unwrap_or_default(),
        binding.public_key_hash.clone(),
    )
}

fn validate_status(
    status: &KeyStatus,
    retirement: &Option<Option<Retirement>>,
    revocation: &Option<Revocation>,
    sequence: u64,
) -> Result<(), CoreError> {
    match (status, retirement, revocation) {
        (KeyStatus::Active, None, None)
        | (KeyStatus::Retired, Some(Some(_)), None)
        | (KeyStatus::Revoked, Some(_), Some(_)) => {}
        _ => {
            return Err(invalid(
                "key status fields do not match their closed variant",
            ));
        }
    }
    if let Some(Some(retired)) = retirement {
        if !matches!(
            retired.reason_category,
            ReasonCategory::AdministrativeWithdrawal | ReasonCategory::Superseded
        ) || retired.lifecycle_sequence == 0
            || retired.lifecycle_sequence > sequence
        {
            return Err(invalid("invalid retirement provenance"));
        }
    }
    if let Some(revoked) = revocation {
        if revoked.lifecycle_sequence == 0 || revoked.lifecycle_sequence > sequence {
            return Err(invalid("invalid revocation sequence"));
        }
        validate_revocation(
            &revoked.reason_category,
            &revoked.semantics,
            &revoked.cutoff,
            &revoked.cutoff_evidence,
        )?;
    }
    Ok(())
}

fn validate_revocation(
    reason: &ReasonCategory,
    semantics: &RevocationSemantics,
    cutoff: &Option<JacsTime>,
    evidence: &Option<String>,
) -> Result<(), CoreError> {
    match semantics {
        RevocationSemantics::DenyAll if cutoff.is_none() && evidence.is_none() => Ok(()),
        RevocationSemantics::DenyAtOrAfter
            if cutoff.is_some()
                && evidence.is_some()
                && !matches!(
                    reason,
                    ReasonCategory::SuspectedCompromise
                        | ReasonCategory::ConfirmedCompromise
                        | ReasonCategory::KeyLoss
                        | ReasonCategory::Unknown
                ) =>
        {
            identity::validate_digest(
                evidence
                    .as_deref()
                    .ok_or_else(|| invalid("cutoff evidence missing"))?,
            )
        }
        _ => Err(invalid(
            "revocation semantics, reason, and cutoff fields disagree",
        )),
    }
}

fn validate_material(
    key_id: &str,
    algorithm: &str,
    public_key: &str,
    not_before: &JacsTime,
    not_after: &Option<JacsTime>,
) -> Result<Vec<u8>, CoreError> {
    if identity::canonical_algorithm(algorithm)? != algorithm {
        return Err(invalid(
            "new key records require canonical algorithm tokens",
        ));
    }
    let bytes = identity::decode_binary(public_key)?;
    if identity::canonical_key_id(algorithm, &bytes)? != key_id {
        return Err(invalid("canonical key ID does not match exact public key"));
    }
    if not_after.as_ref().is_some_and(|end| end <= not_before) {
        return Err(invalid("key validity interval must be nonempty"));
    }
    Ok(bytes)
}

fn validate_legacy(
    binding: &LegacyBinding,
    identity_id: &str,
    key: &KeyRecord,
    bytes: &[u8],
) -> Result<(), CoreError> {
    identity::validate_legacy_lookup(
        identity_id,
        &binding.jacs_version,
        &binding.signer_lookup_id,
    )?;
    let digest = match binding.legacy_hash_profile.as_str() {
        "jacs-core-raw-public-key-hash-v1" if binding.legacy_public_key_material.is_none() => {
            crate::verify::sha256_hex(bytes)
        }
        "jacs-native-public-key-hash-v1" => {
            let retained = identity::decode_binary(
                binding
                    .legacy_public_key_material
                    .as_deref()
                    .ok_or_else(|| {
                        invalid("native legacy hash requires retained normalized bytes")
                    })?,
            )?;
            let text = std::str::from_utf8(&retained)
                .map_err(|_| invalid("native legacy bytes must be UTF-8"))?;
            let white = |c: char| matches!(c,'\u{0009}'..='\u{000d}'|'\u{0020}'|'\u{0085}'|'\u{00a0}'|'\u{1680}'|'\u{2000}'..='\u{200a}'|'\u{2028}'|'\u{2029}'|'\u{202f}'|'\u{205f}'|'\u{3000}');
            if text.contains('\u{feff}') || text.contains('\r') || text.trim_matches(white) != text
            {
                return Err(invalid(
                    "legacy public material is not the retained normalized representation",
                ));
            }
            if retained != bytes {
                use base64::Engine as _;
                let body = text
                    .strip_prefix("-----BEGIN PUBLIC KEY-----\n")
                    .and_then(|text| text.strip_suffix("\n-----END PUBLIC KEY-----"))
                    .ok_or_else(|| invalid("unsupported normalized legacy public key encoding"))?;
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(body.lines().collect::<String>())
                    .map_err(|_| invalid("invalid legacy PEM body"))?;
                if decoded != bytes {
                    use ed25519_dalek::pkcs8::DecodePublicKey;
                    let canonical = match key.algorithm.as_str() {
                        "ed25519" => ed25519_dalek::VerifyingKey::from_public_key_der(&decoded)
                            .map(|key| key.to_bytes().to_vec())
                            .map_err(|_| invalid("invalid legacy Ed25519 SPKI"))?,
                        _ => {
                            return Err(invalid(
                                "legacy public material does not decode to canonical key bytes",
                            ));
                        }
                    };
                    if canonical != bytes {
                        return Err(invalid(
                            "legacy public material selects a different canonical key",
                        ));
                    }
                }
            }
            crate::verify::sha256_hex(&retained)
        }
        _ => return Err(invalid("unknown or inconsistent legacy hash profile")),
    };
    if digest != binding.public_key_hash {
        return Err(invalid("legacy public key hash mismatch"));
    }
    Ok(())
}

fn validate_key(key: &KeyRecord, manifest: &IdentityManifest) -> Result<(), CoreError> {
    let bytes = validate_material(
        &key.key_id,
        &key.algorithm,
        &key.public_key,
        &key.not_before,
        &key.not_after,
    )?;
    validate_status(
        &key.status,
        &key.retirement,
        &key.revocation,
        manifest.sequence,
    )?;
    if key.purposes.is_empty() {
        return Err(invalid("key purposes cannot be empty"));
    }
    ordered_unique(
        key.purposes.iter().map(|purpose| purpose.to_wire()),
        "key purposes",
    )?;
    ordered_unique(
        key.legacy_bindings.iter().map(legacy_order),
        "legacy bindings",
    )?;
    for binding in &key.legacy_bindings {
        validate_legacy(binding, &manifest.identity, key, &bytes)?;
    }
    Ok(())
}

fn configured_recovery(
    authorities: &[RecoveryAuthority],
    threshold: Option<u64>,
) -> Result<bool, CoreError> {
    let active = authorities
        .iter()
        .filter(|authority| authority.status == KeyStatus::Active)
        .try_fold(0_u64, |sum, authority| {
            sum.checked_add(authority.threshold_weight)
                .ok_or_else(|| invalid("recovery weight overflow"))
        })?;
    match threshold {
        None if active == 0 => Ok(false),
        Some(threshold)
            if threshold > 0 && threshold <= active && threshold <= 9_007_199_254_740_991 =>
        {
            Ok(true)
        }
        _ => Err(invalid(
            "recovery threshold does not match active configured authorities",
        )),
    }
}

fn validate_manifest(
    manifest: &IdentityManifest,
    at: &JacsTime,
    policy: &LifecyclePolicy,
) -> Result<(), CoreError> {
    if manifest.profile != "jacs-identity-v1"
        || manifest.identity.is_empty()
        || manifest.sequence > 9_007_199_254_740_991
    {
        return Err(invalid(
            "invalid identity manifest profile, identity, or sequence",
        ));
    }
    if manifest.independent_compromise_recovery
        != configured_recovery(&manifest.recovery_authorities, manifest.recovery_threshold)?
    {
        return Err(invalid(
            "independentCompromiseRecovery must be derived from the recovery set",
        ));
    }
    ordered_unique(
        manifest.keys.iter().map(|key| &key.key_id),
        "operational keys",
    )?;
    ordered_unique(
        manifest.recovery_authorities.iter().map(|key| &key.key_id),
        "recovery authorities",
    )?;
    ordered_unique(
        manifest
            .signatures
            .iter()
            .map(|signature| &signature.key_id),
        "signature descriptors",
    )?;
    if manifest.signatures.is_empty() {
        return Err(invalid("manifest requires signatures"));
    }
    let mut ids = BTreeSet::new();
    for key in std::iter::once(&manifest.identity_root).chain(&manifest.keys) {
        validate_key(key, manifest)?;
        if !ids.insert(key.key_id.clone()) {
            return Err(invalid("canonical key occurs in multiple collections"));
        }
    }
    for key in &manifest.keys {
        if key.algorithm == "es256"
            && key.purposes.iter().any(|purpose| {
                !matches!(
                    purpose,
                    KeyPurpose::A2aArtifact | KeyPurpose::EcosystemExport(_)
                )
            })
        {
            return Err(invalid(
                "ES256 keys may serve only explicitly registered compatibility operations",
            ));
        }
        if key.purposes.iter().any(|purpose| {
            matches!(
                purpose,
                KeyPurpose::IdentityRoot | KeyPurpose::Recovery | KeyPurpose::AuthorityTime
            )
        }) {
            return Err(invalid("operational key has a control-plane purpose"));
        }
    }
    let root = &manifest.identity_root;
    if root.algorithm == "es256" {
        return Err(invalid(
            "ES256 is confined to explicitly authorized compatibility operations",
        ));
    }
    if !root.purposes.contains(&KeyPurpose::IdentityRoot) || root.status != KeyStatus::Active {
        return Err(invalid(
            "current identity root must be active and carry identity_root",
        ));
    }
    if policy.profile_mode == IdentityProfileMode::Separated
        && root.purposes != [KeyPurpose::IdentityRoot]
    {
        return Err(invalid("separated profile root has operational purposes"));
    }
    if policy.profile_mode != IdentityProfileMode::Separated
        && manifest.independent_compromise_recovery
    {
        return Err(invalid(
            "local compatibility profile cannot claim independent recovery",
        ));
    }
    if policy.profile_mode != IdentityProfileMode::Separated {
        let mut purposes = vec![KeyPurpose::IdentityRoot];
        purposes.extend(
            manifest
                .current_bindings
                .iter()
                .filter(|binding| binding.canonical_key_id == root.key_id)
                .map(|binding| binding.purpose.clone()),
        );
        purposes.sort_by_key(|purpose| purpose.to_wire().into_owned());
        purposes.dedup();
        if purposes != root.purposes {
            return Err(invalid(
                "compatibility root purposes must exactly match its selected operation bindings",
            ));
        }
        if policy.profile_mode == IdentityProfileMode::LocalCompatibilityCombined
            && ![
                (
                    SigningOperation::SignDocument,
                    "jacs-document-v2",
                    KeyPurpose::Document,
                ),
                (
                    SigningOperation::LegacyRawSign,
                    "jacs-legacy-raw-v1",
                    KeyPurpose::LegacyRaw,
                ),
            ]
            .iter()
            .all(|(operation, profile, purpose)| {
                manifest.current_bindings.iter().any(|binding| {
                    &binding.operation == operation
                        && binding.signature_profile == *profile
                        && &binding.purpose == purpose
                        && binding.canonical_key_id == root.key_id
                        && binding.jacs_version.is_some()
                        && binding.signer_lookup_id.is_some()
                })
            })
        {
            return Err(invalid(
                "combined local profile requires exact document and legacy-raw root bindings",
            ));
        }
    }
    for authority in &manifest.recovery_authorities {
        if authority.algorithm == "es256" {
            return Err(invalid(
                "ES256 compatibility keys cannot authorize identity recovery",
            ));
        }
        validate_material(
            &authority.key_id,
            &authority.algorithm,
            &authority.public_key,
            &authority.not_before,
            &authority.not_after,
        )?;
        validate_status(
            &authority.status,
            &authority.retirement,
            &authority.revocation,
            manifest.sequence,
        )?;
        if authority.threshold_weight == 0
            || authority.threshold_weight > 9_007_199_254_740_991
            || !ids.insert(authority.key_id.clone())
        {
            return Err(invalid("invalid or duplicate recovery authority"));
        }
    }
    validate_bindings(manifest, at, policy)?;
    Ok(())
}

fn validate_bindings(
    manifest: &IdentityManifest,
    at: &JacsTime,
    policy: &LifecyclePolicy,
) -> Result<(), CoreError> {
    ordered_unique(
        manifest.current_bindings.iter().map(binding_order),
        "current bindings",
    )?;
    let mut selections = BTreeSet::new();
    for binding in &manifest.current_bindings {
        if !selections.insert((
            binding.operation.to_wire().into_owned(),
            binding.signature_profile.clone(),
        )) || !binding.operation.accepts_purpose(&binding.purpose)
        {
            return Err(invalid("ambiguous or wrong-purpose current binding"));
        }
        let status = binding.operation == SigningOperation::PublishStatusCheckpoint
            && binding.signature_profile == "jacs-status-checkpoint-v1"
            && binding.purpose == KeyPurpose::Status;
        if !status
            && !policy.allowed_bindings.contains(&(
                binding.operation.clone(),
                binding.signature_profile.clone(),
                binding.purpose.clone(),
            ))
        {
            return Err(invalid("binding is not in the selected profile registry"));
        }
        let key = find_key(manifest, &binding.canonical_key_id)
            .ok_or_else(|| invalid("current binding key missing"))?;
        if !key.eligible_at(at) || !key.purposes.contains(&binding.purpose) {
            return Err(invalid(
                "current binding key is inactive, expired, or wrong-purpose",
            ));
        }
        if key.key_id == manifest.identity_root.key_id
            && policy.profile_mode == IdentityProfileMode::Separated
        {
            return Err(invalid(
                "operational binding cannot select a separated identity root",
            ));
        }
        if status
            && (key.purposes != [KeyPurpose::Status]
                || binding.jacs_version.is_some()
                || binding.signer_lookup_id.is_some())
        {
            return Err(invalid("status binding must select a dedicated status key"));
        }
        match (&binding.jacs_version, &binding.signer_lookup_id) {
            (None, None) => {}
            (Some(version), Some(lookup))
                if key.legacy_bindings.iter().any(|legacy| {
                    &legacy.jacs_version == version && &legacy.signer_lookup_id == lookup
                }) => {}
            _ => {
                return Err(invalid(
                    "current binding legacy identity/version is not authorized",
                ));
            }
        }
    }
    if policy.require_portable_status
        && !selections.contains(&(
            "PublishStatusCheckpoint".into(),
            "jacs-status-checkpoint-v1".into(),
        ))
    {
        return Err(invalid(
            "portable status requires one current dedicated status key",
        ));
    }
    Ok(())
}
