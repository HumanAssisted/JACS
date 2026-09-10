use super::*;
use crate::identity::StatusAuthority;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityScope {
    Local,
    Portable,
    Managed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatusCheckpointPayload {
    pub profile: String,
    pub operation: SigningOperation,
    pub purpose: KeyPurpose,
    pub identity_anchor: IdentityAnchor,
    pub status_authority: StatusAuthority,
    pub authority_scope: AuthorityScope,
    pub status_sequence: u64,
    pub checkpoint_time: JacsTime,
    pub complete_through: JacsTime,
    pub lifecycle_sequence: u64,
    pub lifecycle_record_digest: String,
    #[serde(deserialize_with = "nullable")]
    pub current_status_key_id: Option<String>,
    pub revocation_epoch: u64,
    #[serde(deserialize_with = "nullable")]
    pub previous_status_checkpoint_digest: Option<String>,
}

impl StatusCheckpointPayload {
    pub fn digest(&self) -> Result<String, CoreError> {
        hash("JACS-STATUS-CHECKPOINT-V1", self)
    }
    pub fn signature_input(&self, signature: &LifecycleSignature) -> Result<Vec<u8>, CoreError> {
        let mut envelope = value(self)?;
        envelope["signature"] = json!({"keyId":signature.key_id,"algorithm":signature.algorithm});
        identity::new_profile_signature_input(
            "JACS-STATUS-CHECKPOINT-V1",
            "jacs-status-checkpoint-v1",
            &envelope,
        )
    }
    pub fn evidence_digest(&self, signature: &LifecycleSignature) -> Result<String, CoreError> {
        let mut envelope = value(self)?;
        envelope["signature"] = value(signature)?;
        identity::digest_json("JACS-STATUS-CHECKPOINT-EVIDENCE-V1", &envelope)
    }
}

/// Validate status structure, retained predecessor, and freshness against
/// independently supplied evaluation time. Local/managed authentication must
/// additionally come from their owner/authority ledger; this returns no trust.
pub fn validate_status_checkpoint(
    state: &StructuralLifecycleState,
    previous: Option<&StatusCheckpointPayload>,
    candidate: &StatusCheckpointPayload,
    expected_authority: &StatusAuthority,
    evaluation_time: &JacsTime,
    maximum_age_seconds: u64,
) -> Result<(), CoreError> {
    if candidate.profile != "jacs-status-checkpoint-v1"
        || candidate.operation != SigningOperation::PublishStatusCheckpoint
        || candidate.purpose != KeyPurpose::Status
        || &candidate.identity_anchor != state.anchor()
        || &candidate.status_authority != expected_authority
        || candidate.lifecycle_sequence != state.manifest().sequence
        || candidate.lifecycle_record_digest != state.digest()
        || candidate.revocation_epoch != candidate.lifecycle_sequence
    {
        return Err(invalid(
            "status checkpoint does not bind the selected identity authority and exact lifecycle head",
        ));
    }
    let expected_scope = match expected_authority {
        StatusAuthority::LocalOwnerStore { .. } => AuthorityScope::Local,
        StatusAuthority::PortableRootStatus { identity_anchor }
            if identity_anchor == state.anchor() =>
        {
            AuthorityScope::Portable
        }
        StatusAuthority::AuthorityBackedStatus { .. } => AuthorityScope::Managed,
        _ => {
            return Err(invalid(
                "portable status authority selects another identity anchor",
            ));
        }
    };
    if candidate.authority_scope != expected_scope
        || candidate.complete_through > candidate.checkpoint_time
        || candidate.checkpoint_time > *evaluation_time
    {
        return Err(invalid(
            "status scope or checkpoint/completeness time is invalid",
        ));
    }
    let age = evaluation_time
        .unix_seconds()
        .checked_sub(candidate.complete_through.unix_seconds())
        .ok_or_else(|| invalid("status age overflow"))?;
    if age < 0
        || u64::try_from(age).map_err(|_| invalid("negative status age"))? > maximum_age_seconds
    {
        return Err(invalid("status completeness horizon is stale"));
    }
    if expected_scope == AuthorityScope::Portable {
        let selected = state
            .manifest()
            .current_bindings
            .iter()
            .find(|binding| {
                binding.operation == SigningOperation::PublishStatusCheckpoint
                    && binding.signature_profile == "jacs-status-checkpoint-v1"
            })
            .ok_or_else(|| invalid("portable status selection unavailable"))?;
        if candidate.current_status_key_id.as_deref() != Some(selected.canonical_key_id.as_str()) {
            return Err(invalid("status checkpoint names a noncurrent status key"));
        }
    } else if candidate.current_status_key_id.is_some() {
        return Err(invalid(
            "owner/managed status cannot claim a portable status signing key",
        ));
    }
    match previous {
        None if candidate.status_sequence == 0
            && candidate.previous_status_checkpoint_digest.is_none() => {}
        Some(previous) if candidate == previous => {}
        Some(previous) => {
            if previous.identity_anchor != candidate.identity_anchor
                || previous.status_authority != candidate.status_authority
                || candidate.status_sequence
                    != previous
                        .status_sequence
                        .checked_add(1)
                        .ok_or_else(|| invalid("status sequence overflow"))?
                || candidate.previous_status_checkpoint_digest.as_deref()
                    != Some(previous.digest()?.as_str())
                || candidate.checkpoint_time < previous.checkpoint_time
                || candidate.complete_through < previous.complete_through
                || candidate.lifecycle_sequence < previous.lifecycle_sequence
                || candidate.revocation_epoch < previous.revocation_epoch
                || candidate.lifecycle_sequence == previous.lifecycle_sequence
                    && candidate.lifecycle_record_digest != previous.lifecycle_record_digest
            {
                return Err(invalid(
                    "status rollback, sequence gap, or conflicting retained head",
                ));
            }
        }
        _ => {
            return Err(invalid(
                "status genesis requires sequence zero and null predecessor",
            ));
        }
    }
    Ok(())
}

/// Verify the portable signature after structural status validation. For an
/// ordinary checkpoint only the exact selected operational status key may sign.
/// Root-changing/bootstrap checkpoint authorization uses the explicit candidate
/// chain context; a caller cannot supply an arbitrary proposed root.
pub fn verify_portable_status_checkpoint(
    state: &StructuralLifecycleState,
    previous_state: Option<&StructuralLifecycleState>,
    previous_checkpoint: Option<&StatusCheckpointPayload>,
    payload: &StatusCheckpointPayload,
    signature: &LifecycleSignature,
    acceptance_time: &JacsTime,
) -> Result<(), CoreError> {
    if payload.authority_scope != AuthorityScope::Portable
        || payload.identity_anchor != *state.anchor()
        || payload.lifecycle_record_digest != state.digest()
    {
        return Err(invalid("portable checkpoint identity/head mismatch"));
    }
    let root_bootstrap = matches!(
        state.manifest().event,
        LifecycleEvent::Genesis {}
            | LifecycleEvent::RotateRoot { .. }
            | LifecycleEvent::CompromiseRecovery { .. }
            | LifecycleEvent::AuthorizeOperationalKey {
                status_bootstrap_mode: StatusBootstrapMode::RootBootstrap,
                ..
            }
            | LifecycleEvent::UpdateCurrentBindings {
                status_transition_mode: StatusTransitionMode::RootEmergency,
                ..
            }
            | LifecycleEvent::RotateOperationalKey {
                status_transition_mode: StatusTransitionMode::RootEmergency,
                ..
            }
    );
    let initial_checkpoint = match previous_checkpoint {
        None => {
            state.manifest().sequence == 0
                && payload.status_sequence == 0
                && payload.previous_status_checkpoint_digest.is_none()
        }
        Some(previous) => {
            previous.lifecycle_sequence < state.manifest().sequence
                && payload.status_sequence
                    == previous
                        .status_sequence
                        .checked_add(1)
                        .ok_or_else(|| invalid("status sequence overflow"))?
                && payload.previous_status_checkpoint_digest.as_deref()
                    == Some(previous.digest()?.as_str())
        }
    };
    let root_signer = root_bootstrap
        && initial_checkpoint
        && signature.key_id == state.manifest().identity_root.key_id;
    if initial_checkpoint
        && matches!(
            state.manifest().event,
            LifecycleEvent::AuthorizeOperationalKey {
                status_bootstrap_mode: StatusBootstrapMode::RootBootstrap,
                ..
            } | LifecycleEvent::UpdateCurrentBindings {
                status_transition_mode: StatusTransitionMode::RootEmergency,
                ..
            } | LifecycleEvent::RotateOperationalKey {
                status_transition_mode: StatusTransitionMode::RootEmergency,
                ..
            }
        )
        && !root_signer
    {
        return Err(invalid(
            "status bootstrap/emergency checkpoint requires the accepted identity root",
        ));
    }
    let key = if root_signer {
        &state.manifest().identity_root
    } else {
        let selected = state.resolve_current(
            &SigningOperation::PublishStatusCheckpoint,
            "jacs-status-checkpoint-v1",
            &KeyPurpose::Status,
            acceptance_time,
        )?;
        if signature.key_id != selected.key_id {
            return Err(invalid("checkpoint signer is not the selected status key"));
        }
        if matches!(
            state.manifest().event,
            LifecycleEvent::RotateRoot { .. } | LifecycleEvent::CompromiseRecovery { .. }
        ) && previous_state.is_none_or(|previous| {
            previous.anchor() != state.anchor()
                || state.manifest().previous_manifest.as_deref() != Some(previous.digest())
                || find_key(previous.manifest(), &selected.key_id).is_none_or(|prior| {
                    prior.purposes != [KeyPurpose::Status] || !prior.eligible_at(acceptance_time)
                })
        }) {
            return Err(invalid(
                "root-change checkpoint requires new root or previously authorized dedicated status key",
            ));
        }
        selected
    };
    if !key.eligible_at(acceptance_time) || signature.algorithm != key.algorithm {
        return Err(invalid(
            "checkpoint signer is ineligible at independently supplied acceptance time",
        ));
    }
    identity::verify_signature(
        &key.algorithm,
        &key.public_key_bytes()?,
        &payload.signature_input(signature)?,
        &identity::decode_binary(&signature.value)?,
    )
}
