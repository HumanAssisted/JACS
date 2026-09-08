use super::*;

impl StructuralLifecycleState {
    /// Evaluate every observed direct child of an unambiguous base. An ordinary
    /// fork cannot select a winner by input order. Recovery/fork-resolution
    /// exceptions require their complete threshold-authorized evidence.
    pub fn advance_candidates(
        &self,
        candidates: &[IdentityManifest],
        acceptance_time: &JacsTime,
        policy: &LifecyclePolicy,
    ) -> Result<Self, CoreError> {
        let mut verified = BTreeMap::new();
        let mut resolutions = Vec::new();
        for candidate in candidates {
            if matches!(candidate.event, LifecycleEvent::ResolveFork { .. }) {
                resolutions.push(candidate);
                continue;
            }
            let state = self.advance_one(candidate.clone(), acceptance_time, policy, None)?;
            verified.insert(state.digest.clone(), state);
        }
        let mut resolved = BTreeMap::new();
        for resolution in resolutions {
            let LifecycleEvent::ResolveFork {
                selected_child_digest,
                rejected_child_digests,
                ..
            } = &resolution.event
            else {
                unreachable!()
            };
            let selected = verified
                .get(selected_child_digest)
                .ok_or_else(|| invalid("selected fork child is unavailable"))?;
            if matches!(
                selected.manifest.event,
                LifecycleEvent::CompromiseRecovery { .. } | LifecycleEvent::ResolveFork { .. }
            ) {
                return Err(invalid(
                    "fork resolution cannot select a recovery/resolution child",
                ));
            }
            if verified.keys().any(|digest| {
                digest != selected_child_digest && !rejected_child_digests.contains(digest)
            }) {
                return Err(invalid(
                    "fork resolution omitted an observed competing child",
                ));
            }
            let state =
                self.advance_one(resolution.clone(), acceptance_time, policy, Some(selected))?;
            resolved.insert(state.digest.clone(), state);
        }
        let recoveries: Vec<_> = verified
            .values()
            .filter(|state| {
                matches!(
                    state.manifest.event,
                    LifecycleEvent::CompromiseRecovery { .. }
                )
            })
            .collect();
        if !resolved.is_empty() {
            if resolved.len() != 1 || !recoveries.is_empty() {
                return Err(invalid(
                    "conflicting threshold-authorized fork/recovery decisions require external re-anchor",
                ));
            }
            return resolved
                .into_values()
                .next()
                .ok_or_else(|| invalid("fork resolution missing"));
        }
        if !recoveries.is_empty() {
            if recoveries.len() != 1
                || verified.values().any(|state| {
                    requires_recovery(&state.manifest.event)
                        && !matches!(
                            state.manifest.event,
                            LifecycleEvent::CompromiseRecovery { .. }
                        )
                })
            {
                return Err(invalid(
                    "competing recovery-threshold children require external re-anchor",
                ));
            }
            return Ok(recoveries[0].clone());
        }
        if verified.len() != 1 {
            return Err(invalid("ordinary lifecycle fork or missing next child"));
        }
        verified
            .into_values()
            .next()
            .ok_or_else(|| invalid("lifecycle child missing"))
    }

    /// Validate a genesis against an independently selected immutable anchor.
    /// The supplied time must come from the store's fenced acceptance operation.
    pub fn genesis(
        manifest: IdentityManifest,
        expected_anchor: &IdentityAnchor,
        acceptance_time: &JacsTime,
        policy: &LifecyclePolicy,
    ) -> Result<Self, CoreError> {
        if manifest.sequence != 0
            || manifest.previous_manifest.is_some()
            || !matches!(manifest.event, LifecycleEvent::Genesis {})
        {
            return Err(invalid(
                "genesis requires sequence zero and null predecessor",
            ));
        }
        validate_manifest(&manifest, acceptance_time, policy)?;
        let digest = manifest.digest()?;
        let anchor = IdentityAnchor::Portable {
            jacs_id: manifest.identity.clone(),
            genesis_manifest_digest: digest.clone(),
            genesis_root_canonical_key_id: manifest.identity_root.key_id.clone(),
        };
        if &anchor != expected_anchor {
            return Err(invalid(
                "genesis does not match independently selected identity anchor",
            ));
        }
        let mut seen_keys = BTreeSet::new();
        let mut binding_history = BTreeMap::new();
        for key in std::iter::once(&manifest.identity_root).chain(&manifest.keys) {
            if !key.eligible_at(acceptance_time) {
                return Err(invalid(
                    "genesis keys must all be active and time-valid at acceptance",
                ));
            }
            seen_keys.insert(key.key_id.clone());
            remember_bindings(key, &mut binding_history)?;
        }
        for authority in &manifest.recovery_authorities {
            if authority.status != KeyStatus::Active
                || &authority.not_before > acceptance_time
                || authority
                    .not_after
                    .as_ref()
                    .is_some_and(|end| acceptance_time >= end)
            {
                return Err(invalid(
                    "genesis recovery authorities must be active and time-valid",
                ));
            }
            seen_keys.insert(authority.key_id.clone());
        }
        verify_authorization(None, &manifest, acceptance_time, policy)?;
        Ok(Self {
            anchor,
            manifest,
            digest: digest.clone(),
            seen_keys,
            historical_roots: BTreeMap::new(),
            binding_history,
            evaluation_times: BTreeMap::from([(digest, acceptance_time.clone())]),
        })
    }

    /// Validate exactly one next event. Stores must retain observed competing
    /// children as conflicts and use `advance_candidates` before selecting a head.
    pub fn advance(
        &self,
        candidate: IdentityManifest,
        acceptance_time: &JacsTime,
        policy: &LifecyclePolicy,
    ) -> Result<Self, CoreError> {
        if candidate.digest()? == self.digest {
            return Ok(self.clone());
        }
        self.advance_one(candidate, acceptance_time, policy, None)
    }

    fn advance_one(
        &self,
        candidate: IdentityManifest,
        at: &JacsTime,
        policy: &LifecyclePolicy,
        selected: Option<&Self>,
    ) -> Result<Self, CoreError> {
        if candidate.sequence
            != self
                .manifest
                .sequence
                .checked_add(1)
                .ok_or_else(|| invalid("lifecycle sequence overflow"))?
            || candidate.previous_manifest.as_deref() != Some(self.digest.as_str())
            || candidate.identity != self.manifest.identity
            || candidate.profile != self.manifest.profile
        {
            return Err(invalid(
                "lifecycle gap, rollback, conflicting sequence, or identity change",
            ));
        }
        if self
            .evaluation_times
            .get(&self.digest)
            .is_none_or(|previous| at < previous)
        {
            return Err(invalid("lifecycle acceptance clock rollback"));
        }
        validate_manifest(&candidate, at, policy)?;
        verify_authorization(Some(&self.manifest), &candidate, at, policy)?;
        let mut expected = self.manifest.clone();
        let mut history = self.historical_roots.clone();
        let sequence = candidate.sequence;
        match &candidate.event {
            LifecycleEvent::Genesis {} => {
                return Err(invalid("genesis cannot follow existing history"));
            }
            LifecycleEvent::AuthorizeOperationalKey {
                key,
                status_bootstrap_mode,
                new_current_binding,
            } => {
                fresh_key(key, &self.seen_keys, at)?;
                if key.purposes == [KeyPurpose::Status] {
                    if *status_bootstrap_mode != StatusBootstrapMode::RootBootstrap
                        || status_key(&self.manifest).is_some()
                        || new_current_binding.as_ref().is_none_or(|binding| {
                            binding.operation != SigningOperation::PublishStatusCheckpoint
                                || binding.signature_profile != "jacs-status-checkpoint-v1"
                                || binding.canonical_key_id != key.key_id
                        })
                    {
                        return Err(invalid(
                            "status key authorization is only the one-time root bootstrap",
                        ));
                    }
                } else if *status_bootstrap_mode != StatusBootstrapMode::NotApplicable
                    || key.purposes.contains(&KeyPurpose::Status)
                {
                    return Err(invalid(
                        "invalid status bootstrap mode or combined status purpose",
                    ));
                }
                expected.keys.push(key.clone());
                if let Some(binding) = new_current_binding {
                    if binding.canonical_key_id != key.key_id {
                        return Err(invalid("new binding must select authorized new key"));
                    }
                    expected.current_bindings.push(binding.clone());
                }
            }
            LifecycleEvent::BindLegacyVersion {
                key_id,
                prior_key_record_digest,
                jacs_version,
                signer_lookup_id,
                legacy_hash_profile,
                legacy_public_key_material,
                public_key_hash,
            } => {
                if self.binding_history.contains_key(jacs_version) {
                    return Err(invalid(
                        "legacy version is already assigned in identity history",
                    ));
                }
                let key = if expected.identity_root.key_id == *key_id {
                    &mut expected.identity_root
                } else {
                    expected
                        .keys
                        .iter_mut()
                        .find(|key| key.key_id == *key_id)
                        .ok_or_else(|| invalid("legacy binding key missing"))?
                };
                require_hash("JACS-KEY-RECORD-DIGEST-V1", key, prior_key_record_digest)?;
                if !key.eligible_at(at) {
                    return Err(invalid("legacy binding requires active time-valid key"));
                }
                key.legacy_bindings.push(LegacyBinding {
                    jacs_version: jacs_version.clone(),
                    signer_lookup_id: signer_lookup_id.clone(),
                    legacy_hash_profile: legacy_hash_profile.clone(),
                    legacy_public_key_material: legacy_public_key_material.clone(),
                    public_key_hash: public_key_hash.clone(),
                });
                key.legacy_bindings.sort_by_key(legacy_order);
            }
            LifecycleEvent::UpdateCurrentBindings {
                prior_current_bindings_digest,
                new_current_bindings,
                status_transition_mode,
            } => {
                require_hash(
                    "JACS-CURRENT-BINDINGS-V1",
                    &expected.current_bindings,
                    prior_current_bindings_digest,
                )?;
                require_status_mode(&expected, &candidate, status_transition_mode)?;
                expected.current_bindings = new_current_bindings.clone();
            }
            LifecycleEvent::RotateOperationalKey {
                old_key_id,
                old_key_record_digest,
                new_key,
                retired_at,
                reason_category,
                binding_replacements,
                status_transition_mode,
            } => {
                fresh_key(new_key, &self.seen_keys, at)?;
                if *reason_category != ReasonCategory::Superseded {
                    return Err(invalid("rotation retirement reason must be superseded"));
                }
                let key = operational_mut(&mut expected, old_key_id, old_key_record_digest)?;
                *key = retired_record(key, retired_at, reason_category, sequence)?;
                replace_bindings(
                    &mut expected.current_bindings,
                    old_key_id,
                    &new_key.key_id,
                    binding_replacements,
                )?;
                expected.keys.push(new_key.clone());
                require_status_mode(&self.manifest, &candidate, status_transition_mode)?;
            }
            LifecycleEvent::RetireOperationalKey {
                key_id,
                prior_key_record_digest,
                retired_at,
                reason_category,
                removed_current_bindings,
            } => {
                let key = operational_mut(&mut expected, key_id, prior_key_record_digest)?;
                *key = retired_record(key, retired_at, reason_category, sequence)?;
                remove_bindings(
                    &mut expected.current_bindings,
                    key_id,
                    None,
                    removed_current_bindings,
                )?;
            }
            LifecycleEvent::RevokeOperationalKey {
                key_id,
                prior_key_record_digest,
                reason_category,
                semantics,
                removed_current_bindings,
                cutoff,
                cutoff_evidence,
            } => {
                let key = operational_mut(&mut expected, key_id, prior_key_record_digest)?;
                *key = revoked_record(
                    key,
                    reason_category,
                    semantics,
                    cutoff,
                    cutoff_evidence,
                    sequence,
                )?;
                remove_bindings(
                    &mut expected.current_bindings,
                    key_id,
                    None,
                    removed_current_bindings,
                )?;
            }
            LifecycleEvent::ConstrainRootPurposes {
                root_key_id,
                prior_root_key_record_digest,
                old_purposes,
                new_purposes,
                removed_at: _,
                removed_current_bindings,
            } => {
                let key = &mut expected.identity_root;
                require_hash(
                    "JACS-KEY-RECORD-DIGEST-V1",
                    key,
                    prior_root_key_record_digest,
                )?;
                if key.key_id != *root_key_id
                    || key.purposes != *old_purposes
                    || new_purposes.len() >= old_purposes.len()
                    || !new_purposes.contains(&KeyPurpose::IdentityRoot)
                    || new_purposes
                        .iter()
                        .any(|purpose| !old_purposes.contains(purpose))
                {
                    return Err(invalid(
                        "root purpose change must be a strict authority-preserving subset",
                    ));
                }
                let removed: Vec<_> = old_purposes
                    .iter()
                    .filter(|purpose| !new_purposes.contains(purpose))
                    .cloned()
                    .collect();
                key.purposes = new_purposes.clone();
                remove_bindings(
                    &mut expected.current_bindings,
                    root_key_id,
                    Some(&removed),
                    removed_current_bindings,
                )?;
            }
            LifecycleEvent::RotateRoot {
                old_root_key_id,
                old_root_key_record_digest,
                retired_old_root,
                new_root,
                retired_at,
                reason_category,
                binding_replacements,
            } => {
                let old = &self.manifest.identity_root;
                require_hash("JACS-KEY-RECORD-DIGEST-V1", old, old_root_key_record_digest)?;
                if old.key_id != *old_root_key_id
                    || *reason_category != ReasonCategory::Superseded
                    || retired_record(old, retired_at, reason_category, sequence)?
                        != *retired_old_root
                {
                    return Err(invalid("root rotation old-root transform mismatch"));
                }
                validate_root_replacement(old, new_root, &self.seen_keys, at)?;
                history.insert(old.key_id.clone(), retired_old_root.clone());
                expected.identity_root = new_root.clone();
                replace_bindings(
                    &mut expected.current_bindings,
                    old_root_key_id,
                    &new_root.key_id,
                    binding_replacements,
                )?;
            }
            LifecycleEvent::RevokeHistoricalRoot {
                historical_root_key_id,
                prior_historical_root_record_digest,
                revoked_historical_root,
                reason_category,
                semantics,
                cutoff,
                cutoff_evidence,
            } => {
                let old = history
                    .get(historical_root_key_id)
                    .ok_or_else(|| invalid("historical root not retained"))?;
                require_hash(
                    "JACS-KEY-RECORD-DIGEST-V1",
                    old,
                    prior_historical_root_record_digest,
                )?;
                if revoked_record(
                    old,
                    reason_category,
                    semantics,
                    cutoff,
                    cutoff_evidence,
                    sequence,
                )? != *revoked_historical_root
                {
                    return Err(invalid("historical root revocation transform mismatch"));
                }
                history.insert(
                    historical_root_key_id.clone(),
                    revoked_historical_root.clone(),
                );
            }
            LifecycleEvent::ChangeRecoveryAuthorities {
                previous_recovery_set_digest,
                new_recovery_authorities,
                new_recovery_threshold,
                changes,
            } => {
                if changes.is_empty() {
                    return Err(invalid("recovery change list cannot be empty"));
                }
                require_hash(
                    "JACS-RECOVERY-SET-DIGEST-V1",
                    &json!({"authorities":self.manifest.recovery_authorities,"threshold":self.manifest.recovery_threshold}),
                    previous_recovery_set_digest,
                )?;
                let (authorities, threshold) =
                    recovery_changes(&self.manifest, changes, at, sequence, &self.seen_keys)?;
                if authorities != *new_recovery_authorities || threshold != *new_recovery_threshold
                {
                    return Err(invalid("recovery change projection mismatch"));
                }
                expected.recovery_authorities = authorities;
                expected.recovery_threshold = threshold;
                expected.independent_compromise_recovery =
                    configured_recovery(&expected.recovery_authorities, threshold)?;
            }
            LifecycleEvent::CompromiseRecovery {
                base_manifest_digest,
                revoked_root_key_id,
                revoked_root_key_record_digest,
                revoked_old_root,
                reason_category,
                revocation_semantics,
                new_root,
                new_recovery_authorities,
                new_recovery_threshold,
                recovery_changes: changes,
                binding_replacements,
                superseded_child_digests,
            } => {
                let old = &self.manifest.identity_root;
                if base_manifest_digest != &self.digest
                    || revoked_root_key_id != &old.key_id
                    || *revocation_semantics != RevocationSemantics::DenyAll
                {
                    return Err(invalid(
                        "compromise recovery does not name its accepted base and revoked root",
                    ));
                }
                require_hash(
                    "JACS-KEY-RECORD-DIGEST-V1",
                    old,
                    revoked_root_key_record_digest,
                )?;
                if revoked_record(
                    old,
                    reason_category,
                    revocation_semantics,
                    &None,
                    &None,
                    sequence,
                )? != *revoked_old_root
                {
                    return Err(invalid("compromise recovery old-root transform mismatch"));
                }
                if let Some(children) = superseded_child_digests {
                    ordered_unique(children.iter(), "superseded children")?;
                    for child in children {
                        identity::validate_digest(child)?;
                    }
                }
                validate_root_replacement(old, new_root, &self.seen_keys, at)?;
                let (authorities, threshold) =
                    recovery_changes(&self.manifest, changes, at, sequence, &self.seen_keys)?;
                if authorities != *new_recovery_authorities || threshold != *new_recovery_threshold
                {
                    return Err(invalid("compromise recovery set transform mismatch"));
                }
                expected.identity_root = new_root.clone();
                history.insert(old.key_id.clone(), revoked_old_root.clone());
                expected.recovery_authorities = authorities;
                expected.recovery_threshold = threshold;
                expected.independent_compromise_recovery =
                    configured_recovery(&expected.recovery_authorities, threshold)?;
                replace_bindings(
                    &mut expected.current_bindings,
                    revoked_root_key_id,
                    &new_root.key_id,
                    binding_replacements,
                )?;
            }
            LifecycleEvent::ResolveFork {
                base_manifest_digest,
                selected_child_digest,
                rejected_child_digests,
                selected_state_digest,
            } => {
                let selected=selected.ok_or_else(||invalid("fork resolution requires the complete independently verified selected child"))?;
                if base_manifest_digest != &self.digest
                    || selected_child_digest != &selected.digest
                    || selected_state_digest != &selected.manifest.state_digest()?
                    || rejected_child_digests.is_empty()
                    || rejected_child_digests.contains(selected_child_digest)
                {
                    return Err(invalid(
                        "fork resolution base, selected state, or rejected-child set mismatch",
                    ));
                }
                ordered_unique(rejected_child_digests.iter(), "rejected child digests")?;
                for child in rejected_child_digests {
                    identity::validate_digest(child)?;
                }
                expected = selected.manifest.clone();
                history = selected.historical_roots.clone();
            }
            LifecycleEvent::StrengthenRevocation {
                target_collection,
                key_id,
                prior_key_record_digest,
                strengthened_key_record,
                prior_semantics,
                new_semantics,
            } => {
                if *prior_semantics != RevocationSemantics::DenyAtOrAfter
                    || *new_semantics != RevocationSemantics::DenyAll
                {
                    return Err(invalid(
                        "revocation can only strengthen deny_at_or_after to deny_all",
                    ));
                }
                match target_collection {
                    TargetCollection::Operational => {
                        let key = operational_mut(&mut expected, key_id, prior_key_record_digest)?;
                        strengthen_record(key, strengthened_key_record)?;
                    }
                    TargetCollection::HistoricalRoot => {
                        let key = history
                            .get_mut(key_id)
                            .ok_or_else(|| invalid("historical root missing"))?;
                        require_hash("JACS-KEY-RECORD-DIGEST-V1", key, prior_key_record_digest)?;
                        strengthen_record(key, strengthened_key_record)?;
                    }
                    TargetCollection::Recovery => {
                        let key = expected
                            .recovery_authorities
                            .iter_mut()
                            .find(|key| &key.key_id == key_id)
                            .ok_or_else(|| invalid("recovery key missing"))?;
                        require_hash("JACS-KEY-RECORD-DIGEST-V1", key, prior_key_record_digest)?;
                        let mut next = key.clone();
                        strengthen_revocation(&mut next.revocation)?;
                        if value(&next)? != *strengthened_key_record {
                            return Err(invalid(
                                "strengthened recovery record changed unrelated fields",
                            ));
                        }
                        *key = next;
                    }
                }
            }
        }
        expected.keys.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        expected.current_bindings.sort_by_key(binding_order);
        if expected.state_value() != candidate.state_value() {
            return Err(invalid(
                "lifecycle event does not explain the complete resulting state",
            ));
        }
        let mut result = self.clone();
        result.historical_roots = history;
        for key in std::iter::once(&candidate.identity_root).chain(&candidate.keys) {
            result.seen_keys.insert(key.key_id.clone());
            remember_bindings(key, &mut result.binding_history)?;
        }
        for key in &candidate.recovery_authorities {
            result.seen_keys.insert(key.key_id.clone());
        }
        result.digest = candidate.digest()?;
        result
            .evaluation_times
            .insert(result.digest.clone(), at.clone());
        result.manifest = candidate;
        Ok(result)
    }
}

fn remember_bindings(
    key: &KeyRecord,
    history: &mut BTreeMap<String, String>,
) -> Result<(), CoreError> {
    for binding in &key.legacy_bindings {
        if history
            .get(&binding.jacs_version)
            .is_some_and(|id| id != &key.key_id)
        {
            return Err(invalid(
                "legacy identity/version cannot be reassigned across key history",
            ));
        }
        history.insert(binding.jacs_version.clone(), key.key_id.clone());
    }
    Ok(())
}

fn validate_root_replacement(
    old: &KeyRecord,
    new: &KeyRecord,
    seen: &BTreeSet<String>,
    at: &JacsTime,
) -> Result<(), CoreError> {
    fresh_key(new, seen, at)?;
    if !new.purposes.contains(&KeyPurpose::IdentityRoot)
        || new
            .purposes
            .iter()
            .any(|purpose| !old.purposes.contains(purpose))
    {
        return Err(invalid("root replacement cannot expand authority"));
    }
    Ok(())
}

fn require_status_mode(
    previous: &IdentityManifest,
    next: &IdentityManifest,
    mode: &StatusTransitionMode,
) -> Result<(), CoreError> {
    if (status_key(previous) == status_key(next)) != (*mode == StatusTransitionMode::NotApplicable)
    {
        return Err(invalid(
            "status transition mode does not match status selection change",
        ));
    }
    Ok(())
}

fn strengthen_revocation(revocation: &mut Option<Revocation>) -> Result<(), CoreError> {
    let revoked = revocation
        .as_mut()
        .ok_or_else(|| invalid("revocation record missing"))?;
    if revoked.semantics != RevocationSemantics::DenyAtOrAfter {
        return Err(invalid("only cutoff revocation may be strengthened"));
    }
    revoked.semantics = RevocationSemantics::DenyAll;
    revoked.cutoff = None;
    revoked.cutoff_evidence = None;
    Ok(())
}

fn strengthen_record(key: &mut KeyRecord, expected: &Value) -> Result<(), CoreError> {
    let mut next = key.clone();
    strengthen_revocation(&mut next.revocation)?;
    if value(&next)? != *expected {
        return Err(invalid("strengthened key record changed unrelated fields"));
    }
    *key = next;
    Ok(())
}

fn require_hash<T: Serialize>(label: &str, record: &T, expected: &str) -> Result<(), CoreError> {
    identity::validate_digest(expected)?;
    if hash(label, record)? != expected {
        return Err(invalid("prior record digest mismatch"));
    }
    Ok(())
}

fn retired_record(
    key: &KeyRecord,
    at: &JacsTime,
    reason: &ReasonCategory,
    sequence: u64,
) -> Result<KeyRecord, CoreError> {
    if key.status != KeyStatus::Active
        || !matches!(
            reason,
            ReasonCategory::AdministrativeWithdrawal | ReasonCategory::Superseded
        )
    {
        return Err(invalid("invalid retirement transition"));
    }
    let mut result = key.clone();
    result.status = KeyStatus::Retired;
    result.retirement = Some(Some(Retirement {
        declared_at: at.clone(),
        reason_category: reason.clone(),
        lifecycle_sequence: sequence,
    }));
    Ok(result)
}

fn revoked_record(
    key: &KeyRecord,
    reason: &ReasonCategory,
    semantics: &RevocationSemantics,
    cutoff: &Option<JacsTime>,
    evidence: &Option<String>,
    sequence: u64,
) -> Result<KeyRecord, CoreError> {
    if key.status == KeyStatus::Revoked {
        return Err(invalid(
            "revoked keys cannot be revoked again or reactivated",
        ));
    }
    validate_revocation(reason, semantics, cutoff, evidence)?;
    let mut result = key.clone();
    result.status = KeyStatus::Revoked;
    result.retirement = Some(key.retirement.clone().flatten());
    result.revocation = Some(Revocation {
        reason_category: reason.clone(),
        semantics: semantics.clone(),
        cutoff: cutoff.clone(),
        cutoff_evidence: evidence.clone(),
        lifecycle_sequence: sequence,
    });
    Ok(result)
}

fn remove_bindings(
    bindings: &mut Vec<CurrentBinding>,
    key_id: &str,
    purposes: Option<&[KeyPurpose]>,
    removed: &[CurrentBinding],
) -> Result<(), CoreError> {
    let affected: Vec<_> = bindings
        .iter()
        .filter(|binding| {
            binding.canonical_key_id == key_id
                && purposes.is_none_or(|purposes| purposes.contains(&binding.purpose))
        })
        .cloned()
        .collect();
    if affected != removed {
        return Err(invalid(
            "removedCurrentBindings must name every and only affected binding",
        ));
    }
    bindings.retain(|binding| !affected.contains(binding));
    Ok(())
}

fn replace_bindings(
    bindings: &mut Vec<CurrentBinding>,
    old: &str,
    new: &str,
    replacements: &[BindingReplacement],
) -> Result<(), CoreError> {
    ordered_unique(
        replacements.iter().map(|replacement| {
            (
                binding_order(&replacement.old),
                binding_order(&replacement.new),
            )
        }),
        "binding replacements",
    )?;
    let affected: Vec<_> = bindings
        .iter()
        .filter(|binding| binding.canonical_key_id == old)
        .cloned()
        .collect();
    if affected
        != replacements
            .iter()
            .map(|replacement| replacement.old.clone())
            .collect::<Vec<_>>()
    {
        return Err(invalid(
            "binding replacements must include exactly all old-key selections",
        ));
    }
    for replacement in replacements {
        if replacement.new.canonical_key_id != new
            || replacement.old.operation != replacement.new.operation
            || replacement.old.purpose != replacement.new.purpose
            || replacement.old.signature_profile != replacement.new.signature_profile
        {
            return Err(invalid(
                "key replacement cannot change operation, purpose, or profile",
            ));
        }
    }
    bindings.retain(|binding| binding.canonical_key_id != old);
    bindings.extend(
        replacements
            .iter()
            .map(|replacement| replacement.new.clone()),
    );
    bindings.sort_by_key(binding_order);
    Ok(())
}

fn operational_mut<'a>(
    manifest: &'a mut IdentityManifest,
    id: &str,
    digest: &str,
) -> Result<&'a mut KeyRecord, CoreError> {
    let key = manifest
        .keys
        .iter_mut()
        .find(|key| key.key_id == id)
        .ok_or_else(|| invalid("operational key not present in prior state"))?;
    require_hash("JACS-KEY-RECORD-DIGEST-V1", key, digest)?;
    Ok(key)
}

fn fresh_key(key: &KeyRecord, seen: &BTreeSet<String>, at: &JacsTime) -> Result<(), CoreError> {
    if seen.contains(&key.key_id) || !key.eligible_at(at) {
        return Err(invalid(
            "new key must be never before seen, active, and time-valid",
        ));
    }
    Ok(())
}

fn recovery_changes(
    previous: &IdentityManifest,
    changes: &[RecoveryChange],
    at: &JacsTime,
    sequence: u64,
    seen: &BTreeSet<String>,
) -> Result<(Vec<RecoveryAuthority>, Option<u64>), CoreError> {
    let mut authorities = previous.recovery_authorities.clone();
    let mut threshold = previous.recovery_threshold;
    let mut targets = BTreeSet::new();
    let mut order = Vec::new();
    for change in changes {
        let encoded = value(change)?;
        let key = match change {
            RecoveryChange::AddAuthority { authority } => authority.key_id.as_str(),
            RecoveryChange::RetireAuthority { key_id, .. }
            | RecoveryChange::RevokeAuthority { key_id, .. }
            | RecoveryChange::SetAuthorityWeight { key_id, .. } => key_id,
            RecoveryChange::SetRecoveryThreshold { .. } => "",
        };
        if !targets.insert(key.to_string()) {
            return Err(invalid("duplicate recovery-change target"));
        }
        order.push((
            encoded["type"].as_str().unwrap_or_default().to_string(),
            key.to_string(),
            crate::canonical::canonicalize_json_try(&encoded["body"])?,
        ));
        match change {
            RecoveryChange::AddAuthority { authority } => {
                if seen.contains(&authority.key_id)
                    || authority.status != KeyStatus::Active
                    || &authority.not_before > at
                    || authority.not_after.as_ref().is_some_and(|end| at >= end)
                {
                    return Err(invalid("new recovery authority is reused or ineligible"));
                }
                authorities.push(authority.clone());
            }
            RecoveryChange::RetireAuthority {
                key_id,
                retired_at,
                reason_category,
            } => {
                let authority = authorities
                    .iter_mut()
                    .find(|authority| &authority.key_id == key_id)
                    .ok_or_else(|| invalid("recovery authority missing"))?;
                if authority.status != KeyStatus::Active
                    || !matches!(
                        reason_category,
                        ReasonCategory::AdministrativeWithdrawal | ReasonCategory::Superseded
                    )
                {
                    return Err(invalid("invalid recovery-authority retirement"));
                }
                authority.status = KeyStatus::Retired;
                authority.retirement = Some(Some(Retirement {
                    declared_at: retired_at.clone(),
                    reason_category: reason_category.clone(),
                    lifecycle_sequence: sequence,
                }));
            }
            RecoveryChange::RevokeAuthority {
                key_id,
                reason_category,
                semantics,
                cutoff,
                cutoff_evidence,
            } => {
                let authority = authorities
                    .iter_mut()
                    .find(|authority| &authority.key_id == key_id)
                    .ok_or_else(|| invalid("recovery authority missing"))?;
                if authority.status == KeyStatus::Revoked {
                    return Err(invalid("recovery authority revocation is terminal"));
                }
                validate_revocation(reason_category, semantics, cutoff, cutoff_evidence)?;
                authority.status = KeyStatus::Revoked;
                authority.retirement = Some(authority.retirement.clone().flatten());
                authority.revocation = Some(Revocation {
                    reason_category: reason_category.clone(),
                    semantics: semantics.clone(),
                    cutoff: cutoff.clone(),
                    cutoff_evidence: cutoff_evidence.clone(),
                    lifecycle_sequence: sequence,
                });
            }
            RecoveryChange::SetAuthorityWeight {
                key_id,
                old_weight,
                new_weight,
            } => {
                let authority = authorities
                    .iter_mut()
                    .find(|authority| &authority.key_id == key_id)
                    .ok_or_else(|| invalid("recovery authority missing"))?;
                if authority.threshold_weight != *old_weight
                    || old_weight == new_weight
                    || *new_weight == 0
                    || authority.status != KeyStatus::Active
                {
                    return Err(invalid("invalid recovery weight change"));
                }
                authority.threshold_weight = *new_weight;
            }
            RecoveryChange::SetRecoveryThreshold {
                old_threshold,
                new_threshold,
            } => {
                if &threshold != old_threshold || old_threshold == new_threshold {
                    return Err(invalid("invalid recovery threshold change"));
                }
                threshold = *new_threshold;
            }
        }
    }
    ordered_unique(order, "recovery changes")?;
    authorities.sort_by(|left, right| left.key_id.cmp(&right.key_id));
    configured_recovery(&authorities, threshold)?;
    Ok((authorities, threshold))
}

fn status_key(manifest: &IdentityManifest) -> Option<&str> {
    manifest
        .current_bindings
        .iter()
        .find(|binding| {
            binding.operation == SigningOperation::PublishStatusCheckpoint
                && binding.signature_profile == "jacs-status-checkpoint-v1"
        })
        .map(|binding| binding.canonical_key_id.as_str())
}

fn requires_recovery(event: &LifecycleEvent) -> bool {
    matches!(
        event,
        LifecycleEvent::ChangeRecoveryAuthorities { .. }
            | LifecycleEvent::ResolveFork { .. }
            | LifecycleEvent::CompromiseRecovery { .. }
            | LifecycleEvent::StrengthenRevocation {
                target_collection: TargetCollection::Recovery,
                ..
            }
    )
}

fn verify_authorization(
    previous: Option<&IdentityManifest>,
    candidate: &IdentityManifest,
    at: &JacsTime,
    policy: &LifecyclePolicy,
) -> Result<(), CoreError> {
    let prior = previous.unwrap_or(candidate);
    let mut records: BTreeMap<String, (String, Vec<u8>, bool)> = BTreeMap::new();
    for key in std::iter::once(&prior.identity_root).chain(&prior.keys) {
        records.insert(
            key.key_id.clone(),
            (
                key.algorithm.clone(),
                key.public_key_bytes()?,
                key.eligible_at(at),
            ),
        );
    }
    for key in &prior.recovery_authorities {
        records.insert(
            key.key_id.clone(),
            (
                key.algorithm.clone(),
                identity::decode_binary(&key.public_key)?,
                key.status == KeyStatus::Active
                    && &key.not_before <= at
                    && key.not_after.as_ref().is_none_or(|end| at < end),
            ),
        );
    }
    let new_key = match &candidate.event {
        LifecycleEvent::RotateRoot { new_root, .. }
        | LifecycleEvent::CompromiseRecovery { new_root, .. } => Some(new_root),
        LifecycleEvent::AuthorizeOperationalKey { key, .. } => Some(key),
        LifecycleEvent::RotateOperationalKey { new_key, .. } => Some(new_key),
        _ => None,
    };
    if let Some(key) = new_key {
        records.insert(
            key.key_id.clone(),
            (
                key.algorithm.clone(),
                key.public_key_bytes()?,
                key.eligible_at(at),
            ),
        );
    }
    let input = candidate.signature_input()?;
    let mut signers = BTreeSet::new();
    for signature in &candidate.signatures {
        let (algorithm, bytes, eligible) = records
            .get(&signature.key_id)
            .ok_or_else(|| invalid("unrecognized lifecycle signer"))?;
        if !eligible || algorithm != &signature.algorithm {
            return Err(invalid(
                "lifecycle signer is inactive, expired, or has wrong algorithm",
            ));
        }
        identity::verify_signature(
            algorithm,
            bytes,
            &input,
            &identity::decode_binary(&signature.value)?,
        )?;
        if !signers.insert(signature.key_id.as_str()) {
            return Err(invalid("duplicate lifecycle signer"));
        }
    }
    if !matches!(candidate.event, LifecycleEvent::CompromiseRecovery { .. })
        && !signers.contains(prior.identity_root.key_id.as_str())
    {
        return Err(invalid("current identity-root authorization required"));
    }
    if let LifecycleEvent::RotateRoot { new_root, .. }
    | LifecycleEvent::CompromiseRecovery { new_root, .. } = &candidate.event
        && !signers.contains(new_root.key_id.as_str())
    {
        return Err(invalid("proposed identity-root authorization required"));
    }
    if requires_recovery(&candidate.event) {
        let threshold = prior
            .recovery_threshold
            .ok_or_else(|| invalid("no configured independent recovery authority"))?;
        let mut weight = 0_u64;
        for authority in &prior.recovery_authorities {
            if signers.contains(authority.key_id.as_str()) {
                weight = weight
                    .checked_add(authority.threshold_weight)
                    .ok_or_else(|| invalid("recovery signature weight overflow"))?;
            }
        }
        if weight < threshold {
            return Err(invalid("live recovery signature threshold not met"));
        }
    }
    if policy.require_portable_status
        && previous.is_some()
        && status_key(prior) != status_key(candidate)
    {
        let new = status_key(candidate)
            .ok_or_else(|| invalid("portable status selection cannot disappear"))?;
        if !signers.contains(new) {
            return Err(invalid(
                "proposed status key must acknowledge lifecycle event",
            ));
        }
        let mode = match &candidate.event {
            LifecycleEvent::UpdateCurrentBindings {
                status_transition_mode,
                ..
            }
            | LifecycleEvent::RotateOperationalKey {
                status_transition_mode,
                ..
            } => Some(status_transition_mode),
            LifecycleEvent::AuthorizeOperationalKey {
                status_bootstrap_mode: StatusBootstrapMode::RootBootstrap,
                ..
            } if status_key(prior).is_none() => None,
            _ => {
                return Err(invalid(
                    "status selection change requires explicit status transition mode",
                ));
            }
        };
        match mode {
            Some(StatusTransitionMode::Normal)
                if status_key(prior).is_some_and(|old| signers.contains(old)) => {}
            Some(StatusTransitionMode::RootEmergency) | None => {}
            _ => {
                return Err(invalid(
                    "normal status transition requires both old and new status-key acknowledgments",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DetachedSigner, Ed25519DalekSigner};
    const ID: &str = "550e8400-e29b-41d4-a716-446655440000";
    const VERSION: &str = "550e8400-e29b-41d4-a716-446655440001";
    fn time(second: u8) -> JacsTime {
        JacsTime::parse(&format!("2026-09-04T00:00:{second:02}Z")).unwrap()
    }
    fn key(signer: &dyn DetachedSigner, purpose: KeyPurpose) -> KeyRecord {
        KeyRecord {
            key_id: identity::canonical_key_id("ed25519", signer.public_key()).unwrap(),
            algorithm: "ed25519".into(),
            public_key: identity::encode_binary(signer.public_key()),
            purposes: vec![purpose],
            legacy_bindings: vec![],
            status: KeyStatus::Active,
            not_before: time(0),
            not_after: None,
            retirement: None,
            revocation: None,
        }
    }
    fn sign(manifest: &mut IdentityManifest, signers: &[&dyn DetachedSigner]) {
        manifest.signatures = signers
            .iter()
            .map(|signer| LifecycleSignature {
                key_id: identity::canonical_key_id("ed25519", signer.public_key()).unwrap(),
                algorithm: "ed25519".into(),
                value: String::new(),
            })
            .collect();
        manifest
            .signatures
            .sort_by(|left, right| left.key_id.cmp(&right.key_id));
        let bytes = manifest.signature_input().unwrap();
        for signature in &mut manifest.signatures {
            let signer = signers
                .iter()
                .find(|signer| {
                    identity::canonical_key_id("ed25519", signer.public_key()).unwrap()
                        == signature.key_id
                })
                .unwrap();
            signature.value = identity::encode_binary(&signer.sign(&bytes).unwrap());
        }
    }
    fn fixture() -> (
        IdentityManifest,
        IdentityAnchor,
        LifecyclePolicy,
        Ed25519DalekSigner,
        Ed25519DalekSigner,
    ) {
        let root = crate::ed25519_signer_for_tests();
        let operational = crate::ed25519_signer_for_tests();
        let recovery = crate::ed25519_signer_for_tests();
        let mut document = key(&operational, KeyPurpose::Document);
        document.legacy_bindings.push(LegacyBinding {
            jacs_version: VERSION.into(),
            signer_lookup_id: format!("{ID}:{VERSION}"),
            legacy_hash_profile: "jacs-core-raw-public-key-hash-v1".into(),
            legacy_public_key_material: None,
            public_key_hash: crate::verify::sha256_hex(operational.public_key()),
        });
        let mut manifest = IdentityManifest {
            profile: "jacs-identity-v1".into(),
            identity: ID.into(),
            sequence: 0,
            previous_manifest: None,
            identity_root: key(&root, KeyPurpose::IdentityRoot),
            independent_compromise_recovery: true,
            recovery_authorities: vec![RecoveryAuthority {
                key_id: identity::canonical_key_id("ed25519", recovery.public_key()).unwrap(),
                algorithm: "ed25519".into(),
                public_key: identity::encode_binary(recovery.public_key()),
                status: KeyStatus::Active,
                not_before: time(0),
                not_after: None,
                threshold_weight: 1,
                retirement: None,
                revocation: None,
            }],
            recovery_threshold: Some(1),
            current_bindings: vec![CurrentBinding {
                operation: SigningOperation::SignDocument,
                purpose: KeyPurpose::Document,
                signature_profile: "jacs-document-v2".into(),
                canonical_key_id: document.key_id.clone(),
                jacs_version: Some(VERSION.into()),
                signer_lookup_id: Some(format!("{ID}:{VERSION}")),
            }],
            keys: vec![document],
            issued_at: time(0),
            event: LifecycleEvent::Genesis {},
            signatures: vec![],
        };
        sign(&mut manifest, &[&root]);
        let anchor = IdentityAnchor::Portable {
            jacs_id: ID.into(),
            genesis_manifest_digest: manifest.digest().unwrap(),
            genesis_root_canonical_key_id: manifest.identity_root.key_id.clone(),
        };
        let policy = LifecyclePolicy {
            profile_mode: IdentityProfileMode::Separated,
            require_portable_status: false,
            allowed_bindings: vec![(
                SigningOperation::SignDocument,
                "jacs-document-v2".into(),
                KeyPurpose::Document,
            )],
        };
        (manifest, anchor, policy, root, recovery)
    }
    fn next(state: &StructuralLifecycleState, event: LifecycleEvent) -> IdentityManifest {
        let mut manifest = state.manifest().clone();
        manifest.sequence += 1;
        manifest.previous_manifest = Some(state.digest().into());
        manifest.event = event;
        manifest.issued_at = time(1);
        manifest.signatures.clear();
        manifest
    }
    #[test]
    fn genesis_binds_independent_anchor_and_exact_operation_key() {
        let (manifest, anchor, policy, _, _) = fixture();
        let raw = serde_json::to_string(&manifest).unwrap();
        let parsed = IdentityManifest::parse(&raw).unwrap();
        assert_eq!(parsed, manifest);
        let state = StructuralLifecycleState::genesis(parsed, &anchor, &time(0), &policy).unwrap();
        let selected = state
            .resolve_current(
                &SigningOperation::SignDocument,
                "jacs-document-v2",
                &KeyPurpose::Document,
                &time(1),
            )
            .unwrap();
        assert_eq!(selected.key_id, state.manifest().keys[0].key_id);
        assert!(
            state
                .resolve_current(
                    &SigningOperation::SignDocument,
                    "jacs-document-v2",
                    &KeyPurpose::Response,
                    &time(1)
                )
                .is_err()
        );
        assert!(state.recovery_threshold_currently_satisfiable(&time(1)));
        let wrong = IdentityAnchor::Portable {
            jacs_id: ID.into(),
            genesis_manifest_digest: identity::digest_bytes("fixture", b"unrelated"),
            genesis_root_canonical_key_id: state.manifest().identity_root.key_id.clone(),
        };
        assert!(StructuralLifecycleState::genesis(manifest, &wrong, &time(0), &policy).is_err());
    }
    #[test]
    fn ordinary_root_rotation_requires_both_roots_and_retains_genesis_anchor() {
        let (manifest, anchor, policy, root, _) = fixture();
        let state =
            StructuralLifecycleState::genesis(manifest, &anchor, &time(0), &policy).unwrap();
        let new_signer = crate::ed25519_signer_for_tests();
        let new_root = key(&new_signer, KeyPurpose::IdentityRoot);
        let old = &state.manifest().identity_root;
        let mut candidate = next(
            &state,
            LifecycleEvent::RotateRoot {
                old_root_key_id: old.key_id.clone(),
                old_root_key_record_digest: old.digest().unwrap(),
                retired_old_root: retired_record(old, &time(1), &ReasonCategory::Superseded, 1)
                    .unwrap(),
                new_root: new_root.clone(),
                retired_at: time(1),
                reason_category: ReasonCategory::Superseded,
                binding_replacements: vec![],
            },
        );
        candidate.identity_root = new_root;
        sign(&mut candidate, &[&root]);
        assert!(state.advance(candidate.clone(), &time(1), &policy).is_err());
        sign(&mut candidate, &[&root, &new_signer]);
        let advanced = state.advance(candidate.clone(), &time(1), &policy).unwrap();
        assert_eq!(advanced.anchor(), &anchor);
        assert_eq!(advanced.manifest().sequence, 1);
        assert_eq!(
            advanced
                .advance(candidate, &time(2), &policy)
                .unwrap()
                .evaluation_time(advanced.digest()),
            Some(&time(1))
        );
        assert!(
            advanced
                .advance(state.manifest().clone(), &time(2), &policy)
                .is_err()
        );
    }
    #[test]
    fn revocation_removes_exact_bindings_and_never_restores_live_use() {
        let (manifest, anchor, policy, root, _) = fixture();
        let state =
            StructuralLifecycleState::genesis(manifest, &anchor, &time(0), &policy).unwrap();
        let old = &state.manifest().keys[0];
        let mut candidate = next(
            &state,
            LifecycleEvent::RevokeOperationalKey {
                key_id: old.key_id.clone(),
                prior_key_record_digest: old.digest().unwrap(),
                reason_category: ReasonCategory::ConfirmedCompromise,
                semantics: RevocationSemantics::DenyAll,
                removed_current_bindings: state.manifest().current_bindings.clone(),
                cutoff: None,
                cutoff_evidence: None,
            },
        );
        candidate.keys[0] = revoked_record(
            old,
            &ReasonCategory::ConfirmedCompromise,
            &RevocationSemantics::DenyAll,
            &None,
            &None,
            1,
        )
        .unwrap();
        candidate.current_bindings.clear();
        sign(&mut candidate, &[&root]);
        let revoked = state.advance(candidate, &time(1), &policy).unwrap();
        assert!(
            revoked
                .resolve_current(
                    &SigningOperation::SignDocument,
                    "jacs-document-v2",
                    &KeyPurpose::Document,
                    &time(2)
                )
                .is_err()
        );
        let mut reused = next(
            &revoked,
            LifecycleEvent::AuthorizeOperationalKey {
                key: old.clone(),
                status_bootstrap_mode: StatusBootstrapMode::NotApplicable,
                new_current_binding: None,
            },
        );
        reused.keys.push(old.clone());
        reused
            .keys
            .sort_by(|left, right| left.key_id.cmp(&right.key_id));
        sign(&mut reused, &[&root]);
        assert!(revoked.advance(reused, &time(2), &policy).is_err());
    }
    #[test]
    fn compromise_recovery_requires_prior_threshold_and_new_root() {
        let (manifest, anchor, policy, _, recovery) = fixture();
        let state =
            StructuralLifecycleState::genesis(manifest, &anchor, &time(0), &policy).unwrap();
        let new_signer = crate::ed25519_signer_for_tests();
        let new_root = key(&new_signer, KeyPurpose::IdentityRoot);
        let old = &state.manifest().identity_root;
        let mut candidate = next(
            &state,
            LifecycleEvent::CompromiseRecovery {
                base_manifest_digest: state.digest().into(),
                revoked_root_key_id: old.key_id.clone(),
                revoked_root_key_record_digest: old.digest().unwrap(),
                revoked_old_root: revoked_record(
                    old,
                    &ReasonCategory::ConfirmedCompromise,
                    &RevocationSemantics::DenyAll,
                    &None,
                    &None,
                    1,
                )
                .unwrap(),
                reason_category: ReasonCategory::ConfirmedCompromise,
                revocation_semantics: RevocationSemantics::DenyAll,
                new_root: new_root.clone(),
                new_recovery_authorities: state.manifest().recovery_authorities.clone(),
                new_recovery_threshold: Some(1),
                recovery_changes: vec![],
                binding_replacements: vec![],
                superseded_child_digests: None,
            },
        );
        candidate.identity_root = new_root;
        sign(&mut candidate, &[&new_signer]);
        assert!(state.advance(candidate.clone(), &time(1), &policy).is_err());
        sign(&mut candidate, &[&recovery, &new_signer]);
        let advanced = state.advance(candidate, &time(1), &policy).unwrap();
        assert_eq!(advanced.anchor(), &anchor);
    }
    #[test]
    fn observed_ordinary_forks_fail_independent_of_input_order() {
        let (manifest, anchor, policy, root, _) = fixture();
        let state =
            StructuralLifecycleState::genesis(manifest, &anchor, &time(0), &policy).unwrap();
        let mut children = vec![];
        for _ in 0..2 {
            let signer = crate::ed25519_signer_for_tests();
            let new_key = key(&signer, KeyPurpose::Document);
            let mut candidate = next(
                &state,
                LifecycleEvent::AuthorizeOperationalKey {
                    key: new_key.clone(),
                    status_bootstrap_mode: StatusBootstrapMode::NotApplicable,
                    new_current_binding: None,
                },
            );
            candidate.keys.push(new_key);
            candidate.keys.sort_by(|a, b| a.key_id.cmp(&b.key_id));
            sign(&mut candidate, &[&root]);
            children.push(candidate);
        }
        assert!(
            state
                .advance_candidates(&children, &time(1), &policy)
                .is_err()
        );
        children.reverse();
        assert!(
            state
                .advance_candidates(&children, &time(1), &policy)
                .is_err()
        );
        state
            .advance_candidates(&children[..1], &time(1), &policy)
            .unwrap();
    }
    #[test]
    fn status_checkpoints_bind_current_lifecycle_and_retained_completeness() {
        let (manifest, anchor, policy, _, _) = fixture();
        let state =
            StructuralLifecycleState::genesis(manifest, &anchor, &time(0), &policy).unwrap();
        let authority = crate::identity::StatusAuthority::LocalOwnerStore {
            canonical_store_id: ID.into(),
            owner_id: "posix-uid:501".into(),
            bootstrap_digest: identity::digest_bytes("fixture", b"owner"),
        };
        let checkpoint = StatusCheckpointPayload {
            profile: "jacs-status-checkpoint-v1".into(),
            operation: SigningOperation::PublishStatusCheckpoint,
            purpose: KeyPurpose::Status,
            identity_anchor: anchor,
            status_authority: authority.clone(),
            authority_scope: AuthorityScope::Local,
            status_sequence: 0,
            checkpoint_time: time(1),
            complete_through: time(1),
            lifecycle_sequence: 0,
            lifecycle_record_digest: state.digest().into(),
            current_status_key_id: None,
            revocation_epoch: 0,
            previous_status_checkpoint_digest: None,
        };
        validate_status_checkpoint(&state, None, &checkpoint, &authority, &time(2), 1).unwrap();
        assert!(
            validate_status_checkpoint(&state, None, &checkpoint, &authority, &time(3), 1).is_err()
        );
        let mut refresh = checkpoint.clone();
        refresh.status_sequence = 1;
        refresh.previous_status_checkpoint_digest = Some(checkpoint.digest().unwrap());
        refresh.checkpoint_time = time(2);
        refresh.complete_through = time(2);
        validate_status_checkpoint(&state, Some(&checkpoint), &refresh, &authority, &time(3), 1)
            .unwrap();
        refresh.revocation_epoch = 1;
        assert!(
            validate_status_checkpoint(
                &state,
                Some(&checkpoint),
                &refresh,
                &authority,
                &time(3),
                1
            )
            .is_err()
        );
    }
}
