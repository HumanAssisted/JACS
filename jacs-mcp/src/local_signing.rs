//! Authority for one explicitly configured local MCP process.
//!
//! This is an operator-selected local agent, not a human-approval service or
//! a remotely delegated capability protocol. The MCP client may sign content
//! through this closed inventory as that agent. It cannot select another key,
//! administer trust, enable network access, or edit arbitrary files.

use anyhow::{Context, bail, ensure};
use jacs::agent::{Agent, boilerplate::BoilerPlate};
use jacs::config::{Config, NetworkCapability, is_network_access_allowed};
use jacs::crypt::KeyManager;
use jacs_binding_core::AgentWrapper;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Limit local tool arguments before parsing/signing embedded documents.
pub(crate) const MAX_ARGUMENT_BYTES: usize = 1024 * 1024;

/// One closed inventory: used for advertisement, dispatch and handler checks.
/// Compile-time tool features still apply. V1 signing, identity/key
/// administration, raw signing and request authentication are not in this scope.
pub(crate) fn allows_tool(tool: &str) -> bool {
    matches!(
        tool,
        "jacs_verify_document"
            | "jacs_sign_document"
            | "jacs_create_agreement_v2"
            | "jacs_apply_agreement_v2"
            | "jacs_sign_agreement_v2"
            | "jacs_verify_agreement_v2"
            | "jacs_detect_agreement_v2_branch_conflict"
            | "jacs_merge_agreement_v2_transcript_branches"
            | "jacs_resolve_agreement_v2_branch_conflict"
    )
}

pub(crate) fn is_file_tool(tool: &str) -> bool {
    matches!(
        tool,
        "jacs_sign_text"
            | "jacs_verify_text"
            | "jacs_sign_image"
            | "jacs_verify_image"
            | "jacs_extract_media_signature"
    )
}

#[derive(Debug, Clone)]
pub(crate) struct LocalSigningScope {
    agent_id: String,
    agent_version: String,
    public_key_hash: String,
    storage_root: PathBuf,
    pub(crate) files: Option<crate::path_policy::LocalFilePolicy>,
}

impl LocalSigningScope {
    pub(crate) fn load(path: &Path) -> anyhow::Result<(AgentWrapper, Self)> {
        require_offline()?;
        let selected = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        // Canonicalize only the parent. Following the final component here
        // would bypass Config::from_file's descriptor-level no-follow read.
        let parent = selected
            .parent()
            .context("Local signing config has no directory")?
            .canonicalize()
            .context("Local signing config directory not found")?;
        let config_path = parent.join(
            selected
                .file_name()
                .context("Local signing config has no filename")?,
        );
        let metadata =
            std::fs::symlink_metadata(&config_path).context("Local signing config not found")?;
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "Local signing config must be a regular file, not a symlink"
        );
        let config_path_str = config_path
            .to_str()
            .context("Local signing config path is not UTF-8")?;
        let config = Config::from_file(config_path_str).context("Read local signing config")?;
        // Explicit local authorization never inherits the unsigned-config
        // compatibility switch or ambient identity/path/storage overrides.
        ensure!(
            config.is_signed,
            "Local signing requires an existing signed JACS config; run jacs init first"
        );
        ensure!(
            config.jacs_default_storage().as_deref() == Some("fs"),
            "Local MCP signing requires filesystem storage in its selected config"
        );
        let public = Agent::from_config_public_only(config.clone())
            .context("Validate local signing identity without private-key use")?;
        let scope = Self {
            agent_id: public.get_id()?,
            agent_version: public.get_version()?,
            public_key_hash: jacs::crypt::hash::hash_public_key(&public.get_public_key()?),
            storage_root: config_path
                .parent()
                .context("Local signing config has no directory")?
                .to_path_buf(),
            files: crate::path_policy::LocalFilePolicy::capture(&config_path, &config)?,
        };
        scope.validate_document_directory()?;

        // The public-only pass rejects pending key-rotation recovery. Loading
        // this exact parsed config now retains the existing encrypted disk key;
        // no config reload, ephemeral key or unsigned bootstrap is allowed.
        let password = public
            .resolve_password()
            .context("Resolve local signer password")?;
        let mut agent = Agent::from_config(config, Some(&password))
            .context("Unlock configured local signer")?;
        // Core accepts absolute key/data paths. Generated documents are always
        // stored below this explicit config directory, even when key material
        // lives elsewhere and the generic loader would choose `/` as its root.
        agent.set_storage_root(scope.storage_root.clone())?;
        scope.validate_agent(&agent)?;
        // Loading a public identity and an encrypted private file separately
        // is not proof they form a pair. Check privately before exposing tools:
        // no document is persisted and this signature is never returned.
        let check = format!(
            "jacs-mcp/local-sign/key-check/v1:{}:{}",
            scope.public_key_hash,
            uuid::Uuid::new_v4()
        );
        let signature = agent
            .sign_string(&check)
            .context("Check local signing key")?;
        let algorithm = agent
            .get_key_algorithm()
            .context("Local signer has no algorithm")?;
        jacs::crypt::verify_string_with_algorithm(
            agent.get_public_key()?,
            &check,
            &signature,
            algorithm,
        )
        .context("Local signing private key does not match the configured public identity")?;
        let wrapper = AgentWrapper::from_inner(Arc::new(Mutex::new(agent)));
        wrapper.set_private_key_password(Some(password))?;
        tracing::info!(
            event = "mcp_local_signing_authorized",
            agent_id = %scope.agent_id,
            public_key_hash = %scope.public_key_hash,
            documents_directory = %scope.storage_root.join("documents").display(),
            "Local agent JSON/Agreement signing enabled; not per-action human approval"
        );
        Ok((wrapper, scope))
    }

    pub(crate) fn authorize(&self, tool: &str, agent: &Agent) -> anyhow::Result<()> {
        ensure!(
            self.allows_tool(tool),
            "Tool is outside the selected local signing scope; file tools require JACS_MCP_BASE_DIR at startup"
        );
        // Embedders must not expand the offline scope by changing ambient
        // network flags after construction. CLI environments are immutable.
        require_offline()?;
        if let Some(files) = &self.files {
            files.validate_environment()?;
        }
        self.validate_agent(agent)?;
        self.validate_document_directory()
    }

    pub(crate) fn allows_tool(&self, tool: &str) -> bool {
        allows_tool(tool) || (self.files.is_some() && is_file_tool(tool))
    }

    fn validate_agent(&self, agent: &Agent) -> anyhow::Result<()> {
        ensure!(
            agent.get_id()? == self.agent_id
                && agent.get_version()? == self.agent_version
                && jacs::crypt::hash::hash_public_key(&agent.get_public_key()?)
                    == self.public_key_hash,
            "Local signer identity changed after authorization"
        );
        ensure!(
            agent.storage_ref().root() == Some(self.storage_root.as_path()),
            "Local document storage changed after authorization"
        );
        ensure!(
            agent.ready() && !agent.is_ephemeral(),
            "Local signer is not a loaded persistent identity"
        );
        Ok(())
    }

    fn validate_document_directory(&self) -> anyhow::Result<()> {
        let directory = self.storage_root.join("documents");
        match std::fs::symlink_metadata(&directory) {
            Ok(metadata) => ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "Local document directory must be a real directory, not a file or symlink"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("Inspect local document directory"),
        }
        Ok(())
    }
}

fn require_offline() -> anyhow::Result<()> {
    for capability in [
        NetworkCapability::DnsLookup,
        NetworkCapability::RemoteKeyFetch,
        NetworkCapability::RegistryLookup,
        NetworkCapability::RemoteSchemaFetch,
        NetworkCapability::JwksFetch,
        NetworkCapability::AgentCardFetch,
    ] {
        if is_network_access_allowed(capability) {
            bail!(
                "Local MCP signing is offline; unset JACS_ALLOW_NETWORK and {} before starting",
                capability.env_var()
            );
        }
    }
    Ok(())
}
