//! Atomic encrypted `AgentMaterial` files shared by the CLI and MCP.
//!
//! Callers select paths before granting authority. Files must live in an
//! existing app-private directory. No plaintext private-key format is accepted.
//! Cooperative updates use a permanent lock file and compare the entire old
//! encrypted material before replacement, preventing stale writers.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use jacs_core::agent::CoreAgent;
use jacs_core::material::{AgentMaterial, UnlockSecret};
use jacs_core::sign::SigningAlgorithm;

pub const MAX_MATERIAL_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// Errors deliberately omit paths, secret values and attacker-controlled input.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("encrypted vault I/O failed")]
    Io,
    #[error("vault path must be a regular private file in an app-private directory")]
    UnsafePath,
    #[error("refusing to overwrite an existing vault")]
    AlreadyExists,
    #[error("vault is busy; retry after the current operation completes")]
    Busy,
    #[error("vault changed since it was read; reload before retrying")]
    Conflict,
    #[error("encrypted material is malformed, unsigned, or exceeds the size limit")]
    InvalidMaterial,
    #[error("password must contain 1 through 1024 UTF-8 bytes")]
    InvalidPassword,
    #[error("could not unlock or authenticate the encrypted identity")]
    UnlockFailed,
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("private vault filesystem policy is unavailable on this platform")]
    UnsupportedPlatform,
    #[error(
        "vault replacement completed, but directory durability could not be confirmed; inspect the current vault before retrying"
    )]
    CommittedNotDurable,
}

pub type Result<T> = std::result::Result<T, VaultError>;

fn password_policy(password: &str) -> Result<()> {
    if password.is_empty() || password.len() > MAX_PASSWORD_BYTES {
        return Err(VaultError::InvalidPassword);
    }
    Ok(())
}

/// Validate encrypted representation and authenticate its public identity.
/// This does not establish registry trust; applications must pin the public key.
pub fn validate_material(material: &AgentMaterial) -> Result<()> {
    jacs_core::envelope::validate_encrypted_private_key(&material.encrypted_private_key)
        .map_err(|_| VaultError::InvalidMaterial)?;
    CoreAgent::validate_identity(&material.agent, &material.public_key, material.algorithm)
        .map_err(|_| VaultError::InvalidMaterial)?;
    if !material.config.is_object() {
        return Err(VaultError::InvalidMaterial);
    }
    let encoded = serde_json::to_vec(material).map_err(|_| VaultError::InvalidMaterial)?;
    if encoded.len() > MAX_MATERIAL_BYTES {
        return Err(VaultError::InvalidMaterial);
    }
    Ok(())
}

pub fn parse_material(input: &[u8]) -> Result<AgentMaterial> {
    if input.len() > MAX_MATERIAL_BYTES {
        return Err(VaultError::InvalidMaterial);
    }
    let material = jacs_core::strict_json::deserialize_strict_json_slice(input)
        .map_err(|_| VaultError::InvalidMaterial)?;
    validate_material(&material)?;
    Ok(material)
}

pub fn unlock(material: &AgentMaterial, password: &str) -> Result<CoreAgent> {
    password_policy(password)?;
    validate_material(material)?;
    CoreAgent::from_encrypted_material(material.clone(), UnlockSecret::Password(password))
        .map_err(|_| VaultError::UnlockFailed)
}

pub fn create_material(algorithm: SigningAlgorithm, password: &str) -> Result<AgentMaterial> {
    password_policy(password)?;
    let agent = CoreAgent::ephemeral(algorithm).map_err(|_| VaultError::Crypto)?;
    agent
        .export_encrypted_material(password)
        .map_err(|_| VaultError::Crypto)
}

pub fn reencrypt(
    material: &AgentMaterial,
    old_password: &str,
    new_password: &str,
) -> Result<AgentMaterial> {
    password_policy(new_password)?;
    unlock(material, old_password)?
        .export_encrypted_material(new_password)
        .map_err(|_| VaultError::Crypto)
}

/// Prepare a new key with an old-key-authorized transition proof. The returned
/// material is self-contained; the caller must persist it before using it.
/// Omitted algorithm selects ML-DSA-87. The core rejects PQ downgrades.
pub fn rotate(
    material: &AgentMaterial,
    old_password: &str,
    new_password: &str,
    algorithm: Option<SigningAlgorithm>,
) -> Result<AgentMaterial> {
    password_policy(new_password)?;
    let agent = unlock(material, old_password)?;
    let prepared = agent
        .prepare_key_rotation(algorithm)
        .map_err(|_| VaultError::Crypto)?;
    prepared
        .export_encrypted_material(new_password)
        .map_err(|_| VaultError::Crypto)
}

fn private_metadata(metadata: &fs::Metadata, directory: bool) -> Result<()> {
    if (directory && !metadata.is_dir()) || (!directory && !metadata.is_file()) {
        return Err(VaultError::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no preconditions and returns the process uid.
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid
            || metadata.mode() & 0o077 != 0
            || (!directory && metadata.nlink() != 1)
        {
            return Err(VaultError::UnsafePath);
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        // A normal directory does not prove an owner-only Windows ACL.
        // Fail closed until native ACL inspection/creation is implemented.
        Err(VaultError::UnsupportedPlatform)
    }
}

fn checked_path(path: &Path) -> Result<PathBuf> {
    let file_name = path.file_name().ok_or(VaultError::UnsafePath)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = fs::symlink_metadata(parent).map_err(|_| VaultError::UnsafePath)?;
    if metadata.file_type().is_symlink() {
        return Err(VaultError::UnsafePath);
    }
    private_metadata(&metadata, true)?;
    let parent = fs::canonicalize(parent).map_err(|_| VaultError::UnsafePath)?;
    Ok(parent.join(file_name))
}

fn safe_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Open the reparse point itself; metadata below rejects it.
        options.custom_flags(0x0020_0000);
    }
    options
}

fn open_private(path: &Path) -> Result<File> {
    let file = safe_options()
        .read(true)
        .open(path)
        .map_err(|_| VaultError::Io)?;
    private_metadata(&file.metadata().map_err(|_| VaultError::Io)?, false)?;
    Ok(file)
}

pub fn read_material(path: &Path) -> Result<AgentMaterial> {
    let path = checked_path(path)?;
    let file = open_private(&path)?;
    if file.metadata().map_err(|_| VaultError::Io)?.len() > MAX_MATERIAL_BYTES as u64 {
        return Err(VaultError::InvalidMaterial);
    }
    let mut bytes = Vec::new();
    file.take(MAX_MATERIAL_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| VaultError::Io)?;
    parse_material(&bytes)
}

fn lock(path: &Path) -> Result<File> {
    let mut name = path
        .file_name()
        .ok_or(VaultError::UnsafePath)?
        .to_os_string();
    name.push(".lock");
    let file = safe_options()
        .read(true)
        .write(true)
        .create(true)
        .open(path.with_file_name(name))
        .map_err(|_| VaultError::UnsafePath)?;
    private_metadata(&file.metadata().map_err(|_| VaultError::Io)?, false)?;
    file.try_lock().map_err(|_| VaultError::Busy)?;
    Ok(file)
}

fn persist(path: &Path, material: &AgentMaterial, replace: bool) -> Result<()> {
    validate_material(material)?;
    let bytes = serde_json::to_vec(material).map_err(|_| VaultError::InvalidMaterial)?;
    let parent = path.parent().ok_or(VaultError::UnsafePath)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|_| VaultError::Io)?;
    temporary.write_all(&bytes).map_err(|_| VaultError::Io)?;
    temporary.as_file().sync_all().map_err(|_| VaultError::Io)?;
    if replace {
        temporary.persist(path).map_err(|_| VaultError::Io)?;
    } else {
        temporary.persist_noclobber(path).map_err(|error| {
            if error.error.kind() == std::io::ErrorKind::AlreadyExists {
                VaultError::AlreadyExists
            } else {
                VaultError::Io
            }
        })?;
    }
    #[cfg(unix)]
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| VaultError::CommittedNotDurable)?;
    Ok(())
}

/// Atomic no-clobber creation. Existing identities are never overwritten.
pub fn write_material(path: &Path, material: &AgentMaterial) -> Result<()> {
    let path = checked_path(path)?;
    let _lock = lock(&path)?;
    persist(&path, material, false)
}

/// Atomic replacement only when the complete current material still matches
/// what the caller unlocked. A permanent advisory lock serializes all writers.
pub fn replace_material(
    path: &Path,
    expected: &AgentMaterial,
    replacement: &AgentMaterial,
) -> Result<()> {
    let path = checked_path(path)?;
    let _lock = lock(&path)?;
    if read_material(&path)? != *expected {
        return Err(VaultError::Conflict);
    }
    persist(&path, replacement, true)
}
