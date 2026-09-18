//! Generated-code durable recovery, distinct from the short device-transfer code.
//! No I/O. Only encrypted AgentMaterial crosses the platform boundary.
use crate::{AgentMaterial, CoreAgent, CoreError, SigningAlgorithm};
use rand::{TryRng, rngs::SysRng};
use zeroize::Zeroizing;

/// Sixteen independent random bytes, losslessly encoded as 32 hexadecimal digits.
pub const RECOVERY_CODE_ENTROPY_BITS: usize = 128;
const CODE_BYTES: usize = RECOVERY_CODE_ENTROPY_BITS / 8;

/// Code is deliberately not serializable or Debug-printable as plaintext.
pub struct RecoveryExport {
    pub code: Zeroizing<String>,
    pub material: AgentMaterial,
}

impl std::fmt::Debug for RecoveryExport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryExport").finish_non_exhaustive()
    }
}

/// Generate eight groups of four uppercase hexadecimal digits using the OS CSPRNG.
/// This is a generated recovery secret, not a password, seed or transfer code.
pub fn generate_recovery_code() -> Result<Zeroizing<String>, CoreError> {
    let mut bytes = Zeroizing::new([0u8; CODE_BYTES]);
    SysRng
        .try_fill_bytes(bytes.as_mut())
        .map_err(|_| CoreError::EncryptionFailed("secure randomness unavailable".into()))?;
    let mut code = Zeroizing::new(String::with_capacity(39));
    const HEX: &[u8] = b"0123456789ABCDEF";
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 && index % 2 == 0 {
            code.push('-');
        }
        code.push(HEX[usize::from(byte >> 4)] as char);
        code.push(HEX[usize::from(byte & 15)] as char);
    }
    Ok(code)
}

/// Accept pasted codes with ASCII whitespace, optional hyphens and either case.
/// Return the exact grouped spelling used as the envelope secret. Reject short
/// transfer codes and other passwords; never include the supplied code in errors.
pub fn normalize_recovery_code(code: &str) -> Result<Zeroizing<String>, CoreError> {
    let invalid =
        || CoreError::InvalidPasswordFormat("expected 32 hexadecimal recovery digits".into());
    if code.len() > 256 {
        return Err(invalid());
    }
    let mut result = Zeroizing::new(String::with_capacity(39));
    let mut count = 0;
    for byte in code.bytes() {
        if byte == b'-' || byte.is_ascii_whitespace() {
            continue;
        }
        if !byte.is_ascii_hexdigit() || count == CODE_BYTES * 2 {
            return Err(invalid());
        }
        if count > 0 && count % 4 == 0 {
            result.push('-');
        }
        result.push(byte.to_ascii_uppercase() as char);
        count += 1;
    }
    if count != CODE_BYTES * 2 {
        return Err(invalid());
    }
    Ok(result)
}

/// Generate a fresh secret and export using the standard JACS envelope defaults.
/// Does not change the identity or replace any stored backup. The owning host
/// controls session locking, upload/read-back, save acknowledgement and commit.
pub fn export_recovery(agent: &CoreAgent) -> Result<RecoveryExport, CoreError> {
    let code = generate_recovery_code()?;
    let material = agent.export_encrypted_material(&code)?;
    crate::transfer::validate_transfer_material(&material)?;
    Ok(RecoveryExport { code, material })
}

/// Restore only against independently authenticated registration pins. The
/// existing strict pinned import validates the public self-signature, envelope,
/// algorithm and derived private/public-key match before returning a handle.
pub fn import_recovery(
    material: AgentMaterial,
    code: &str,
    expected_agent_id: &str,
    expected_public_key: &[u8],
    expected_algorithm: SigningAlgorithm,
) -> Result<CoreAgent, CoreError> {
    let code = normalize_recovery_code(code)?;
    crate::transfer::import_transferred_agent(
        material,
        &code,
        expected_agent_id,
        expected_public_key,
        expected_algorithm,
    )
}

/// Read-back verification without persistence or an escaping signing handle.
/// Returns only the verified public identity. Consumers also compare its current
/// registered jacsVersion; key/ID pins alone do not establish version freshness.
pub fn verify_recovery(
    material: AgentMaterial,
    code: &str,
    expected_agent_id: &str,
    expected_public_key: &[u8],
    expected_algorithm: SigningAlgorithm,
) -> Result<serde_json::Value, CoreError> {
    let mut agent = import_recovery(
        material,
        code,
        expected_agent_id,
        expected_public_key,
        expected_algorithm,
    )?;
    let identity = agent.export_agent();
    agent.clear_secrets();
    Ok(identity)
}
