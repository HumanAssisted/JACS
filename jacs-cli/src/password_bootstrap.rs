use std::env;
use std::error::Error;
use std::path::Path;

const PRIVATE_KEY_PASSWORD_ENV: &str = "JACS_PRIVATE_KEY_PASSWORD";
const CLI_PASSWORD_FILE_ENV: &str = "JACS_PASSWORD_FILE";
const DEFAULT_LEGACY_PASSWORD_FILE: &str = "./jacs_keys/.jacs_password";

pub(crate) fn quickstart_password_bootstrap_help() -> &'static str {
    "Password bootstrap options (prefer exactly one explicit source):
  1) Direct env (recommended):
     export JACS_PRIVATE_KEY_PASSWORD='your-strong-password'
  2) Export from a secret file:
     export JACS_PRIVATE_KEY_PASSWORD=\"$(cat /path/to/password)\"
  3) CLI convenience (file path):
     export JACS_PASSWORD_FILE=/path/to/password
If both JACS_PRIVATE_KEY_PASSWORD and JACS_PASSWORD_FILE are set, CLI warns and uses JACS_PRIVATE_KEY_PASSWORD.
If neither is set, CLI will try legacy ./jacs_keys/.jacs_password when present."
}

fn set_private_key_password_env(password: &str) {
    // SAFETY: CLI process is single-threaded for command handling at this point.
    unsafe {
        env::set_var(PRIVATE_KEY_PASSWORD_ENV, password);
    }
}

fn read_password_from_file(path: &Path, source_name: &str) -> Result<String, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let metadata = std::fs::metadata(path)
            .map_err(|e| format!("Failed to read {} '{}': {}", source_name, path.display(), e))?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "{} '{}' has insecure permissions (mode {:04o}). \
                File must not be group-readable or world-readable. \
                Fix with: chmod 600 '{}'\n\n{}",
                source_name,
                path.display(),
                mode,
                path.display(),
                quickstart_password_bootstrap_help()
            ));
        }
    }

    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {} '{}': {}", source_name, path.display(), e))?;
    let password = raw.trim_end_matches(|c| c == '\n' || c == '\r');
    if password.is_empty() {
        return Err(format!(
            "{} '{}' is empty. {}",
            source_name,
            path.display(),
            quickstart_password_bootstrap_help()
        ));
    }
    Ok(password.to_string())
}

fn get_non_empty_env_var(key: &str) -> Result<Option<String>, String> {
    match env::var(key) {
        Ok(value) => {
            if value.trim().is_empty() {
                Err(format!(
                    "{} is set but empty. {}",
                    key,
                    quickstart_password_bootstrap_help()
                ))
            } else {
                Ok(Some(value))
            }
        }
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(format!(
            "{} contains non-UTF-8 data. {}",
            key,
            quickstart_password_bootstrap_help()
        )),
    }
}

/// Resolve the private key password from CLI sources and return it.
///
/// Returns `Ok(Some(password))` when a password is found from env var,
/// password file, or legacy file. Returns `Ok(None)` when no CLI-level
/// password is available (the core layer will try the OS keychain).
///
/// Also sets the `JACS_PRIVATE_KEY_PASSWORD` env var as a side-effect
/// for backward compatibility with code paths that still read it.
pub(crate) fn ensure_cli_private_key_password() -> Result<Option<String>, String> {
    let env_password = get_non_empty_env_var(PRIVATE_KEY_PASSWORD_ENV)?;
    let password_file = get_non_empty_env_var(CLI_PASSWORD_FILE_ENV)?;

    if let Some(password) = env_password {
        if password_file.is_some() {
            eprintln!(
                "Warning: both JACS_PRIVATE_KEY_PASSWORD and {} are set. \
                 Using JACS_PRIVATE_KEY_PASSWORD (highest priority).",
                CLI_PASSWORD_FILE_ENV
            );
        }
        set_private_key_password_env(&password);
        return Ok(Some(password));
    }

    if let Some(path) = password_file {
        let password = read_password_from_file(Path::new(path.trim()), CLI_PASSWORD_FILE_ENV)?;
        set_private_key_password_env(&password);
        return Ok(Some(password));
    }

    let legacy_path = Path::new(DEFAULT_LEGACY_PASSWORD_FILE);
    if legacy_path.exists() {
        let password = read_password_from_file(legacy_path, "legacy password file")?;
        set_private_key_password_env(&password);
        eprintln!(
            "Using legacy password source '{}'. Prefer JACS_PRIVATE_KEY_PASSWORD or {}.",
            legacy_path.display(),
            CLI_PASSWORD_FILE_ENV
        );
        #[cfg(feature = "keychain")]
        {
            if jacs::keystore::keychain::is_available() {
                eprintln!(
                    "Warning: A plaintext password file '{}' was found. \
                     Consider migrating to the OS keychain with `jacs keychain set` \
                     and then deleting the password file.",
                    legacy_path.display()
                );
            }
        }
        return Ok(Some(password));
    }

    Ok(None)
}

pub(crate) fn wrap_quickstart_error_with_password_help(
    context: &str,
    err: impl std::fmt::Display,
) -> Box<dyn Error> {
    Box::new(std::io::Error::other(format!(
        "{}: {}\n\n{}",
        context,
        err,
        quickstart_password_bootstrap_help()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::ffi::OsString;
    use tempfile::tempdir;

    struct EnvGuard {
        saved: Vec<(&'static str, Option<OsString>)>,
    }

    impl EnvGuard {
        fn capture(keys: &[&'static str]) -> Self {
            Self {
                saved: keys
                    .iter()
                    .map(|key| (*key, std::env::var_os(key)))
                    .collect(),
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in self.saved.drain(..) {
                match value {
                    Some(value) => {
                        // SAFETY: These unit tests are marked serial and restore prior process env.
                        unsafe {
                            std::env::set_var(key, value);
                        }
                    }
                    None => {
                        // SAFETY: These unit tests are marked serial and restore prior process env.
                        unsafe {
                            std::env::remove_var(key);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn quickstart_help_mentions_env_precedence_warning() {
        let help = quickstart_password_bootstrap_help();
        assert!(help.contains("prefer exactly one explicit source"));
        assert!(help.contains("CLI warns and uses JACS_PRIVATE_KEY_PASSWORD"));
    }

    #[test]
    #[serial]
    fn ensure_cli_private_key_password_reads_password_file_when_env_absent() {
        let _guard = EnvGuard::capture(&[PRIVATE_KEY_PASSWORD_ENV, CLI_PASSWORD_FILE_ENV]);
        let temp = tempdir().expect("tempdir");
        let password_file = temp.path().join("password.txt");
        std::fs::write(&password_file, "TestP@ss123!#\n").expect("write password file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&password_file, std::fs::Permissions::from_mode(0o600))
                .expect("chmod password file");
        }

        // SAFETY: These unit tests are marked serial and restore prior process env.
        unsafe {
            std::env::remove_var(PRIVATE_KEY_PASSWORD_ENV);
            std::env::set_var(CLI_PASSWORD_FILE_ENV, &password_file);
        }

        let resolved =
            ensure_cli_private_key_password().expect("password bootstrap should succeed");

        assert_eq!(
            resolved.as_deref(),
            Some("TestP@ss123!#"),
            "resolved password should match password file content"
        );
        assert_eq!(
            std::env::var(PRIVATE_KEY_PASSWORD_ENV).expect("env password"),
            "TestP@ss123!#"
        );
    }

    #[test]
    #[serial]
    fn ensure_cli_private_key_password_prefers_env_when_sources_are_ambiguous() {
        let _guard = EnvGuard::capture(&[PRIVATE_KEY_PASSWORD_ENV, CLI_PASSWORD_FILE_ENV]);
        let temp = tempdir().expect("tempdir");
        let password_file = temp.path().join("password.txt");
        std::fs::write(&password_file, "DifferentP@ss456$\n").expect("write password file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&password_file, std::fs::Permissions::from_mode(0o600))
                .expect("chmod password file");
        }

        // SAFETY: These unit tests are marked serial and restore prior process env.
        unsafe {
            std::env::set_var(PRIVATE_KEY_PASSWORD_ENV, "TestP@ss123!#");
            std::env::set_var(CLI_PASSWORD_FILE_ENV, &password_file);
        }

        let resolved =
            ensure_cli_private_key_password().expect("password bootstrap should succeed");

        assert_eq!(
            resolved.as_deref(),
            Some("TestP@ss123!#"),
            "env var should win over password file"
        );
        assert_eq!(
            std::env::var(PRIVATE_KEY_PASSWORD_ENV).expect("env password"),
            "TestP@ss123!#"
        );
    }
}
