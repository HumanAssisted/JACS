use jacs_cli::password_bootstrap::ensure_cli_private_key_password;
use jacs::agent::Agent;
use std::error::Error;

fn resolve_dns_policy_overrides(
    ignore_dns: bool,
    require_strict: bool,
    require_dns: bool,
    non_strict: bool,
) -> (Option<bool>, Option<bool>, Option<bool>) {
    if ignore_dns {
        (Some(false), Some(false), Some(false))
    } else if require_strict {
        (Some(true), Some(true), Some(true))
    } else if require_dns {
        (Some(true), Some(true), Some(false))
    } else if non_strict {
        (Some(true), Some(false), Some(false))
    } else {
        (None, None, None)
    }
}

fn resolve_config_path() -> String {
    std::env::var("JACS_CONFIG")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "./jacs.config.json".to_string())
}

/// Load a JACS agent from the default config path with password from the
/// CLI resolution chain (env var, password file, keychain, prompt).
pub(crate) fn load_agent() -> Result<Agent, jacs::error::JacsError> {
    let mut config = jacs::config::Config::from_file(&resolve_config_path())?;
    config.apply_env_overrides();
    let password = ensure_cli_private_key_password()
        .map_err(|e| jacs::error::JacsError::Internal { message: e })?;
    Agent::from_config(config, password.as_deref())
}

pub(crate) fn load_agent_with_cli_dns_policy(
    ignore_dns: bool,
    require_strict: bool,
    require_dns: bool,
    non_strict: bool,
) -> Result<Agent, Box<dyn Error>> {
    let (dns_validate, dns_required, dns_strict) =
        resolve_dns_policy_overrides(ignore_dns, require_strict, require_dns, non_strict);
    let mut agent = load_agent()?;
    if let Some(v) = dns_validate {
        agent.set_dns_validate(v);
    }
    if let Some(v) = dns_required {
        agent.set_dns_required(v);
    }
    if let Some(v) = dns_strict {
        agent.set_dns_strict(v);
    }
    Ok(agent)
}

#[cfg(test)]
mod tests {
    use super::resolve_dns_policy_overrides;

    #[test]
    fn dns_policy_defaults_to_no_overrides() {
        assert_eq!(
            resolve_dns_policy_overrides(false, false, false, false),
            (None, None, None)
        );
    }

    #[test]
    fn dns_policy_prioritizes_ignore_dns() {
        assert_eq!(
            resolve_dns_policy_overrides(true, true, true, true),
            (Some(false), Some(false), Some(false))
        );
    }

    #[test]
    fn dns_policy_prioritizes_require_strict_over_require_dns() {
        assert_eq!(
            resolve_dns_policy_overrides(false, true, true, true),
            (Some(true), Some(true), Some(true))
        );
    }

    #[test]
    fn dns_policy_sets_expected_non_strict_flags() {
        assert_eq!(
            resolve_dns_policy_overrides(false, false, false, true),
            (Some(true), Some(false), Some(false))
        );
    }
}
