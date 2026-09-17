//! A2A CLI serving helpers.
//!
//! The URL inside an Agent Card is signed, and the trust verifier uses its
//! origin to resolve the sibling JWKS and compatibility-binding documents.
//! These helpers keep that signed origin aligned with the endpoint operators
//! actually publish.

use jacs::a2a::AgentCard;
use jacs::agent::Agent;
use jacs::agent::boilerplate::BoilerPlate;
use jacs::error::JacsError;
use serde_json::Value;

fn exact_textual_loopback_host(host: &str) -> bool {
    let host = host.trim_matches(['[', ']']);
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
}

fn explicit_http_origin_names_exact_loopback(raw_origin: &str) -> bool {
    let Some((scheme, remainder)) = raw_origin.split_once("://") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("http") {
        return false;
    }
    let authority = remainder.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    if let Some(after_open) = authority.strip_prefix('[') {
        let Some((host, suffix)) = after_open.split_once(']') else {
            return false;
        };
        return host.eq_ignore_ascii_case("::1")
            && (suffix.is_empty()
                || suffix
                    .strip_prefix(':')
                    .is_some_and(|port| port.parse::<u16>().is_ok_and(|port| port != 0)));
    }
    let host = match authority.rsplit_once(':') {
        Some((host, port))
            if !host.contains(':') && port.parse::<u16>().is_ok_and(|port| port != 0) =>
        {
            host
        }
        Some(_) => return false,
        None => authority,
    };
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1"
}

fn validate_explicit_origin(raw_origin: &str) -> Result<String, String> {
    let raw_origin = raw_origin.trim();
    if raw_origin.is_empty() {
        return Err("--origin must not be empty".to_string());
    }
    let url = reqwest::Url::parse(raw_origin)
        .map_err(|error| format!("invalid A2A canonical --origin '{raw_origin}': {error}"))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err("A2A canonical --origin must not contain credentials".to_string());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("A2A canonical --origin must not contain a query or fragment".to_string());
    }
    if url.path() != "/" && !url.path().is_empty() {
        return Err("A2A canonical --origin must not contain a path".to_string());
    }
    let host = url
        .host_str()
        .ok_or_else(|| "A2A canonical --origin must include a host".to_string())?;
    if url.port() == Some(0) {
        return Err("A2A canonical --origin must not use port 0".to_string());
    }
    match url.scheme() {
        "https" => {}
        "http"
            if exact_textual_loopback_host(host)
                && explicit_http_origin_names_exact_loopback(raw_origin) => {}
        "http" => {
            return Err(
                "A2A canonical --origin must use HTTPS; HTTP is allowed only for an exact textual loopback host"
                    .to_string(),
            );
        }
        scheme => {
            return Err(format!(
                "A2A canonical --origin must use HTTPS (or loopback HTTP), not '{scheme}'"
            ));
        }
    }
    Ok(url.origin().ascii_serialization())
}

/// Resolve the canonical origin embedded in the signed Agent Card.
///
/// Without `--origin`, only exact loopback listeners are safe to advertise:
/// the built-in server is plaintext HTTP. Public/wildcard listeners require an
/// explicit HTTPS origin, normally the reverse proxy that terminates TLS.
pub fn resolve_a2a_serve_origin(
    bind_host: &str,
    bind_port: u16,
    explicit_origin: Option<&str>,
) -> Result<String, String> {
    if let Some(origin) = explicit_origin {
        return validate_explicit_origin(origin);
    }
    if bind_port == 0 {
        return Err("A2A serving does not support port 0 because the signed origin must be known before binding".to_string());
    }
    if !exact_textual_loopback_host(bind_host) {
        return Err(format!(
            "A2A listener host '{bind_host}' is not an exact loopback host. Pass --origin https://agent.example.com so the signed Agent Card names the TLS origin published by your reverse proxy."
        ));
    }
    let normalized_host = bind_host.trim_matches(['[', ']']);
    let authority = if normalized_host == "::1" {
        format!("[::1]:{bind_port}")
    } else {
        format!("{}:{bind_port}", normalized_host.to_ascii_lowercase())
    };
    Ok(format!("http://{authority}"))
}

/// Format a `tiny_http` bind address, including brackets for IPv6 literals.
pub fn a2a_bind_address(host: &str, port: u16) -> String {
    let host = host.trim_matches(['[', ']']);
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Generate the bound discovery set with the signed interface URL rooted at
/// `canonical_origin`.
pub fn generate_a2a_serve_documents(
    agent: &mut Agent,
    canonical_origin: &str,
) -> Result<(AgentCard, Vec<(String, Value)>), JacsError> {
    let canonical_origin =
        validate_explicit_origin(canonical_origin).map_err(JacsError::ValidationError)?;
    let mut card = jacs::a2a::agent_card::export_agent_card(agent)?;
    let agent_id = agent.get_id()?;
    let interface = card.supported_interfaces.first_mut().ok_or_else(|| {
        JacsError::ValidationError(
            "A2A Agent Card must contain at least one supported interface".to_string(),
        )
    })?;
    interface.url = format!("{canonical_origin}/agent/{agent_id}");

    let key_directory = agent
        .config
        .as_ref()
        .ok_or(JacsError::AgentNotLoaded)?
        .jacs_key_directory()
        .clone()
        .unwrap_or_else(|| jacs::paths::local_keys_dir().to_string_lossy().into_owned());
    let documents = jacs::a2a::extension::generate_bound_well_known_documents(
        agent,
        &key_directory,
        Some(card.clone()),
    )?;
    Ok((card, documents))
}
