//! Fail-closed HTTP GETs for trust-boundary resources.
//!
//! This module centralizes SSRF, redirect, DNS-rebinding, timeout, response-size,
//! and MIME controls. Callers remain responsible for interpreting HTTP status
//! codes and strictly parsing the returned bytes.

use crate::error::JacsError;
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, LOCATION};
use reqwest::{StatusCode, Url};
use std::collections::HashSet;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

const DEFAULT_MAX_REDIRECTS: usize = 3;
const DEFAULT_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_DNS_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_DNS_CONCURRENCY: usize = 8;
const MAX_DNS_ADDRESSES: usize = 16;

/// Which redirect destinations a request may follow.
#[derive(Clone, Debug)]
pub(crate) enum RedirectScope {
    /// Every hop must retain the initial scheme, host, and effective port.
    SameOrigin,
    /// Every hop must be HTTPS and its host must match an explicit allowlist.
    /// Entries match themselves and their subdomains.
    AllowedHosts(Vec<String>),
}

/// Security policy for one outbound trust-boundary surface.
#[derive(Clone, Debug)]
pub(crate) struct SecureFetchPolicy {
    surface: &'static str,
    max_redirects: usize,
    max_response_bytes: usize,
    total_timeout: Duration,
    connect_timeout: Duration,
    dns_timeout: Duration,
    expected_mime_types: &'static [&'static str],
    redirect_scope: RedirectScope,
    allow_exact_loopback: bool,
    accept_invalid_certs: bool,
}

impl SecureFetchPolicy {
    pub(crate) fn new(
        surface: &'static str,
        max_response_bytes: usize,
        expected_mime_types: &'static [&'static str],
    ) -> Self {
        Self {
            surface,
            max_redirects: DEFAULT_MAX_REDIRECTS,
            max_response_bytes,
            total_timeout: DEFAULT_TOTAL_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            dns_timeout: DEFAULT_DNS_TIMEOUT,
            expected_mime_types,
            redirect_scope: RedirectScope::SameOrigin,
            allow_exact_loopback: false,
            accept_invalid_certs: false,
        }
    }

    pub(crate) fn max_redirects(mut self, max_redirects: usize) -> Self {
        self.max_redirects = max_redirects;
        self
    }

    pub(crate) fn timeouts(
        mut self,
        total_timeout: Duration,
        connect_timeout: Duration,
        dns_timeout: Duration,
    ) -> Self {
        self.total_timeout = total_timeout;
        self.connect_timeout = connect_timeout;
        self.dns_timeout = dns_timeout;
        self
    }

    pub(crate) fn redirect_scope(mut self, redirect_scope: RedirectScope) -> Self {
        self.redirect_scope = redirect_scope;
        self
    }

    /// Permit private addresses only when the initial URL literally names
    /// `localhost`, `127.0.0.1`, or `::1`. Redirects cannot change that origin.
    pub(crate) fn allow_exact_loopback(mut self, allow: bool) -> Self {
        self.allow_exact_loopback = allow;
        self
    }

    pub(crate) fn accept_invalid_certs(mut self, accept: bool) -> Self {
        self.accept_invalid_certs = accept;
        self
    }
}

/// Bounded response returned after all URL, DNS, redirect, and body checks.
#[derive(Debug)]
pub(crate) struct SecureFetchResponse {
    pub(crate) status: StatusCode,
    pub(crate) body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Origin {
    scheme: String,
    host: String,
    port: u16,
}

fn origin(url: &Url) -> Result<Origin, JacsError> {
    let host = normalized_host(url)?;
    let port = url.port_or_known_default().ok_or_else(|| {
        network_error(format!(
            "URL '{}' does not have a known or explicit port",
            safe_url(url)
        ))
    })?;
    Ok(Origin {
        scheme: url.scheme().to_ascii_lowercase(),
        host,
        port,
    })
}

fn network_error(message: impl Into<String>) -> JacsError {
    JacsError::NetworkError(message.into())
}

fn safe_url(url: &Url) -> String {
    let mut safe = url.clone();
    let _ = safe.set_username("");
    let _ = safe.set_password(None);
    if safe.query().is_some() {
        safe.set_query(Some("redacted"));
    }
    safe.set_fragment(None);
    safe.to_string()
}

fn normalized_host(url: &Url) -> Result<String, JacsError> {
    url.host_str()
        .map(|host| {
            host.trim_matches(['[', ']'])
                .trim_end_matches('.')
                .to_ascii_lowercase()
        })
        .filter(|host| !host.is_empty())
        .ok_or_else(|| network_error(format!("URL '{}' has no host", safe_url(url))))
}

fn is_textual_loopback_host(host: &str) -> bool {
    let host = host
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase();
    host == "localhost" || host == "127.0.0.1" || host == "::1"
}

/// Whether the original URL text explicitly names one of the three supported
/// loopback development hosts. This intentionally inspects the raw authority:
/// WHATWG URL parsing canonicalizes obfuscated IPv4 forms such as `2130706433`
/// to `127.0.0.1`, which must not silently gain development-only privileges.
pub(crate) fn is_exact_textual_loopback_endpoint(raw_url: &str) -> bool {
    let Some((scheme, remainder)) = raw_url.split_once("://") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
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
        let valid_suffix =
            suffix.is_empty() || suffix.strip_prefix(':').is_some_and(valid_explicit_port);
        return host.eq_ignore_ascii_case("::1") && valid_suffix;
    }

    let (host, valid_suffix) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, valid_explicit_port(port)),
        None => (authority, true),
    };
    valid_suffix && (host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1")
}

fn valid_explicit_port(port: &str) -> bool {
    !port.is_empty() && port.parse::<u16>().is_ok_and(|port| port != 0)
}

/// Validate transport-level URL syntax without making a network request.
/// DNS and address-class validation still happens immediately before connect.
pub(crate) fn validate_transport_url(
    url: &Url,
    allow_exact_loopback: bool,
    surface: &str,
) -> Result<(), JacsError> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err(network_error(format!(
            "{} URL '{}' must not contain credentials",
            surface,
            safe_url(url)
        )));
    }
    if url.fragment().is_some() {
        return Err(network_error(format!(
            "{} URL '{}' must not contain a fragment",
            surface,
            safe_url(url)
        )));
    }
    match url.scheme() {
        "https" => {}
        "http" if allow_exact_loopback && url.host_str().is_some_and(is_textual_loopback_host) => {}
        _ => {
            return Err(network_error(format!(
                "{} URL '{}' must use HTTPS; HTTP is allowed only for an explicitly configured textual loopback endpoint",
                surface,
                safe_url(url)
            )));
        }
    }
    let endpoint = origin(url)?;
    if endpoint.port == 0 {
        return Err(network_error(format!(
            "{} URL '{}' must not use port 0",
            surface,
            safe_url(url)
        )));
    }
    Ok(())
}

fn host_matches_allowlist(host: &str, allowed_hosts: &[String]) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    allowed_hosts.iter().any(|allowed| {
        let allowed = allowed
            .trim()
            .trim_matches(['[', ']'])
            .trim_end_matches('.')
            .to_ascii_lowercase();
        !allowed.is_empty() && (host == allowed || host.ends_with(&format!(".{allowed}")))
    })
}

fn scope_allows(
    url: &Url,
    initial_origin: &Origin,
    scope: &RedirectScope,
) -> Result<bool, JacsError> {
    match scope {
        RedirectScope::SameOrigin => Ok(origin(url)? == *initial_origin),
        RedirectScope::AllowedHosts(allowed_hosts) => {
            let host = normalized_host(url)?;
            Ok(host_matches_allowlist(&host, allowed_hosts))
        }
    }
}

fn ipv4_is_public(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !matches!(
        (a, b, c),
        (0, _, _)
            | (10, _, _)
            | (100, 64..=127, _)
            | (127, _, _)
            | (169, 254, _)
            | (172, 16..=31, _)
            | (192, 0, 0)
            | (192, 0, 2)
            | (192, 88, 99)
            | (192, 168, _)
            | (198, 18..=19, _)
            | (198, 51, 100)
            | (203, 0, 113)
            | (224..=255, _, _)
    )
}

fn ipv6_is_public(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    let global_unicast = (segments[0] & 0xe000) == 0x2000;
    let ietf_special = segments[0] == 0x2001 && segments[1] <= 0x01ff;
    let documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
    let additional_documentation = segments[0] == 0x3fff && (segments[1] & 0xf000) == 0x0000;
    let deprecated_six_to_four = segments[0] == 0x2002;
    global_unicast
        && !ietf_special
        && !documentation
        && !additional_documentation
        && !deprecated_six_to_four
        && ip.to_ipv4_mapped().is_none()
}

fn ip_is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ipv4_is_public(ip),
        IpAddr::V6(ip) => ipv6_is_public(ip),
    }
}

fn ip_is_loopback(ip: IpAddr) -> bool {
    ip.is_loopback()
}

struct DnsPermit {
    state: &'static (Mutex<usize>, Condvar),
}

impl Drop for DnsPermit {
    fn drop(&mut self) {
        if let Ok(mut active) = self.state.0.lock() {
            *active = active.saturating_sub(1);
            self.state.1.notify_one();
        }
    }
}

fn dns_state() -> &'static (Mutex<usize>, Condvar) {
    static STATE: OnceLock<(Mutex<usize>, Condvar)> = OnceLock::new();
    STATE.get_or_init(|| (Mutex::new(0), Condvar::new()))
}

fn acquire_dns_permit(timeout: Duration) -> Result<DnsPermit, JacsError> {
    let state = dns_state();
    let deadline = Instant::now() + timeout;
    let mut active = state
        .0
        .lock()
        .map_err(|_| network_error("DNS concurrency limiter lock was poisoned"))?;
    loop {
        if *active < MAX_DNS_CONCURRENCY {
            *active += 1;
            return Ok(DnsPermit { state });
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(network_error(
                "DNS resolution timed out waiting for a bounded resolver slot",
            ));
        }
        let (next, result) = state
            .1
            .wait_timeout(active, remaining)
            .map_err(|_| network_error("DNS concurrency limiter lock was poisoned"))?;
        active = next;
        if result.timed_out() && *active >= MAX_DNS_CONCURRENCY {
            return Err(network_error(
                "DNS resolution timed out waiting for a bounded resolver slot",
            ));
        }
    }
}

fn resolve_with_deadline(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<Vec<SocketAddr>, JacsError> {
    if timeout.is_zero() {
        return Err(network_error("DNS resolution timed out"));
    }

    let literal = host.trim_matches(['[', ']']);
    if let Ok(ip) = literal.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let permit = acquire_dns_permit(timeout)?;
    let deadline = Instant::now() + timeout;
    let host_owned = host.to_string();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("jacs-secure-dns".to_string())
        .spawn(move || {
            let _permit = permit;
            let result = (host_owned.as_str(), port)
                .to_socket_addrs()
                .map(|addresses| {
                    addresses
                        .take(MAX_DNS_ADDRESSES.saturating_add(1))
                        .collect::<Vec<_>>()
                });
            let _ = sender.send(result);
        })
        .map_err(|e| network_error(format!("Failed to start DNS resolver: {e}")))?;

    let remaining = deadline.saturating_duration_since(Instant::now());
    let addresses = receiver
        .recv_timeout(remaining)
        .map_err(|_| network_error(format!("DNS resolution for '{host}' timed out")))?
        .map_err(|e| network_error(format!("DNS resolution for '{host}' failed: {e}")))?;

    if addresses.is_empty() {
        return Err(network_error(format!(
            "DNS resolution for '{host}' returned no addresses"
        )));
    }
    if addresses.len() > MAX_DNS_ADDRESSES {
        return Err(network_error(format!(
            "DNS resolution for '{host}' returned more than {MAX_DNS_ADDRESSES} addresses"
        )));
    }
    Ok(addresses)
}

fn validate_resolved_addresses(
    url: &Url,
    addresses: Vec<SocketAddr>,
    allowed_loopback_origin: Option<&Origin>,
) -> Result<Vec<SocketAddr>, JacsError> {
    let current_origin = origin(url)?;
    let loopback_allowed = allowed_loopback_origin == Some(&current_origin);
    let mut unique = HashSet::new();
    let mut result = Vec::new();

    for address in addresses {
        let allowed = if loopback_allowed {
            ip_is_loopback(address.ip())
        } else {
            ip_is_public(address.ip())
        };
        if !allowed {
            return Err(network_error(format!(
                "Refusing {} URL '{}': DNS returned private, loopback, link-local, reserved, or mixed address {}",
                if loopback_allowed {
                    "mixed-address loopback"
                } else {
                    "non-public"
                },
                safe_url(url),
                address.ip()
            )));
        }
        if unique.insert(address) {
            result.push(address);
        }
    }
    Ok(result)
}

/// Read at most `max_bytes`, detecting both declared and streaming overflow.
pub(crate) fn read_body_capped<R: Read>(
    mut reader: R,
    max_bytes: usize,
) -> Result<Vec<u8>, JacsError> {
    let mut body = Vec::new();
    let read = reader
        .by_ref()
        .take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut body)
        .map_err(|e| network_error(format!("Failed to read HTTP response body: {e}")))?;
    if read > max_bytes {
        return Err(network_error(format!(
            "HTTP response exceeded maximum allowed size of {max_bytes} bytes"
        )));
    }
    Ok(body)
}

fn validate_success_headers(
    response: &reqwest::blocking::Response,
    policy: &SecureFetchPolicy,
) -> Result<(), JacsError> {
    let content_lengths = response.headers().get_all(CONTENT_LENGTH);
    if content_lengths.iter().count() > 1 {
        return Err(network_error(format!(
            "{} response has multiple Content-Length headers",
            policy.surface
        )));
    }
    if let Some(length) = content_lengths.iter().next() {
        let length = length.to_str().map_err(|_| {
            network_error(format!(
                "{} response has a non-ASCII Content-Length",
                policy.surface
            ))
        })?;
        let length = length.parse::<u64>().map_err(|_| {
            network_error(format!(
                "{} response has an invalid Content-Length",
                policy.surface
            ))
        })?;
        if length > policy.max_response_bytes as u64 {
            return Err(network_error(format!(
                "{} response exceeded maximum allowed size of {} bytes",
                policy.surface, policy.max_response_bytes
            )));
        }
    }

    let encodings = response.headers().get_all(CONTENT_ENCODING);
    for encoding in encodings.iter() {
        let encoding = encoding.to_str().map_err(|_| {
            network_error(format!(
                "{} response has a non-ASCII Content-Encoding",
                policy.surface
            ))
        })?;
        if !encoding.eq_ignore_ascii_case("identity") {
            return Err(network_error(format!(
                "{} response uses unsupported Content-Encoding '{}'",
                policy.surface, encoding
            )));
        }
    }

    let content_types = response.headers().get_all(CONTENT_TYPE);
    if content_types.iter().count() != 1 {
        return Err(network_error(format!(
            "{} response must include exactly one Content-Type header",
            policy.surface
        )));
    }
    let raw_content_type = content_types
        .iter()
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            network_error(format!(
                "{} response has an invalid Content-Type header",
                policy.surface
            ))
        })?;
    let mime = raw_content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if !policy
        .expected_mime_types
        .iter()
        .any(|expected| mime.eq_ignore_ascii_case(expected))
    {
        return Err(network_error(format!(
            "{} response has an unexpected Content-Type; expected one of {:?}",
            policy.surface, policy.expected_mime_types
        )));
    }
    Ok(())
}

fn redirect_target(
    current: &Url,
    response: &reqwest::blocking::Response,
) -> Result<Url, JacsError> {
    let locations = response.headers().get_all(LOCATION);
    if locations.iter().count() != 1 {
        return Err(network_error(format!(
            "Redirect from '{}' must include exactly one Location header",
            safe_url(current)
        )));
    }
    let location = locations
        .iter()
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            network_error(format!(
                "Redirect from '{}' has invalid Location",
                safe_url(current)
            ))
        })?;
    current.join(location).map_err(|e| {
        network_error(format!(
            "Redirect from '{}' has an invalid Location: {}",
            safe_url(current),
            e
        ))
    })
}

fn is_followable_redirect(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

/// Perform one secure blocking GET. Redirects are followed manually so every
/// hop is independently parsed, resolved, address-checked, and pinned.
pub(crate) fn secure_get(
    initial_url: &str,
    accept: &'static str,
    policy: &SecureFetchPolicy,
) -> Result<SecureFetchResponse, JacsError> {
    let initial = Url::parse(initial_url)
        .map_err(|e| network_error(format!("Invalid {} URL: {}", policy.surface, e)))?;
    let initial_origin = origin(&initial)?;
    let allowed_loopback_origin = if policy.allow_exact_loopback
        && is_exact_textual_loopback_endpoint(initial_url)
        && initial.host_str().is_some_and(is_textual_loopback_host)
    {
        Some(initial_origin.clone())
    } else {
        None
    };

    validate_transport_url(&initial, allowed_loopback_origin.is_some(), policy.surface)?;
    if !scope_allows(&initial, &initial_origin, &policy.redirect_scope)? {
        return Err(network_error(format!(
            "Initial {} URL '{}' is outside the configured host policy",
            policy.surface,
            safe_url(&initial)
        )));
    }

    let started = Instant::now();
    let mut current = initial;
    let mut redirects = 0usize;

    loop {
        let remaining = policy.total_timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(network_error(format!(
                "{} request timed out after {:?}",
                policy.surface, policy.total_timeout
            )));
        }

        validate_transport_url(
            &current,
            allowed_loopback_origin.as_ref() == Some(&origin(&current)?),
            policy.surface,
        )?;
        if !scope_allows(&current, &initial_origin, &policy.redirect_scope)? {
            return Err(network_error(format!(
                "Refusing {} redirect outside the configured origin/host policy: '{}'",
                policy.surface,
                safe_url(&current)
            )));
        }

        let host = normalized_host(&current)?;
        let port = current.port_or_known_default().ok_or_else(|| {
            network_error(format!(
                "{} URL '{}' has no port",
                policy.surface,
                safe_url(&current)
            ))
        })?;
        let dns_timeout = policy.dns_timeout.min(remaining);
        let addresses = resolve_with_deadline(&host, port, dns_timeout)?;
        let addresses =
            validate_resolved_addresses(&current, addresses, allowed_loopback_origin.as_ref())?;

        let remaining = policy.total_timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(network_error(format!(
                "{} request timed out after {:?}",
                policy.surface, policy.total_timeout
            )));
        }
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(remaining)
            .connect_timeout(policy.connect_timeout.min(remaining))
            .danger_accept_invalid_certs(policy.accept_invalid_certs)
            .resolve_to_addrs(&host, &addresses)
            .build()
            .map_err(|e| {
                network_error(format!(
                    "Failed to build {} HTTP client: {}",
                    policy.surface, e
                ))
            })?;

        let response = client
            .get(current.clone())
            .header(ACCEPT, accept)
            .send()
            .map_err(|e| {
                let timed_out = e.is_timeout();
                let connect = e.is_connect();
                let detail = e.without_url();
                if timed_out {
                    network_error(format!(
                        "{} request timed out for '{}': {}",
                        policy.surface,
                        safe_url(&current),
                        detail
                    ))
                } else if connect {
                    network_error(format!(
                        "Failed to connect for {} request to '{}': {}",
                        policy.surface,
                        safe_url(&current),
                        detail
                    ))
                } else {
                    network_error(format!(
                        "{} HTTP request to '{}' failed: {}",
                        policy.surface,
                        safe_url(&current),
                        detail
                    ))
                }
            })?;

        if is_followable_redirect(response.status()) {
            if redirects >= policy.max_redirects {
                return Err(network_error(format!(
                    "{} request exceeded maximum redirect count of {}",
                    policy.surface, policy.max_redirects
                )));
            }
            let next = redirect_target(&current, &response)?;
            if !scope_allows(&next, &initial_origin, &policy.redirect_scope)? {
                return Err(network_error(format!(
                    "Refusing {} redirect outside the configured origin/host policy: '{}'",
                    policy.surface,
                    safe_url(&next)
                )));
            }
            validate_transport_url(
                &next,
                allowed_loopback_origin.as_ref() == Some(&origin(&next)?),
                policy.surface,
            )?;
            current = next;
            redirects += 1;
            continue;
        }

        let status = response.status();
        if !status.is_success() {
            return Ok(SecureFetchResponse {
                status,
                body: Vec::new(),
            });
        }

        validate_success_headers(&response, policy)?;
        let body = read_body_capped(response, policy.max_response_bytes).map_err(|error| {
            network_error(format!(
                "{} response body failed security checks: {}",
                policy.surface, error
            ))
        })?;
        return Ok(SecureFetchResponse { status, body });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread::JoinHandle;

    fn spawn_server<F>(requests: usize, handler: F) -> (String, JoinHandle<()>)
    where
        F: Fn(&str, usize) -> String + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handler = Arc::new(handler);
        let join = std::thread::spawn(move || {
            for index in 0..requests {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut request = [0_u8; 4096];
                let read = stream.read(&mut request).unwrap_or(0);
                let request = String::from_utf8_lossy(&request[..read]);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/");
                let response = handler(path, index);
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        (format!("http://{address}"), join)
    }

    fn loopback_policy(max_bytes: usize) -> SecureFetchPolicy {
        SecureFetchPolicy::new("secure-fetch test", max_bytes, &["application/json"])
            .allow_exact_loopback(true)
            .timeouts(
                Duration::from_secs(2),
                Duration::from_secs(1),
                Duration::from_secs(1),
            )
    }

    #[test]
    fn follows_only_manually_validated_same_origin_redirects() {
        let (base, join) = spawn_server(2, |path, _| {
            if path == "/start" {
                "HTTP/1.1 302 Found\r\nLocation: /ok\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
            } else {
                "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_string()
            }
        });

        let response = secure_get(
            &format!("{base}/start"),
            "application/json",
            &loopback_policy(32),
        )
        .unwrap();
        join.join().unwrap();
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, b"{}");
    }

    #[test]
    fn rejects_cross_origin_redirect_before_connect() {
        let (base, join) = spawn_server(1, |_, _| {
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/private\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
        });
        let error = secure_get(&base, "application/json", &loopback_policy(32)).unwrap_err();
        join.join().unwrap();
        assert!(error.to_string().contains("origin/host policy"));
    }

    #[test]
    fn rejects_declared_and_streaming_oversize_responses() {
        let (declared_base, declared_join) = spawn_server(1, |_, _| {
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{}".to_string()
        });
        let declared = secure_get(&declared_base, "application/json", &loopback_policy(8));
        declared_join.join().unwrap();
        assert!(
            declared
                .unwrap_err()
                .to_string()
                .contains("maximum allowed size")
        );

        let (streamed_base, streamed_join) = spawn_server(1, |_, _| {
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n0123456789".to_string()
        });
        let streamed = secure_get(&streamed_base, "application/json", &loopback_policy(8));
        streamed_join.join().unwrap();
        assert!(
            streamed
                .unwrap_err()
                .to_string()
                .contains("maximum allowed size")
        );
    }

    #[test]
    fn total_timeout_is_enforced() {
        let (base, join) = spawn_server(1, |_, _| {
            std::thread::sleep(Duration::from_millis(250));
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_string()
        });
        let policy = loopback_policy(32).timeouts(
            Duration::from_millis(50),
            Duration::from_millis(25),
            Duration::from_millis(25),
        );
        let error = secure_get(&base, "application/json", &policy).unwrap_err();
        join.join().unwrap();
        assert!(error.to_string().contains("timed out"));
    }

    #[test]
    fn preserves_status_and_rejects_wrong_mime_on_success() {
        let (missing_base, missing_join) = spawn_server(1, |_, _| {
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
        });
        let missing = secure_get(&missing_base, "application/json", &loopback_policy(32)).unwrap();
        missing_join.join().unwrap();
        assert_eq!(missing.status, StatusCode::NOT_FOUND);

        let (wrong_base, wrong_join) = spawn_server(1, |_, _| {
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_string()
        });
        let wrong = secure_get(&wrong_base, "application/json", &loopback_policy(32));
        wrong_join.join().unwrap();
        assert!(wrong.unwrap_err().to_string().contains("Content-Type"));
    }

    #[test]
    fn private_addresses_require_explicit_textual_loopback_policy() {
        let policy = SecureFetchPolicy::new("secure-fetch test", 32, &["application/json"]);
        let error = secure_get("http://127.0.0.1:9/", "application/json", &policy).unwrap_err();
        assert!(error.to_string().contains("loopback"));
    }

    #[test]
    fn rejects_credentials_fragments_and_reserved_ranges() {
        let credentials = Url::parse("https://user@example.com/key").unwrap();
        assert!(validate_transport_url(&credentials, false, "test").is_err());
        let fragment = Url::parse("https://example.com/key#secret").unwrap();
        assert!(validate_transport_url(&fragment, false, "test").is_err());
        assert!(!ip_is_public("10.0.0.1".parse().unwrap()));
        assert!(!ip_is_public("169.254.169.254".parse().unwrap()));
        assert!(!ip_is_public("100.64.0.1".parse().unwrap()));
        assert!(!ip_is_public("2001:db8::1".parse().unwrap()));
        assert!(ip_is_public("8.8.8.8".parse().unwrap()));
        assert!(ip_is_public("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn security_errors_redact_credentials_queries_and_fragments() {
        let url = Url::parse(
            "https://alice:super-secret@example.com/key?access_token=also-secret#fragment-secret",
        )
        .unwrap();
        let rendered = validate_transport_url(&url, false, "test")
            .unwrap_err()
            .to_string();
        assert!(!rendered.contains("alice"));
        assert!(!rendered.contains("super-secret"));
        assert!(!rendered.contains("also-secret"));
        assert!(!rendered.contains("fragment-secret"));
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn loopback_allowance_requires_exact_raw_authority() {
        assert!(is_exact_textual_loopback_endpoint(
            "http://localhost:8080/path"
        ));
        assert!(is_exact_textual_loopback_endpoint("http://127.0.0.1/path"));
        assert!(is_exact_textual_loopback_endpoint("http://[::1]:8080/"));
        assert!(!is_exact_textual_loopback_endpoint("http://2130706433/"));
        assert!(!is_exact_textual_loopback_endpoint("http://0x7f000001/"));
        assert!(!is_exact_textual_loopback_endpoint(
            "http://localhost.evil.example/"
        ));
        assert!(!is_exact_textual_loopback_endpoint("http://localhost:0/"));
    }

    #[test]
    fn rejects_mixed_public_and_private_dns_answers() {
        let public_url = Url::parse("https://keys.example/key").unwrap();
        let mixed = vec![
            "8.8.8.8:443".parse().unwrap(),
            "10.0.0.1:443".parse().unwrap(),
        ];
        assert!(validate_resolved_addresses(&public_url, mixed, None).is_err());

        let loopback_url = Url::parse("http://localhost:8080/key").unwrap();
        let loopback_origin = origin(&loopback_url).unwrap();
        let mixed_loopback = vec![
            "127.0.0.1:8080".parse().unwrap(),
            "8.8.8.8:8080".parse().unwrap(),
        ];
        assert!(
            validate_resolved_addresses(&loopback_url, mixed_loopback, Some(&loopback_origin),)
                .is_err()
        );
    }

    #[test]
    fn schema_allowlist_requires_label_boundary() {
        let allowed = vec!["hai.ai".to_string()];
        assert!(host_matches_allowlist("schema.hai.ai", &allowed));
        assert!(!host_matches_allowlist("hai.ai.attacker.example", &allowed));
    }

    #[test]
    fn capped_reader_accepts_exact_limit() {
        assert_eq!(
            read_body_capped(std::io::Cursor::new(b"1234"), 4).unwrap(),
            b"1234"
        );
    }
}
