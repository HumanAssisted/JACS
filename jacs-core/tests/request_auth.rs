//! Cross-platform request-bound credentials must authenticate the transmitted bytes.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jacs_core::request_auth::{
    build_request_auth_header_at, inspect_unverified_request_auth_header, request_auth_replay_ttl,
    verify_request_auth_header_with_trusted_key_without_replay as verify,
};
use jacs_core::{CoreAgent, CoreError, SigningAlgorithm};

const NOW: u64 = 1_800_000_000;
const URL: &str = "https://hai.example/api/v1/link/session?token=a%2Fb&z=1";
const BODY: &[u8] = b"{\"ciphertext\":\"exact serialized bytes\"}";

fn lookup(agent: &CoreAgent) -> String {
    let identity = agent.export_agent();
    format!(
        "{}:{}",
        identity["jacsId"].as_str().unwrap(),
        identity["jacsVersion"].as_str().unwrap()
    )
}

#[test]
fn every_algorithm_authenticates_exact_request_and_survives_lock_for_verification() {
    for algorithm in [
        SigningAlgorithm::Ed25519,
        SigningAlgorithm::Pq2025,
        SigningAlgorithm::Es256,
    ] {
        let mut agent = CoreAgent::ephemeral(algorithm).unwrap();
        let header =
            build_request_auth_header_at(&agent, "POST", URL, BODY, "hai.ai", NOW).unwrap();
        assert!(header.starts_with("JACS v2."));
        let id = lookup(&agent);
        let claims = verify(
            &header,
            agent.public_key(),
            &id,
            "POST",
            URL,
            BODY,
            "hai.ai",
            60,
            NOW,
        )
        .unwrap();
        assert_eq!(claims.key_id, id);
        assert_eq!(claims.method, "POST");
        assert_eq!(claims.target, "/api/v1/link/session?token=a%2Fb&z=1");
        assert_eq!(claims.audience, "hai.ai");
        assert_eq!(
            SigningAlgorithm::from_wire_str(&claims.signing_algorithm),
            Some(algorithm)
        );
        assert_eq!(request_auth_replay_ttl(&claims, 60, NOW).unwrap(), 61);
        agent.clear_secrets();
        assert!(
            verify(
                &header,
                agent.public_key(),
                &id,
                "POST",
                URL,
                BODY,
                "hai.ai",
                60,
                NOW
            )
            .is_ok()
        );
        assert!(matches!(
            agent.build_request_auth_header("POST", URL, BODY, "hai.ai"),
            Err(CoreError::Locked)
        ));
    }
}

#[test]
fn changes_to_each_request_dimension_or_key_are_rejected() {
    let agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).unwrap();
    let header = build_request_auth_header_at(&agent, "POST", URL, BODY, "hai.ai", NOW).unwrap();
    let id = lookup(&agent);
    for (method, url, body, audience, key_id) in [
        ("GET", URL, BODY, "hai.ai", id.as_str()),
        (
            "POST",
            "https://attacker.example/api/v1/link/session?token=a%2Fb&z=1",
            BODY,
            "hai.ai",
            id.as_str(),
        ),
        (
            "POST",
            "http://hai.example/api/v1/link/session?token=a%2Fb&z=1",
            BODY,
            "hai.ai",
            id.as_str(),
        ),
        (
            "POST",
            "https://hai.example/api/v1/link/other?token=a%2Fb&z=1",
            BODY,
            "hai.ai",
            id.as_str(),
        ),
        (
            "POST",
            "https://hai.example/api/v1/link/session?z=1&token=a%2Fb",
            BODY,
            "hai.ai",
            id.as_str(),
        ),
        (
            "POST",
            URL,
            b"{ \"ciphertext\":\"exact serialized bytes\"}",
            "hai.ai",
            id.as_str(),
        ),
        ("POST", URL, BODY, "other-deployment", id.as_str()),
        ("POST", URL, BODY, "hai.ai", "other-agent:other-version"),
    ] {
        assert!(
            verify(
                &header,
                agent.public_key(),
                key_id,
                method,
                url,
                body,
                audience,
                60,
                NOW
            )
            .is_err()
        );
    }
    let wrong = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).unwrap();
    assert!(
        verify(
            &header,
            wrong.public_key(),
            &id,
            "POST",
            URL,
            BODY,
            "hai.ai",
            60,
            NOW
        )
        .is_err()
    );
}

#[test]
fn nonce_is_fresh_time_bounds_and_skew_aware_replay_ttl_match_native() {
    let agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).unwrap();
    let first = build_request_auth_header_at(&agent, "GET", URL, &[], "hai.ai", NOW).unwrap();
    let second = build_request_auth_header_at(&agent, "GET", URL, &[], "hai.ai", NOW).unwrap();
    assert_ne!(first, second);
    let claims = inspect_unverified_request_auth_header(&first).unwrap();
    assert_ne!(
        claims.nonce,
        inspect_unverified_request_auth_header(&second)
            .unwrap()
            .nonce
    );
    let id = lookup(&agent);
    assert!(
        verify(
            &first,
            agent.public_key(),
            &id,
            "GET",
            URL,
            &[],
            "hai.ai",
            60,
            NOW + 60
        )
        .is_ok()
    );
    assert!(
        verify(
            &first,
            agent.public_key(),
            &id,
            "GET",
            URL,
            &[],
            "hai.ai",
            60,
            NOW + 61
        )
        .is_err()
    );
    assert!(
        verify(
            &first,
            agent.public_key(),
            &id,
            "GET",
            URL,
            &[],
            "hai.ai",
            60,
            NOW - 300
        )
        .is_ok()
    );
    assert!(
        verify(
            &first,
            agent.public_key(),
            &id,
            "GET",
            URL,
            &[],
            "hai.ai",
            60,
            NOW - 301
        )
        .is_err()
    );
    assert_eq!(
        request_auth_replay_ttl(&claims, 60, NOW - 300).unwrap(),
        361
    );
    assert!(request_auth_replay_ttl(&claims, 60, NOW + 61).is_err());
    assert!(request_auth_replay_ttl(&claims, 0, NOW).is_err());
}

#[test]
fn strict_header_parser_rejects_legacy_noncanonical_and_duplicate_json() {
    let agent = CoreAgent::ephemeral(SigningAlgorithm::Ed25519).unwrap();
    let header = build_request_auth_header_at(&agent, "GET", URL, &[], "hai.ai", NOW).unwrap();
    let claims = inspect_unverified_request_auth_header(&header).unwrap();
    let signature = header.rsplit('.').next().unwrap();
    let noncanonical = serde_json::to_string_pretty(&claims).unwrap();
    let bad = format!(
        "JACS v2.{}.{}",
        URL_SAFE_NO_PAD.encode(noncanonical),
        signature
    );
    assert!(inspect_unverified_request_auth_header(&bad).is_err());
    let raw = URL_SAFE_NO_PAD
        .decode(header.split('.').nth(1).unwrap())
        .unwrap();
    let duplicate = String::from_utf8(raw)
        .unwrap()
        .replacen("{", "{\"audience\":\"hai.ai\",", 1);
    let bad = format!(
        "JACS v2.{}.{}",
        URL_SAFE_NO_PAD.encode(duplicate),
        signature
    );
    assert!(inspect_unverified_request_auth_header(&bad).is_err());
    for bad in [
        "JACS agent:123:signature".to_string(),
        format!("{header}.extra"),
        "JACS v2.a.b".to_string(),
        "x".repeat(65537),
    ] {
        assert!(inspect_unverified_request_auth_header(&bad).is_err());
    }
}

#[test]
fn native_url_normalization_and_invalid_targets_are_preserved() {
    let agent = CoreAgent::ephemeral(SigningAlgorithm::Es256).unwrap();
    let header = build_request_auth_header_at(
        &agent,
        " post ",
        "https://HAI.EXAMPLE:443/a/../api?x=%2f",
        BODY,
        "hai.ai",
        NOW,
    )
    .unwrap();
    verify(
        &header,
        agent.public_key(),
        &lookup(&agent),
        "POST",
        "https://hai.example/api?x=%2f",
        BODY,
        "hai.ai",
        60,
        NOW,
    )
    .unwrap();
    for url in [
        "/api",
        "ftp://hai.example/api",
        "https://user:password@hai.example/api",
        "https://hai.example/api#fragment",
    ] {
        assert!(build_request_auth_header_at(&agent, "POST", url, BODY, "hai.ai", NOW).is_err());
    }
    assert!(build_request_auth_header_at(&agent, "POST\r\nX", URL, BODY, "hai.ai", NOW).is_err());
    assert!(build_request_auth_header_at(&agent, "POST", URL, BODY, " ", NOW).is_err());
}
