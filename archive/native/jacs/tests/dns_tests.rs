use jacs::dns::bootstrap as dns;

#[test]
fn test_pubkey_digest_encoding() {
    let pk: Vec<u8> = b"test-public-key-bytes".to_vec();
    let b64 = dns::pubkey_digest_b64(&pk);
    let hex = dns::pubkey_digest_hex(&pk);
    // Precomputed SHA-256 for input (raw bytes)
    assert_eq!(
        hex,
        "5f48189c30fe3e016110848e1370efcb956db36fa1f9621889e3e95fa683a9ff"
    );
    assert_eq!(b64, "X0gYnDD+PgFhEISOE3Dvy5Vts2+h+WIYiePpX6aDqf8=");
}

#[test]
fn test_build_and_parse_txt_b64() {
    let agent_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let digest = "X0gYnDD+PgFhEISOE3Dvy5Vts2+h+WIYiePpX6aDqf8=";
    let txt = dns::build_agent_dns_txt(agent_id, digest, dns::DigestEncoding::Base64);
    assert!(txt.contains("v=jacs"));
    assert!(txt.contains("jacs_agent_id=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));
    assert!(txt.contains("alg=SHA-256"));
    assert!(txt.contains("enc=base64"));
    assert!(txt.contains("jac_public_key_hash=X0gYnDD+"));
    let parsed = dns::parse_agent_txt(&txt).expect("parse");
    assert_eq!(parsed.v, "jacs");
    assert_eq!(parsed.jacs_agent_id, agent_id);
    assert_eq!(parsed.alg, "SHA-256");
    assert!(matches!(parsed.enc, dns::DigestEncoding::Base64));
    assert_eq!(parsed.digest, digest);
}

#[test]
fn test_build_and_parse_txt_hex() {
    let agent_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    let digest = "5f48189c30fe3e016110848e1370efcb956db36fa1f9621889e3e95fa683a9ff";
    let txt = dns::build_agent_dns_txt(agent_id, digest, dns::DigestEncoding::Hex);
    let parsed = dns::parse_agent_txt(&txt).expect("parse");
    assert_eq!(parsed.jacs_agent_id, agent_id);
    assert!(matches!(parsed.enc, dns::DigestEncoding::Hex));
    assert_eq!(parsed.digest, digest);
}

#[test]
fn test_record_owner() {
    assert_eq!(
        dns::record_owner("example.com"),
        "_v1.agent.jacs.example.com."
    );
    assert_eq!(
        dns::record_owner("example.com."),
        "_v1.agent.jacs.example.com."
    );
}

#[test]
fn test_emitters() {
    let rr = dns::build_dns_record(
        "example.com",
        3600,
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "HASH",
        dns::DigestEncoding::Base64,
    );
    let plain = dns::emit_plain_bind(&rr);
    assert!(plain.contains("IN TXT \"v=jacs;"));
    let r53 = dns::emit_route53_change_batch(&rr);
    assert!(r53.contains("\"TXT\""));
    let gcloud = dns::emit_gcloud_dns(&rr, "Z");
    assert!(gcloud.contains("gcloud dns record-sets transaction add"));
    let azure = dns::emit_azure_cli(&rr, "RG", "example.com", "_v1.agent.jacs");
    assert!(azure.contains("az network dns record-set txt create"));
    let cf = dns::emit_cloudflare_curl(&rr, "ZONE");
    assert!(cf.contains("client/v4/zones/ZONE/dns_records"));
}

#[test]
fn test_verify_pubkey_via_embedded_fallback() {
    let pk: Vec<u8> = b"test-public-key-bytes".to_vec();
    let hex = dns::pubkey_digest_hex(&pk);
    // No domain -> fallback to embedded hex
    dns::verify_pubkey_via_dns_or_embedded(
        &pk,
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        None,
        Some(&hex),
        false,
    )
    .expect("embedded ok");

    // Mismatch should fail
    let err = dns::verify_pubkey_via_dns_or_embedded(
        &pk,
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        None,
        Some("deadbeef"),
        false,
    )
    .unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("embedded fingerprint mismatch"),
        "Expected embedded fingerprint mismatch error, got: {}",
        err_msg
    );
}

#[test]
fn legacy_version_cannot_be_used_for_discovery() {
    let txt = dns::build_agent_dns_txt(
        "agent",
        &dns::pubkey_digest_b64(b"key"),
        dns::DigestEncoding::Base64,
    )
    .replace("v=jacs", "v=hai.ai");
    assert!(dns::parse_agent_txt(&txt).is_err());
    assert!(dns::find_jacs_txt_record(vec![txt], "example.test").is_err());
}

#[test]
fn fingerprints_decode_to_exact_raw_key_digest() {
    let key = [0xff, 0xfe, b'\r', b'k'];
    let legacy = jacs::crypt::hash::hash_public_key(&key);
    assert_ne!(legacy, dns::pubkey_digest_hex(&key));
    for (digest, encoding) in [
        (dns::pubkey_digest_b64(&key), dns::DigestEncoding::Base64),
        (
            dns::pubkey_digest_hex(&key).to_uppercase(),
            dns::DigestEncoding::Hex,
        ),
    ] {
        let fields =
            dns::parse_agent_txt(&dns::build_agent_dns_txt("agent", &digest, encoding)).unwrap();
        assert!(dns::record_matches_public_key(&fields, &key));
        assert!(!dns::record_matches_public_key(&fields, b"other"));
    }
    let fields = dns::parse_agent_txt(&dns::build_agent_dns_txt(
        "agent",
        &legacy,
        dns::DigestEncoding::Hex,
    ))
    .unwrap();
    assert!(!dns::record_matches_public_key(&fields, &key));
}

#[test]
fn malformed_or_ambiguous_txt_tags_are_rejected() {
    let valid = dns::build_agent_dns_txt(
        "agent",
        &dns::pubkey_digest_b64(b"key"),
        dns::DigestEncoding::Base64,
    );
    for invalid in [
        valid.replace("SHA-256", "SHA-1"),
        valid.replace("v=jacs", "v=jacs-extra"),
        valid.replace("enc=base64", "enc=BASE64"),
        valid.replace("jacs_agent_id=agent", "jacs_agent_id="),
        valid.replace("jacs_agent_id=agent", "jacs_agent_id=two agents"),
        format!("{valid}; v=jacs"),
        format!("{valid}; uri="),
        format!("{valid}; malformed"),
        valid.replace(&dns::pubkey_digest_b64(b"key"), "AAAA"),
        valid.trim_end_matches('=').to_string(),
        valid.replace("enc=base64", "enc=hex"),
        format!("{valid}\n"),
    ] {
        assert!(
            dns::parse_agent_txt(&invalid).is_err(),
            "accepted {invalid}"
        );
    }
    for digest in ["a".repeat(63), "a".repeat(65), "z".repeat(64)] {
        assert!(
            dns::parse_agent_txt(&dns::build_agent_dns_txt(
                "agent",
                &digest,
                dns::DigestEncoding::Hex
            ))
            .is_err()
        );
    }
}

#[test]
fn optional_uri_is_validated_and_rotation_keeps_exact_identity_and_key() {
    let record = |id, key: &[u8], uri| {
        dns::build_agent_dns_txt_with_uri(
            id,
            &dns::pubkey_digest_b64(key),
            dns::DigestEncoding::Base64,
            uri,
        )
        .unwrap()
    };
    let old_uri = "https://keys.example.test/old";
    let records = vec![
        record("other-agent", b"other", None),
        "v=jacs; jacs_agent_id=unrelated-agent; enc=unknown; jac_public_key_hash=malformed".into(),
        record("agent", b"old", Some(old_uri)),
        record("agent", b"new", Some("https://keys.example.test/new")),
    ];
    let selected = dns::select_agent_txt_records(&records, "example.test", "agent").unwrap();
    assert_eq!(selected.len(), 2);
    assert_eq!(
        dns::match_agent_txt_record(&records, "example.test", "agent", b"old")
            .unwrap()
            .uri
            .as_deref(),
        Some(old_uri)
    );
    assert!(dns::match_agent_txt_record(&records, "example.test", "agent", b"new").is_ok());
    assert!(dns::match_agent_txt_record(&records, "example.test", "agent", b"other").is_err());
    assert!(dns::select_agent_txt_records(&records, "example.test", "absent-agent").is_err());
    assert!(dns::find_jacs_txt_record(records.clone(), "example.test").is_err());
    let mut conflict = records.clone();
    conflict.push(record(
        "agent",
        b"old",
        Some("https://keys.example.test/conflict"),
    ));
    assert!(dns::select_agent_txt_records(&conflict, "example.test", "agent").is_err());
    let malformed = vec![format!("{}; jacs_agent_id=agent", records[0])];
    assert!(dns::select_agent_txt_records(&malformed, "example.test", "agent").is_err());
    // Encoding aliases cannot disguise a conflicting locator for the same digest.
    let mut conflict = records.clone();
    conflict.push(dns::build_agent_dns_txt(
        "agent",
        &dns::pubkey_digest_hex(b"old"),
        dns::DigestEncoding::Hex,
    ));
    assert!(dns::select_agent_txt_records(&conflict, "example.test", "agent").is_err());
    for uri in [
        "http://keys.example.test/key",
        "https://user@keys.example.test/key",
        "https://keys.example.test/key#fragment",
        "not a URL",
        "https://keys.example.test/a b",
    ] {
        assert!(
            dns::build_agent_dns_txt_with_uri(
                "agent",
                &dns::pubkey_digest_b64(b"key"),
                dns::DigestEncoding::Base64,
                Some(uri)
            )
            .is_err()
        );
    }
}
