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
    let digest = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    let txt = dns::build_agent_dns_txt(agent_id, digest, dns::DigestEncoding::Base64);
    assert!(txt.contains("v=hai.ai"));
    assert!(txt.contains("jacs_agent_id=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));
    assert!(txt.contains("alg=SHA-256"));
    assert!(txt.contains("enc=base64"));
    assert!(txt.contains("jac_public_key_hash=abcdabcd"));
    let parsed = dns::parse_agent_txt(&txt).expect("parse");
    assert_eq!(parsed.v, "hai.ai");
    assert_eq!(parsed.jacs_agent_id, agent_id);
    assert_eq!(parsed.alg, "SHA-256");
    assert!(matches!(parsed.enc, dns::DigestEncoding::Base64));
    assert_eq!(parsed.digest, digest);
}

#[test]
fn test_build_and_parse_txt_hex() {
    let agent_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    let digest = "2cf216e19b7c9b9275cb764097b367dbb4334a80586788d9ecc17f5e951461a2";
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
    assert!(plain.contains("IN TXT \"v=hai.ai;"));
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
    assert!(err.contains("embedded fingerprint mismatch"));
}
