//! Inspect real attachment-mode email signing with disposable in-memory keys.
//! No config files, mail delivery, remote key lookup or user keys are used.

use jacs::email::{FieldStatus, get_jacs_attachment, sign_email, verify_email};
use jacs::simple::SimpleAgent;
use serde_json::Value;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (sender, _) = SimpleAgent::ephemeral(Some("ed25519"))?;
    let (recipient, _) = SimpleAgent::ephemeral(Some("ed25519"))?;
    // In this local example the key is passed directly. A real recipient must
    // establish the key's attribution separately from signature verification.
    let public_key = sender.get_public_key()?;
    let raw_email = concat!(
        "From: sender@example.test\r\n",
        "To: recipient@example.test\r\n",
        "Subject: Synthetic email provenance\r\n",
        "Date: Mon, 14 Sep 2026 12:00:00 +0000\r\n",
        "Message-ID: <synthetic-provenance@example.test>\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/mixed; boundary=synthetic-boundary\r\n\r\n",
        "--synthetic-boundary\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n\r\n",
        "Synthetic body for envelope inspection.\r\n",
        "--synthetic-boundary\r\n",
        "Content-Type: application/octet-stream; name=receipt.txt\r\n",
        "Content-Disposition: attachment; filename=receipt.txt\r\n\r\n",
        "Synthetic receipt\r\n",
        "--synthetic-boundary--\r\n",
    );

    let signed_email = sign_email(raw_email.as_bytes(), &sender)?;
    let result = verify_email(&signed_email, &recipient, &public_key)?;
    assert!(result.valid, "synthetic email must verify: {result:?}");
    let attachment = get_jacs_attachment(&signed_email)?;
    let document: Value = serde_json::from_slice(&attachment)?;
    assert!(document["content"]["headers"].is_object());
    assert_eq!(
        document["content"]["attachments"][0]["filename"],
        "receipt.txt"
    );
    assert!(document["jacsSignature"]["signature"].is_string());
    assert!(document.get("payload").is_none());
    println!("Actual signed attachment (synthetic data only):");
    println!("{}", std::str::from_utf8(&attachment)?);
    println!(
        "Field verification: {}",
        serde_json::to_string_pretty(&result)?
    );

    let tampered = std::str::from_utf8(&signed_email)?.replacen(
        "Synthetic body for envelope inspection.",
        "Changed body for envelope inspection.",
        1,
    );
    assert_ne!(tampered.as_bytes(), signed_email.as_slice());
    let tampered_result = verify_email(tampered.as_bytes(), &recipient, &public_key)?;
    assert!(!tampered_result.valid);
    assert!(
        tampered_result
            .field_results
            .iter()
            .any(|field| { field.field == "body_plain" && field.status == FieldStatus::Fail })
    );
    assert!(verify_email(&signed_email, &recipient, &recipient.get_public_key()?).is_err());

    // Re-signing links the previous attachment bytes. The one-key email API
    // does not verify ancestors, even when this example reuses the same sender.
    let forwarded = sign_email(&signed_email, &sender)?;
    let forwarding_result = verify_email(&forwarded, &recipient, &public_key)?;
    assert!(!forwarding_result.valid);
    assert_eq!(forwarding_result.chain.len(), 2);
    assert!(forwarding_result.chain[0].valid);
    assert!(!forwarding_result.chain[1].valid);
    assert!(
        forwarding_result
            .field_results
            .iter()
            .all(|field| field.status != FieldStatus::Fail)
    );
    println!(
        "Forwarding inspection: {}",
        serde_json::to_string_pretty(&forwarding_result)?
    );
    println!("Signature checks do not establish mailbox identity, truth or human approval.");
    Ok(())
}
