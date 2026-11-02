//! Regression tests for MIME parts that no JACS email signature covers.
//!
//! A JACS email signature covers the selected text/plain body, the selected
//! text/html body (attachment transport only) and every attachment. Mail
//! clients can still show any other MIME leaf part. Each test takes mail in a
//! real producer's shape (HAI hosted delivery, the haiai SDK composers and the
//! JACS signer itself), adds one such part after signing, and checks that
//! verification fails and that signing refuses the part. The unmodified
//! producer shapes keep verifying.

use base64::Engine as _;
use serial_test::serial;
use sha2::{Digest as _, Sha256};

use crate::email::{
    EMAIL_TEST_MUTEX, EmailError, EmailVerificationReason, EmailVerificationStatus, FieldStatus,
    HAI_BANNER_CONTENT_DISPOSITION, HAI_BANNER_CONTENT_ID_HEADER, HAI_BANNER_CONTENT_TYPE,
    HAI_BANNER_FILENAME, HAI_LOGO_CID, HAI_LOGO_CONTENT_DISPOSITION, HAI_LOGO_CONTENT_ID_HEADER,
    HAI_LOGO_CONTENT_TYPE, HAI_LOGO_FILENAME, InlineEmailTemplateVersion, VerificationMode,
    add_jacs_attachment_named, build_html_inline_email_signature_payload,
    embed_jacs_header_in_logo_png, escape_html_attr, escape_html_text,
    extract_topmost_inline_jacs_envelope, get_jacs_attachment_named, remove_jacs_attachment_named,
    render_inline_email_message_main, sign_email, sign_email_named_with_extras, verify_email,
    verify_email_named, verify_html_inline_email_content, verify_html_inline_email_document,
    verify_signed_email,
};
use crate::simple::SimpleAgent;

const HAI_SIGNATURE_FILENAME: &str = "hai.ai.signature.jacs.yaml";
const VERIFY_URL: &str = "https://hai.ai/verify/2f7c1d0e-unsigned-parts-test";
const ALT: &str = "hai-inline-alt-test";
const REL: &str = "hai-inline-rel-test";
const PAYMENT: &str = "Updated payment details: account 12-34-56. Please pay today.";

struct Signer {
    agent: SimpleAgent,
    public_key: Vec<u8>,
}

fn signer() -> Signer {
    let (agent, _info) =
        SimpleAgent::ephemeral(Some("ed25519")).expect("create ephemeral Ed25519 agent");
    let public_key = agent.get_public_key().expect("ephemeral public key");
    Signer { agent, public_key }
}

fn sha256_label(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn png(rgba: [u8; 4]) -> Vec<u8> {
    let image = image::RgbaImage::from_pixel(64, 64, image::Rgba(rgba));
    let mut bytes = Vec::new();
    image
        .write_to(
            &mut std::io::Cursor::new(&mut bytes),
            image::ImageFormat::Png,
        )
        .expect("encode png");
    bytes
}

fn base64_lines(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD
        .encode(bytes)
        .as_bytes()
        .chunks(76)
        .map(|chunk| {
            format!(
                "{}\r\n",
                std::str::from_utf8(chunk).expect("base64 is ASCII")
            )
        })
        .collect()
}

fn push_base64_attachment(
    email: &mut String,
    boundary: &str,
    content_type: &str,
    filename: &str,
    bytes: &[u8],
) {
    email.push_str(&format!("--{boundary}\r\n"));
    email.push_str(&format!(
        "Content-Type: {content_type}; name=\"{filename}\"\r\n"
    ));
    email.push_str(&format!(
        "Content-Disposition: attachment; filename=\"{filename}\"\r\n"
    ));
    email.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
    email.push_str(&base64_lines(bytes));
}

fn push_inline_image(
    email: &mut String,
    boundary: &str,
    content_type: &str,
    filename: &str,
    content_id_header: &str,
    disposition: &str,
    bytes: &[u8],
) {
    email.push_str(&format!("--{boundary}\r\n"));
    email.push_str(&format!(
        "Content-Type: {content_type}; name=\"{filename}\"\r\n"
    ));
    email.push_str(&format!("Content-ID: {content_id_header}\r\n"));
    email.push_str(&format!(
        "Content-Disposition: {disposition}; filename=\"{filename}\"\r\n"
    ));
    email.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
    email.push_str(&base64_lines(bytes));
}

/// Insert `part` (its headers, a blank line and its body) as the last part of
/// the multipart whose boundary is `boundary`.
fn append_part_to(raw: &[u8], boundary: &str, part: &str) -> Vec<u8> {
    let text = String::from_utf8(raw.to_vec()).expect("test mail is UTF-8");
    let closing = format!("--{boundary}--");
    let at = text.rfind(&closing).expect("closing boundary");
    format!("{}--{boundary}\r\n{part}\r\n{}", &text[..at], &text[at..]).into_bytes()
}

/// Insert `part` as the last part of the message's top-level multipart.
fn append_part(raw: &[u8], part: &str) -> Vec<u8> {
    use mail_parser::MimeHeaders as _;
    let message = mail_parser::MessageParser::default()
        .parse(raw)
        .expect("parse test mail");
    let boundary = message
        .content_type()
        .and_then(|ct| ct.attribute("boundary"))
        .expect("top-level multipart boundary")
        .to_string();
    append_part_to(raw, &boundary, part)
}

/// Parts a sender's signature does not cover, as an attacker or a list
/// gateway could add them after signing, with the start of the description
/// verification reports for each.
fn added_parts() -> Vec<(&'static str, String, &'static str)> {
    vec![
        (
            "second text/plain",
            format!("Content-Type: text/plain; charset=utf-8\r\n\r\n{PAYMENT}"),
            "text/plain part, 60 bytes",
        ),
        (
            "second text/html",
            format!("Content-Type: text/html; charset=utf-8\r\n\r\n<p>{PAYMENT}</p>"),
            "text/html part, 67 bytes",
        ),
        (
            "text/plain attachment without filename",
            format!(
                "Content-Type: text/plain; charset=utf-8\r\nContent-Disposition: attachment\r\n\r\n{PAYMENT}"
            ),
            "text/plain part, disposition attachment,",
        ),
        (
            "image without filename",
            format!(
                "Content-Type: image/png\r\nContent-ID: <payment-qr@example.com>\r\nContent-Transfer-Encoding: base64\r\n\r\n{}",
                base64_lines(&png([200, 30, 30, 255])).trim_end()
            ),
            "image/png part, Content-ID <payment-qr@example.com>,",
        ),
        (
            "message/rfc822",
            format!(
                "Content-Type: message/rfc822\r\n\r\nFrom: billing@example.com\r\nTo: recipient@example.com\r\nSubject: New account\r\n\r\n{PAYMENT}"
            ),
            "message/rfc822 part,",
        ),
        (
            "part without Content-Type",
            format!("Content-Transfer-Encoding: 7bit\r\n\r\n{PAYMENT}"),
            "part without Content-Type,",
        ),
    ]
}

fn failing_fields(result: &crate::email::ContentVerificationResult) -> Vec<String> {
    result
        .field_results
        .iter()
        .filter(|field| field.status == FieldStatus::Fail)
        .map(|field| field.field.clone())
        .collect()
}

fn assert_reported(result: &crate::email::ContentVerificationResult, expected: &str, label: &str) {
    assert_eq!(failing_fields(result), vec!["unsigned_parts[0]"], "{label}");
    let reported = result
        .field_results
        .iter()
        .find(|field| field.field == "unsigned_parts[0]")
        .and_then(|field| field.current_value.clone())
        .unwrap_or_default();
    assert!(
        reported.starts_with(expected) && reported.ends_with("not covered by the signature"),
        "{label}: {reported}"
    );
}

fn assert_no_unsigned_parts(raw: &[u8], label: &str) {
    let parts = crate::email::extract_email_parts(raw).expect("parse producer mail");
    assert!(
        parts.unsigned_parts.is_empty(),
        "{label}: {:?}",
        parts.unsigned_parts
    );
}

fn second_logo_part() -> String {
    format!(
        "Content-Type: image/png; name=\"{HAI_LOGO_FILENAME}\"\r\nContent-ID: {HAI_LOGO_CONTENT_ID_HEADER}\r\nContent-Disposition: inline; filename=\"{HAI_LOGO_FILENAME}\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}",
        base64_lines(&png([200, 30, 30, 255])).trim_end()
    )
}

// ---------------------------------------------------------------------------
// Producer shapes
// ---------------------------------------------------------------------------

/// HAI hosted delivery, attachment transport
/// (`build_hosted_rfc5322_with_json_attachment` in hai `api/src/hosted/delivery.rs`).
fn hai_attachment_message(
    html: Option<&str>,
    agent_envelope: &str,
    extra_json: Option<(&[u8], &str)>,
) -> Vec<u8> {
    let body = "Hello from a hosted HAI agent.\n\nSecond paragraph.";
    let mut email = String::new();
    email.push_str("From: <agent@hai.ai>\r\nTo: recipient@example.com\r\n");
    email.push_str("Subject: Hosted attachment delivery\r\n");
    email.push_str("Date: Sun, 01 Nov 2026 12:00:00 +0000\r\n");
    email.push_str("Message-ID: <hosted-attachment@hai.ai>\r\nMIME-Version: 1.0\r\n");
    email.push_str("Content-Type: multipart/mixed; boundary=\"hai-hosted-test\"\r\n\r\n");
    email.push_str("--hai-hosted-test\r\n");
    match html {
        Some(html) => {
            email.push_str(
                "Content-Type: multipart/alternative; boundary=\"hai-hosted-alt-test\"\r\n\r\n",
            );
            email.push_str("--hai-hosted-alt-test\r\n");
            email.push_str("Content-Type: text/plain; charset=utf-8\r\n");
            email.push_str("Content-Transfer-Encoding: 8bit\r\n\r\n");
            email.push_str(body);
            email.push_str("\r\n--hai-hosted-alt-test\r\n");
            email.push_str("Content-Type: text/html; charset=utf-8\r\n");
            email.push_str("Content-Transfer-Encoding: 8bit\r\n\r\n");
            email.push_str(html);
            email.push_str("\r\n--hai-hosted-alt-test--\r\n");
        }
        None => {
            email.push_str("Content-Type: text/plain; charset=utf-8\r\n");
            email.push_str("Content-Transfer-Encoding: 8bit\r\n\r\n");
            email.push_str(body);
            email.push_str("\r\n");
        }
    }
    push_base64_attachment(
        &mut email,
        "hai-hosted-test",
        "application/json",
        "jacs-signature.json",
        agent_envelope.as_bytes(),
    );
    if let Some((bytes, filename)) = extra_json {
        push_base64_attachment(
            &mut email,
            "hai-hosted-test",
            "application/json",
            filename,
            bytes,
        );
    }
    email.push_str("--hai-hosted-test--\r\n");
    email.into_bytes()
}

/// HAI's attachment countersignature (`HaiSigningAuthority::sign_email`):
/// signed extras, then the JSON document re-rendered as YAML.
fn hai_countersign_attachment(raw: &[u8], hai: &Signer) -> Vec<u8> {
    let mut extras = serde_json::Map::new();
    extras.insert(
        "hai_legal".to_string(),
        serde_json::json!("hai.ai verifies the signature on the stored email record."),
    );
    extras.insert(
        "hai_signature_info".to_string(),
        serde_json::json!("Synthetic HAI countersignature for tests."),
    );
    let signed = sign_email_named_with_extras(raw, &hai.agent, HAI_SIGNATURE_FILENAME, &extras)
        .expect("HAI countersignature");
    let json = get_jacs_attachment_named(&signed, HAI_SIGNATURE_FILENAME).expect("HAI document");
    let yaml = crate::convert::jacs_to_yaml(std::str::from_utf8(&json).expect("UTF-8 document"))
        .expect("render YAML");
    let without_json =
        remove_jacs_attachment_named(&signed, HAI_SIGNATURE_FILENAME).expect("remove JSON");
    add_jacs_attachment_named(&without_json, yaml.as_bytes(), HAI_SIGNATURE_FILENAME)
        .expect("attach YAML")
}

fn hosted_agent_envelope(agent: &Signer) -> String {
    agent
        .agent
        .sign_message(&serde_json::json!({ "content_hash": "sha256:hosted-agent-test" }))
        .expect("hosted agent envelope")
        .raw
}

fn hai_signed_attachment(agent: &Signer, hai: &Signer, html: bool) -> Vec<u8> {
    let html = html.then_some("<p>Hello from a hosted HAI agent.</p><p>Second paragraph.</p>");
    hai_countersign_attachment(
        &hai_attachment_message(html, &hosted_agent_envelope(agent), None),
        hai,
    )
}

fn verify_hai_attachment(raw: &[u8], hai: &Signer) -> crate::email::ContentVerificationResult {
    verify_email_named(raw, &hai.agent, &hai.public_key, HAI_SIGNATURE_FILENAME)
        .expect("HAI countersignature document verifies")
}

fn inline_body(version: InlineEmailTemplateVersion) -> &'static str {
    match version {
        InlineEmailTemplateVersion::V1 => "Hello from a hosted HAI agent.\nSecond line.",
        InlineEmailTemplateVersion::V2 => {
            "Your Agreement is ready to review.\nhttps://example.com/conversation?view=private&lang=en#invitation-token"
        }
        InlineEmailTemplateVersion::V3 => {
            "Welcome to MediationBench practice.\nhttps://example.com/practice"
        }
    }
}

/// HAI hosted delivery, HTML-inline transport
/// (`build_hosted_inline_rfc5322_inner` in hai `api/src/hosted/delivery.rs`).
fn hai_inline_message(
    version: InlineEmailTemplateVersion,
    envelope: &str,
    logo: &[u8],
    calendar: Option<&[u8]>,
) -> Vec<u8> {
    let body = inline_body(version);
    let verify = escape_html_attr(VERIFY_URL);
    let html = format!(
        concat!(
            r#"<html data-hai-template-version="{tv}"><body>{main}"#,
            r#"<a data-hai-logo-verify-link="v1" href="{verify}"><br><br><img src="cid:{cid}" alt="HAI verification logo"></a>"#,
            r#"<script type="application/jacs+json" data-hai-jacs-envelope="v1">{envelope}</script>"#,
            r#"<footer data-hai-verify-footer="v1">This email is sent from an AI agent. Verify at "#,
            r#"<a data-hai-verify-link="v1" href="{verify}">{verify}</a></footer></body></html>"#
        ),
        tv = version.as_str(),
        main = render_inline_email_message_main(body, version),
        verify = verify,
        cid = HAI_LOGO_CID,
        envelope = envelope,
    );
    let text = format!("{body}\n\nThis email is sent from an AI agent. Verify at {VERIFY_URL}");

    let mut email = String::new();
    email.push_str("From: <agent@hai.ai>\r\nTo: recipient@example.com\r\n");
    email.push_str("Subject: Hosted inline delivery\r\n");
    email.push_str("Date: Sun, 01 Nov 2026 12:00:00 +0000\r\n");
    email.push_str("Message-ID: <hosted-inline@hai.ai>\r\nMIME-Version: 1.0\r\n");
    email.push_str(&format!(
        "Content-Type: multipart/alternative; boundary=\"{ALT}\"\r\n\r\n"
    ));
    email.push_str(&format!(
        "--{ALT}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{text}\r\n"
    ));
    email.push_str(&format!(
        "--{ALT}\r\nContent-Type: multipart/related; boundary=\"{REL}\"\r\n\r\n"
    ));
    email.push_str(&format!(
        "--{REL}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{html}\r\n"
    ));
    if version == InlineEmailTemplateVersion::V3 {
        push_inline_image(
            &mut email,
            REL,
            HAI_BANNER_CONTENT_TYPE,
            HAI_BANNER_FILENAME,
            HAI_BANNER_CONTENT_ID_HEADER,
            HAI_BANNER_CONTENT_DISPOSITION,
            &png([40, 90, 160, 255]),
        );
    }
    push_inline_image(
        &mut email,
        REL,
        HAI_LOGO_CONTENT_TYPE,
        HAI_LOGO_FILENAME,
        HAI_LOGO_CONTENT_ID_HEADER,
        HAI_LOGO_CONTENT_DISPOSITION,
        logo,
    );
    email.push_str(&format!("--{REL}--\r\n"));
    if let Some(calendar) = calendar {
        email.push_str(&format!("--{ALT}\r\n"));
        email.push_str(
            "Content-Type: text/calendar; charset=utf-8; method=PUBLISH; name=\"hai-word.ics\"\r\n",
        );
        email.push_str("Content-Disposition: inline; filename=\"hai-word.ics\"\r\n");
        email.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
        email.push_str(&base64_lines(calendar));
    }
    email.push_str(&format!("--{ALT}--\r\n"));
    email.into_bytes()
}

const CALENDAR: &[u8] = b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//HAI//Word//EN\r\nMETHOD:PUBLISH\r\nBEGIN:VEVENT\r\nUID:unsigned-parts-test@hai.ai\r\nDTSTAMP:20261101T120000Z\r\nDTSTART:20261102T120000Z\r\nSUMMARY:Check in\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

fn base_logo() -> Vec<u8> {
    png([20, 20, 20, 255])
}

/// The composed HAI inline message before HAI countersigns it: the hosted
/// agent's envelope and the unsigned logo.
fn hai_inline_composed(
    agent: &Signer,
    version: InlineEmailTemplateVersion,
    calendar: Option<&[u8]>,
) -> Vec<u8> {
    let agent_doc = hosted_agent_envelope(agent);
    let agent_hidden = serde_json::json!({
        "compactHeader": sha256_label(agent_doc.as_bytes()),
        "jacsEnvelope": serde_json::from_str::<serde_json::Value>(&agent_doc).unwrap(),
    })
    .to_string();
    hai_inline_message(version, &agent_hidden, &base_logo(), calendar)
}

/// HAI's inline countersignature (`HaiSigningAuthority::countersign_html_inline_email`):
/// sign the inline pre-image with a parent hash, replace the hidden envelope
/// and put the matching compact header in the logo.
fn hai_signed_inline(
    agent: &Signer,
    hai: &Signer,
    version: InlineEmailTemplateVersion,
    calendar: Option<&[u8]>,
) -> Vec<u8> {
    let composed = hai_inline_composed(agent, version, calendar);
    let current = extract_topmost_inline_jacs_envelope(&composed).expect("agent envelope");
    let current: serde_json::Value = serde_json::from_str(&current).unwrap();
    let agent_envelope = current["jacsEnvelope"].clone();
    let mut payload = build_html_inline_email_signature_payload(&composed).expect("inline payload");
    payload.parent_signature_hash = Some(sha256_label(
        serde_json::to_string(&agent_envelope).unwrap().as_bytes(),
    ));
    let mut payload_value = serde_json::to_value(&payload).unwrap();
    payload_value.as_object_mut().unwrap().insert(
        "hai_legal".to_string(),
        serde_json::json!("hai.ai verifies the signature on the stored email record."),
    );
    let hai_doc = hai
        .agent
        .sign_message(&payload_value)
        .expect("HAI inline countersignature")
        .raw;
    let hai_envelope: serde_json::Value = serde_json::from_str(&hai_doc).unwrap();
    let compact = sha256_label(serde_json::to_string(&hai_envelope).unwrap().as_bytes());
    let hidden = serde_json::json!({
        "compactHeader": compact,
        "jacsEnvelope": hai_envelope,
        "agentEnvelope": agent_envelope,
    })
    .to_string();
    let logo = embed_jacs_header_in_logo_png(&base_logo(), &compact)
        .expect("signed logo")
        .bytes;
    hai_inline_message(version, &hidden, &logo, calendar)
}

/// haiai `build_rfc5322_email` (Rust, Node and Go share this shape).
fn haiai_attachment_message(attachments: &[(&str, &str, &[u8])]) -> Vec<u8> {
    let body =
        "Hello from the haiai SDK.\n\nVerify this agent's reputation: https://hai.ai/agents/agent";
    let mut email = String::new();
    email.push_str("From: <agent@hai.ai>\r\nTo: recipient@example.com\r\n");
    email.push_str("Subject: haiai SDK attachment mail\r\n");
    email.push_str("Date: Sun, 01 Nov 2026 12:00:00 +0000\r\n");
    email.push_str("Message-ID: <haiai-attachment@hai.ai>\r\nMIME-Version: 1.0\r\n");
    if attachments.is_empty() {
        email.push_str("Content-Type: text/plain; charset=utf-8\r\n");
        email.push_str("Content-Transfer-Encoding: 8bit\r\n\r\n");
        email.push_str(body);
        email.push_str("\r\n");
        return email.into_bytes();
    }
    email.push_str("Content-Type: multipart/mixed; boundary=\"hai-boundary-test\"\r\n\r\n");
    email.push_str("--hai-boundary-test\r\n");
    email.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    email.push_str("Content-Transfer-Encoding: 8bit\r\n\r\n");
    email.push_str(body);
    email.push_str("\r\n");
    for (filename, content_type, bytes) in attachments {
        push_base64_attachment(
            &mut email,
            "hai-boundary-test",
            content_type,
            filename,
            bytes,
        );
    }
    email.push_str("--hai-boundary-test--\r\n");
    email.into_bytes()
}

const SDK_ATTACHMENTS: &[(&str, &str, &[u8])] = &[
    ("notes.txt", "text/plain", b"Synthetic notes\n"),
    ("report.pdf", "application/pdf", b"%PDF-1.4 synthetic\n"),
];

/// haiai `build_html_inline_rfc5322_email_with_headers` (Rust SDK).
fn haiai_inline_message(html: &str, logo: &[u8], attachments: &[(&str, &str, &[u8])]) -> Vec<u8> {
    let text = format!(
        "Hello from the haiai SDK.\nSecond line.\n\nThis email is sent from an AI agent. Verify at {VERIFY_URL}"
    );
    let mut alternative = String::new();
    alternative.push_str("--hai-alt-test\r\n");
    alternative.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    alternative.push_str("Content-Transfer-Encoding: 8bit\r\n\r\n");
    alternative.push_str(&text);
    alternative.push_str("\r\n--hai-alt-test\r\n");
    alternative.push_str(
        "Content-Type: multipart/related; boundary=\"hai-related-test\"; type=\"text/html\"\r\n\r\n",
    );
    alternative.push_str("--hai-related-test\r\n");
    alternative.push_str("Content-Type: text/html; charset=utf-8\r\n");
    alternative.push_str("Content-Transfer-Encoding: 8bit\r\n\r\n");
    alternative.push_str(html);
    alternative.push_str("\r\n");
    push_inline_image(
        &mut alternative,
        "hai-related-test",
        HAI_LOGO_CONTENT_TYPE,
        HAI_LOGO_FILENAME,
        HAI_LOGO_CONTENT_ID_HEADER,
        "inline",
        logo,
    );
    alternative.push_str("--hai-related-test--\r\n--hai-alt-test--\r\n");

    let mut email = String::new();
    email.push_str("From: <agent@hai.ai>\r\nTo: recipient@example.com\r\n");
    email.push_str("Subject: haiai SDK inline mail\r\n");
    email.push_str("Date: Sun, 01 Nov 2026 12:00:00 +0000\r\n");
    email.push_str("Message-ID: <haiai-inline@hai.ai>\r\nMIME-Version: 1.0\r\n");
    if attachments.is_empty() {
        email.push_str("Content-Type: multipart/alternative; boundary=\"hai-alt-test\"\r\n\r\n");
        email.push_str(&alternative);
        return email.into_bytes();
    }
    email.push_str("Content-Type: multipart/mixed; boundary=\"hai-mixed-test\"\r\n\r\n");
    email.push_str("--hai-mixed-test\r\n");
    email.push_str("Content-Type: multipart/alternative; boundary=\"hai-alt-test\"\r\n\r\n");
    email.push_str(&alternative);
    for (filename, content_type, bytes) in attachments {
        push_base64_attachment(&mut email, "hai-mixed-test", content_type, filename, bytes);
    }
    email.push_str("--hai-mixed-test--\r\n");
    email.into_bytes()
}

/// haiai `render_html_inline_email_body` with the logo linked (no `<br><br>`).
fn haiai_inline_html(envelope: &str) -> String {
    let verify = escape_html_attr(VERIFY_URL);
    format!(
        concat!(
            r#"<html data-hai-template-version="v1"><body>"#,
            r#"<main data-hai-message-body="v1">{body}</main>"#,
            r#"<a data-hai-logo-verify-link="v1" href="{verify}"><img src="cid:{cid}" alt="HAI verification logo"></a>"#,
            r#"<script type="application/jacs+json" data-hai-jacs-envelope="v1">{envelope}</script>"#,
            r#"<footer data-hai-verify-footer="v1">This email is sent from an AI agent. Verify at "#,
            r#"<a data-hai-verify-link="v1" href="{verify}">{verify}</a></footer></body></html>"#
        ),
        body = escape_html_text("Hello from the haiai SDK.\nSecond line.").replace('\n', "<br>"),
        verify = verify,
        cid = HAI_LOGO_CID,
        envelope = envelope,
    )
}

/// The haiai SDK inline flow: sign the placeholder pre-image, then compose the
/// final message with the hidden envelope and the signed logo.
fn haiai_signed_inline(agent: &Signer, attachments: &[(&str, &str, &[u8])]) -> Vec<u8> {
    let placeholder = haiai_inline_message(&haiai_inline_html("{}"), &base_logo(), attachments);
    let payload = build_html_inline_email_signature_payload(&placeholder).expect("inline payload");
    let doc = agent
        .agent
        .sign_message(&serde_json::to_value(payload).unwrap())
        .expect("SDK inline signature")
        .raw;
    let compact = sha256_label(doc.as_bytes());
    let hidden = serde_json::json!({
        "compactHeader": compact,
        "jacsEnvelope": serde_json::from_str::<serde_json::Value>(&doc).unwrap(),
    })
    .to_string();
    let logo = embed_jacs_header_in_logo_png(&base_logo(), &compact)
        .expect("signed logo")
        .bytes;
    haiai_inline_message(&haiai_inline_html(&hidden), &logo, attachments)
}

/// Output of haiai `python/src/haiai/mime.py` `build_rfc5322_email`, produced
/// by the Python standard library with a fixed boundary, date and Message-ID.
const PYTHON_SDK_MESSAGE: &[u8] = b"Content-Type: multipart/mixed;\r\n boundary=\"===============haiai-python-fixture==\"\r\nMIME-Version: 1.0\r\nFrom: agent@hai.ai\r\nTo: recipient@example.com\r\nSubject: Python SDK composer fixture\r\nDate: Sun, 01 Nov 2026 12:00:00 GMT\r\nMessage-ID: <python-sdk-fixture@hai.ai>\r\nMIME-Version: 1.0\r\n\r\n--===============haiai-python-fixture==\r\nContent-Type: text/plain; charset=\"utf-8\"\r\nMIME-Version: 1.0\r\nContent-Transfer-Encoding: base64\r\n\r\nU3ludGhldGljIGJvZHkgZnJvbSB0aGUgUHl0aG9uIFNESyBjb21wb3Nlci4=\r\n\r\n--===============haiai-python-fixture==\r\nContent-Type: text/plain\r\nMIME-Version: 1.0\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"notes.txt\"\r\n\r\nU3ludGhldGljIG5vdGVzCg==\r\n\r\n--===============haiai-python-fixture==\r\nContent-Type: application/pdf\r\nMIME-Version: 1.0\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"report.pdf\"\r\n\r\nJVBERi0xLjQgc3ludGhldGljCg==\r\n\r\n--===============haiai-python-fixture==--\r\n";

fn assert_inline_verified(raw: &[u8], signer: &Signer, label: &str) {
    let result = verify_signed_email(
        raw,
        &signer.agent,
        &signer.public_key,
        VerificationMode::Strict,
    )
    .expect("inline verification runs");
    assert_eq!(
        result.status,
        EmailVerificationStatus::Verified,
        "{label}: {result:?}"
    );
    let (doc, parts) =
        verify_html_inline_email_document(raw, &signer.agent, &signer.public_key).unwrap();
    let content = verify_html_inline_email_content(&doc, &parts);
    assert!(content.valid, "{label}: {:?}", content.field_results);
}

// ---------------------------------------------------------------------------
// Attachment transport
// ---------------------------------------------------------------------------

#[test]
#[serial(jacs_env)]
fn unsigned_parts_attachment_transport_added_parts_fail_verification() {
    let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let agent = signer();
    let hai = signer();
    let countersigned = hai_signed_attachment(&agent, &hai, true);
    assert!(verify_hai_attachment(&countersigned, &hai).valid);
    let sdk_signed = sign_email(&haiai_attachment_message(SDK_ATTACHMENTS), &agent.agent).unwrap();

    let mut still_verified = Vec::new();
    for (name, part, expected) in added_parts() {
        let result = verify_hai_attachment(&append_part(&countersigned, &part), &hai);
        println!(
            "HAI countersigned attachment + {name}: valid={}",
            result.valid
        );
        if result.valid {
            still_verified.push(format!("HAI countersigned + {name}"));
        } else {
            assert_reported(&result, expected, name);
        }

        let tampered = append_part(&sdk_signed, &part);
        let result = verify_signed_email(
            &tampered,
            &agent.agent,
            &agent.public_key,
            VerificationMode::Strict,
        )
        .unwrap();
        println!("SDK attachment + {name}: {:?}", result.status);
        if result.status != EmailVerificationStatus::Failed {
            still_verified.push(format!("SDK attachment + {name}"));
        } else {
            assert_eq!(
                result.reasons,
                vec![EmailVerificationReason::CanonicalPreimageHashMismatch]
            );
            let content = verify_email(&tampered, &agent.agent, &agent.public_key).unwrap();
            if name == "second text/html" {
                // The SDK message is text-only, so this part becomes its HTML body.
                assert_eq!(failing_fields(&content), vec!["body_html"], "{name}");
            } else {
                assert_reported(&content, expected, name);
            }
        }
    }
    assert!(
        still_verified.is_empty(),
        "added parts that still verify: {still_verified:?}"
    );
}

#[test]
#[serial(jacs_env)]
fn unsigned_parts_attachment_transport_unsigned_html_body_fails_verification() {
    let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let agent = signer();
    let hai = signer();
    let text_only = hai_signed_attachment(&agent, &hai, false);
    assert!(verify_hai_attachment(&text_only, &hai).valid);

    let with_html = append_part(
        &text_only,
        &format!("Content-Type: text/html; charset=utf-8\r\n\r\n<p>{PAYMENT}</p>"),
    );
    let result = verify_hai_attachment(&with_html, &hai);
    println!(
        "text-only HAI attachment + text/html: valid={} fields={:?}",
        result.valid,
        result
            .field_results
            .iter()
            .map(|f| (&f.field, &f.status))
            .collect::<Vec<_>>()
    );
    assert!(!result.valid, "an unsigned HTML body still verifies");
    let html = result
        .field_results
        .iter()
        .find(|f| f.field == "body_html")
        .expect("body_html result");
    assert_eq!(html.status, FieldStatus::Fail);
    assert_eq!(failing_fields(&result), vec!["body_html"]);
    assert_eq!(
        html.current_value.as_deref(),
        Some("present but not signed")
    );
    assert!(html.original_hash.is_none() && html.current_hash.is_some());
}

#[test]
#[serial(jacs_env)]
fn unsigned_parts_sign_email_refuses_parts_it_cannot_cover() {
    let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let agent = signer();
    let base = hai_attachment_message(
        Some("<p>Hello from a hosted HAI agent.</p>"),
        &hosted_agent_envelope(&agent),
        None,
    );

    let mut accepted = Vec::new();
    for (name, part, expected) in added_parts() {
        match sign_email(&append_part(&base, &part), &agent.agent) {
            Err(EmailError::UnsupportedFeature(message)) => {
                println!("sign_email + {name}: refused: {message}");
                assert!(
                    message.starts_with(
                        "email has 1 MIME part that is neither a body nor an attachment; first: "
                    ) && message.contains(expected),
                    "{name}: {message}"
                );
            }
            Err(other) => panic!("{name}: unexpected error {other}"),
            Ok(_) => {
                println!("sign_email + {name}: signed");
                accepted.push(name);
            }
        }
    }
    assert!(accepted.is_empty(), "signing accepted: {accepted:?}");

    let all_parts = added_parts()
        .into_iter()
        .fold(base, |raw, (_, part, _)| append_part(&raw, &part));
    match sign_email(&all_parts, &agent.agent).map(|_| ()) {
        Err(EmailError::UnsupportedFeature(message)) => assert!(
            message.starts_with(
                "email has 6 MIME parts that are neither a body nor an attachment; first: text/plain part,"
            ),
            "{message}"
        ),
        other => panic!("six added parts: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// HTML-inline transport
// ---------------------------------------------------------------------------

const INLINE_VERSIONS: [InlineEmailTemplateVersion; 3] = [
    InlineEmailTemplateVersion::V1,
    InlineEmailTemplateVersion::V2,
    InlineEmailTemplateVersion::V3,
];

#[test]
#[serial(jacs_env)]
fn unsigned_parts_inline_transport_added_parts_fail_verification() {
    let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let agent = signer();
    let hai = signer();

    let mut still_verified = Vec::new();
    for version in INLINE_VERSIONS {
        let signed = hai_signed_inline(&agent, &hai, version, None);
        assert_inline_verified(&signed, &hai, version.as_str());

        let mut cases: Vec<(&str, Vec<u8>, &str)> = added_parts()
            .into_iter()
            .map(|(name, part, expected)| (name, append_part(&signed, &part), expected))
            .collect();
        cases.push((
            "second HAI logo part",
            append_part_to(&signed, REL, &second_logo_part()),
            "",
        ));

        for (name, tampered, expected) in cases {
            let strict = verify_signed_email(
                &tampered,
                &hai.agent,
                &hai.public_key,
                VerificationMode::Strict,
            )
            .unwrap();
            let (doc, parts) =
                verify_html_inline_email_document(&tampered, &hai.agent, &hai.public_key).unwrap();
            let content = verify_html_inline_email_content(&doc, &parts);
            println!(
                "inline {} + {name}: strict={:?} content_valid={}",
                version.as_str(),
                strict.status,
                content.valid
            );
            if strict.status != EmailVerificationStatus::Failed || content.valid {
                still_verified.push(format!("{} + {name}", version.as_str()));
            } else {
                assert_eq!(
                    strict.reasons,
                    vec![EmailVerificationReason::CanonicalPreimageHashMismatch]
                );
                if expected.is_empty() {
                    // The second logo stays an attachment the signature does not list.
                    assert_eq!(failing_fields(&content), vec!["attachments"], "{name}");
                } else {
                    assert_reported(&content, expected, name);
                }
            }
        }
    }
    assert!(
        still_verified.is_empty(),
        "added parts that still verify: {still_verified:?}"
    );
}

#[test]
#[serial(jacs_env)]
fn unsigned_parts_inline_text_body_added_to_html_only_signature_fails() {
    let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let signer = signer();
    let version = InlineEmailTemplateVersion::V1;
    let text_part = format!(
        "--{ALT}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{}\n\nThis email is sent from an AI agent. Verify at {VERIFY_URL}\r\n",
        inline_body(version)
    );
    let without_text = |raw: Vec<u8>| -> Vec<u8> {
        let text = String::from_utf8(raw).unwrap();
        assert_eq!(text.matches(&text_part).count(), 1);
        text.replacen(&text_part, "", 1).into_bytes()
    };

    let pre_image = without_text(hai_inline_message(version, "{}", &base_logo(), None));
    let payload = build_html_inline_email_signature_payload(&pre_image).unwrap();
    assert!(payload.body_plain.is_none());
    let doc = signer
        .agent
        .sign_message(&serde_json::to_value(payload).unwrap())
        .unwrap()
        .raw;
    let compact = sha256_label(doc.as_bytes());
    let hidden = serde_json::json!({
        "compactHeader": compact,
        "jacsEnvelope": serde_json::from_str::<serde_json::Value>(&doc).unwrap(),
    })
    .to_string();
    let logo = embed_jacs_header_in_logo_png(&base_logo(), &compact)
        .unwrap()
        .bytes;
    let received = hai_inline_message(version, &hidden, &logo, None);

    let (doc, parts) =
        verify_html_inline_email_document(&received, &signer.agent, &signer.public_key).unwrap();
    let content = verify_html_inline_email_content(&doc, &parts);
    println!(
        "html-only inline signature + text/plain: valid={}",
        content.valid
    );
    assert!(!content.valid, "an unsigned text body still verifies");
    let text = content
        .field_results
        .iter()
        .find(|f| f.field == "body_plain")
        .expect("body_plain result");
    assert_eq!(text.status, FieldStatus::Fail);
    assert_eq!(failing_fields(&content), vec!["body_plain"]);

    let (doc, parts) = verify_html_inline_email_document(
        &without_text(received),
        &signer.agent,
        &signer.public_key,
    )
    .unwrap();
    assert!(verify_html_inline_email_content(&doc, &parts).valid);
}

#[test]
#[serial(jacs_env)]
fn unsigned_parts_inline_signing_refuses_parts_it_cannot_cover() {
    let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let agent = signer();
    let composed = hai_inline_composed(&agent, InlineEmailTemplateVersion::V1, None);

    let mut cases: Vec<(&str, Vec<u8>, &str)> = added_parts()
        .into_iter()
        .map(|(name, part, expected)| (name, append_part(&composed, &part), expected))
        .collect();
    cases.push((
        "second HAI logo part",
        append_part_to(&composed, REL, &second_logo_part()),
        "inline email has 2 HAI logo parts; the transport adds exactly one",
    ));

    let mut accepted = Vec::new();
    for (name, raw, expected) in cases {
        match build_html_inline_email_signature_payload(&raw) {
            Err(EmailError::UnsupportedFeature(message)) => {
                println!("inline payload + {name}: refused: {message}");
                assert!(message.contains(expected), "{name}: {message}");
            }
            Err(other) => panic!("{name}: unexpected error {other}"),
            Ok(_) => {
                println!("inline payload + {name}: built");
                accepted.push(name);
            }
        }
    }
    assert!(accepted.is_empty(), "inline signing accepted: {accepted:?}");
}

// ---------------------------------------------------------------------------
// Producer shapes keep verifying
// ---------------------------------------------------------------------------

#[test]
#[serial(jacs_env)]
fn unsigned_parts_hai_attachment_shapes_verify() {
    let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let agent = signer();
    let hai = signer();
    let envelope = hosted_agent_envelope(&agent);
    let resolution = br#"{"jacsId":"resolution-test","note":"synthetic"}"#;

    for (label, raw) in [
        ("text", hai_attachment_message(None, &envelope, None)),
        (
            "text and html",
            hai_attachment_message(Some("<p>Hello.</p>"), &envelope, None),
        ),
        (
            "resolution artifact",
            hai_attachment_message(
                None,
                &envelope,
                Some((resolution, "resolution-0b9c2e7a.json")),
            ),
        ),
    ] {
        assert_no_unsigned_parts(&raw, label);
        let countersigned = hai_countersign_attachment(&raw, &hai);
        assert_no_unsigned_parts(&countersigned, label);
        let result = verify_hai_attachment(&countersigned, &hai);
        assert!(result.valid, "{label}: {:?}", result.field_results);
    }

    // An SDK-signed attachment email that HAI then countersigns.
    let sdk_signed = sign_email(&haiai_attachment_message(SDK_ATTACHMENTS), &agent.agent).unwrap();
    let result = verify_hai_attachment(&hai_countersign_attachment(&sdk_signed, &hai), &hai);
    assert!(result.valid, "SDK then HAI: {:?}", result.field_results);
}

#[test]
#[serial(jacs_env)]
fn unsigned_parts_hai_inline_shapes_verify() {
    let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let agent = signer();
    let hai = signer();
    for version in INLINE_VERSIONS {
        assert_no_unsigned_parts(
            &hai_inline_composed(&agent, version, None),
            version.as_str(),
        );
        let signed = hai_signed_inline(&agent, &hai, version, None);
        assert_no_unsigned_parts(&signed, version.as_str());
        assert_inline_verified(&signed, &hai, version.as_str());
    }
    let with_calendar =
        hai_signed_inline(&agent, &hai, InlineEmailTemplateVersion::V1, Some(CALENDAR));
    assert_inline_verified(&with_calendar, &hai, "v1 with calendar");
}

#[test]
#[serial(jacs_env)]
fn unsigned_parts_sdk_shapes_verify() {
    let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let agent = signer();

    for (label, raw) in [
        ("haiai text", haiai_attachment_message(&[])),
        (
            "haiai attachments",
            haiai_attachment_message(SDK_ATTACHMENTS),
        ),
        ("haiai Python", PYTHON_SDK_MESSAGE.to_vec()),
    ] {
        assert_no_unsigned_parts(&raw, label);
        let signed = sign_email(&raw, &agent.agent).expect("sign SDK mail");
        assert_no_unsigned_parts(&signed, label);
        let result = verify_signed_email(
            &signed,
            &agent.agent,
            &agent.public_key,
            VerificationMode::Strict,
        )
        .unwrap();
        assert_eq!(
            result.status,
            EmailVerificationStatus::Verified,
            "{label}: {result:?}"
        );
    }

    assert_inline_verified(&haiai_signed_inline(&agent, &[]), &agent, "haiai inline");
    assert_inline_verified(
        &haiai_signed_inline(&agent, SDK_ATTACHMENTS),
        &agent,
        "haiai inline with attachments",
    );
}

#[test]
#[serial(jacs_env)]
fn unsigned_parts_forwarded_and_relayed_mail_still_verifies() {
    let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let first = signer();
    let second = signer();

    let signed = sign_email(&haiai_attachment_message(SDK_ATTACHMENTS), &first.agent).unwrap();
    let forwarded = sign_email(&signed, &second.agent).expect("forward re-sign");
    let result = verify_email(&forwarded, &second.agent, &second.public_key).unwrap();
    assert!(
        result
            .field_results
            .iter()
            .all(|field| field.status != FieldStatus::Fail),
        "forwarded fields: {:?}",
        result.field_results
    );
    assert_eq!(result.chain.len(), 2);

    // Preamble and epilogue text is not a MIME part.
    let text = String::from_utf8(signed).unwrap();
    let relayed = text
        .replacen(
            "\r\n\r\n--hai-boundary-test\r\n",
            "\r\n\r\nThis is a multi-part message in MIME format.\r\n\r\n--hai-boundary-test\r\n",
            1,
        )
        .replace(
            "--hai-boundary-test--\r\n",
            "--hai-boundary-test--\r\nEpilogue added by a relay.\r\n",
        );
    assert!(relayed.contains("This is a multi-part message"));
    let result = verify_email(relayed.as_bytes(), &first.agent, &first.public_key).unwrap();
    assert!(result.valid, "relayed: {:?}", result.field_results);
}

#[test]
fn unsigned_parts_checked_in_email_fixtures_have_none() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/email");
    let mut checked = 0;
    for dir in ["fixtures", "html_inline"] {
        let mut paths: Vec<_> = std::fs::read_dir(root.join(dir))
            .expect("fixture directory")
            .map(|entry| entry.expect("fixture entry").path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "eml"))
            .collect();
        paths.sort();
        for path in paths {
            let raw = std::fs::read(&path).expect("read fixture");
            let parts = crate::email::extract_email_parts(&raw)
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            assert!(
                parts.unsigned_parts.is_empty(),
                "{}: {:?}",
                path.display(),
                parts.unsigned_parts
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 36, "every checked-in .eml fixture was parsed");
}

/// The haiai SDKs do not require attachment filenames. A text attachment with
/// an empty filename was never covered by the signature; signing now refuses
/// it. Other attachment types with an empty filename stay signed attachments.
#[test]
#[serial(jacs_env)]
fn unsigned_parts_sdk_attachment_with_empty_filename() {
    let _lock = EMAIL_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let agent = signer();

    let text = haiai_attachment_message(&[("", "text/plain", b"Synthetic notes\n")]);
    match sign_email(&text, &agent.agent).map(|_| ()) {
        Err(EmailError::UnsupportedFeature(message)) => assert!(
            message.contains("text/plain part, disposition attachment,"),
            "{message}"
        ),
        other => panic!("text attachment without a filename: {other:?}"),
    }

    let pdf = haiai_attachment_message(&[("", "application/pdf", b"%PDF-1.4 synthetic\n")]);
    assert_no_unsigned_parts(&pdf, "PDF attachment without a filename");
    let signed = sign_email(&pdf, &agent.agent).expect("sign PDF attachment");
    let result = verify_email(&signed, &agent.agent, &agent.public_key).unwrap();
    assert!(result.valid, "{:?}", result.field_results);
}
