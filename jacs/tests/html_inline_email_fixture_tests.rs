use jacs::email::{SignedEmailTransport, detect_signed_email_transport, extract_email_parts};

const FIXTURES: &[(&str, &str)] = &[
    (
        "plain_text",
        "tests/fixtures/email/html_inline/01_plain_text.eml",
    ),
    (
        "text_with_attachment",
        "tests/fixtures/email/html_inline/02_text_with_attachment.eml",
    ),
    (
        "generated_html",
        "tests/fixtures/email/html_inline/03_generated_html.eml",
    ),
    (
        "reply_with_quoted_markers",
        "tests/fixtures/email/html_inline/04_reply_with_quoted_markers.eml",
    ),
    (
        "missing_logo",
        "tests/fixtures/email/html_inline/05_missing_logo.eml",
    ),
    (
        "stripped_logo",
        "tests/fixtures/email/html_inline/06_stripped_logo.eml",
    ),
    (
        "mismatched_logo",
        "tests/fixtures/email/html_inline/07_mismatched_logo.eml",
    ),
    (
        "tampered_body",
        "tests/fixtures/email/html_inline/08_tampered_body.eml",
    ),
];

#[test]
fn html_inline_email_fixtures_are_parseable_rfc5322() {
    for (name, path) in FIXTURES {
        let raw = std::fs::read(path).unwrap_or_else(|err| panic!("{name}: read {path}: {err}"));
        let parts = extract_email_parts(&raw).unwrap_or_else(|err| panic!("{name}: parse: {err}"));

        assert!(parts.headers.contains_key("from"), "{name}: missing From");
        assert!(parts.headers.contains_key("to"), "{name}: missing To");
        assert!(
            parts.headers.contains_key("subject"),
            "{name}: missing Subject"
        );
        assert!(parts.body_plain.is_some(), "{name}: missing text body");
    }
}

#[test]
fn html_inline_attachment_fixture_has_user_attachment() {
    let raw = std::fs::read("tests/fixtures/email/html_inline/02_text_with_attachment.eml")
        .expect("read attachment fixture");
    let parts = extract_email_parts(&raw).expect("parse attachment fixture");

    assert_eq!(parts.attachments.len(), 1);
    assert_eq!(parts.attachments[0].filename, "notes.txt");
}

#[test]
fn signed_email_transport_detection_classifies_attachment_and_inline_modes() {
    let attachment = std::fs::read("tests/fixtures/email/fixtures/01_canonical_baseline.eml")
        .expect("read attachment fixture");
    let inline = std::fs::read("tests/fixtures/email/html_inline/03_generated_html.eml")
        .expect("read html inline fixture");

    assert_eq!(
        detect_signed_email_transport(&attachment).expect("detect attachment transport"),
        SignedEmailTransport::AttachmentJacs
    );
    assert_eq!(
        detect_signed_email_transport(&inline).expect("detect inline transport"),
        SignedEmailTransport::HtmlInline
    );
}
