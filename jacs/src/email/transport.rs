use super::canonicalize::extract_email_parts;
use super::error::EmailError;
use html5ever::interface::{Attribute, QualName};
use html5ever::tendril::StrTendril;
use html5ever::tokenizer::{
    BufferQueue, Doctype, Tag, TagKind, Token, TokenSink, TokenSinkResult, Tokenizer,
    states::RawKind,
};
use mail_parser::{MessageParser, MimeHeaders as _};
use std::cell::{Cell, RefCell};

use super::types::ParsedAttachment;

pub const HAI_JACS_ENVELOPE_MARKER: &str = "data-hai-jacs-envelope";
pub const HAI_VERIFY_FOOTER_MARKER: &str = "data-hai-verify-footer";
pub const HAI_VERIFY_LINK_MARKER: &str = "data-hai-verify-link";
pub const HAI_LOGO_VERIFY_LINK_MARKER: &str = "data-hai-logo-verify-link";
pub const HAI_JACS_ENVELOPE_SCRIPT_TYPE: &str = "application/jacs+json";
pub const HAI_JACS_ENVELOPE_SCRIPT_PREFIX: &str = "<script type=\"application/jacs+json\"";
pub const HAI_LOGO_CID: &str = "hai-jacs-logo@hai.ai";
pub const HAI_LOGO_CONTENT_ID_HEADER: &str = "<hai-jacs-logo@hai.ai>";
pub const HAI_LOGO_CONTENT_DISPOSITION: &str = "inline";
pub const HAI_LOGO_CONTENT_TYPE: &str = "image/png";
pub const HAI_LOGO_FILENAME: &str = "hai-jacs-logo.png";
pub const HAI_HIDDEN_ENVELOPE_MAX_BYTES: usize = 8 * 1024;

/// Escape plain text for insertion into HAI-owned HTML email text nodes.
pub fn escape_html_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Escape plain text for insertion into HAI-owned HTML email attribute values.
pub fn escape_html_attr(value: &str) -> String {
    escape_html_text(value)
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignedEmailTransport {
    AttachmentJacs,
    HtmlInline,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineLogoPart {
    pub content_id: String,
    pub content_type: String,
    pub content_disposition: Option<String>,
    pub size_bytes: usize,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedLogoPng {
    pub bytes: Vec<u8>,
    pub size_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrippedInlineEmailArtifacts {
    pub html_without_artifacts: String,
    pub logo_size_bytes: Option<usize>,
}

pub fn detect_signed_email_transport(raw_email: &[u8]) -> Result<SignedEmailTransport, EmailError> {
    let parts = extract_email_parts(raw_email)?;

    if !parts.jacs_attachments.is_empty() {
        return Ok(SignedEmailTransport::AttachmentJacs);
    }

    if let Some(html) = parts.body_html {
        let html = String::from_utf8_lossy(&html.content);
        if html.contains(HAI_JACS_ENVELOPE_MARKER)
            || html.contains(HAI_VERIFY_FOOTER_MARKER)
            || html.contains(HAI_VERIFY_LINK_MARKER)
            || html.contains(HAI_LOGO_CID)
        {
            return Ok(SignedEmailTransport::HtmlInline);
        }
    }

    Err(EmailError::MissingJacsSignature)
}

pub fn extract_topmost_inline_jacs_envelope(raw_email: &[u8]) -> Result<String, EmailError> {
    let parts = extract_email_parts(raw_email)?;
    let Some(html) = parts.body_html else {
        return Err(EmailError::MissingJacsSignature);
    };
    let html = String::from_utf8_lossy(&html.content);

    extract_topmost_inline_jacs_envelope_from_html(&html).ok_or(EmailError::MissingJacsSignature)
}

pub fn extract_inline_logo_part(raw_email: &[u8]) -> Result<InlineLogoPart, EmailError> {
    let message = MessageParser::default().parse(raw_email).ok_or_else(|| {
        EmailError::InvalidEmailFormat("Cannot parse email for inline logo extraction".into())
    })?;

    for part in &message.parts {
        let Some(content_id) = part.content_id().map(normalize_content_id) else {
            continue;
        };
        if content_id != HAI_LOGO_CID {
            continue;
        }

        let content_type = part
            .content_type()
            .map(|ct| format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or("")))
            .unwrap_or_default();
        let content_disposition = part.content_disposition().map(|d| d.ctype().to_string());
        if content_disposition.as_deref() != Some("inline") {
            return Err(EmailError::MissingJacsSignature);
        }

        let content = part.contents().to_vec();
        return Ok(InlineLogoPart {
            content_id,
            content_type,
            content_disposition,
            size_bytes: content.len(),
            content,
        });
    }

    Err(EmailError::MissingJacsSignature)
}

pub fn embed_jacs_header_in_logo_png(
    base_logo_png: &[u8],
    compact_jacs_header: &str,
) -> Result<SignedLogoPng, EmailError> {
    require_png_logo(base_logo_png)?;
    let robust_logo = jacs_media::embed_signature_with_format(
        jacs_media::MediaFormat::Png,
        base_logo_png,
        compact_jacs_header,
        true,
        false,
    )
    .map_err(|err| EmailError::InvalidJacsDocument(format!("logo embed failed: {err}")))?;

    let bytes = jacs_media::png::embed(&robust_logo, compact_jacs_header, false, false)
        .map_err(|err| EmailError::InvalidJacsDocument(format!("logo embed failed: {err}")))?;
    Ok(SignedLogoPng {
        size_bytes: bytes.len(),
        bytes,
    })
}

pub fn extract_jacs_header_from_logo_png(
    signed_logo_png: &[u8],
) -> Result<Option<String>, EmailError> {
    require_png_logo(signed_logo_png)?;
    jacs_media::extract_signature_with_format(jacs_media::MediaFormat::Png, signed_logo_png, true)
        .map_err(|err| EmailError::InvalidJacsDocument(format!("logo extraction failed: {err}")))
}

pub fn remove_inline_signature_artifacts(
    raw_email: &[u8],
) -> Result<StrippedInlineEmailArtifacts, EmailError> {
    let parts = extract_email_parts(raw_email)?;
    let Some(html) = parts.body_html else {
        return Err(EmailError::MissingJacsSignature);
    };
    let html = String::from_utf8_lossy(&html.content);
    let logo_size_bytes = extract_inline_logo_part(raw_email)
        .ok()
        .map(|logo| logo.size_bytes);

    Ok(StrippedInlineEmailArtifacts {
        html_without_artifacts: strip_inline_signature_artifacts_from_html(&html),
        logo_size_bytes,
    })
}

pub(crate) fn is_inline_logo_attachment_artifact(att: &ParsedAttachment) -> bool {
    att.content_type == "image/png"
        && att.filename == "hai-jacs-logo.png"
        && att.content_disposition.as_deref() == Some("inline")
}

fn require_png_logo(bytes: &[u8]) -> Result<(), EmailError> {
    match jacs_media::detect_format(bytes) {
        Ok(jacs_media::MediaFormat::Png) => Ok(()),
        Ok(other) => Err(EmailError::UnsupportedFeature(format!(
            "signed email logo transport requires PNG, got {other:?}"
        ))),
        Err(err) => Err(EmailError::InvalidEmailFormat(format!(
            "invalid signed email logo image: {err}"
        ))),
    }
}

pub fn extract_topmost_inline_jacs_envelope_from_html(html: &str) -> Option<String> {
    let input = BufferQueue::default();
    input.push_back(StrTendril::from(html));

    let tokenizer = Tokenizer::new(EnvelopeSink::default(), Default::default());
    let _ = tokenizer.feed(&input);
    tokenizer.end();

    tokenizer.sink.captured.into_inner()
}

pub fn strip_inline_signature_artifacts_from_html(html: &str) -> String {
    normalize_html(html, true)
}

pub fn normalize_html_for_equivalence(html: &str) -> String {
    normalize_html(html, false)
}

pub fn html_bodies_equivalent(expected_html: &str, received_html: &str) -> bool {
    normalize_html_for_equivalence(expected_html) == normalize_html_for_equivalence(received_html)
}

fn normalize_html(html: &str, strip_artifacts: bool) -> String {
    let input = BufferQueue::default();
    input.push_back(StrTendril::from(html));

    let tokenizer = Tokenizer::new(HtmlNormalizeSink::new(strip_artifacts), Default::default());
    let _ = tokenizer.feed(&input);
    tokenizer.end();

    tokenizer.sink.output.into_inner()
}

#[derive(Default)]
struct EnvelopeSink {
    in_target_script: Cell<bool>,
    current_script: RefCell<String>,
    captured: RefCell<Option<String>>,
}

impl TokenSink for EnvelopeSink {
    type Handle = ();

    fn process_token(&self, token: Token, _line_number: u64) -> TokenSinkResult<Self::Handle> {
        match token {
            Token::TagToken(tag)
                if tag.kind == TagKind::StartTag
                    && tag.name.as_ref() == "script"
                    && self.captured.borrow().is_none()
                    && is_jacs_envelope_script(&tag.attrs) =>
            {
                self.in_target_script.set(true);
                self.current_script.borrow_mut().clear();
                TokenSinkResult::RawData(RawKind::ScriptData)
            }
            Token::CharacterTokens(text) if self.in_target_script.get() => {
                self.current_script.borrow_mut().push_str(&text);
                TokenSinkResult::Continue
            }
            Token::TagToken(tag)
                if tag.kind == TagKind::EndTag
                    && tag.name.as_ref() == "script"
                    && self.in_target_script.get() =>
            {
                self.in_target_script.set(false);
                let body = self.current_script.borrow().trim().to_string();
                *self.captured.borrow_mut() = Some(body);
                TokenSinkResult::Continue
            }
            _ => TokenSinkResult::Continue,
        }
    }
}

fn is_jacs_envelope_script(attrs: &[Attribute]) -> bool {
    has_attr_value(attrs, "type", "application/jacs+json")
        && has_attr_value(attrs, HAI_JACS_ENVELOPE_MARKER, "v1")
}

fn has_attr_value(attrs: &[Attribute], name: &str, value: &str) -> bool {
    attrs.iter().any(|attr| {
        attr_name(&attr.name) == name && attr.value.as_ref().eq_ignore_ascii_case(value)
    })
}

fn attr_name(name: &QualName) -> &str {
    name.local.as_ref()
}

#[derive(Default)]
struct HtmlNormalizeSink {
    output: RefCell<String>,
    skip_depth: Cell<usize>,
    strip_artifacts: bool,
}

impl HtmlNormalizeSink {
    fn new(strip_artifacts: bool) -> Self {
        Self {
            output: RefCell::new(String::new()),
            skip_depth: Cell::new(0),
            strip_artifacts,
        }
    }
}

impl TokenSink for HtmlNormalizeSink {
    type Handle = ();

    fn process_token(&self, token: Token, _line_number: u64) -> TokenSinkResult<Self::Handle> {
        if self.skip_depth.get() > 0 {
            return self.process_skipped_token(token);
        }

        match token {
            Token::DoctypeToken(doctype) => {
                write_doctype(&mut self.output.borrow_mut(), &doctype);
                TokenSinkResult::Continue
            }
            Token::TagToken(tag)
                if self.strip_artifacts
                    && tag.kind == TagKind::StartTag
                    && should_remove_artifact_element(&tag) =>
            {
                if should_skip_subtree(&tag) {
                    self.skip_depth.set(1);
                    if tag.name.as_ref() == "script" {
                        return TokenSinkResult::RawData(RawKind::ScriptData);
                    }
                }
                TokenSinkResult::Continue
            }
            Token::TagToken(tag) => {
                write_tag(&mut self.output.borrow_mut(), &tag);
                TokenSinkResult::Continue
            }
            Token::CharacterTokens(text) => {
                write_escaped_text(&mut self.output.borrow_mut(), &text);
                TokenSinkResult::Continue
            }
            Token::NullCharacterToken => {
                self.output.borrow_mut().push('\u{fffd}');
                TokenSinkResult::Continue
            }
            Token::CommentToken(_) | Token::EOFToken | Token::ParseError(_) => {
                TokenSinkResult::Continue
            }
        }
    }
}

impl HtmlNormalizeSink {
    fn process_skipped_token(&self, token: Token) -> TokenSinkResult<()> {
        match token {
            Token::TagToken(tag)
                if tag.kind == TagKind::StartTag
                    && !tag.self_closing
                    && !is_void_element(tag.name.as_ref()) =>
            {
                self.skip_depth.set(self.skip_depth.get() + 1);
                if tag.name.as_ref() == "script" {
                    TokenSinkResult::RawData(RawKind::ScriptData)
                } else {
                    TokenSinkResult::Continue
                }
            }
            Token::TagToken(tag) if tag.kind == TagKind::EndTag => {
                self.skip_depth.set(self.skip_depth.get().saturating_sub(1));
                TokenSinkResult::Continue
            }
            _ => TokenSinkResult::Continue,
        }
    }
}

fn should_remove_artifact_element(tag: &Tag) -> bool {
    has_attr_value(&tag.attrs, HAI_JACS_ENVELOPE_MARKER, "v1")
        || has_attr_value(&tag.attrs, HAI_VERIFY_FOOTER_MARKER, "v1")
        || has_attr_value(&tag.attrs, "data-hai-logo-verify-link", "v1")
        || (tag.name.as_ref() == "img"
            && has_attr_value(&tag.attrs, "src", &format!("cid:{HAI_LOGO_CID}")))
}

fn should_skip_subtree(tag: &Tag) -> bool {
    !tag.self_closing && !is_void_element(tag.name.as_ref()) && tag.name.as_ref() != "img"
}

fn is_void_element(name: &str) -> bool {
    matches!(
        name,
        "area"
            | "base"
            | "br"
            | "col"
            | "embed"
            | "hr"
            | "img"
            | "input"
            | "link"
            | "meta"
            | "source"
            | "track"
            | "wbr"
    )
}

fn write_doctype(output: &mut String, doctype: &Doctype) {
    output.push_str("<!doctype");
    if let Some(name) = &doctype.name {
        output.push(' ');
        output.push_str(name);
    }
    output.push('>');
}

fn write_tag(output: &mut String, tag: &Tag) {
    match tag.kind {
        TagKind::StartTag => {
            output.push('<');
            output.push_str(tag.name.as_ref());
            let mut attrs = tag.attrs.iter().collect::<Vec<_>>();
            attrs.sort_by(|left, right| {
                attr_name(&left.name)
                    .cmp(attr_name(&right.name))
                    .then_with(|| left.value.as_ref().cmp(right.value.as_ref()))
            });
            for attr in attrs {
                output.push(' ');
                output.push_str(attr_name(&attr.name));
                output.push_str("=\"");
                write_escaped_attr(output, &attr.value);
                output.push('"');
            }
            if tag.self_closing {
                output.push('/');
            }
            output.push('>');
        }
        TagKind::EndTag => {
            output.push_str("</");
            output.push_str(tag.name.as_ref());
            output.push('>');
        }
    }
}

fn write_escaped_text(output: &mut String, text: &str) {
    for ch in text.chars() {
        match ch {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            _ => output.push(ch),
        }
    }
}

fn write_escaped_attr(output: &mut String, text: &str) {
    for ch in text.chars() {
        match ch {
            '&' => output.push_str("&amp;"),
            '"' => output.push_str("&quot;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            _ => output.push(ch),
        }
    }
}

fn normalize_content_id(content_id: &str) -> String {
    content_id
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html_text_nodes_without_treating_text_as_html() {
        assert_eq!(
            escape_html_text("<script>alert('x' & \"y\")</script>"),
            "&lt;script&gt;alert('x' &amp; \"y\")&lt;/script&gt;"
        );
    }

    #[test]
    fn escapes_html_attribute_values() {
        assert_eq!(
            escape_html_attr("https://hai.ai/?q=<x>&quote=\"yes\"&single='yes'"),
            "https://hai.ai/?q=&lt;x&gt;&amp;quote=&quot;yes&quot;&amp;single=&#39;yes&#39;"
        );
    }

    #[test]
    fn detects_attachment_transport() {
        let raw = include_bytes!("../../tests/fixtures/email/fixtures/01_canonical_baseline.eml");

        assert_eq!(
            detect_signed_email_transport(raw).unwrap(),
            SignedEmailTransport::AttachmentJacs
        );
    }

    #[test]
    fn detects_html_inline_transport() {
        let raw = include_bytes!("../../tests/fixtures/email/html_inline/03_generated_html.eml");

        assert_eq!(
            detect_signed_email_transport(raw).unwrap(),
            SignedEmailTransport::HtmlInline
        );
    }

    #[test]
    fn extracts_topmost_inline_jacs_envelope_with_html_parser() {
        let raw = include_bytes!(
            "../../tests/fixtures/email/html_inline/04_reply_with_quoted_markers.eml"
        );

        let envelope = extract_topmost_inline_jacs_envelope(raw).unwrap();

        assert!(envelope.contains("\"fixture\":\"04-topmost\""));
        assert!(!envelope.contains("quoted-original"));
    }

    #[test]
    fn strips_only_inline_signature_artifacts_from_html() {
        let html = concat!(
            "<!doctype html><html data-hai-template-version=\"v1\"><body>",
            "<p>Keep text mentioning data-hai-jacs-envelope and cid:hai-jacs-logo@hai.ai.</p>",
            "<a data-hai-logo-verify-link=\"v1\" href=\"https://hai.ai/verify/email/test\">",
            "<img src=\"cid:hai-jacs-logo@hai.ai\" alt=\"HAI verification\"></a>",
            "<script type=\"application/jacs+json\" data-hai-jacs-envelope=\"v1\">secret</script>",
            "<footer data-hai-verify-footer=\"v1\">footer <a data-hai-verify-link=\"v1\">verify</a></footer>",
            "<p>Keep final text.</p>",
            "</body></html>"
        );

        let stripped = strip_inline_signature_artifacts_from_html(html);

        assert!(stripped.contains("Keep text mentioning data-hai-jacs-envelope"));
        assert!(stripped.contains("cid:hai-jacs-logo@hai.ai."));
        assert!(stripped.contains("Keep final text."));
        assert!(!stripped.contains("application/jacs+json"));
        assert!(!stripped.contains("<footer"));
        assert!(!stripped.contains("<img"));
        assert!(!stripped.contains("data-hai-logo-verify-link"));
        assert!(!stripped.contains(">secret<"));
        assert!(!stripped.contains(">footer"));
    }

    #[test]
    fn removes_inline_signature_artifacts_from_raw_email() {
        let raw = include_bytes!("../../tests/fixtures/email/html_inline/03_generated_html.eml");

        let stripped = remove_inline_signature_artifacts(raw).unwrap();

        assert!(stripped.logo_size_bytes.is_some());
        assert!(
            stripped
                .html_without_artifacts
                .contains("Hello from a signed HAI agent.")
        );
        assert!(
            !stripped
                .html_without_artifacts
                .contains("data-hai-jacs-envelope")
        );
        assert!(
            !stripped
                .html_without_artifacts
                .contains("data-hai-verify-footer")
        );
        assert!(
            !stripped
                .html_without_artifacts
                .contains("data-hai-logo-verify-link")
        );
        assert!(!stripped.html_without_artifacts.contains("<img"));
    }

    #[test]
    fn normalizes_equivalent_html_for_equivalence() {
        let left = r#"<DIV data-b="2" data-a="1">Tom &amp; Jerry</DIV>"#;
        let right = r#"<div data-a="1" data-b="2">Tom & Jerry</div>"#;

        assert_eq!(
            normalize_html_for_equivalence(left),
            normalize_html_for_equivalence(right)
        );
        assert!(html_bodies_equivalent(left, right));
    }

    #[test]
    fn html_equivalence_detects_user_visible_changes() {
        assert!(html_bodies_equivalent("<p>Hello</p>", "<p>Hello</p>"));
        assert!(!html_bodies_equivalent("<p>Hello</p>", "<p>Hell0</p>"));
    }

    #[test]
    fn extracts_inline_logo_by_exact_content_id() {
        let raw = include_bytes!("../../tests/fixtures/email/html_inline/03_generated_html.eml");

        let logo = extract_inline_logo_part(raw).unwrap();

        assert_eq!(logo.content_id, HAI_LOGO_CID);
        assert_eq!(logo.content_type, "image/png");
        assert_eq!(logo.content_disposition.as_deref(), Some("inline"));
        assert_eq!(logo.size_bytes, logo.content.len());
        assert!(logo.size_bytes > 0);
    }

    #[test]
    fn ignores_unrelated_inline_images() {
        let raw = include_bytes!("../../tests/fixtures/email/fixtures/25_with_inline_images.eml");

        assert!(extract_inline_logo_part(raw).is_err());
    }

    #[test]
    fn wrong_logo_content_id_is_not_accepted() {
        let raw = include_str!("../../tests/fixtures/email/html_inline/03_generated_html.eml")
            .replace(
                "Content-ID: <hai-jacs-logo@hai.ai>",
                "Content-ID: <other-logo@hai.ai>",
            );

        assert!(extract_inline_logo_part(raw.as_bytes()).is_err());
    }

    #[test]
    fn logo_content_id_requires_inline_disposition() {
        let raw = include_str!("../../tests/fixtures/email/html_inline/03_generated_html.eml")
            .replace(
                "Content-Disposition: inline; filename=\"hai-jacs-logo.png\"",
                "Content-Disposition: attachment; filename=\"hai-jacs-logo.png\"",
            );

        assert!(extract_inline_logo_part(raw.as_bytes()).is_err());
    }

    #[test]
    fn embeds_and_extracts_logo_header_from_png_bytes() {
        let base = make_fixture_png();
        let signed = embed_jacs_header_in_logo_png(&base, "fixture-header").unwrap();
        let extracted = extract_jacs_header_from_logo_png(&signed.bytes).unwrap();
        let metadata_extracted = jacs_media::extract_signature_with_format(
            jacs_media::MediaFormat::Png,
            &signed.bytes,
            false,
        )
        .unwrap();
        let channels =
            jacs_media::observed_channels(jacs_media::MediaFormat::Png, &signed.bytes, true)
                .unwrap();

        assert_eq!(signed.size_bytes, signed.bytes.len());
        assert!(signed.size_bytes > base.len());
        assert_eq!(extracted.as_deref(), Some("fixture-header"));
        assert_eq!(metadata_extracted.as_deref(), Some("fixture-header"));
        assert_eq!(channels, (true, true));
    }

    #[test]
    fn extracts_logo_header_after_metadata_strip() {
        let base = make_fixture_png();
        let signed = embed_jacs_header_in_logo_png(&base, "fixture-header").unwrap();
        let stripped = jacs_media::png::bytes_without_jacs_chunk(&signed.bytes).unwrap();
        let extracted = extract_jacs_header_from_logo_png(&stripped).unwrap();
        let channels =
            jacs_media::observed_channels(jacs_media::MediaFormat::Png, &stripped, true).unwrap();

        assert_eq!(extracted.as_deref(), Some("fixture-header"));
        assert_eq!(channels, (false, true));
    }

    #[test]
    fn logo_header_adapter_rejects_jpeg_and_webp() {
        let jpeg = make_fixture_jpeg();
        let webp = b"RIFF\x00\x00\x00\x00WEBPrest".to_vec();

        assert!(embed_jacs_header_in_logo_png(&jpeg, "fixture-header").is_err());
        assert!(embed_jacs_header_in_logo_png(&webp, "fixture-header").is_err());
    }

    fn make_fixture_png() -> Vec<u8> {
        let img = image::RgbaImage::from_pixel(64, 64, image::Rgba([32, 64, 128, 255]));
        let mut buf = Vec::new();
        let mut cur = std::io::Cursor::new(&mut buf);
        img.write_to(&mut cur, image::ImageFormat::Png)
            .expect("png encode");
        buf
    }

    fn make_fixture_jpeg() -> Vec<u8> {
        let img = image::RgbImage::from_pixel(64, 64, image::Rgb([32, 64, 128]));
        let mut buf = Vec::new();
        let mut cur = std::io::Cursor::new(&mut buf);
        img.write_to(&mut cur, image::ImageFormat::Jpeg)
            .expect("jpeg encode");
        buf
    }
}
