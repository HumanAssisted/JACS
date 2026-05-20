//! JSON <-> HTML conversion for JACS documents.
//!
//! Provides conversion between JSON and self-contained HTML documents. The
//! HTML embeds the exact JSON in a `<script>` tag for lossless extraction.

use crate::error::JacsError;

/// Convert a JSON string to a self-contained HTML document.
///
/// The HTML output:
/// - Embeds the exact JSON in a `<script type="application/json" id="jacs-data">` tag
/// - Renders a human-readable view of the document content
/// - Includes inline CSS (no external dependencies)
/// - Displays JACS metadata (ID, version, signer, timestamp, algorithm) when present
///
/// # Errors
///
/// Returns `JacsError::ConversionError` if the input is not valid JSON.
pub fn jacs_to_html(json_str: &str) -> Result<String, JacsError> {
    // Validate input is JSON
    let value: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| JacsError::conversion("JSON", "HTML", format!("invalid JSON input: {}", e)))?;

    // Extract JACS metadata fields if present
    let jacs_id = value.get("jacsId").and_then(|v| v.as_str()).unwrap_or("");
    let jacs_version = value
        .get("jacsVersion")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let jacs_version_date = value
        .get("jacsVersionDate")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let jacs_type = value.get("jacsType").and_then(|v| v.as_str()).unwrap_or("");
    let jacs_level = value
        .get("jacsLevel")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Extract signature metadata if present
    let (signer_agent_id, signing_algorithm) = value
        .get("jacsSignature")
        .and_then(|sig| sig.as_array())
        .and_then(|sigs| sigs.first())
        .map(|sig| {
            let agent_id = sig.get("agentID").and_then(|v| v.as_str()).unwrap_or("");
            let algorithm = sig
                .get("signingAlgorithm")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            (agent_id, algorithm)
        })
        .unwrap_or(("", ""));

    // Check for jacsFiles
    let has_files = value
        .get("jacsFiles")
        .and_then(|f| f.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false);

    let files_section = if has_files {
        let files = value["jacsFiles"].as_array().unwrap();
        let mut files_html = String::from(
            r#"<div class="jacs-section"><h2>Attached Files</h2><table><tr><th>Name</th><th>Hash</th><th>MIME Type</th></tr>"#,
        );
        for file in files {
            let name = file
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let hash = file.get("hash").and_then(|v| v.as_str()).unwrap_or("");
            let mime = file.get("mediaType").and_then(|v| v.as_str()).unwrap_or("");
            files_html.push_str(&format!(
                "<tr><td>{}</td><td><code>{}</code></td><td>{}</td></tr>",
                html_escape(name),
                html_escape(&hash[..hash.len().min(32)]),
                html_escape(mime)
            ));
        }
        files_html.push_str("</table></div>");
        files_html
    } else {
        String::new()
    };

    // Build human-readable content preview (top-level keys, excluding JACS internal fields)
    let content_section = if let Some(obj) = value.as_object() {
        let mut content_html =
            String::from(r#"<div class="jacs-section"><h2>Document Content</h2><dl>"#);
        for (key, val) in obj {
            if key.starts_with("jacs") || key == "$schema" || key == "id" || key == "version" {
                continue;
            }
            let display_val = match val {
                serde_json::Value::String(s) => html_escape(s),
                serde_json::Value::Null => "null".to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Array(a) => format!("[{} items]", a.len()),
                serde_json::Value::Object(o) => format!("{{...}} ({} keys)", o.len()),
            };
            content_html.push_str(&format!(
                "<dt>{}</dt><dd>{}</dd>",
                html_escape(key),
                display_val
            ));
        }
        content_html.push_str("</dl></div>");
        content_html
    } else {
        String::new()
    };

    // Build the metadata section (only if there is JACS metadata)
    let has_metadata = !jacs_id.is_empty()
        || !jacs_type.is_empty()
        || !signer_agent_id.is_empty()
        || !jacs_version_date.is_empty();

    let metadata_section = if has_metadata {
        let mut meta = String::from(r#"<div class="jacs-section"><h2>JACS Metadata</h2><table>"#);
        if !jacs_id.is_empty() {
            meta.push_str(&format!(
                "<tr><td><strong>Document ID</strong></td><td><code>{}</code></td></tr>",
                html_escape(jacs_id)
            ));
        }
        if !jacs_version.is_empty() {
            meta.push_str(&format!(
                "<tr><td><strong>Version</strong></td><td><code>{}</code></td></tr>",
                html_escape(jacs_version)
            ));
        }
        if !jacs_type.is_empty() {
            meta.push_str(&format!(
                "<tr><td><strong>Document Type</strong></td><td>{}</td></tr>",
                html_escape(jacs_type)
            ));
        }
        if !jacs_level.is_empty() {
            meta.push_str(&format!(
                "<tr><td><strong>Level</strong></td><td>{}</td></tr>",
                html_escape(jacs_level)
            ));
        }
        if !jacs_version_date.is_empty() {
            meta.push_str(&format!(
                "<tr><td><strong>Timestamp</strong></td><td>{}</td></tr>",
                html_escape(jacs_version_date)
            ));
        }
        if !signer_agent_id.is_empty() {
            meta.push_str(&format!(
                "<tr><td><strong>Signer Agent ID</strong></td><td><code>{}</code></td></tr>",
                html_escape(signer_agent_id)
            ));
        }
        if !signing_algorithm.is_empty() {
            meta.push_str(&format!(
                "<tr><td><strong>Signing Algorithm</strong></td><td>{}</td></tr>",
                html_escape(signing_algorithm)
            ));
        }
        meta.push_str("</table></div>");
        meta
    } else {
        String::new()
    };

    let title = if !jacs_type.is_empty() {
        format!("JACS Document - {}", html_escape(jacs_type))
    } else {
        "JACS Document".to_string()
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 900px; margin: 0 auto; padding: 2rem; background: #f8f9fa; color: #212529; }}
h1 {{ color: #495057; border-bottom: 2px solid #dee2e6; padding-bottom: 0.5rem; }}
h2 {{ color: #495057; margin-top: 1.5rem; }}
.jacs-section {{ background: #fff; border: 1px solid #dee2e6; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; }}
table {{ border-collapse: collapse; width: 100%; }}
td, th {{ padding: 0.5rem 1rem; border-bottom: 1px solid #dee2e6; text-align: left; }}
th {{ background: #f1f3f5; }}
code {{ background: #e9ecef; padding: 0.15rem 0.4rem; border-radius: 3px; font-size: 0.9em; }}
dl {{ display: grid; grid-template-columns: max-content 1fr; gap: 0.3rem 1rem; }}
dt {{ font-weight: 600; color: #495057; }}
dd {{ margin: 0; }}
.jacs-footer {{ margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #dee2e6; font-size: 0.85rem; color: #868e96; }}
</style>
</head>
<body>
<h1>{title}</h1>
{metadata_section}
{content_section}
{files_section}
<div class="jacs-footer">
<p>This document was generated by JACS (JSON AI Communication Standard). The embedded JSON data can be extracted for cryptographic verification.</p>
</div>
<script type="application/json" id="jacs-data">{json_data}</script>
</body>
</html>"#,
        title = title,
        metadata_section = metadata_section,
        content_section = content_section,
        files_section = files_section,
        // Escape all "</" sequences in JSON to prevent HTML injection (XSS).
        // Any "</script>" (case-insensitive) in the JSON would prematurely close the
        // <script> tag. The standard mitigation is to replace "</" with "<\/" which
        // is safe because "\/" is a valid JSON escape for "/" (RFC 8259 Section 7).
        // This escaping is reversed in html_to_jacs() after extraction to preserve
        // byte-identical round-trip.
        json_data = json_str.replace("</", r"<\/"),
    );

    Ok(html)
}

/// Extract JSON from an HTML document that was produced by [`jacs_to_html`].
///
/// Looks for a `<script type="application/json" id="jacs-data">` tag and
/// extracts the JSON content between the opening and closing tags.
///
/// # Errors
///
/// Returns `JacsError::ConversionError` if:
/// - The input does not contain the expected `<script>` tag
/// - The extracted content is not valid JSON
/// - The input is empty or not HTML
pub fn html_to_jacs(html_str: &str) -> Result<String, JacsError> {
    if html_str.is_empty() {
        return Err(JacsError::conversion("HTML", "JSON", "input is empty"));
    }

    // Look for the JACS data script tag
    let open_tag = r#"<script type="application/json" id="jacs-data">"#;
    let close_tag = "</script>";

    let start = html_str.find(open_tag).ok_or_else(|| {
        JacsError::conversion(
            "HTML",
            "JSON",
            "no <script type=\"application/json\" id=\"jacs-data\"> tag found in HTML",
        )
    })?;

    let json_start = start + open_tag.len();

    // Find the closing </script> tag after our opening tag
    let json_end = html_str[json_start..].find(close_tag).ok_or_else(|| {
        JacsError::conversion(
            "HTML",
            "JSON",
            "found opening jacs-data script tag but no closing </script> tag",
        )
    })?;

    let json_str = &html_str[json_start..json_start + json_end];

    // Reverse the "</" -> "<\/" escaping applied by jacs_to_html to prevent
    // script injection. This restores the original JSON byte-for-byte.
    let json_str = json_str.replace(r"<\/", "</");

    // Validate it is actually JSON
    let _: serde_json::Value = serde_json::from_str(&json_str).map_err(|e| {
        JacsError::conversion(
            "HTML",
            "JSON",
            format!("embedded JSON in script tag is malformed: {}", e),
        )
    })?;

    Ok(json_str.to_string())
}

/// Escape special HTML characters in a string.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_contains_doctype() {
        let json = r#"{"hello": "world"}"#;
        let html = jacs_to_html(json).unwrap();
        assert!(
            html.starts_with("<!DOCTYPE html>"),
            "HTML should start with DOCTYPE"
        );
    }

    #[test]
    fn html_contains_embedded_json() {
        let json = r#"{"hello": "world"}"#;
        let html = jacs_to_html(json).unwrap();
        assert!(
            html.contains(r#"<script type="application/json" id="jacs-data">"#),
            "HTML should contain the JACS data script tag"
        );
    }

    #[test]
    fn html_embedded_json_matches_input() {
        let json = r#"{"hello": "world"}"#;
        let html = jacs_to_html(json).unwrap();
        let extracted = html_to_jacs(&html).unwrap();
        assert_eq!(extracted, json, "Extracted JSON should match the input");
    }

    #[test]
    fn html_round_trip_simple() {
        let json = r#"{"key": "value", "number": 42}"#;
        let html = jacs_to_html(json).unwrap();
        let back = html_to_jacs(&html).unwrap();
        assert_eq!(back, json);
    }

    #[test]
    fn html_renders_jacs_id() {
        let json = r#"{"jacsId": "test-doc-123", "jacsType": "document"}"#;
        let html = jacs_to_html(json).unwrap();
        assert!(
            html.contains("test-doc-123"),
            "HTML should render the jacsId visibly"
        );
    }

    #[test]
    fn html_renders_signature_agent_id() {
        let json =
            r#"{"jacsSignature": [{"agentID": "agent-abc-456", "signingAlgorithm": "ed25519"}]}"#;
        let html = jacs_to_html(json).unwrap();
        assert!(
            html.contains("agent-abc-456"),
            "HTML should render the signer agent ID"
        );
    }

    #[test]
    fn html_renders_timestamp() {
        let json = r#"{"jacsVersionDate": "2026-03-24T12:00:00Z"}"#;
        let html = jacs_to_html(json).unwrap();
        assert!(
            html.contains("2026-03-24T12:00:00Z"),
            "HTML should render the timestamp"
        );
    }

    #[test]
    fn html_to_jacs_no_script_tag_returns_error() {
        let html = "<html><body>No script tag here</body></html>";
        let result = html_to_jacs(html);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("no <script"),
            "Should mention missing tag: {}",
            msg
        );
    }

    #[test]
    fn html_to_jacs_malformed_json_returns_error() {
        let html = r#"<html><script type="application/json" id="jacs-data">{not valid json}</script></html>"#;
        let result = html_to_jacs(html);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("malformed"),
            "Should mention malformed JSON: {}",
            msg
        );
    }

    #[test]
    fn html_to_jacs_from_non_html_returns_error() {
        let result = html_to_jacs("just plain text, not html at all");
        assert!(result.is_err());
    }

    #[test]
    fn html_output_is_self_contained() {
        let json = r#"{"hello": "world"}"#;
        let html = jacs_to_html(json).unwrap();
        assert!(
            !html.contains(r#"<link rel="stylesheet""#),
            "HTML should not have external CSS links"
        );
        assert!(
            !html.contains(r#"<script src=""#),
            "HTML should not have external script sources"
        );
    }

    #[test]
    fn jacs_to_html_invalid_json_returns_error() {
        let result = jacs_to_html("{not valid}");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("Conversion from JSON to HTML failed"),
            "Should mention conversion direction: {}",
            msg
        );
    }

    // =========================================================================
    // HTML-specific edge case tests (Task 007)
    // =========================================================================

    #[test]
    fn html_structure_has_head_and_body() {
        let json = r#"{"test": true}"#;
        let html = jacs_to_html(json).unwrap();
        assert!(html.contains("<head>"), "HTML should have <head>");
        assert!(html.contains("<body>"), "HTML should have <body>");
        assert!(html.contains("</head>"), "HTML should have </head>");
        assert!(html.contains("</body>"), "HTML should have </body>");
    }

    #[test]
    fn html_has_charset_utf8() {
        let json = r#"{"test": true}"#;
        let html = jacs_to_html(json).unwrap();
        assert!(
            html.contains("charset=\"UTF-8\"") || html.contains("charset=UTF-8"),
            "HTML should declare UTF-8 charset"
        );
    }

    #[test]
    fn html_inline_css_no_external_links() {
        let json = r#"{"test": true}"#;
        let html = jacs_to_html(json).unwrap();
        assert!(
            html.contains("<style>"),
            "HTML should have inline <style> tag"
        );
        assert!(
            !html.contains(r#"<link rel="stylesheet""#),
            "HTML should not have external stylesheet link"
        );
        assert!(
            !html.contains(r#"<script src="#),
            "HTML should not have external script source"
        );
    }

    #[test]
    fn html_renders_document_type() {
        let json = r#"{"jacsType": "document", "jacsId": "test-123"}"#;
        let html = jacs_to_html(json).unwrap();
        let script_pos = html.find(r#"<script type="application/json""#).unwrap();
        let visible = &html[..script_pos];
        assert!(
            visible.contains("document"),
            "jacsType should be visible in HTML body"
        );
    }

    #[test]
    fn html_renders_signing_algorithm() {
        let json = r#"{"jacsSignature": [{"agentID": "agent-1", "signingAlgorithm": "ed25519"}]}"#;
        let html = jacs_to_html(json).unwrap();
        let script_pos = html.find(r#"<script type="application/json""#).unwrap();
        let visible = &html[..script_pos];
        assert!(
            visible.contains("ed25519"),
            "signingAlgorithm should be visible in HTML body"
        );
    }

    #[test]
    fn html_renders_document_level() {
        let json = r#"{"jacsLevel": "signed", "jacsId": "test-456"}"#;
        let html = jacs_to_html(json).unwrap();
        let script_pos = html.find(r#"<script type="application/json""#).unwrap();
        let visible = &html[..script_pos];
        assert!(
            visible.contains("signed"),
            "jacsLevel should be visible in HTML body"
        );
    }

    #[test]
    fn html_handles_document_without_signature() {
        // Unsigned document should produce valid HTML without crashing
        let json = r#"{"name": "test doc", "content": "hello world"}"#;
        let html = jacs_to_html(json).unwrap();
        assert!(html.starts_with("<!DOCTYPE html>"));
        // Should still be extractable
        let back = html_to_jacs(&html).unwrap();
        assert_eq!(back, json);
    }

    #[test]
    fn html_handles_document_with_files_array() {
        let json = r#"{"jacsId": "test", "jacsFiles": [{"name": "doc.pdf", "hash": "abc123def456", "mediaType": "application/pdf"}]}"#;
        let html = jacs_to_html(json).unwrap();
        assert!(
            html.contains("doc.pdf"),
            "File name should be visible in HTML"
        );
        assert!(
            html.contains("application/pdf"),
            "MIME type should be visible in HTML"
        );
    }

    #[test]
    fn html_script_tag_json_not_html_escaped() {
        // JSON inside the script tag should be raw, not HTML-entity-escaped
        let json = r#"{"key": "value with <html> & \"quotes\""}"#;
        let html = jacs_to_html(json).unwrap();
        let extracted = html_to_jacs(&html).unwrap();
        assert_eq!(extracted, json, "Extracted JSON should be raw, not escaped");
    }

    #[test]
    fn html_extraction_ignores_other_script_tags() {
        // HTML with multiple script tags -- should only extract from id="jacs-data"
        let html = r#"<!DOCTYPE html><html><head>
<script type="text/javascript">console.log("not this one");</script>
</head><body>
<script type="application/json" id="other-data">{"wrong": true}</script>
<script type="application/json" id="jacs-data">{"right": true}</script>
</body></html>"#;
        let extracted = html_to_jacs(html).unwrap();
        let value: serde_json::Value = serde_json::from_str(&extracted).unwrap();
        assert_eq!(
            value["right"], true,
            "Should extract from jacs-data, not other tags"
        );
    }

    #[test]
    fn html_to_jacs_empty_string_returns_error() {
        let result = html_to_jacs("");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("empty"), "Should mention empty input: {}", msg);
    }

    #[test]
    fn html_to_jacs_json_string_returns_error() {
        // Raw JSON (not wrapped in HTML) should fail
        let result = html_to_jacs(r#"{"hello": "world"}"#);
        assert!(
            result.is_err(),
            "Raw JSON should not be extractable as HTML"
        );
    }

    #[test]
    fn html_round_trip_json_with_script_close_tag() {
        // Regression test for XSS/injection via </script> in JSON values.
        // A JSON value containing "</script>" must not break the HTML structure
        // or enable script injection.
        let json = r#"{"key": "</script><script>alert(1)</script>"}"#;
        let html = jacs_to_html(json).unwrap();

        // The raw "</script>" must NOT appear unescaped in the HTML output
        // (outside the controlled closing tag). It should be escaped as "<\/script>".
        let script_tag_start = html
            .find(r#"<script type="application/json" id="jacs-data">"#)
            .unwrap();
        let after_open =
            script_tag_start + r#"<script type="application/json" id="jacs-data">"#.len();
        let embedded_region = &html[after_open..];
        // The first unescaped </script> should be the actual closing tag, not injected
        let first_close = embedded_region.find("</script>").unwrap();
        // The embedded JSON should use the escaped form
        assert!(
            embedded_region[..first_close].contains(r"<\/script>"),
            "Embedded JSON should have </script> escaped as <\\/script>"
        );

        // Round-trip must produce identical JSON
        let extracted = html_to_jacs(&html).unwrap();
        assert_eq!(
            extracted, json,
            "Round-trip should produce identical JSON even with </script> in values"
        );
    }

    #[test]
    fn html_script_injection_does_not_create_extra_script_tags() {
        // Verify that malicious JSON cannot inject working script tags via </script> injection.
        // The attack: JSON containing "</script>" would close the data script tag early,
        // allowing an attacker to inject arbitrary <script> content.
        let json = r#"{"payload": "</script><script>alert('xss')</script>"}"#;
        let html = jacs_to_html(json).unwrap();

        // The embedded JSON region should NOT contain an unescaped "</script>"
        // (other than the actual closing tag placed by the template).
        let open_tag = r#"<script type="application/json" id="jacs-data">"#;
        let data_start = html.find(open_tag).unwrap() + open_tag.len();
        let data_region = &html[data_start..];
        // The first unescaped "</script>" should be the real closing tag,
        // meaning everything before it is safely escaped JSON.
        let first_close = data_region.find("</script>").unwrap();
        let json_region = &data_region[..first_close];
        // The JSON region must not contain unescaped "</script>"
        assert!(
            !json_region.contains("</script>"),
            "JSON region should not contain unescaped </script>"
        );
        // But it should contain the escaped form
        assert!(
            json_region.contains(r"<\/script>"),
            "JSON region should contain escaped <\\/script>"
        );

        // Extraction should still work correctly and produce identical JSON
        let extracted = html_to_jacs(&html).unwrap();
        assert_eq!(extracted, json);
    }

    #[test]
    fn html_round_trip_preserves_special_chars_in_values() {
        // JSON with characters that need HTML escaping in values
        let json = r#"{"content": "a < b & c > d", "formula": "x \"plus\" y"}"#;
        let html = jacs_to_html(json).unwrap();
        let extracted = html_to_jacs(&html).unwrap();
        assert_eq!(
            extracted, json,
            "Special chars in values should survive HTML round-trip"
        );
    }
}
