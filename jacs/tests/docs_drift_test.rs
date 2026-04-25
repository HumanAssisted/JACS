//! Structural lint for v0.10.0 doc surface.
//!
//! These tests pin every major doc surface that the provenance-expansion feature
//! requires an edit in. A future edit that accidentally removes a CLI reference
//! entry or breaks a SUMMARY.md link will surface in CI.
//!
//! Source of design: `~/personal/hai/docs/jacs/PROVENANCE_EXPANSION_PRD.md` §10
//! and the Task 14 doc-surface audit.

use std::fs;
use std::path::Path;

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()
}

#[test]
fn changelog_mentions_provenance_expansion_in_v011() {
    let path = repo_root().join("CHANGELOG.md");
    let text = fs::read_to_string(&path).unwrap();
    let section_start = text
        .find("## 0.10.0")
        .expect("CHANGELOG missing 0.10.0 section");
    let section = &text[section_start..];
    // Covers: the five verbs + error kind + crate + owner clarifications (strict, YAML, end-of-file)
    // + schema hardening (signatureBlockVersion, canonicalization) + security knobs (marker-collision, refuse-overwrite).
    for keyword in [
        "sign-text",
        "sign-image",
        "MissingSignature",
        "jacs-media",
        "strict",
        "YAML",
        "signatureBlockVersion",
        "canonicalization",
        "refuse-overwrite",
        "extract-media-signature",
    ] {
        assert!(
            section.contains(keyword),
            "CHANGELOG 0.10.0 section missing '{keyword}'"
        );
    }
}

#[test]
fn jacsbook_summary_links_both_new_guides() {
    let path = repo_root().join("jacs/docs/jacsbook/src/SUMMARY.md");
    let text = fs::read_to_string(&path).unwrap();
    for link in ["guides/inline-text-signing.md", "guides/media-signing.md"] {
        assert!(
            text.contains(link),
            "jacsbook SUMMARY.md missing link to {link}"
        );
    }
}

#[test]
fn jacsbook_guides_cite_prd_source_of_design() {
    // Every writer is instructed to add a "Source of design" footer linking back to the PRD.
    // This test keeps writers honest: the PRD citation is the path-to-TRD the owner asked for.
    for guide in [
        "jacs/docs/jacsbook/src/guides/inline-text-signing.md",
        "jacs/docs/jacsbook/src/guides/media-signing.md",
    ] {
        let text = fs::read_to_string(repo_root().join(guide)).unwrap();
        assert!(
            text.contains("PROVENANCE_EXPANSION_PRD.md"),
            "{guide} missing citation of the source PRD — every guide must link back to design source"
        );
        assert!(
            text.contains("Source of design"),
            "{guide} missing 'Source of design' footer"
        );
    }
}

#[test]
fn cli_reference_page_lists_new_verbs() {
    let path = repo_root().join("jacs/docs/jacsbook/src/reference/cli-commands.md");
    let text = fs::read_to_string(&path).unwrap();
    for verb in [
        "sign-text",
        "verify-text",
        "sign-image",
        "verify-image",
        "extract-media-signature",
    ] {
        assert!(
            text.contains(verb),
            "cli-commands.md reference missing entry for `{verb}`"
        );
    }
}
