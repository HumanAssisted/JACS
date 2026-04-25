//! Structural lint — the first-creation research document must exist with the
//! required H2 sections. Prevents silent deletion of the Part-C deliverable
//! and guarantees CI fails if the doc is removed or gutted.
//!
//! See PRD docs/prds/PROVENANCE_EXPANSION_PRD.md §4.3 (Q5: defer; document only)
//! and Task 04 of the provenance expansion plan.

use std::fs;
use std::path::PathBuf;

#[test]
fn first_creation_research_doc_exists_with_required_sections() {
    // jacs/tests/... is two levels below the repo root; traverse up once from
    // CARGO_MANIFEST_DIR (= .../JACS/jacs) to reach the repo root.
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("CARGO_MANIFEST_DIR should have a parent")
        .join("docs/prds/FIRST_CREATION_RESEARCH.md");

    let content = fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "FIRST_CREATION_RESEARCH.md missing at {}. See PRD §4.3 / Task 04.",
            path.display()
        )
    });

    for section in [
        "## Threat Model",
        "## Candidate 1: RFC 3161",
        "## Candidate 2: Sigstore Rekor",
        "## Candidate 3: Self-Hosted Trillian + Witnesses",
        "## Recommendation",
        "## Ship or Defer",
    ] {
        assert!(
            content.contains(section),
            "FIRST_CREATION_RESEARCH.md missing required section `{}` — see PRD §4.3 deliverables",
            section
        );
    }

    // Path-to-TRD: every reader arriving from the jacsbook guides / READMEs needs
    // a one-step link back to the source of design. The lint keeps this honest.
    assert!(
        content.contains("PROVENANCE_EXPANSION_PRD.md"),
        "FIRST_CREATION_RESEARCH.md missing citation of the source PRD — readers need the path-to-TRD"
    );
    assert!(
        content.contains("Source of design"),
        "FIRST_CREATION_RESEARCH.md missing `Source of design` footer"
    );
}
