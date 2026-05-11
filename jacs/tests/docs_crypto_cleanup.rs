use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN_DOC_PATTERNS: &[&str] = &["RSA-PSS", "rsa-pss", "RS256"];

#[test]
fn jacsbook_docs_do_not_advertise_rsa() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let roots = [
        manifest_dir.join("docs/jacsbook/src"),
        manifest_dir.join("docs/jacsbook/book"),
    ];

    let mut failures = Vec::new();
    for root in roots {
        scan_docs(&root, &mut failures);
    }

    assert!(
        failures.is_empty(),
        "jacsbook docs still contain removed RSA terms:\n{}",
        failures.join("\n")
    );
}

fn scan_docs(path: &Path, failures: &mut Vec<String>) {
    if should_skip(path) {
        return;
    }

    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return,
    };

    if metadata.is_dir() {
        let entries = fs::read_dir(path).expect("read jacsbook docs directory");
        for entry in entries {
            let entry = entry.expect("read jacsbook docs directory entry");
            scan_docs(&entry.path(), failures);
        }
        return;
    }

    if !metadata.is_file() {
        return;
    }

    let Ok(text) = fs::read_to_string(path) else {
        return;
    };

    for (line_index, line) in text.lines().enumerate() {
        for pattern in FORBIDDEN_DOC_PATTERNS {
            if line.contains(pattern) {
                failures.push(format!(
                    "{}:{} contains {}",
                    path.display(),
                    line_index + 1,
                    pattern
                ));
            }
        }
    }
}

fn should_skip(path: &Path) -> bool {
    let path = path.to_string_lossy().to_ascii_lowercase();
    path.contains("changelog") || path.contains("release")
}
