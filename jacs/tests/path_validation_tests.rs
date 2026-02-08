//! Integration tests for path safety validation (require_relative_path_safe).
//! Prevents path traversal when building paths from untrusted input (e.g. publicKeyHash).

use jacs::validation::require_relative_path_safe;

#[test]
fn require_relative_path_safe_rejects_double_dot() {
    assert!(require_relative_path_safe("..").is_err());
    assert!(require_relative_path_safe("a/..").is_err());
    assert!(require_relative_path_safe("../b").is_err());
}

#[test]
fn require_relative_path_safe_rejects_slash() {
    assert!(require_relative_path_safe("/etc/passwd").is_err());
    assert!(require_relative_path_safe("public_keys/../../etc/passwd").is_err());
}

#[test]
fn require_relative_path_safe_rejects_backslash() {
    assert!(require_relative_path_safe("a\\..\\b").is_err());
    assert!(require_relative_path_safe("..\\etc").is_err());
}

#[test]
fn require_relative_path_safe_rejects_null() {
    assert!(require_relative_path_safe("hash\0withnull").is_err());
    assert!(require_relative_path_safe("\0").is_err());
}

#[test]
fn require_relative_path_safe_rejects_empty_segment() {
    assert!(require_relative_path_safe("a//b").is_err());
    assert!(require_relative_path_safe("").is_err()); // "" splits to [""], empty segment rejected
}

#[test]
fn require_relative_path_safe_rejects_dot_segment() {
    assert!(require_relative_path_safe(".").is_err());
    assert!(require_relative_path_safe("a/./b").is_err());
}

#[test]
fn require_relative_path_safe_accepts_safe_hash() {
    assert!(
        require_relative_path_safe(
            "0ee2c3638a3ca80b3d9915c6f18a85ccc7be3cb4685316b5dbfa76f95a20d584"
        )
        .is_ok()
    );
    assert!(require_relative_path_safe("abc123").is_ok());
}

#[test]
fn require_relative_path_safe_accepts_multiple_safe_segments() {
    assert!(require_relative_path_safe("public_keys/abc123.pem").is_ok());
    assert!(require_relative_path_safe("public_keys/abc123.enc_type").is_ok());
}

#[test]
fn require_relative_path_safe_rejects_traversal_in_segment() {
    assert!(require_relative_path_safe("public_keys/../etc/passwd").is_err());
    assert!(require_relative_path_safe("..").is_err());
}

#[test]
fn require_relative_path_safe_windows_style_backslash_traversal_rejected() {
    assert!(require_relative_path_safe("a\\..\\b").is_err());
}

#[test]
fn require_relative_path_safe_path_exactly_double_dot_rejected() {
    assert!(require_relative_path_safe("..").is_err());
}

#[test]
fn require_relative_path_safe_accepts_three_safe_segments() {
    assert!(require_relative_path_safe("a/b/c").is_ok());
}

#[test]
fn require_relative_path_safe_leading_slash_rejects_empty_first_segment() {
    // "/a/b" split by / and \ gives ["", "a", "b"] -> first segment "" is rejected
    assert!(require_relative_path_safe("/a/b").is_err());
}

#[test]
fn require_relative_path_safe_trailing_slash_rejects_empty_segment() {
    // "a/b/" gives ["a", "b", ""] -> empty segment rejected
    assert!(require_relative_path_safe("a/b/").is_err());
}

#[test]
fn require_relative_path_safe_rejects_windows_drive_prefixed_paths() {
    assert!(require_relative_path_safe("C:\\Windows\\System32\\drivers\\etc\\hosts").is_err());
    assert!(require_relative_path_safe("D:/tmp/file.json").is_err());
    assert!(require_relative_path_safe("E:").is_err());
}

#[test]
fn require_relative_path_safe_allows_uuid_colon_filename() {
    // JACS commonly uses UUID:UUID filenames for agent/document identifiers.
    assert!(
        require_relative_path_safe(
            "550e8400-e29b-41d4-a716-446655440000:550e8400-e29b-41d4-a716-446655440001"
        )
        .is_ok()
    );
}
