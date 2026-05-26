//! Wave 1 / Task 002 smoke test: prove the empty `jacs-core` crate is
//! reachable from its own test target. Adding the test before the crate
//! exists is the red step; the green step is the crate compiling and the
//! placeholder assertion passing.

#[test]
fn jacs_core_smoke() {
    assert_eq!(2 + 2, 4);
}
