use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let target_dir =
        PathBuf::from(env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string()));
    let release_dir = target_dir.join("release");
    let bin_dir = PathBuf::from("/usr/bin"); // Change this to the appropriate system directory if needed

    // Copy the 'jacs' binary to the system directory
    fs::copy(release_dir.join("jacs"), bin_dir.join("jacs")).unwrap();
}
