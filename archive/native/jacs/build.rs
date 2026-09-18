use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    // Single-source guard for the agreement v2 schema. jacs and jacs-core are
    // separately published crates that each ship their own copy of
    // schemas/agreement/v2/agreement.schema.json (cross-crate include_str! would
    // break `cargo package`). jacs-core is the source of truth; this guard fails
    // the workspace build if the jacs copy drifts. It is skipped automatically in
    // the published-crate context where the jacs-core sibling is absent.
    {
        let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
        let jacs_copy = manifest_dir.join("schemas/agreement/v2/agreement.schema.json");
        let core_copy =
            manifest_dir.join("../jacs-core/schemas/agreement/v2/agreement.schema.json");
        println!("cargo:rerun-if-changed={}", jacs_copy.display());
        println!("cargo:rerun-if-changed={}", core_copy.display());
        if core_copy.exists() && jacs_copy.exists() {
            let core_bytes = fs::read(&core_copy).unwrap_or_default();
            let jacs_bytes = fs::read(&jacs_copy).unwrap_or_default();
            if core_bytes != jacs_bytes {
                panic!(
                    "agreement v2 schema drift: '{}' (source of truth) differs from '{}'. \
Copy jacs-core's schema over the jacs copy: \
cp jacs-core/schemas/agreement/v2/agreement.schema.json jacs/schemas/agreement/v2/agreement.schema.json",
                    core_copy.display(),
                    jacs_copy.display()
                );
            }
        }
    }

    if let Ok(package_name) = env::var("CARGO_PKG_NAME")
        && package_name == "jacs"
    {
        let target_dir =
            PathBuf::from(env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string()));
        let release_dir = target_dir.join("release");

        // Get the directories in the system's PATH
        let path_dirs = env::var_os("PATH").unwrap_or_default();
        let path_dirs = env::split_paths(&path_dirs).collect::<Vec<_>>();

        // Find a suitable directory to install the binary
        let install_dir = path_dirs.into_iter().find(|dir| dir.is_dir());

        match install_dir {
            Some(dir) => {
                let bin_file = release_dir.join("jacs");
                let install_file = dir.join("jacs");

                // Check if the 'jacs' binary exists
                if bin_file.exists() {
                    // Copy the 'jacs' binary to the installation directory
                    match fs::copy(&bin_file, &install_file) {
                        Ok(_) => println!("Installed 'jacs' to '{}'", install_file.display()),
                        Err(err) => println!(
                            "Warning: Failed to install 'jacs' to '{}': {}",
                            install_file.display(),
                            err
                        ),
                    }
                } else {
                    println!(
                        "Warning: 'jacs' binary not found at '{}'",
                        bin_file.display()
                    );
                }
            }
            None => {
                println!("Warning: No suitable directory found in PATH to install 'jacs'");
            }
        }
    }
}
