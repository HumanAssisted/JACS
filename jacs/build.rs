use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    if let Ok(package_name) = env::var("CARGO_PKG_NAME") {
        if package_name == "jacs" {
            let target_dir = PathBuf::from(
                env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string()),
            );
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
}
