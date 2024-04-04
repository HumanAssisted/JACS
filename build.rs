use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let target_dir = PathBuf::from(env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string()));
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

            // Copy the 'jacs' binary to the installation directory
            fs::copy(&bin_file, &install_file).unwrap_or_else(|err| {
                eprintln!("Failed to install 'jacs' to '{}': {}", install_file.display(), err);
                std::process::exit(1);
            });

            println!("Installed 'jacs' to '{}'", install_file.display());
        }
        None => {
            eprintln!("No suitable directory found in PATH to install 'jacs'");
            std::process::exit(1);
        }
    }
}