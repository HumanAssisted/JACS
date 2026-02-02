use crate::agent::Agent;
use crate::agent::FileLoader;
use std::error::Error;
use std::fs;
use tracing::{error, info};

use std::fs::Permissions;
#[cfg(all(not(target_arch = "wasm32"), not(target_os = "windows")))]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use walkdir::WalkDir;

/// off by default
/// /// This environment variable determine if files are saved to the filesystem at all
/// if you are building something that passing data through to a database, you'd set this flag to 0 or False
const _JACS_USE_SECURITY: &str = "JACS_USE_SECURITY";

pub trait SecurityTraits {
    fn use_security(&self) -> bool;
    fn use_fs_security(&self) -> bool;
    fn check_data_directory(&self) -> Result<(), Box<dyn Error>>;
    fn is_executable(&self, path: &std::path::Path) -> bool;
    fn quarantine_file(&self, file_path: &Path) -> Result<(), Box<dyn Error>>;
    fn mark_file_not_executable(&self, path: &std::path::Path) -> Result<(), Box<dyn Error>>;
}

impl SecurityTraits for Agent {
    /// this function attempts to detect executable files
    /// if they should be there alert the user
    /// /// it will move all exuctable documents in JACS_DATA_DIRECTORY a quarantine directory
    fn check_data_directory(&self) -> Result<(), Box<dyn Error>> {
        if !self.use_security() {
            info!("JACS_USE_SECURITY security is off");
            return Ok(());
        }
        if !self.use_fs_security() {
            info!("filesystem security is off because the config is not using filestyem ");
            return Ok(());
        }

        let data_dir = self
            .config
            .as_ref()
            .unwrap()
            .jacs_data_directory()
            .as_deref()
            .unwrap_or_default();
        let dir = Path::new(&data_dir);

        for entry in WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
        {
            if self.is_executable(entry.path()) {
                let _ = self.quarantine_file(entry.path());
            }
        }
        Ok(())
    }
    /// determine if the system is configured ot use security features
    /// EXPERIMENTAL
    fn use_security(&self) -> bool {
        matches!(self.config.as_ref().unwrap().jacs_use_security(), Some(value) if matches!(value.to_lowercase().as_str(), "true" | "1"))
    }

    fn use_fs_security(&self) -> bool {
        self.use_filesystem()
    }
    // Mark the file as not executable (Unix)
    #[cfg(all(not(target_arch = "wasm32"), not(target_os = "windows")))]
    fn mark_file_not_executable(&self, path: &std::path::Path) -> Result<(), Box<dyn Error>> {
        std::fs::set_permissions(Path::new(path), Permissions::from_mode(0o600))?;
        Ok(())
    }

    // Mark the file as not executable (Windows)
    // On Windows, we can't easily remove execute permissions via standard Rust APIs.
    // The file has already been moved to quarantine, which is the primary security measure.
    #[cfg(all(not(target_arch = "wasm32"), target_os = "windows"))]
    fn mark_file_not_executable(&self, path: &std::path::Path) -> Result<(), Box<dyn Error>> {
        // On Windows, files are executable based on extension, not permissions.
        // We could use Windows ACL APIs via the `windows` crate, but for now
        // we rely on quarantine and log a warning.
        warn!(
            "Windows: Cannot modify execute permissions for {:?}. File has been quarantined.",
            path
        );
        Ok(())
    }

    // WASM stub - no filesystem permissions
    #[cfg(target_arch = "wasm32")]
    fn mark_file_not_executable(&self, _path: &std::path::Path) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    // Check if file is executable (Unix)
    #[cfg(all(not(target_arch = "wasm32"), not(target_os = "windows")))]
    fn is_executable(&self, path: &std::path::Path) -> bool {
        if !self.use_fs_security() {
            info!(
                "is_executable not possible because security is off: {}",
                path.to_string_lossy()
            );
            return false;
        }

        let metadata = match path.metadata() {
            Ok(metadata) => metadata,
            Err(_) => return false,
        };

        // On Unix-like systems, check if any executable bits are set
        metadata.permissions().mode() & 0o111 != 0
    }

    // Check if file is executable (Windows)
    #[cfg(all(not(target_arch = "wasm32"), target_os = "windows"))]
    fn is_executable(&self, path: &std::path::Path) -> bool {
        use std::io::Read;

        if !self.use_fs_security() {
            info!(
                "is_executable check on Windows: {}",
                path.to_string_lossy()
            );
            return false;
        }

        // On Windows, check file extension for known executable types
        if let Some(ext) = path.extension() {
            let ext_lower = ext.to_str().unwrap_or("").to_lowercase();
            if matches!(ext_lower.as_str(), "exe" | "bat" | "cmd" | "ps1" | "com" | "scr") {
                return true;
            }
        }

        // Also check for the MZ header indicative of PE files
        // This catches executables that may have been renamed
        if let Ok(mut file) = std::fs::File::open(path) {
            let mut buffer = [0u8; 2];
            if file.read_exact(&mut buffer).is_ok() && buffer == [0x4D, 0x5A] {
                // MZ header
                return true;
            }
        }

        false
    }

    // WASM stub - no filesystem
    #[cfg(target_arch = "wasm32")]
    fn is_executable(&self, _path: &std::path::Path) -> bool {
        false
    }
    fn quarantine_file(&self, file_path: &Path) -> Result<(), Box<dyn Error>> {
        if !self.use_fs_security() {
            info!(
                "quarantine not possible because filesystem is not used: {}",
                file_path.to_string_lossy()
            );
            return Ok(());
        }

        let data_dir = self
            .config
            .as_ref()
            .unwrap()
            .jacs_data_directory()
            .as_deref()
            .unwrap_or_default();
        let quarantine_dir = Path::new(&data_dir).join("quarantine");

        if !quarantine_dir.exists() {
            fs::create_dir_all(&quarantine_dir).map_err(|e| {
                format!(
                    "Failed to create quarantine directory '{}': {}. \
                    Check that the parent directory exists and has write permissions.",
                    quarantine_dir.display(),
                    e
                )
            })?;
            // Set directory permissions (Unix only)
            #[cfg(all(not(target_arch = "wasm32"), not(target_os = "windows")))]
            {
                let permissions = Permissions::from_mode(0o755);
                fs::set_permissions(&quarantine_dir, permissions).map_err(|e| {
                    format!(
                        "Failed to set permissions on quarantine directory '{}': {}",
                        quarantine_dir.display(),
                        e
                    )
                })?;
            }
        }

        let file_name = match file_path.file_name() {
            Some(name) => name,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Invalid file path",
                )
                .into());
            }
        };
        let dest_path = quarantine_dir.join(file_name);
        error!(
            "security: moving {:?} to {:?} as it may be executable.",
            file_name, dest_path
        );
        // Move the file to the quarantine directory
        fs::rename(file_path, &dest_path)?;
        self.mark_file_not_executable(&dest_path)?;

        Ok(())
    }
}
