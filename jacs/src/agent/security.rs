use crate::agent::Agent;
use crate::agent::FileLoader;
use crate::error;
use std::error::Error;
use std::fs;
use tracing::info;

use std::fs::Permissions;
#[cfg(not(target_arch = "wasm32"))]
#[cfg(not(target_os = "windows"))]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use walkdir::WalkDir;

/// off by default
/// /// This environment variable determine if files are saved to the filesystem at all
/// if you are building something that passing data through to a database, you'd set this flag to 0 or False
const JACS_USE_SECURITY: &str = "JACS_USE_SECURITY";

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
    // Mark the file as not executable
    #[cfg(not(target_arch = "wasm32"))]
    #[cfg(not(target_os = "windows"))]
    fn mark_file_not_executable(&self, path: &std::path::Path) -> Result<(), Box<dyn Error>> {
        std::fs::set_permissions(Path::new(path), Permissions::from_mode(0o600))?;
        Ok(())
    }

    // Mark the file as not executable
    #[cfg(not(target_arch = "wasm32"))]
    #[cfg(target_os = "windows")]
    fn mark_file_not_executable(&self, path: &std::path::Path) -> Result<(), Box<dyn Error>> {
        use std::os::windows::fs::MetadataExt;
        use windows::Win32::Security::ACL;
        use windows::Win32::Security::Authorization::{
            DACL_SECURITY_INFORMATION, SetNamedSecurityInfoW,
        };

        // Remove execute permissions by modifying the ACL
        let wide_path = windows::core::PWSTR::from_raw(
            dest_path
                .as_os_str()
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>()
                .as_mut_ptr(),
        );
        unsafe {
            SetNamedSecurityInfoW(
                wide_path,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&ACL::default()),
                None,
            )?;
        }
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
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

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg(target_os = "windows")]
    fn is_executable(&self, path: &std::path::Path) -> bool {
        if !use_fs_security() {
            info!(
                "is_executable  not detectable on window: {}",
                path.to_string_lossy()
            );
            return false;
        }

        // First, check the file extension
        if let Some(ext) = path.extension() {
            match ext.to_str().unwrap_or("").to_lowercase().as_str() {
                "exe" | "bat" | "cmd" | "ps1" => {
                    let _ = quarantine_file(path)?;
                }
                _ => (),
            }
        }

        // check for the MZ header indicative of PE files
        // This requires reading the first two bytes of the file
        if let Ok(mut file) = std::fs::File::open(path) {
            let mut buffer = [0; 2];
            if std::io::Read::read(&mut file, &mut buffer).is_ok() {
                if buffer == [0x4D, 0x5A] {
                    // MZ header in hex
                    return true;
                }
            }
        }

        false
    }
    fn quarantine_file(&self, file_path: &Path) -> Result<(), Box<dyn Error>> {
        if !self.use_fs_security() {
            info!(
                "is_executable not possible because filesystem is not used: {}",
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
        let mut quarantine_dir = Path::new(&data_dir);
        let binding = quarantine_dir.join("quarantine");
        quarantine_dir = &binding;

        if !quarantine_dir.exists() {
            fs::create_dir_all(quarantine_dir)?;
            let permissions = Permissions::from_mode(0o644);
            fs::set_permissions(quarantine_dir, permissions)?;
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
