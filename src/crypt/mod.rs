pub mod pq;
pub mod ringwrapper;
pub mod rsawrapper;

use chrono::Utc;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
enum CryptoSigningAlgorithm {
    RsaPss,
    RingEd25519,
    PqDilithium,
}
/* usage
    match algo {
        CryptoSigningAlgorithm::RsaPss => println!("Using RSA-PSS"),
        CryptoSigningAlgorithm::RingEd25519 => println!("Using ring-Ed25519"),
        CryptoSigningAlgorithm::PqDilithium => println!("Using pq-dilithium"),
    }
*/

fn save_file(file_path: &str, filename: &str, content: &[u8]) -> std::io::Result<String> {
    let full_path = Path::new(file_path).join(filename);

    if full_path.exists() {
        let backup_path = create_backup_path(&full_path)?;
        fs::copy(&full_path, backup_path)?;
    }

    fs::write(full_path.clone(), content)?;
    // .to_string_lossy().into_owned()
    match full_path.into_os_string().into_string() {
        Ok(path_string) => Ok(path_string),
        Err(os_string) => {
            // Convert the OsString into an io::Error
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Path contains invalid unicode: {:?}", os_string),
            ))
        }
    }
}

fn load_file(file_path: &str, filename: &str) -> std::io::Result<String> {
    let full_path = Path::new(file_path).join(filename);
    return std::fs::read_to_string(full_path);
}

// Helper function to create a backup file name based on the current timestamp
fn create_backup_path(file_path: &Path) -> std::io::Result<PathBuf> {
    let timestamp = Utc::now().format("backup-%Y-%m-%d-%H-%M").to_string();
    let file_stem =
        file_path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to read file stem",
            ))?;
    let extension = file_path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("");

    let backup_filename = format!("{}.{}.{}", timestamp, file_stem, extension);
    let backup_path = file_path.with_file_name(backup_filename);

    Ok(backup_path)
}
