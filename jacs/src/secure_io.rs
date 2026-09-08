use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ParentSymlinkPolicy {
    /// Reject symlinks in parent path components. This is the default for
    /// JACS-owned config, key, trust, and journal state.
    Reject,
    /// Resolve the parent once, then operate relative to the opened directory.
    /// This is an explicit compatibility mode for user paths that may pass
    /// through system symlinks such as macOS `/var -> /private/var`.
    AllowResolvedParent,
}

pub(crate) fn read_no_follow(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    read_no_follow_with_policy(path, ParentSymlinkPolicy::Reject)
}

pub(crate) fn read_no_follow_bounded(
    path: impl AsRef<Path>,
    max_bytes: usize,
) -> io::Result<Vec<u8>> {
    read_no_follow_bounded_with_policy(path, max_bytes, ParentSymlinkPolicy::Reject)
}

pub(crate) fn read_no_follow_allow_resolved_parent(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    read_no_follow_with_policy(path, ParentSymlinkPolicy::AllowResolvedParent)
}

pub(crate) fn read_to_string_no_follow(path: impl AsRef<Path>) -> io::Result<String> {
    read_to_string_no_follow_with_policy(path, ParentSymlinkPolicy::Reject)
}

pub(crate) fn read_to_string_no_follow_allow_resolved_parent(
    path: impl AsRef<Path>,
) -> io::Result<String> {
    read_to_string_no_follow_with_policy(path, ParentSymlinkPolicy::AllowResolvedParent)
}

pub(crate) fn write_new_file(path: impl AsRef<Path>, bytes: &[u8], mode: u32) -> io::Result<()> {
    write_new_file_with_policy(path, bytes, mode, ParentSymlinkPolicy::Reject)
}

pub(crate) fn write_new_file_allow_resolved_parent(
    path: impl AsRef<Path>,
    bytes: &[u8],
    mode: u32,
) -> io::Result<()> {
    write_new_file_with_policy(path, bytes, mode, ParentSymlinkPolicy::AllowResolvedParent)
}

pub(crate) fn write_atomic_replace_no_symlink(
    path: impl AsRef<Path>,
    bytes: &[u8],
    mode: u32,
    require_existing_regular: bool,
) -> io::Result<()> {
    write_atomic_replace_no_symlink_with_policy(
        path,
        bytes,
        mode,
        require_existing_regular,
        ParentSymlinkPolicy::Reject,
    )
}

pub(crate) fn write_atomic_replace_no_symlink_allow_resolved_parent(
    path: impl AsRef<Path>,
    bytes: &[u8],
    mode: u32,
    require_existing_regular: bool,
) -> io::Result<()> {
    write_atomic_replace_no_symlink_with_policy(
        path,
        bytes,
        mode,
        require_existing_regular,
        ParentSymlinkPolicy::AllowResolvedParent,
    )
}

/// Open or create a persistent advisory-lock file without following symlinks.
///
/// On Unix this operation is anchored to an already-opened, symlink-free
/// parent directory and uses `O_NOFOLLOW | O_CLOEXEC`. Before permissions are
/// tightened or callers acquire a lock, the opened inode must be a regular
/// file owned by the effective user with exactly one hard link. This prevents
/// a lock path from being used as a chmod/lock oracle for another file.
///
/// On Windows, Rust-created handles are non-inheritable and the final component
/// is opened with `FILE_FLAG_OPEN_REPARSE_POINT` before regular-file
/// validation. Other non-Unix targets receive the strongest portable
/// pre/post-open symlink and regular-file checks available in `std`.
pub(crate) fn open_private_lock_file_no_follow(path: impl AsRef<Path>) -> io::Result<File> {
    let path = path.as_ref();
    ensure_parent_exists(path, ParentSymlinkPolicy::Reject).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "failed to create or validate advisory-lock parent for '{}': {error}",
                path.display()
            ),
        )
    })?;

    #[cfg(unix)]
    {
        let parent = OpenedParent::open(path, ParentSymlinkPolicy::Reject).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "failed to anchor advisory-lock parent for '{}': {error}",
                    path.display()
                ),
            )
        })?;
        run_parent_open_test_hook(path);
        let file = parent.open_private_lock_file().map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "failed to open advisory-lock file '{}': {error}",
                    path.display()
                ),
            )
        })?;
        validate_private_lock_file(&file, path)?;
        Ok(file)
    }

    #[cfg(not(unix))]
    {
        open_private_lock_file_portable(path)
    }
}

fn read_to_string_no_follow_with_policy(
    path: impl AsRef<Path>,
    policy: ParentSymlinkPolicy,
) -> io::Result<String> {
    let bytes = read_no_follow_with_policy(path, policy)?;
    String::from_utf8(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn read_no_follow_with_policy(
    path: impl AsRef<Path>,
    policy: ParentSymlinkPolicy,
) -> io::Result<Vec<u8>> {
    let path = path.as_ref();

    #[cfg(unix)]
    {
        let parent = OpenedParent::open(path, policy)?;
        run_parent_open_test_hook(path);
        parent.read_no_follow()
    }

    #[cfg(not(unix))]
    {
        if policy == ParentSymlinkPolicy::Reject {
            return Err(unsupported_authority_path_platform());
        }
        let mut file = open_no_follow(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }
}

fn read_no_follow_bounded_with_policy(
    path: impl AsRef<Path>,
    max_bytes: usize,
    policy: ParentSymlinkPolicy,
) -> io::Result<Vec<u8>> {
    let path = path.as_ref();

    #[cfg(unix)]
    {
        let parent = OpenedParent::open(path, policy)?;
        run_parent_open_test_hook(path);
        parent.read_no_follow_bounded(max_bytes)
    }

    #[cfg(not(unix))]
    {
        if policy == ParentSymlinkPolicy::Reject {
            return Err(unsupported_authority_path_platform());
        }
        let file = open_no_follow(path)?;
        read_file_bounded(file, max_bytes, path)
    }
}

fn read_file_bounded(file: impl Read, max_bytes: usize, path: &Path) -> io::Result<Vec<u8>> {
    let limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(max_bytes.min(8 * 1024));
    file.take(limit).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "refusing to read '{}' because it exceeds the {}-byte limit",
                path.display(),
                max_bytes
            ),
        ));
    }
    Ok(bytes)
}

fn write_new_file_with_policy(
    path: impl AsRef<Path>,
    bytes: &[u8],
    mode: u32,
    policy: ParentSymlinkPolicy,
) -> io::Result<()> {
    let path = path.as_ref();
    ensure_parent_exists(path, policy)?;

    #[cfg(unix)]
    {
        let parent = OpenedParent::open(path, policy)?;
        parent.create_new(bytes, mode)
    }

    #[cfg(not(unix))]
    {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        let _ = mode;

        let mut file = options.open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }
}

fn write_atomic_replace_no_symlink_with_policy(
    path: impl AsRef<Path>,
    bytes: &[u8],
    mode: u32,
    require_existing_regular: bool,
    policy: ParentSymlinkPolicy,
) -> io::Result<()> {
    let path = path.as_ref();
    ensure_parent_exists(path, policy)?;

    #[cfg(unix)]
    {
        let parent = OpenedParent::open(path, policy)?;
        run_parent_open_test_hook(path);
        parent.atomic_replace(bytes, mode, require_existing_regular)
    }

    #[cfg(not(unix))]
    {
        let _ = policy;
        validate_final_entry_path(path, require_existing_regular)?;

        run_parent_open_test_hook(path);
        let parent = parent_or_current(path);
        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        let _ = mode;

        tmp.write_all(bytes)?;
        tmp.as_file_mut().sync_all()?;
        tmp.persist(path).map_err(|e| e.error)?;
        sync_parent_dir(path);
        Ok(())
    }
}

fn ensure_parent_exists(path: &Path, policy: ParentSymlinkPolicy) -> io::Result<()> {
    #[cfg(not(unix))]
    if policy == ParentSymlinkPolicy::Reject {
        return Err(unsupported_authority_path_platform());
    }

    let parent = parent_or_current(path);
    if parent.as_os_str().is_empty() || parent == Path::new(".") {
        return Ok(());
    }

    #[cfg(unix)]
    {
        match policy {
            ParentSymlinkPolicy::Reject => create_dir_all_no_symlink(parent),
            ParentSymlinkPolicy::AllowResolvedParent => fs::create_dir_all(parent),
        }
    }

    #[cfg(not(unix))]
    {
        let _ = policy;
        fs::create_dir_all(parent)
    }
}

#[cfg(not(unix))]
fn unsupported_authority_path_platform() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "race-safe owner/ACL validation for authority-bearing paths is unsupported on this platform; place authority in an authenticated deployment control plane",
    )
}

#[cfg(unix)]
struct OpenedParent {
    dir: File,
    file_name: std::ffi::CString,
    display_path: PathBuf,
    authority_path: bool,
}

#[cfg(unix)]
impl OpenedParent {
    fn open(path: &Path, policy: ParentSymlinkPolicy) -> io::Result<Self> {
        let parent_path = parent_or_current(path);
        let dir = match policy {
            ParentSymlinkPolicy::Reject => open_authority_dir_no_follow(parent_path)?,
            ParentSymlinkPolicy::AllowResolvedParent => {
                let resolved_parent = fs::canonicalize(parent_path)?;
                open_dir_no_follow(&resolved_parent)?
            }
        };

        Ok(Self {
            dir,
            file_name: final_component_cstring(path)?,
            display_path: path.to_path_buf(),
            authority_path: policy == ParentSymlinkPolicy::Reject,
        })
    }

    fn create_new(&self, bytes: &[u8], mode: u32) -> io::Result<()> {
        if self.authority_path {
            validate_authority_file_mode(mode)?;
        }
        let fd = openat_new_file(self.dir.as_raw_fd(), &self.file_name, mode)?;
        // SAFETY: fd was returned by openat and is now owned by File.
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(bytes)?;
        file.sync_all()?;
        let named = validate_final_entry(
            self.dir.as_raw_fd(),
            &self.file_name,
            &self.display_path,
            true,
            self.authority_path,
        )?
        .expect("new final entry has metadata");
        validate_opened_file(&file, Some(&named), &self.display_path, self.authority_path)?;
        sync_dir(&self.dir)?;
        Ok(())
    }

    fn atomic_replace(
        &self,
        bytes: &[u8],
        mode: u32,
        require_existing_regular: bool,
    ) -> io::Result<()> {
        if self.authority_path {
            validate_authority_file_mode(mode)?;
        }
        validate_final_entry(
            self.dir.as_raw_fd(),
            &self.file_name,
            &self.display_path,
            require_existing_regular,
            self.authority_path,
        )?;

        let temp_name = std::ffi::CString::new(format!(".jacs-tmp-{}", uuid::Uuid::new_v4()))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let fd = openat_new_file(self.dir.as_raw_fd(), &temp_name, mode)?;
        // SAFETY: fd was returned by openat and is now owned by File.
        let mut tmp = unsafe { File::from_raw_fd(fd) };
        let result = (|| -> io::Result<()> {
            tmp.write_all(bytes)?;
            tmp.sync_all()?;
            validate_opened_file(&tmp, None, &self.display_path, self.authority_path)?;
            renameat(self.dir.as_raw_fd(), &temp_name, &self.file_name)?;
            let renamed = validate_final_entry(
                self.dir.as_raw_fd(),
                &self.file_name,
                &self.display_path,
                true,
                self.authority_path,
            )?
            .expect("renamed final entry has metadata");
            validate_opened_file(
                &tmp,
                Some(&renamed),
                &self.display_path,
                self.authority_path,
            )?;
            sync_dir(&self.dir)?;
            Ok(())
        })();
        if result.is_err() {
            unlinkat(self.dir.as_raw_fd(), &temp_name);
        }
        result
    }

    fn read_no_follow(&self) -> io::Result<Vec<u8>> {
        let expected = validate_final_entry(
            self.dir.as_raw_fd(),
            &self.file_name,
            &self.display_path,
            true,
            self.authority_path,
        )?
        .expect("required existing final entry has metadata");
        let fd = openat_existing_file(self.dir.as_raw_fd(), &self.file_name)?;
        // SAFETY: fd was returned by openat and is now owned by File.
        let mut file = unsafe { File::from_raw_fd(fd) };
        validate_opened_file(
            &file,
            Some(&expected),
            &self.display_path,
            self.authority_path,
        )?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        validate_opened_file(
            &file,
            Some(&expected),
            &self.display_path,
            self.authority_path,
        )?;
        Ok(bytes)
    }

    fn read_no_follow_bounded(&self, max_bytes: usize) -> io::Result<Vec<u8>> {
        let expected = validate_final_entry(
            self.dir.as_raw_fd(),
            &self.file_name,
            &self.display_path,
            true,
            self.authority_path,
        )?
        .expect("required existing final entry has metadata");
        let fd = openat_existing_file(self.dir.as_raw_fd(), &self.file_name)?;
        // SAFETY: fd was returned by openat and is now owned by File.
        let file = unsafe { File::from_raw_fd(fd) };
        validate_opened_file(
            &file,
            Some(&expected),
            &self.display_path,
            self.authority_path,
        )?;
        let bytes = read_file_bounded(&file, max_bytes, &self.display_path)?;
        validate_opened_file(
            &file,
            Some(&expected),
            &self.display_path,
            self.authority_path,
        )?;
        Ok(bytes)
    }

    fn open_private_lock_file(&self) -> io::Result<File> {
        let fd = openat_private_lock_file(self.dir.as_raw_fd(), &self.file_name)?;
        // SAFETY: fd was returned by openat and is now owned by File.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> io::Result<File> {
    if let Ok(meta) = fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        return Err(io::Error::other(format!(
            "refusing to follow symlink at '{}'",
            path.display()
        )));
    }
    File::open(path)
}

#[cfg(not(unix))]
fn open_private_lock_file_portable(path: &Path) -> io::Result<File> {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && metadata.file_type().is_symlink()
    {
        return Err(io::Error::other(format!(
            "refusing advisory lock symlink at '{}'",
            path.display()
        )));
    }

    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // CreateFileW opens the reparse point itself instead of following it.
        // Rust passes non-inheritable security attributes, the Windows
        // equivalent of close-on-exec for this handle.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(io::Error::other(format!(
            "refusing advisory lock path '{}': opened object is not a regular file",
            path.display()
        )));
    }
    Ok(file)
}

#[cfg(not(unix))]
fn validate_final_entry_path(path: &Path, require_existing_regular: bool) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(io::Error::other(format!(
                    "refusing to follow symlink at '{}'",
                    path.display()
                )));
            }
            if require_existing_regular && !meta.file_type().is_file() {
                return Err(io::Error::other(format!(
                    "refusing to update '{}': path is not a regular file",
                    path.display()
                )));
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound && !require_existing_regular => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(not(unix))]
fn sync_parent_dir(path: &Path) {
    let _ = File::open(parent_or_current(path)).and_then(|dir| dir.sync_all());
}

#[cfg(unix)]
fn create_dir_all_no_symlink(path: &Path) -> io::Result<()> {
    let mut dir = if path.is_absolute() {
        open_dir_path(Path::new("/"))?
    } else {
        // A relative authority path inherits the security of the process
        // working directory.  Resolve that directory to its absolute name and
        // prove every ancestor before using it as the descriptor-walk root;
        // checking only `.` would incorrectly claim full-path protection.
        let current = std::env::current_dir()?;
        open_authority_dir_no_follow(&current)?
    };
    validate_authority_directory(&dir, path)?;

    for component in path.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("refusing parent traversal in '{}'", path.display()),
                ));
            }
            std::path::Component::Normal(_) => {
                let name = std::ffi::CString::new(component.as_os_str().as_bytes())
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                match statat_no_follow(dir.as_raw_fd(), &name) {
                    Ok(stat) => {
                        if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
                            return Err(io::Error::other(format!(
                                "refusing to use non-directory parent component '{}' in '{}'",
                                component.as_os_str().to_string_lossy(),
                                path.display()
                            )));
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        // Another process may create this component after the
                        // no-follow stat and before mkdirat. Treat EEXIST as a
                        // race winner, then let the anchored O_NOFOLLOW
                        // open below prove that the resulting entry is a
                        // directory rather than a symlink or other object.
                        match mkdirat(dir.as_raw_fd(), &name, 0o700) {
                            Ok(()) => {}
                            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                            Err(error) => return Err(error),
                        }
                    }
                    Err(e) => return Err(e),
                }

                let next = openat_dir_no_follow(dir.as_raw_fd(), &name)?;
                // SAFETY: fd was returned by openat and is now owned by File.
                dir = unsafe { File::from_raw_fd(next) };
                validate_authority_directory(&dir, path)?;
            }
            std::path::Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported path prefix",
                ));
            }
        }
    }

    Ok(())
}

#[cfg(unix)]
fn open_dir_no_follow(path: &Path) -> io::Result<File> {
    open_dir_no_follow_with_authority(path, false)
}

#[cfg(unix)]
fn open_authority_dir_no_follow(path: &Path) -> io::Result<File> {
    open_dir_no_follow_with_authority(path, true)
}

#[cfg(unix)]
fn open_dir_no_follow_with_authority(path: &Path, authority_path: bool) -> io::Result<File> {
    let mut dir = if path.is_absolute() {
        open_dir_path(Path::new("/"))?
    } else if authority_path {
        // See `create_dir_all_no_symlink`: authority-bearing relative paths
        // must validate the complete absolute ancestry of the current working
        // directory before walking their relative suffix.
        let current = std::env::current_dir()?;
        open_dir_no_follow_with_authority(&current, true)?
    } else {
        open_dir_path(Path::new("."))?
    };
    if authority_path {
        validate_authority_directory(&dir, path)?;
    }

    for component in path.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("refusing parent traversal in '{}'", path.display()),
                ));
            }
            std::path::Component::Normal(_) => {
                let name = std::ffi::CString::new(component.as_os_str().as_bytes())
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                let next = openat_dir_no_follow(dir.as_raw_fd(), &name)?;
                // SAFETY: fd was returned by openat and is now owned by File.
                dir = unsafe { File::from_raw_fd(next) };
                if authority_path {
                    validate_authority_directory(&dir, path)?;
                }
            }
            std::path::Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported path prefix",
                ));
            }
        }
    }

    Ok(dir)
}

/// Create (when absent) and validate a dedicated owner-only authority directory.
///
/// Unix is currently the only platform where this crate can prove the required
/// owner/mode invariants without adding an OS account/ACL dependency. Other
/// platforms fail closed instead of claiming that a pathname is an authority.
pub(crate) fn ensure_owner_only_directory(path: impl AsRef<Path>) -> io::Result<()> {
    let path = path.as_ref();

    #[cfg(unix)]
    {
        create_dir_all_no_symlink(path)?;
        validate_owner_only_directory(path)
    }

    #[cfg(not(unix))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "owner-authenticated authority directories are unsupported on this platform; use an authenticated deployment control plane",
        ))
    }
}

/// Validate an existing dedicated owner-only authority directory without
/// creating it. This is used by read/open paths so a failed lookup has no
/// filesystem side effect.
pub(crate) fn validate_owner_only_directory(path: impl AsRef<Path>) -> io::Result<()> {
    let path = path.as_ref();

    #[cfg(unix)]
    {
        let dir = open_authority_dir_no_follow(path)?;
        let stat = fstat(&dir)?;
        // SAFETY: geteuid has no preconditions.
        let effective_uid = unsafe { libc::geteuid() };
        if stat.st_uid != effective_uid || stat.st_mode & 0o777 != 0o700 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "authority directory '{}' must be owned by effective uid {} with mode 0700",
                    path.display(),
                    effective_uid
                ),
            ));
        }
        Ok(())
    }

    #[cfg(not(unix))]
    {
        let _ = path;
        Err(unsupported_authority_path_platform())
    }
}

#[cfg(unix)]
fn open_dir_path(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW);
    options.open(path)
}

#[cfg(unix)]
fn final_component_cstring(path: &Path) -> io::Result<std::ffi::CString> {
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path '{}' has no final component", path.display()),
        )
    })?;
    std::ffi::CString::new(name.as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

#[cfg(unix)]
fn validate_final_entry(
    dir_fd: libc::c_int,
    file_name: &std::ffi::CStr,
    path: &Path,
    require_existing_regular: bool,
    authority_path: bool,
) -> io::Result<Option<libc::stat>> {
    match statat_no_follow(dir_fd, file_name) {
        Ok(stat) => {
            let file_type = stat.st_mode & libc::S_IFMT;
            if file_type == libc::S_IFLNK {
                return Err(io::Error::other(format!(
                    "refusing to follow symlink at '{}'",
                    path.display()
                )));
            }
            if file_type != libc::S_IFREG {
                return Err(io::Error::other(format!(
                    "refusing to update '{}': path is not a regular file",
                    path.display()
                )));
            }
            if authority_path {
                validate_authority_file_stat(&stat, path)?;
            }
            Ok(Some(stat))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound && !require_existing_regular => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(unix)]
fn fstat(file: &File) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `file` owns a live descriptor and `stat` points to writable memory.
    if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstat returned success, so stat is initialized.
    Ok(unsafe { stat.assume_init() })
}

#[cfg(unix)]
fn validate_authority_directory(file: &File, path: &Path) -> io::Result<()> {
    let stat = fstat(file)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(io::Error::other(format!(
            "authority ancestor '{}' is not a directory",
            path.display()
        )));
    }
    // SAFETY: geteuid has no preconditions.
    let effective_uid = unsafe { libc::geteuid() };
    if stat.st_uid != effective_uid && stat.st_uid != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "authority ancestor '{}' is owned by uid {}, not effective uid {} or root",
                path.display(),
                stat.st_uid,
                effective_uid
            ),
        ));
    }
    let group_or_other_writable = stat.st_mode & 0o022 != 0;
    let root_sticky_exception = stat.st_uid == 0 && stat.st_mode & libc::S_ISVTX != 0;
    if group_or_other_writable && !root_sticky_exception {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "authority ancestor '{}' is writable by group or other",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_authority_file_mode(mode: u32) -> io::Result<()> {
    if mode & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("authority file mode {mode:o} permits group/other writes"),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_authority_file_stat(stat: &libc::stat, path: &Path) -> io::Result<()> {
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(io::Error::other(format!(
            "authority file '{}' is not regular",
            path.display()
        )));
    }
    // SAFETY: geteuid has no preconditions.
    let effective_uid = unsafe { libc::geteuid() };
    if stat.st_uid != effective_uid && stat.st_uid != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "authority file '{}' is owned by uid {}, not effective uid {} or root",
                path.display(),
                stat.st_uid,
                effective_uid
            ),
        ));
    }
    if stat.st_mode & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "authority file '{}' is writable by group or other",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_opened_file(
    file: &File,
    expected: Option<&libc::stat>,
    path: &Path,
    authority_path: bool,
) -> io::Result<()> {
    let actual = fstat(file)?;
    if actual.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(io::Error::other(format!(
            "opened path '{}' is not a regular file",
            path.display()
        )));
    }
    if let Some(expected) = expected
        && (actual.st_dev != expected.st_dev
            || actual.st_ino != expected.st_ino
            || actual.st_uid != expected.st_uid
            || actual.st_mode != expected.st_mode
            || actual.st_nlink != expected.st_nlink
            || actual.st_size != expected.st_size)
    {
        return Err(io::Error::other(format!(
            "opened path '{}' changed identity or metadata during access",
            path.display()
        )));
    }
    if authority_path {
        validate_authority_file_stat(&actual, path)?;
    }
    Ok(())
}

#[cfg(unix)]
fn statat_no_follow(dir_fd: libc::c_int, file_name: &std::ffi::CStr) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: file_name is a valid C string; stat points to writable memory.
    let rc = unsafe {
        libc::fstatat(
            dir_fd,
            file_name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc == 0 {
        // SAFETY: fstatat returned success, so stat is initialized.
        Ok(unsafe { stat.assume_init() })
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn openat_dir_no_follow(
    dir_fd: libc::c_int,
    file_name: &std::ffi::CStr,
) -> io::Result<libc::c_int> {
    let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
    // SAFETY: file_name is a valid C string and dir_fd is expected to be open.
    let fd = unsafe { libc::openat(dir_fd, file_name.as_ptr(), flags) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

#[cfg(unix)]
fn openat_existing_file(
    dir_fd: libc::c_int,
    file_name: &std::ffi::CStr,
) -> io::Result<libc::c_int> {
    let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    // SAFETY: file_name is a valid C string and dir_fd is expected to be open.
    let fd = unsafe { libc::openat(dir_fd, file_name.as_ptr(), flags) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

#[cfg(unix)]
fn openat_new_file(
    dir_fd: libc::c_int,
    file_name: &std::ffi::CStr,
    mode: u32,
) -> io::Result<libc::c_int> {
    let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    // SAFETY: file_name is a valid C string and dir_fd is expected to be open.
    let fd = unsafe { libc::openat(dir_fd, file_name.as_ptr(), flags, mode as libc::c_uint) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

#[cfg(unix)]
fn openat_private_lock_file(
    dir_fd: libc::c_int,
    file_name: &std::ffi::CStr,
) -> io::Result<libc::c_int> {
    const MAX_CREATE_RACE_RETRIES: usize = 16;
    let existing_flags = libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
    let create_flags = existing_flags | libc::O_CREAT | libc::O_EXCL;

    // Split "open existing" from "create new" so concurrent creators cannot
    // hit platform-specific O_CREAT/O_NOFOLLOW ambiguity. Every attempt stays
    // relative to the same anchored parent descriptor. An attacker that keeps
    // replacing the final entry can only force this bounded operation to fail.
    for _ in 0..MAX_CREATE_RACE_RETRIES {
        // SAFETY: file_name is a valid C string and dir_fd is an open directory.
        let existing = unsafe { libc::openat(dir_fd, file_name.as_ptr(), existing_flags) };
        if existing >= 0 {
            return Ok(existing);
        }
        let open_error = io::Error::last_os_error();
        if open_error.kind() != io::ErrorKind::NotFound {
            return Err(open_error);
        }

        // SAFETY: file_name is a valid C string, dir_fd is open, and the mode
        // uses the promoted C unsigned type required by openat's variadic ABI.
        let created = unsafe {
            libc::openat(
                dir_fd,
                file_name.as_ptr(),
                create_flags,
                0o600 as libc::c_uint,
            )
        };
        if created >= 0 {
            return Ok(created);
        }
        let create_error = io::Error::last_os_error();
        if create_error.kind() != io::ErrorKind::AlreadyExists {
            return Err(create_error);
        }
        std::thread::yield_now();
    }

    Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "advisory lock entry changed repeatedly while opening",
    ))
}

#[cfg(unix)]
fn validate_private_lock_file(file: &File, path: &Path) -> io::Result<()> {
    let fd = file.as_raw_fd();
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fd is owned by `file`; stat points to writable memory.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstat returned success, so stat is initialized.
    let stat = unsafe { stat.assume_init() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(io::Error::other(format!(
            "refusing advisory lock path '{}': opened object is not a regular file",
            path.display()
        )));
    }
    // SAFETY: geteuid has no preconditions.
    let effective_uid = unsafe { libc::geteuid() };
    if stat.st_uid != effective_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing advisory lock path '{}': file owner uid {} does not match effective uid {}",
                path.display(),
                stat.st_uid,
                effective_uid
            ),
        ));
    }
    if stat.st_nlink != 1 {
        return Err(io::Error::other(format!(
            "refusing advisory lock path '{}': expected one hard link, found {}",
            path.display(),
            stat.st_nlink
        )));
    }

    // O_CLOEXEC is atomic with open; verify the invariant before returning.
    // SAFETY: F_GETFD reads flags for the valid owned descriptor.
    let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if descriptor_flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if descriptor_flags & libc::FD_CLOEXEC == 0 {
        return Err(io::Error::other(format!(
            "refusing advisory lock path '{}': descriptor is inheritable",
            path.display()
        )));
    }

    // Validate inode identity/ownership/link count before changing mode.
    // SAFETY: fchmod operates on the validated owned regular-file descriptor.
    if unsafe { libc::fchmod(fd, 0o600 as libc::mode_t) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn mkdirat(dir_fd: libc::c_int, file_name: &std::ffi::CStr, mode: u32) -> io::Result<()> {
    // SAFETY: file_name is a valid C string and dir_fd is expected to be open.
    let rc = unsafe { libc::mkdirat(dir_fd, file_name.as_ptr(), mode as libc::mode_t) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn renameat(
    dir_fd: libc::c_int,
    old_name: &std::ffi::CStr,
    new_name: &std::ffi::CStr,
) -> io::Result<()> {
    // SAFETY: both names are valid C strings relative to the same directory fd.
    let rc = unsafe { libc::renameat(dir_fd, old_name.as_ptr(), dir_fd, new_name.as_ptr()) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn unlinkat(dir_fd: libc::c_int, file_name: &std::ffi::CStr) {
    // SAFETY: best-effort cleanup of a temp name relative to the opened dir.
    let _ = unsafe { libc::unlinkat(dir_fd, file_name.as_ptr(), 0) };
}

#[cfg(unix)]
fn sync_dir(dir: &File) -> io::Result<()> {
    dir.sync_all()
}

fn parent_or_current(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(test)]
fn set_parent_open_test_hook<F>(path: std::path::PathBuf, hook: F) -> ParentOpenHookGuard
where
    F: Fn() + Send + Sync + 'static,
{
    let slot = PARENT_OPEN_TEST_HOOK.get_or_init(|| std::sync::Mutex::new(None));
    *slot.lock().expect("parent open hook mutex") = Some((path, std::sync::Arc::new(hook)));
    ParentOpenHookGuard
}

#[cfg(test)]
fn run_parent_open_test_hook(path: &Path) {
    let hook = PARENT_OPEN_TEST_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .expect("parent open hook mutex")
        .clone();
    if let Some((expected_path, hook)) = hook
        && expected_path == path
    {
        hook();
    }
}

#[cfg(not(test))]
fn run_parent_open_test_hook(_path: &Path) {}

#[cfg(test)]
struct ParentOpenHookGuard;

#[cfg(test)]
impl Drop for ParentOpenHookGuard {
    fn drop(&mut self) {
        if let Some(slot) = PARENT_OPEN_TEST_HOOK.get() {
            *slot.lock().expect("parent open hook mutex") = None;
        }
    }
}

#[cfg(test)]
type ParentOpenTestHookInner = std::sync::Mutex<
    Option<(
        std::path::PathBuf,
        std::sync::Arc<dyn Fn() + Send + Sync + 'static>,
    )>,
>;
#[cfg(test)]
static PARENT_OPEN_TEST_HOOK: std::sync::OnceLock<ParentOpenTestHookInner> =
    std::sync::OnceLock::new();

#[cfg(test)]
mod tests {
    use super::*;

    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .expect("secure_io test lock")
    }

    #[test]
    fn bounded_read_rejects_oversized_regular_file_without_returning_prefix() {
        let _lock = test_lock();
        let tmp = tempfile::tempdir().expect("temp dir");
        let path = tmp
            .path()
            .canonicalize()
            .expect("canonical temp dir")
            .join("oversized.key");
        fs::write(&path, vec![0x41; 4097]).expect("write oversized key");

        let error = read_no_follow_bounded(&path, 4096)
            .expect_err("oversized key material must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("4096-byte limit"));
    }

    #[test]
    #[cfg(unix)]
    fn strict_policy_rejects_parent_symlink() {
        let _lock = test_lock();
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().expect("temp dir");
        let root = tmp.path().canonicalize().expect("canonical temp root");
        let safe_dir = root.join("safe");
        fs::create_dir_all(&safe_dir).expect("safe dir");
        fs::write(safe_dir.join("doc.txt"), b"safe original").expect("safe file");

        let link_dir = root.join("link");
        symlink(&safe_dir, &link_dir).expect("link to safe dir");
        let requested_path = link_dir.join("doc.txt");

        let result = write_atomic_replace_no_symlink(&requested_path, b"rewrite", 0o600, true);
        assert!(result.is_err(), "strict policy must reject parent symlinks");
        assert_eq!(
            fs::read(safe_dir.join("doc.txt")).expect("read safe"),
            b"safe original"
        );
    }

    #[test]
    #[cfg(unix)]
    fn compatibility_policy_anchors_parent_before_parent_symlink_swap() {
        let _lock = test_lock();
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().expect("temp dir");
        let root = tmp.path().canonicalize().expect("canonical temp root");
        let safe_dir = root.join("safe");
        let outside_dir = root.join("outside");
        fs::create_dir_all(&safe_dir).expect("safe dir");
        fs::create_dir_all(&outside_dir).expect("outside dir");

        let safe_file = safe_dir.join("doc.txt");
        let outside_file = outside_dir.join("doc.txt");
        fs::write(&safe_file, b"safe original").expect("safe file");
        fs::write(&outside_file, b"outside original").expect("outside file");

        let link_dir = root.join("link");
        symlink(&safe_dir, &link_dir).expect("link to safe dir");
        let requested_path = link_dir.join("doc.txt");

        let link_for_hook = link_dir.clone();
        let outside_for_hook = outside_dir.clone();
        let _hook_guard = set_parent_open_test_hook(requested_path.clone(), move || {
            fs::remove_file(&link_for_hook).expect("remove parent symlink");
            symlink(&outside_for_hook, &link_for_hook).expect("retarget parent symlink");
        });

        write_atomic_replace_no_symlink_allow_resolved_parent(
            &requested_path,
            b"safe rewritten",
            0o600,
            true,
        )
        .expect("compat replace should use originally opened parent");

        assert_eq!(fs::read(&safe_file).expect("read safe"), b"safe rewritten");
        assert_eq!(
            fs::read(&outside_file).expect("read outside"),
            b"outside original",
            "parent path swap must not redirect the atomic replace"
        );
    }

    #[test]
    #[cfg(unix)]
    fn final_symlink_is_rejected_after_parent_open() {
        let _lock = test_lock();
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().expect("temp dir");
        let root = tmp.path().canonicalize().expect("canonical temp root");
        let target = root.join("target.txt");
        let requested_path = root.join("doc.txt");
        fs::write(&requested_path, b"safe original").expect("safe file");
        fs::write(&target, b"target original").expect("target file");

        let requested_for_hook = requested_path.clone();
        let target_for_hook = target.clone();
        let _hook_guard = set_parent_open_test_hook(requested_path.clone(), move || {
            fs::remove_file(&requested_for_hook).expect("remove final file");
            symlink(&target_for_hook, &requested_for_hook).expect("replace final with symlink");
        });

        let result = write_atomic_replace_no_symlink(&requested_path, b"rewrite", 0o600, true);
        assert!(result.is_err(), "final symlink must be rejected");
        assert_eq!(fs::read(&target).expect("read target"), b"target original");
    }

    #[test]
    #[cfg(unix)]
    fn atomic_replace_replaces_hardlink_without_modifying_target() {
        let _lock = test_lock();
        let tmp = tempfile::tempdir().expect("temp dir");
        let root = tmp.path().canonicalize().expect("canonical temp root");
        let target = root.join("target.txt");
        let requested_path = root.join("doc.txt");
        fs::write(&target, b"target original").expect("target file");
        fs::hard_link(&target, &requested_path).expect("hard link");

        write_atomic_replace_no_symlink(&requested_path, b"rewritten", 0o600, true)
            .expect("replace hardlink path");

        assert_eq!(fs::read(&target).expect("read target"), b"target original");
        assert_eq!(
            fs::read(&requested_path).expect("read requested"),
            b"rewritten"
        );
    }

    #[test]
    #[cfg(unix)]
    fn private_lock_open_is_owner_only_single_link_and_close_on_exec() {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::io::AsRawFd;

        let _lock = test_lock();
        let tmp = tempfile::tempdir().expect("temp dir");
        let lock_path = tmp
            .path()
            .canonicalize()
            .expect("canonical temp dir")
            .join("state")
            .join("persistent.lock");
        let file = open_private_lock_file_no_follow(&lock_path).expect("open private lock");
        let metadata = file.metadata().expect("lock metadata");
        assert!(metadata.is_file());
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        // SAFETY: geteuid has no preconditions.
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        // SAFETY: F_GETFD reads flags for the live descriptor owned by file.
        let descriptor_flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
        assert!(descriptor_flags >= 0, "F_GETFD failed");
        assert_ne!(
            descriptor_flags & libc::FD_CLOEXEC,
            0,
            "persistent lock descriptors must never leak through exec"
        );
    }

    #[test]
    #[cfg(unix)]
    fn concurrent_private_lock_openers_share_one_relative_path_inode() {
        use std::os::unix::fs::MetadataExt;

        let _lock = test_lock();
        let cwd = std::env::current_dir()
            .expect("current directory")
            .canonicalize()
            .expect("canonical current directory");
        let tmp = tempfile::tempdir_in(&cwd).expect("temporary directory in cwd");
        let relative_root = tmp
            .path()
            .canonicalize()
            .expect("canonical temporary directory")
            .strip_prefix(&cwd)
            .expect("temporary directory is below cwd")
            .to_path_buf();
        assert!(!relative_root.is_absolute());
        let lock_path = relative_root.join("state").join("persistent.lock");

        let start = std::sync::Arc::new(std::sync::Barrier::new(3));
        let opened = std::sync::Arc::new(std::sync::Barrier::new(3));
        let spawn = |start: std::sync::Arc<std::sync::Barrier>,
                     opened: std::sync::Arc<std::sync::Barrier>| {
            let lock_path = lock_path.clone();
            std::thread::spawn(move || {
                start.wait();
                let file = open_private_lock_file_no_follow(&lock_path)
                    .expect("concurrent relative lock open");
                let metadata = file.metadata().expect("opened lock metadata");
                opened.wait();
                (metadata.dev(), metadata.ino(), metadata.nlink())
            })
        };
        let first = spawn(start.clone(), opened.clone());
        let second = spawn(start.clone(), opened.clone());
        start.wait();
        opened.wait();
        let first = first.join().expect("first opener thread");
        let second = second.join().expect("second opener thread");
        assert_eq!(
            first, second,
            "both openers must use the same single-link inode"
        );
        assert_eq!(first.2, 1);
    }

    #[test]
    #[cfg(unix)]
    fn read_no_follow_honors_parent_policy_and_rejects_final_symlink() {
        let _lock = test_lock();
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().expect("temp dir");
        let root = tmp.path().canonicalize().expect("canonical temp root");
        let safe_dir = root.join("safe");
        fs::create_dir_all(&safe_dir).expect("safe dir");
        let safe_file = safe_dir.join("doc.txt");
        fs::write(&safe_file, b"safe bytes").expect("safe file");

        let link_dir = root.join("link");
        symlink(&safe_dir, &link_dir).expect("link to safe dir");
        let requested_path = link_dir.join("doc.txt");

        assert!(
            read_no_follow(&requested_path).is_err(),
            "strict read must reject parent symlinks"
        );
        assert_eq!(
            read_no_follow_allow_resolved_parent(&requested_path).expect("compat read"),
            b"safe bytes"
        );

        let final_link = root.join("final-link.txt");
        symlink(&safe_file, &final_link).expect("final symlink");
        assert!(
            read_no_follow_allow_resolved_parent(&final_link).is_err(),
            "final symlink must be rejected even in compatibility mode"
        );
    }

    #[test]
    #[cfg(unix)]
    fn authority_walk_rejects_writable_ordinary_ancestor() {
        use std::os::unix::fs::PermissionsExt;

        let _lock = test_lock();
        let tmp = tempfile::tempdir().expect("temp dir");
        // macOS's system temp path starts with the /var symlink. Resolve only
        // this freshly created fixture root, not the authority path under test.
        let root = tmp.path().canonicalize().expect("canonical temp root");
        let writable = root.join("shared");
        let private = writable.join("private");
        fs::create_dir_all(&private).expect("directories");
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o777))
            .expect("make ordinary ancestor writable");
        let file = private.join("authority.json");
        fs::write(&file, b"authority").expect("authority file");

        let error = read_no_follow(&file).expect_err("writable ancestor must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            read_no_follow_allow_resolved_parent(&file).expect("payload compatibility read"),
            b"authority"
        );
    }

    #[test]
    #[cfg(unix)]
    fn authority_walk_rejects_group_writable_final_file() {
        use std::os::unix::fs::PermissionsExt;

        let _lock = test_lock();
        let tmp = tempfile::tempdir().expect("temp dir");
        let root = tmp.path().canonicalize().expect("canonical temp root");
        let file = root.join("authority.json");
        fs::write(&file, b"authority").expect("authority file");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o660))
            .expect("make file group writable");

        let error = read_no_follow(&file).expect_err("writable authority file must fail");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    #[cfg(unix)]
    fn dedicated_authority_directory_requires_owner_only_mode() {
        use std::os::unix::fs::PermissionsExt;

        let _lock = test_lock();
        let tmp = tempfile::tempdir().expect("temp dir");
        let root = tmp.path().canonicalize().expect("canonical temp root");
        let store = root.join("owner-store");
        ensure_owner_only_directory(&store).expect("create private authority directory");
        assert_eq!(
            fs::metadata(&store)
                .expect("store metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        fs::set_permissions(&store, fs::Permissions::from_mode(0o750))
            .expect("weaken store permissions");
        let error = ensure_owner_only_directory(&store)
            .expect_err("existing non-private store must not be silently chmodded");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }
}
