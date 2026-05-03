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
        return parent.read_no_follow();
    }

    #[cfg(not(unix))]
    {
        let _ = policy;
        let mut file = open_no_follow(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }
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
        return parent.create_new(bytes, mode);
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
        return parent.atomic_replace(bytes, mode, require_existing_regular);
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

#[cfg(unix)]
struct OpenedParent {
    dir: File,
    file_name: std::ffi::CString,
    display_path: PathBuf,
}

#[cfg(unix)]
impl OpenedParent {
    fn open(path: &Path, policy: ParentSymlinkPolicy) -> io::Result<Self> {
        let parent_path = parent_or_current(path);
        let dir = match policy {
            ParentSymlinkPolicy::Reject => open_dir_no_follow(parent_path)?,
            ParentSymlinkPolicy::AllowResolvedParent => {
                let resolved_parent = fs::canonicalize(parent_path)?;
                open_dir_no_follow(&resolved_parent)?
            }
        };

        Ok(Self {
            dir,
            file_name: final_component_cstring(path)?,
            display_path: path.to_path_buf(),
        })
    }

    fn create_new(&self, bytes: &[u8], mode: u32) -> io::Result<()> {
        let fd = openat_new_file(self.dir.as_raw_fd(), &self.file_name, mode)?;
        // SAFETY: fd was returned by openat and is now owned by File.
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(bytes)?;
        file.sync_all()?;
        sync_dir(&self.dir);
        Ok(())
    }

    fn atomic_replace(
        &self,
        bytes: &[u8],
        mode: u32,
        require_existing_regular: bool,
    ) -> io::Result<()> {
        validate_final_entry(
            self.dir.as_raw_fd(),
            &self.file_name,
            &self.display_path,
            require_existing_regular,
        )?;

        let temp_name = std::ffi::CString::new(format!(".jacs-tmp-{}", uuid::Uuid::new_v4()))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let fd = openat_new_file(self.dir.as_raw_fd(), &temp_name, mode)?;
        // SAFETY: fd was returned by openat and is now owned by File.
        let mut tmp = unsafe { File::from_raw_fd(fd) };
        let result = (|| -> io::Result<()> {
            tmp.write_all(bytes)?;
            tmp.sync_all()?;
            drop(tmp);
            renameat(self.dir.as_raw_fd(), &temp_name, &self.file_name)?;
            sync_dir(&self.dir);
            Ok(())
        })();
        if result.is_err() {
            unlinkat(self.dir.as_raw_fd(), &temp_name);
        }
        result
    }

    fn read_no_follow(&self) -> io::Result<Vec<u8>> {
        validate_final_entry(
            self.dir.as_raw_fd(),
            &self.file_name,
            &self.display_path,
            true,
        )?;
        let fd = openat_existing_file(self.dir.as_raw_fd(), &self.file_name)?;
        // SAFETY: fd was returned by openat and is now owned by File.
        let mut file = unsafe { File::from_raw_fd(fd) };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(bytes)
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
        open_dir_path(Path::new("."))?
    };

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
                        mkdirat(dir.as_raw_fd(), &name, 0o777)?;
                    }
                    Err(e) => return Err(e),
                }

                let next = openat_dir_no_follow(dir.as_raw_fd(), &name)?;
                // SAFETY: fd was returned by openat and is now owned by File.
                dir = unsafe { File::from_raw_fd(next) };
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
    let mut dir = if path.is_absolute() {
        open_dir_path(Path::new("/"))?
    } else {
        open_dir_path(Path::new("."))?
    };

    for component in path.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::CurDir => {}
            std::path::Component::ParentDir | std::path::Component::Normal(_) => {
                let name = std::ffi::CString::new(component.as_os_str().as_bytes())
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                let next = openat_dir_no_follow(dir.as_raw_fd(), &name)?;
                // SAFETY: fd was returned by openat and is now owned by File.
                dir = unsafe { File::from_raw_fd(next) };
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
) -> io::Result<()> {
    match statat_no_follow(dir_fd, file_name) {
        Ok(stat) => {
            let file_type = stat.st_mode & libc::S_IFMT;
            if file_type == libc::S_IFLNK {
                return Err(io::Error::other(format!(
                    "refusing to follow symlink at '{}'",
                    path.display()
                )));
            }
            if require_existing_regular && file_type != libc::S_IFREG {
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
fn sync_dir(dir: &File) {
    let _ = dir.sync_all();
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
static PARENT_OPEN_TEST_HOOK: std::sync::OnceLock<
    std::sync::Mutex<
        Option<(
            std::path::PathBuf,
            std::sync::Arc<dyn Fn() + Send + Sync + 'static>,
        )>,
    >,
> = std::sync::OnceLock::new();

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
}
