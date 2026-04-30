use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd};

pub(crate) fn read_no_follow(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    let mut file = open_no_follow(path.as_ref())?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

pub(crate) fn read_to_string_no_follow(path: impl AsRef<Path>) -> io::Result<String> {
    let bytes = read_no_follow(path)?;
    String::from_utf8(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub(crate) fn write_new_file(path: impl AsRef<Path>, bytes: &[u8], mode: u32) -> io::Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    #[cfg(unix)]
    {
        let parent = open_parent_dir_no_follow(path)?;
        let file_name = final_component_cstring(path)?;
        let fd = openat_new_file(parent.as_raw_fd(), &file_name, mode)?;
        // SAFETY: fd was returned by openat and is now owned by File.
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(bytes)?;
        file.sync_all()?;
        sync_dir(&parent);
        return Ok(());
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

/// Atomically replace a path without following a symlink at the final path
/// component.
///
/// This helper prevents the common "existing output is a symlink or hard link"
/// write primitive by writing bytes to a sibling temp file and renaming that
/// file over the final entry. On Unix, the parent directory is resolved once,
/// opened, and then the temp-file create plus final rename are performed
/// relative to that descriptor, so a later parent path swap cannot redirect
/// the write. On non-Unix platforms this falls back to path-based replacement
/// after a final symlink check.
pub(crate) fn write_atomic_replace_no_symlink(
    path: impl AsRef<Path>,
    bytes: &[u8],
    mode: u32,
    require_existing_regular: bool,
) -> io::Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    #[cfg(unix)]
    {
        let parent = open_parent_dir_no_follow(path)?;
        run_parent_open_test_hook(path);
        let file_name = final_component_cstring(path)?;
        validate_final_entry(
            parent.as_raw_fd(),
            &file_name,
            path,
            require_existing_regular,
        )?;

        let temp_name = std::ffi::CString::new(format!(".jacs-tmp-{}", uuid::Uuid::new_v4()))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let fd = openat_new_file(parent.as_raw_fd(), &temp_name, mode)?;
        // SAFETY: fd was returned by openat and is now owned by File.
        let mut tmp = unsafe { File::from_raw_fd(fd) };
        let result = (|| -> io::Result<()> {
            tmp.write_all(bytes)?;
            tmp.sync_all()?;
            drop(tmp);
            renameat(parent.as_raw_fd(), &temp_name, &file_name)?;
            sync_dir(&parent);
            Ok(())
        })();
        if result.is_err() {
            unlinkat(parent.as_raw_fd(), &temp_name);
        }
        return result;
    }

    #[cfg(not(unix))]
    {
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
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound && !require_existing_regular => {}
            Err(e) => return Err(e),
        }

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

fn open_no_follow(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(libc::O_NOFOLLOW);
        options.open(path)
    }

    #[cfg(not(unix))]
    {
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
}

#[cfg(not(unix))]
fn sync_parent_dir(path: &Path) {
    let _ = File::open(parent_or_current(path)).and_then(|dir| dir.sync_all());
}

#[cfg(unix)]
fn open_parent_dir_no_follow(path: &Path) -> io::Result<File> {
    let parent = fs::canonicalize(parent_or_current(path))?;
    open_dir_no_follow(&parent)
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
                let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
                // SAFETY: name is a valid C string; dir is an open directory fd.
                let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: fd was returned by openat and is now owned by File.
                dir = unsafe { File::from_raw_fd(fd) };
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
        let stat = unsafe { stat.assume_init() };
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
        return Ok(());
    }

    let err = io::Error::last_os_error();
    if err.kind() == io::ErrorKind::NotFound && !require_existing_regular {
        Ok(())
    } else {
        Err(err)
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

    #[test]
    #[cfg(unix)]
    fn atomic_replace_anchors_parent_before_parent_symlink_swap() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().expect("temp dir");
        let safe_dir = tmp.path().join("safe");
        let outside_dir = tmp.path().join("outside");
        fs::create_dir_all(&safe_dir).expect("safe dir");
        fs::create_dir_all(&outside_dir).expect("outside dir");

        let safe_file = safe_dir.join("doc.txt");
        let outside_file = outside_dir.join("doc.txt");
        fs::write(&safe_file, b"safe original").expect("safe file");
        fs::write(&outside_file, b"outside original").expect("outside file");

        let link_dir = tmp.path().join("link");
        symlink(&safe_dir, &link_dir).expect("link to safe dir");
        let requested_path = link_dir.join("doc.txt");

        let link_for_hook = link_dir.clone();
        let outside_for_hook = outside_dir.clone();
        let _hook_guard = set_parent_open_test_hook(requested_path.clone(), move || {
            fs::remove_file(&link_for_hook).expect("remove parent symlink");
            symlink(&outside_for_hook, &link_for_hook).expect("retarget parent symlink");
        });

        write_atomic_replace_no_symlink(&requested_path, b"safe rewritten", 0o600, true)
            .expect("replace should succeed in originally opened parent");

        assert_eq!(fs::read(&safe_file).expect("read safe"), b"safe rewritten");
        assert_eq!(
            fs::read(&outside_file).expect("read outside"),
            b"outside original",
            "parent path swap must not redirect the atomic replace"
        );
    }
}
