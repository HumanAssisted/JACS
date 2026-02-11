"""
CLI launcher for the JACS binary.

Downloads a prebuilt jacs CLI binary on first use and caches it.
If the download fails, prints fallback instructions (cargo install).
"""

import os
import platform
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

REPO = "HumanAssisted/JACS"


def _get_version():
    """Read version from the installed package metadata."""
    try:
        from importlib.metadata import version

        return version("jacs")
    except Exception:
        return "0.8.0"


def _platform_key():
    system = platform.system().lower()
    machine = platform.machine().lower()

    arch_map = {
        "x86_64": "x64",
        "amd64": "x64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }
    arch = arch_map.get(machine)
    if not arch:
        return None

    os_map = {
        "darwin": "darwin",
        "linux": "linux",
        "windows": "windows",
    }
    os_name = os_map.get(system)
    if not os_name:
        return None

    return f"{os_name}-{arch}"


def _cache_dir():
    """Cache directory for the CLI binary."""
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        base = Path(xdg)
    elif platform.system() == "Darwin":
        base = Path.home() / "Library" / "Caches"
    elif platform.system() == "Windows":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path.home() / ".cache"
    return base / "jacs" / "bin"


def _bin_name():
    return "jacs-cli.exe" if platform.system() == "Windows" else "jacs-cli"


def _download(url, dest):
    """Download a URL to a file path, following redirects."""
    urllib.request.urlretrieve(url, dest)


def ensure_cli():
    """Download the CLI binary if not already cached. Returns the path."""
    cache = _cache_dir()
    bin_path = cache / _bin_name()

    if bin_path.exists():
        return str(bin_path)

    ver = _get_version()
    key = _platform_key()
    if not key:
        return None

    is_windows = platform.system() == "Windows"
    ext = "zip" if is_windows else "tar.gz"
    asset = f"jacs-cli-{ver}-{key}.{ext}"
    url = f"https://github.com/{REPO}/releases/download/cli/v{ver}/{asset}"

    cache.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="jacs-cli-") as tmp:
        archive_path = os.path.join(tmp, asset)
        try:
            print(f"[jacs] Downloading CLI binary from {url}", file=sys.stderr)
            _download(url, archive_path)
        except Exception as e:
            print(f"[jacs] Download failed: {e}", file=sys.stderr)
            return None

        if is_windows:
            import zipfile

            with zipfile.ZipFile(archive_path, "r") as zf:
                zf.extractall(tmp)
            src = os.path.join(tmp, "jacs-cli.exe")
        else:
            with tarfile.open(archive_path, "r:gz") as tf:
                tf.extractall(tmp)
            src = os.path.join(tmp, "jacs-cli")

        if not os.path.exists(src):
            print("[jacs] Binary not found in archive.", file=sys.stderr)
            return None

        # Move to cache
        import shutil

        shutil.move(src, str(bin_path))
        if not is_windows:
            bin_path.chmod(bin_path.stat().st_mode | stat.S_IEXEC)

    print(f"[jacs] CLI binary cached at {bin_path}", file=sys.stderr)
    return str(bin_path)


def main():
    """Entry point for `jacs` CLI command via pip."""
    cli_path = ensure_cli()
    if cli_path is None:
        print(
            "Could not download the JACS CLI binary for your platform.\n"
            "Install it manually:\n"
            "  cargo install jacs --features cli\n"
            f"  OR download from https://github.com/{REPO}/releases",
            file=sys.stderr,
        )
        sys.exit(1)

    result = subprocess.run([cli_path] + sys.argv[1:])
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
