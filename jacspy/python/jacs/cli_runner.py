"""
CLI launcher for the JACS binary.

Downloads a prebuilt jacs CLI binary on first use and caches it.
If the download fails, prints fallback instructions (cargo install).
"""

import os
import platform
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import hashlib
import shutil
from pathlib import Path

REPO = "HumanAssisted/JACS"


def _read_repo_version():
    """Best-effort fallback for source checkouts without installed metadata."""
    pyproject_path = Path(__file__).resolve().parents[2] / "pyproject.toml"
    try:
        contents = pyproject_path.read_text(encoding="utf-8")
    except OSError:
        return None

    match = re.search(r'^version\s*=\s*"([^"]+)"\s*$', contents, re.MULTILINE)
    return match.group(1) if match else None


def _get_version():
    """Read version from the installed package metadata."""
    try:
        from importlib.metadata import version

        return version("jacs")
    except Exception:
        repo_version = _read_repo_version()
        return repo_version or "unknown"


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


def _sha256_file(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def _read_expected_sha256(checksum_path, asset_name):
    checksum_text = Path(checksum_path).read_text(encoding="utf-8").strip()
    if not checksum_text:
        raise ValueError(f"Checksum file was empty: {checksum_path}")

    lines = [line.strip() for line in checksum_text.splitlines() if line.strip()]
    for line in lines:
        match = re.match(r"^([a-fA-F0-9]{64})\s+\*?(.+)$", line)
        if match:
            digest = match.group(1).lower()
            filename = os.path.basename(match.group(2).strip())
            if filename == asset_name:
                return digest

        match = re.match(r"^SHA256\s*\((.+)\)\s*=\s*([a-fA-F0-9]{64})$", line, re.IGNORECASE)
        if match:
            filename = os.path.basename(match.group(1).strip())
            digest = match.group(2).lower()
            if filename == asset_name:
                return digest

        match = re.match(r"^([a-fA-F0-9]{64})$", line)
        if match and len(lines) == 1:
            return match.group(1).lower()

    raise ValueError(f"Checksum for {asset_name} not found in {checksum_path}")


def _validate_archive_member(name):
    member_path = Path(name)
    if member_path.is_absolute():
        raise ValueError(f"Unsafe archive member path: {name}")
    if ".." in member_path.parts:
        raise ValueError(f"Unsafe archive member path: {name}")


def _extract_archive_binary(archive_path, dest_dir, binary_name, is_windows):
    dest_path = os.path.join(dest_dir, binary_name)

    if is_windows:
        import zipfile

        with zipfile.ZipFile(archive_path, "r") as zf:
            candidate = None
            for member in zf.infolist():
                _validate_archive_member(member.filename)
                if member.is_dir():
                    continue
                if Path(member.filename).name == binary_name:
                    if candidate is not None:
                        raise ValueError(f"Archive contained multiple {binary_name} entries")
                    candidate = member
            if candidate is None:
                raise ValueError("Binary not found in archive.")
            with zf.open(candidate, "r") as src, open(dest_path, "wb") as dst:
                shutil.copyfileobj(src, dst)
    else:
        with tarfile.open(archive_path, "r:gz") as tf:
            candidate = None
            for member in tf.getmembers():
                _validate_archive_member(member.name)
                if not member.isfile():
                    continue
                if Path(member.name).name == binary_name:
                    if candidate is not None:
                        raise ValueError(f"Archive contained multiple {binary_name} entries")
                    candidate = member
            if candidate is None:
                raise ValueError("Binary not found in archive.")
            extracted = tf.extractfile(candidate)
            if extracted is None:
                raise ValueError("Binary could not be extracted from archive.")
            with extracted, open(dest_path, "wb") as dst:
                shutil.copyfileobj(extracted, dst)

    return dest_path


def ensure_cli():
    """Download the CLI binary if not already cached. Returns the path."""
    cache = _cache_dir()
    bin_path = cache / _bin_name()

    if bin_path.exists():
        return str(bin_path)

    ver = _get_version()
    if ver == "unknown":
        print("[jacs] Could not determine package version for CLI download.", file=sys.stderr)
        return None
    key = _platform_key()
    if not key:
        return None

    is_windows = platform.system() == "Windows"
    ext = "zip" if is_windows else "tar.gz"
    asset = f"jacs-cli-{ver}-{key}.{ext}"
    url = f"https://github.com/{REPO}/releases/download/cli/v{ver}/{asset}"
    checksum_url = f"{url}.sha256"

    cache.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="jacs-cli-") as tmp:
        archive_path = os.path.join(tmp, asset)
        checksum_path = os.path.join(tmp, f"{asset}.sha256")
        try:
            print(f"[jacs] Downloading checksum for pinned version {ver} from {checksum_url}", file=sys.stderr)
            _download(checksum_url, checksum_path)
            print(f"[jacs] Downloading CLI binary from {url}", file=sys.stderr)
            _download(url, archive_path)
            expected_sha256 = _read_expected_sha256(checksum_path, asset)
            actual_sha256 = _sha256_file(archive_path)
            if expected_sha256 != actual_sha256:
                print(
                    f"[jacs] Checksum mismatch for {asset}: expected {expected_sha256}, got {actual_sha256}",
                    file=sys.stderr,
                )
                return None
        except Exception as e:
            print(f"[jacs] Download failed: {e}", file=sys.stderr)
            return None

        try:
            src = _extract_archive_binary(archive_path, tmp, _bin_name(), is_windows)
        except Exception as e:
            print(f"[jacs] Could not extract CLI binary: {e}", file=sys.stderr)
            return None

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
            "  cargo install jacs-cli\n"
            f"  OR download from https://github.com/{REPO}/releases",
            file=sys.stderr,
        )
        sys.exit(1)

    result = subprocess.run([cli_path] + sys.argv[1:])
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
