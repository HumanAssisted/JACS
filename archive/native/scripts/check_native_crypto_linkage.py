#!/usr/bin/env python3
"""Inspect direct native dependencies and reject nonportable loader paths.

Inspects load commands without loading/executing the library. Cross-compiled
ELF artifacts use readelf; Mach-O artifacts use otool on the macOS builder.
This is not a transitive dependency resolver or proof of static provenance;
the vendored build feature and locked source graph establish that provenance.
"""

import argparse
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile


def dependency_names(output, kind):
    if kind == "elf":
        return re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", output)
    if "cmd LC_" in output:
        # otool -L also displays a dylib's own LC_ID_DYLIB. That identity is
        # not a dependency (Node loads its module by filename), so inspect
        # actual load commands instead of mistaking it for another library.
        return re.findall(
            r"cmd LC_(?:LOAD_DYLIB|LOAD_WEAK_DYLIB|REEXPORT_DYLIB|LAZY_LOAD_DYLIB|LOAD_UPWARD_DYLIB)\s+"
            r"cmdsize \d+\s+name (\S+) \(offset", output,
        )
    return re.findall(r"^\s+(\S+)\s+\(compatibility version", output, re.MULTILINE)


def external_crypto_dependencies(output, kind):
    names = dependency_names(output, kind)
    return [name for name in names if re.match(r"lib(?:ssl|crypto)(?:[.\-]|$)", Path(name).name)]


def nonportable_loader_paths(output, kind):
    def safe_path(value, search=False):
        # A plain ELF SONAME is resolved by the platform loader, but a relative
        # pathname is resolved against the consumer's working directory.
        if kind == "elf" and not search and re.fullmatch(r"[A-Za-z0-9_+.-]+", value):
            return value not in (".", "..")
        parts = value.split("/")
        if any(part in (".", "..", "") for part in parts[1:]):
            return False
        if kind == "macho" and value.startswith(("/usr/lib/", "/System/Library/")):
            return True
        tokens = ("$ORIGIN", "${ORIGIN}") if kind == "elf" else ("@loader_path", "@executable_path")
        if kind == "macho" and not search:
            tokens += ("@rpath",)
        return parts[0] in tokens and (search or len(parts) > 1)

    paths = [name for name in dependency_names(output, kind) if not safe_path(name)]
    if kind == "elf":
        rpaths = re.findall(r"\((?:RPATH|RUNPATH)\).*?\[([^\]]*)\]", output)
        paths.extend(part or "<empty search path>" for value in rpaths for part in value.split(":") if not safe_path(part, search=True))
    else:
        paths.extend(value for value in re.findall(r"cmd LC_RPATH\s+cmdsize \d+\s+path (\S+)", output)
                     if not safe_path(value, search=True))
    return paths


def check_binary(path):
    with path.open("rb") as handle:
        magic = handle.read(4)
    if magic == b"\x7fELF":
        kind, command = "elf", ["readelf", "-d", str(path)]
    elif magic in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        kind, command = "macho", ["otool", "-L", str(path)]
    else:
        raise ValueError(f"unsupported native binary format: {path.name}")
    output = subprocess.check_output(command, text=True, timeout=30)
    if kind == "macho":
        output += subprocess.check_output(["otool", "-l", str(path)], text=True, timeout=30)
    forbidden = external_crypto_dependencies(output, kind)
    if forbidden:
        raise ValueError(f"{path.name} links external OpenSSL: {', '.join(forbidden)}")
    nonportable = nonportable_loader_paths(output, kind)
    if nonportable:
        raise ValueError(f"{path.name} has nonportable loader paths: {', '.join(nonportable)}")
    print(f"NATIVE-CRYPTO-LINKAGE-OK {path.name}")


def check_artifact(path):
    if path.suffix != ".whl":
        check_binary(path)
        return
    with zipfile.ZipFile(path) as wheel, tempfile.TemporaryDirectory(prefix="jacs-wheel-linkage-") as temporary:
        members = [item for item in wheel.infolist() if not item.is_dir() and item.filename.endswith(".so")]
        if not members:
            raise ValueError(f"wheel has no native extension: {path.name}")
        for index, member in enumerate(members):
            # Do not unpack wheel-controlled paths into the filesystem.
            binary = Path(temporary) / f"{index}-{Path(member.filename).name}"
            binary.write_bytes(wheel.read(member))
            check_binary(binary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", type=Path, nargs="+")
    args = parser.parse_args()
    for artifact in args.artifacts:
        check_artifact(artifact)


if __name__ == "__main__":
    main()
