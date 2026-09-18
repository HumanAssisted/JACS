#!/usr/bin/env python3
"""Compile real generated Kotlin and Android adapter source, then test DER.

Uses pinned, SHA-256-verified Apache-licensed Kotlin/AOSP Maven artifacts and
the JNA Android AAR. Does not install an Android SDK, accept SDK license terms,
build an APK/AAR, or emulate Keystore/biometrics. --api-jar can supply the public
android.jar from an independently provisioned SDK instead of AOSP android-all.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    mobile = root / "jacs-mobile"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=mobile / "generated/android-toolchain")
    parser.add_argument("--api-jar", type=Path, help="Installed Android SDK android.jar (API 35)")
    parser.add_argument("--generated-kotlin", type=Path,
                        default=mobile / "generated/kotlin/ai/hai/jacs/jacs_mobile.kt",
                        help="UniFFI Kotlin generated from the current Rust library")
    args = parser.parse_args()
    java = shutil.which("java")
    if not java:
        parser.error("Java 17 or later is required; no toolchain is installed automatically")
    generated = args.generated_kotlin
    if not generated.is_file():
        parser.error("Generate current bindings with bash jacs-mobile/scripts/generate-bindings.sh first")
    if args.api_jar and not args.api_jar.is_file():
        parser.error("--api-jar must name an existing Android API jar")
    args.cache.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((mobile / "scripts/android-source-artifacts.json").read_text())
    if args.api_jar:
        manifest = [item for item in manifest if not item["file"].startswith("android-all-")]

    def fetch(item: dict) -> Path:
        destination = args.cache / item["file"]
        if destination.exists():
            if digest(destination) != item["sha256"]:
                raise RuntimeError(f"Checksum mismatch in cached artifact: {destination.name}")
            return destination
        partial = destination.with_suffix(destination.suffix + ".part")
        try:
            with urllib.request.urlopen(item["url"], timeout=120) as response, partial.open("wb") as output:
                shutil.copyfileobj(response, output, length=1024 * 1024)
            if partial.stat().st_size != item["size"] or digest(partial) != item["sha256"]:
                raise RuntimeError(f"Downloaded artifact failed integrity check: {destination.name}")
            partial.replace(destination)
        finally:
            partial.unlink(missing_ok=True)
        return destination

    with ThreadPoolExecutor(max_workers=4) as pool:
        artifacts = list(pool.map(fetch, manifest))
    with zipfile.ZipFile(args.cache / "jna-5.18.1.aar") as archive:
        jna = args.cache / "jna-classes.jar"
        jna.write_bytes(archive.read("classes.jar"))
    api = args.api_jar or args.cache / "android-all-15-robolectric-12650502.jar"
    stdlib = args.cache / "kotlin-stdlib-2.0.21.jar"
    compile_libraries = [api, jna, stdlib, args.cache / "annotations-13.0.jar"]
    compiler = [path for path in artifacts if path.suffix == ".jar" and not path.name.startswith("android-all-")]
    output = mobile / "generated/android-typecheck.jar"
    classpath = lambda paths: os.pathsep.join(str(path) for path in paths)
    subprocess.run([
        java, "-Xmx1g", "-cp", classpath(compiler),
        "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect",
        "-jvm-target", "17", "-classpath", classpath(compile_libraries), "-d", str(output),
        str(generated), *map(str, sorted((mobile / "platforms/android").glob("*.kt"))),
        *map(str, sorted((mobile / "tests/android").glob("*.kt"))),
    ], check=True)
    subprocess.run([
        java, "-ea", "-cp", classpath([output, stdlib, jna, api]),
        "ai.hai.jacs.platform.VaultStateSmokeKt",
    ], check=True)
    subprocess.run([
        java, "-ea", "-cp", classpath([output, stdlib, jna, api]),
        "ai.hai.jacs.platform.DerEncodingSmokeKt",
    ], check=True)
    print(f"PASS: generated Kotlin and Android adapter compiled against {api.name}")
    print(f"Output: {output}")
    print("This check does not exercise device Keystore, biometrics, or native AAR packaging.")


if __name__ == "__main__":
    main()
