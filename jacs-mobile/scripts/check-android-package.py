#!/usr/bin/env python3
"""Validate the assembled AAR, native ABI/page alignment and Maven dependency."""
import io
from pathlib import Path
import struct
import sys
import xml.etree.ElementTree as ET
import zipfile


def check(project: Path) -> None:
    build = project / "library/build"
    with zipfile.ZipFile(build / "outputs/aar/library-release.aar") as aar:
        manifest = ET.fromstring(aar.read("AndroidManifest.xml"))
        android_name = "{http://schemas.android.com/apk/res/android}name"
        assert any(
            item.get(android_name) == "android.permission.USE_BIOMETRIC"
            for item in manifest.findall("uses-permission")
        ), "AAR lost the biometric permission"
        assert aar.read("proguard.txt"), "AAR lost the consumer R8 rules"
        with zipfile.ZipFile(io.BytesIO(aar.read("classes.jar"))) as classes:
            for name in (
                "ai/hai/jacs/MobileAgent.class",
                "ai/hai/jacs/platform/JacsKeystore.class",
                "ai/hai/jacs/platform/JacsKeystoreSigner.class",
            ):
                assert name in classes.namelist(), f"Missing public class {name}"
        for abi, machine in (("arm64-v8a", 183), ("x86_64", 62)):
            library = aar.read(f"jni/{abi}/libjacs_mobile.so")
            assert library[:6] == b"\x7fELF\x02\x01", f"Expected ELF64 little endian: {abi}"
            assert struct.unpack_from("<H", library, 18)[0] == machine, f"Wrong ELF architecture: {abi}"
            phoff = struct.unpack_from("<Q", library, 32)[0]
            phsize, phcount = struct.unpack_from("<HH", library, 54)
            load_segments = 0
            for index in range(phcount):
                offset = phoff + index * phsize
                if struct.unpack_from("<I", library, offset)[0] == 1:  # PT_LOAD
                    load_segments += 1
                    alignment = struct.unpack_from("<Q", library, offset + 48)[0]
                    assert alignment >= 16384, f"ELF is not 16 KiB page aligned: {abi}"
            assert load_segments, f"No ELF load segments: {abi}"
    poms = list((build / "maven/ai/hai/jacs-mobile").glob("*/*.pom"))
    assert len(poms) == 1, "Expected one Maven release POM"
    namespace = {"m": "http://maven.apache.org/POM/4.0.0"}
    dependencies = ET.parse(poms[0]).findall(".//m:dependency", namespace)
    assert any(
        dependency.findtext("m:groupId", namespaces=namespace) == "net.java.dev.jna"
        and dependency.findtext("m:artifactId", namespaces=namespace) == "jna"
        and dependency.findtext("m:version", namespaces=namespace) == "5.18.1"
        and dependency.findtext("m:type", namespaces=namespace) == "aar"
        for dependency in dependencies
    ), "Maven POM must retain the JNA Android AAR dependency"
    print("PASS: AAR classes, biometric permission, R8 rules, both native ABIs, 16 KiB alignment and JNA Maven dependency")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: check-android-package.py GENERATED_ANDROID_PROJECT")
    check(Path(sys.argv[1]))
