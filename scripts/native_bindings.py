#!/usr/bin/env python3
"""Build and exercise isolated native binding candidates without publishing.

Usage: native_bindings.py {build,test,verify} {npm,python,go,all}
`test` consumes recorded artifacts without rebuilding. `verify` does both.
All three builds run sequentially against one native-only Cargo target directory.
Pass --a2a-native-bin PATH to also exercise the installed Node/Python candidates
with the pinned official A2A SDKs and a prebuilt a2a_v1_peer verifier.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "archive/native"
SURFACES = ("npm", "python", "go")


def run(arguments: list[str], *, cwd: Path, env: dict[str, str], capture=False):
    print("+ " + " ".join(arguments), flush=True)
    result = subprocess.run(arguments, cwd=cwd, env=env, check=True, text=True,
                            stdout=subprocess.PIPE if capture else None)
    return result.stdout if capture else None


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def pinned_rust_environment(env: dict[str, str]) -> dict[str, str]:
    """Use the repository compiler even when Homebrew precedes rustup on PATH."""
    toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    executables = {name: run(["rustup", "which", "--toolchain", toolchain, name],
                             cwd=ROOT, env=env, capture=True).strip()
                   for name in ("cargo", "rustc", "rustdoc")}
    selected = dict(env, CARGO=executables["cargo"], RUSTC=executables["rustc"],
                    RUSTDOC=executables["rustdoc"], RUSTUP_TOOLCHAIN=toolchain)
    selected["PATH"] = str(Path(executables["cargo"]).parent) + os.pathsep + env.get("PATH", "")
    for name in ("cargo", "rustc"):
        actual = run([executables[name], "--version"], cwd=ROOT, env=selected, capture=True).strip()
        if not actual.startswith(f"{name} {toolchain} "):
            raise ValueError(f"expected {name} {toolchain}, found {actual}")
        print(f"Using {actual}", flush=True)
    return selected


def record(output: Path, artifact: Path, version: str) -> None:
    value = {"artifact": artifact.relative_to(output).as_posix(),
             "sha256": digest(artifact), "version": version,
             "platform": platform.system(), "machine": platform.machine()}
    (output / "candidate.json").write_text(json.dumps(value, indent=2) + "\n")
    print(f"Built candidate: {artifact}", flush=True)


def candidate(output: Path) -> tuple[Path, str]:
    value = json.loads((output / "candidate.json").read_text())
    artifact = (output / value["artifact"]).resolve()
    if not artifact.is_relative_to(output.resolve()) or not artifact.is_file():
        raise ValueError("candidate artifact must exist inside its output directory")
    if digest(artifact) != value["sha256"]:
        raise ValueError("candidate checksum mismatch; refusing to install or execute it")
    return artifact, value["version"]


def build(surface: str, output: Path, target: Path, env: dict[str, str]) -> None:
    output.mkdir(parents=True, exist_ok=True)
    if surface == "npm":
        package = NATIVE / "jacsnpm"
        run(["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=package, env=env)
        # The public declaration file contains reviewed narrow result unions
        # and optional feature APIs that napi's generator cannot express.
        declarations = (package / "index.d.ts").read_bytes()
        trailing_newlines = [path for pattern in ("*.js", "*.js.map") for path in package.glob(pattern)
                             if path.read_bytes().endswith(b"\n")]
        try:
            run(["npm", "run", "build"], cwd=package, env=env)
        finally:
            (package / "index.d.ts").write_bytes(declarations)
        # Typecheck wrappers against the actual public declarations, then pack
        # those declarations, not napi's temporary wider approximation.
        run(["npm", "run", "build:ts"], cwd=package, env=env)
        for path in trailing_newlines:
            data = path.read_bytes()
            if not data.endswith(b"\n"):
                path.write_bytes(data + b"\n")
        # npm's JSON describes the exact tarball; never select a stale *.tgz.
        packed = json.loads(run(["npm", "pack", "--ignore-scripts", "--json",
                                 "--pack-destination", str(output)],
                                cwd=package, env=env, capture=True))
        if len(packed) != 1:
            raise ValueError("expected exactly one npm tarball")
        record(output, output / packed[0]["filename"], packed[0]["version"])
    elif surface == "python":
        package = NATIVE / "jacspy"
        with tempfile.TemporaryDirectory(prefix="wheel-", dir=output) as temporary:
            run(["maturin", "build", "--locked", "--release", "--interpreter", sys.executable,
                 "--out", temporary], cwd=package, env=env)
            wheels = list(Path(temporary).glob("*.whl"))
            if len(wheels) != 1:
                raise ValueError("expected exactly one Python wheel")
            artifact = output / wheels[0].name
            shutil.move(wheels[0], artifact)
        version = tomllib.loads((package / "pyproject.toml").read_text())["project"]["version"]
        run([sys.executable, str(ROOT / "scripts/check_python_package_inventory.py"),
             "--license", str(NATIVE / "LICENSE-APACHE"),
             "--notices", str(NATIVE / "THIRD-PARTY-NOTICES"), str(artifact)], cwd=NATIVE, env=env)
        record(output, artifact, version)
    else:
        package = NATIVE / "jacsgo"
        run([sys.executable, str(ROOT / "scripts/native_bindings_sync_go.py"), "--check"],
            cwd=ROOT, env=env)
        run(["cargo", "build", "--locked", "--release", "--manifest-path", "lib/Cargo.toml",
             "--features", "human-approval-vendored,attestation", "--target-dir", str(target)],
            cwd=package, env=env)
        goos = run(["go", "env", "GOOS"], cwd=package, env=env, capture=True).strip()
        goarch = run(["go", "env", "GOARCH"], cwd=package, env=env, capture=True).strip()
        if goos not in {"darwin", "linux"}:
            raise ValueError("native Go candidates currently support macOS and Linux")
        extension = "dylib" if goos == "darwin" else "so"
        version = tomllib.loads((package / "lib/Cargo.toml").read_text())["package"]["version"]
        (output / "artifacts").mkdir(exist_ok=True)
        artifact = output / "artifacts" / f"jacsgo-v{version}-{goos}-{goarch}.{extension}"
        shutil.copy2(target / "release" / f"libjacsgo.{extension}", artifact)
        if goos == "darwin":
            run(["install_name_tool", "-id", "@loader_path/libjacsgo.dylib", str(artifact)],
                cwd=package, env=env)
            run(["codesign", "--force", "--sign", "-", str(artifact)], cwd=package, env=env)
        (output / f"jacsgo-v{version}-sha256sums.txt").write_text(
            f"{digest(artifact)}  {artifact.name}\n")
        record(output, artifact, version)


def test_official_a2a_sdk(surface: str, consumer: Path, env: dict[str, str],
                          native_bin: Path) -> None:
    """Exercise the installed candidate, never the checkout's native bindings."""
    examples = NATIVE / "examples"
    sdk_env = dict(env)
    # A developer's import overrides must not substitute an unstaged binding.
    for name in ("PYTHONPATH", "PYTHONHOME", "JACS_NODE_PACKAGE"):
        sdk_env.pop(name, None)
    if surface == "npm":
        example = examples / "a2a_v1_sdk"
        run(["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
            cwd=example, env=sdk_env)
        run(["npm", "audit", "--package-lock-only", "--audit-level=high"],
            cwd=example, env=sdk_env)
        sdk_env["JACS_NODE_PACKAGE"] = str(consumer / "node_modules/@hai.ai/jacs")
        command = ["node", str(example / "smoke.mjs")]
    elif surface == "python":
        python = consumer / "venv/bin/python"
        run([str(python), "-m", "pip", "install", "--require-hashes", "-r",
             str(examples / "a2a_v1_peer_requirements.txt")], cwd=consumer, env=sdk_env)
        # Keep the peer helper next to its driver without putting the repository
        # or a source jacs package on the consumer's Python import path.
        for name in ("a2a_v1_sdk_python.py", "a2a_v1_peer.py"):
            shutil.copy2(examples / name, consumer / name)
        command = [str(python), str(consumer / "a2a_v1_sdk_python.py"),
                   "--native-bin", str(native_bin)]
    else:
        raise ValueError(f"no official A2A SDK smoke for {surface}")
    # Exercise macOS's /var -> /private/var behavior on Linux too. The examples
    # must canonicalize this existing parent before creating private key paths;
    # secure custody continues to reject symlinks in the paths it receives.
    temporary = consumer / "sdk-temp"
    temporary.mkdir(mode=0o700)
    alias = consumer / "sdk-temp-link"
    alias.symlink_to(temporary.resolve(), target_is_directory=True)
    sdk_env["TMPDIR"] = str(alias)
    run(command, cwd=consumer, env=sdk_env)


def test(surface: str, output: Path, env: dict[str, str],
         a2a_native_bin: Path | None = None) -> None:
    artifact, version = candidate(output)
    if surface != "npm":
        run([sys.executable, str(ROOT / "scripts/check_native_crypto_linkage.py"), str(artifact)],
            cwd=ROOT, env=env)
    fixture = NATIVE / "binding-core/tests/fixtures/human_approved_document_v1.json"
    with tempfile.TemporaryDirectory(prefix=f"jacs-{surface}-consumer-") as temporary:
        consumer = Path(temporary)
        if surface == "npm":
            (consumer / "package.json").write_text('{"name":"jacs-candidate-consumer","private":true}\n')
            run(["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund", str(artifact)],
                cwd=consumer, env=env)
            run(["npm", "audit", "--package-lock-only", "--audit-level=high"], cwd=consumer, env=env)
            binaries = sorted((consumer / "node_modules/@hai.ai/jacs").glob("*.node"))
            if not binaries:
                raise ValueError("installed npm package contains no native addon")
            run([sys.executable, str(ROOT / "scripts/check_native_crypto_linkage.py"),
                 *map(str, binaries)], cwd=consumer, env=env)
            smoke = consumer / "smoke.cjs"
            shutil.copy2(ROOT / "scripts/native_bindings_node_smoke.cjs", smoke)
            shutil.copy2(ROOT / "scripts/native_bindings_node_types.mts", consumer / "consumer.mts")
            run([str(NATIVE / "jacsnpm/node_modules/.bin/tsc"), "--noEmit", "--strict",
                 "--skipLibCheck", "--target", "ES2020", "--module", "NodeNext",
                 "--moduleResolution", "NodeNext", "consumer.mts"], cwd=consumer, env=env)
            run(["node", str(smoke), version], cwd=consumer, env=env)
            run(["node", str(ROOT / "scripts/smoke/verify_human_approval.cjs"),
                 str(consumer / "node_modules/@hai.ai/jacs"), str(fixture)], cwd=consumer, env=env)
        elif surface == "python":
            run([sys.executable, "-m", "venv", str(consumer / "venv")], cwd=consumer, env=env)
            python = consumer / "venv/bin/python"
            run([str(python), "-m", "pip", "install", "--no-index", "--no-deps", str(artifact)],
                cwd=consumer, env=env)
            run([str(python), "-I", str(ROOT / "scripts/native_bindings_python_smoke.py"), version],
                cwd=consumer, env=env)
            run([str(python), "-I", str(ROOT / "scripts/smoke/verify_human_approval.py"), str(fixture)],
                cwd=consumer, env=env)
        else:
            run(["bash", str(NATIVE / "jacsgo/scripts/staged-consumer-smoke.sh"), version,
                 str(output)], cwd=consumer, env=env)
        if a2a_native_bin is not None and surface in {"npm", "python"}:
            test_official_a2a_sdk(surface, consumer, env, a2a_native_bin)
    print(f"OK: installed {surface} {version} candidate verified", flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "test", "verify"))
    parser.add_argument("surface", choices=(*SURFACES, "all"))
    parser.add_argument("--a2a-native-bin", type=Path,
                        help="Also test installed npm/wheel candidates with the official A2A SDKs, "
                             "using this prebuilt a2a_v1_peer verifier")
    args = parser.parse_args(argv)
    target = Path(os.environ.get("JACS_NATIVE_TARGET_DIR", ROOT / "target/native-bindings/cargo")).resolve()
    output = Path(os.environ.get("JACS_NATIVE_OUTPUT_DIR", ROOT / "target/native-bindings/artifacts")).resolve()
    env = dict(os.environ, CARGO_TARGET_DIR=str(target))
    # Cargo's higher-precedence target setting must not route this native build
    # into another worktree's target. Preserve the shared wrapper/cache settings.
    env["CARGO_BUILD_TARGET_DIR"] = str(target)
    env["CARGO_BUILD_BUILD_DIR"] = str(target / "build")
    try:
        a2a_native_bin = (args.a2a_native_bin.resolve(strict=True)
                          if args.a2a_native_bin is not None else None)
        if a2a_native_bin is not None and (not a2a_native_bin.is_file()
                                           or not os.access(a2a_native_bin, os.X_OK)):
            raise ValueError("A2A native verifier must be a prebuilt executable file")
        if args.action in {"build", "verify"}:
            env = pinned_rust_environment(env)
        for surface in SURFACES if args.surface == "all" else (args.surface,):
            if args.action in {"build", "verify"}:
                build(surface, output / surface, target, env)
            if args.action in {"test", "verify"}:
                test(surface, output / surface, env, a2a_native_bin)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"ERROR: native {args.surface} {args.action}: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
