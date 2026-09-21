#!/usr/bin/env python3
"""Build and exercise isolated native binding candidates without publishing.

Usage: native_bindings.py {build,test,verify} {npm,python,go,all}
`test` consumes recorded artifacts without rebuilding. `verify` does both.
All three builds run sequentially against one native-only Cargo target directory.
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


def test(surface: str, output: Path, env: dict[str, str]) -> None:
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
    print(f"OK: installed {surface} {version} candidate verified", flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "test", "verify"))
    parser.add_argument("surface", choices=(*SURFACES, "all"))
    args = parser.parse_args(argv)
    target = Path(os.environ.get("JACS_NATIVE_TARGET_DIR", ROOT / "target/native-bindings/cargo")).resolve()
    output = Path(os.environ.get("JACS_NATIVE_OUTPUT_DIR", ROOT / "target/native-bindings/artifacts")).resolve()
    env = dict(os.environ, CARGO_TARGET_DIR=str(target))
    # Cargo's higher-precedence target setting must not route this native build
    # into another worktree's target. Preserve the shared wrapper/cache settings.
    env["CARGO_BUILD_TARGET_DIR"] = str(target)
    env["CARGO_BUILD_BUILD_DIR"] = str(target / "build")
    try:
        if args.action in {"build", "verify"}:
            env = pinned_rust_environment(env)
        for surface in SURFACES if args.surface == "all" else (args.surface,):
            if args.action in {"build", "verify"}:
                build(surface, output / surface, target, env)
            if args.action in {"test", "verify"}:
                test(surface, output / surface, env)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"ERROR: native {args.surface} {args.action}: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
