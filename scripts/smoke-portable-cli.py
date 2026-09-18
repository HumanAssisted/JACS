#!/usr/bin/env python3
"""Exercise the exact staged CLI binary without native language installers.

Only public test evidence is checked in. Secret material is generated inside a
private temporary directory and destroyed on exit; credentials are never argv.
"""

import argparse
import json
import os
from pathlib import Path
import queue
import secrets
import subprocess
import tempfile
import threading


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def invoke(binary, args, *, password=None, new_password=None, data=None, ok=True):
    env = os.environ.copy()
    env.pop("JACS_PRIVATE_KEY_PASSWORD", None)
    env.pop("JACS_NEW_PRIVATE_KEY_PASSWORD", None)
    env["RUST_LOG"] = "info"
    if password is not None:
        env["JACS_PRIVATE_KEY_PASSWORD"] = password
    if new_password is not None:
        env["JACS_NEW_PRIVATE_KEY_PASSWORD"] = new_password
    completed = subprocess.run(
        [str(binary), *map(str, args)],
        input=data, capture_output=True, text=True, env=env, timeout=60,
    )
    require((completed.returncode == 0) == ok, f"Unexpected exit status for {args[0]}")
    for secret in (password, new_password):
        if secret:
            require(secret not in completed.stdout + completed.stderr, "Secret appeared in command output")
    return completed


def result(binary, args, **options):
    return json.loads(invoke(binary, args, **options).stdout)


def verify_only_mcp(binary):
    env = os.environ.copy()
    env.pop("JACS_PRIVATE_KEY_PASSWORD", None)
    env.pop("JACS_NEW_PRIVATE_KEY_PASSWORD", None)
    env["RUST_LOG"] = "info"
    process = subprocess.Popen(
        [str(binary), "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, env=env,
    )
    lines = queue.Queue()

    def reader():
        for line in process.stdout:
            lines.put(line)
        lines.put(None)

    threading.Thread(target=reader, daemon=True).start()

    def send(message):
        process.stdin.write(json.dumps(message) + "\n")
        process.stdin.flush()

    def receive(request_id):
        for _ in range(16):
            line = lines.get(timeout=15)
            require(line is not None, "MCP exited before replying")
            frame = json.loads(line)
            require(frame.get("jsonrpc") == "2.0", "Non-protocol output on MCP stdout")
            if frame.get("id") == request_id:
                require("error" not in frame, "MCP rejected the smoke request")
                return frame["result"]
        raise RuntimeError("MCP did not return the requested response")

    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": {"name": "jacs-release-smoke", "version": "1"},
        }})
        receive(1)
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        tools = receive(2)["tools"]
        require([tool["name"] for tool in tools] == ["jacs_verify_document"], "Default MCP exposed local key authority")
    finally:
        process.kill()
        _, diagnostic = process.communicate(timeout=10)
    # The CLI initializes structured tracing without contaminating protocol IO.
    require("Starting JACS MCP stdio server" in diagnostic, "MCP startup tracing missing")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--fixture", type=Path, default=Path(__file__).resolve().parents[1] / "jacs-cli/tests/fixtures/pq_public_verification.json")
    args = parser.parse_args()
    binary = args.binary.resolve()
    require("jacs " in invoke(binary, ["--version"]).stdout, "Version output missing")
    fixture = json.loads(args.fixture.read_text())
    require(fixture["public_identity"]["algorithm"] == "pq2025", "Smoke fixture must use ML-DSA-87")

    with tempfile.TemporaryDirectory(prefix="jacs-cli-smoke-") as directory:
        root = Path(directory)
        if os.name == "posix":
            root.chmod(0o700)
        public = root / "trusted-public.json"
        public.write_text(json.dumps(fixture["public_identity"]))
        signed = fixture["signed_document"]
        verified = result(binary, ["verify", "--public-identity", public, "--input", "-"], data=json.dumps(signed))
        require(verified["valid"] is True, "Public PQ verification failed")
        signed["content"]["test_only"] = False
        denied = result(binary, ["verify", "--public-identity", public, "--input", "-"], data=json.dumps(signed), ok=False)
        require(denied["valid"] is False, "Tampered public evidence was accepted")
        verify_only_mcp(binary)
        print("PASS: version, real PQ public verification, tamper rejection, verify-only MCP stdio")

        source = root / "source.json"
        current_secret, next_secret = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        if os.name != "posix":
            failed = invoke(binary, ["create", "--output", source], password=current_secret, ok=False)
            require(not source.exists() and not failed.stdout, "Unsupported private storage did not fail closed")
            print("PASS: native private-file custody fails closed on this platform")
            return

        identity = result(binary, ["create", "--output", source], password=current_secret)
        require(identity["algorithm"] == "pq2025", "Creation silently downgraded the algorithm")
        require(source.stat().st_mode & 0o777 == 0o600, "Encrypted vault is not owner-only")
        require("private_key" not in json.dumps(identity), "Create exposed private material")
        public.write_text(json.dumps(identity))
        signed = result(binary, ["sign", "--agent", source, "--input", "-"], password=current_secret, data='{"test_only":true}')
        require(result(binary, ["verify", "--public-identity", public, "--input", "-"], data=json.dumps(signed))["valid"], "New PQ signature did not verify")

        rewrapped = root / "rewrapped.json"
        rewrapped_identity = result(binary, ["reencrypt", "--agent", source, "--output", rewrapped], password=current_secret, new_password=next_secret)
        require(rewrapped_identity["public_key"] == identity["public_key"], "Re-encryption changed the signing key")
        failed = invoke(binary, ["sign", "--agent", rewrapped, "--input", "-"], password=current_secret, data="{}", ok=False)
        require(not failed.stdout, "Wrong-password signing emitted output")
        result(binary, ["sign", "--agent", rewrapped, "--input", "-"], password=next_secret, data="{}")

        rotated = root / "rotated.json"
        rotated_identity = result(binary, ["rotate", "--agent", rewrapped, "--output", rotated], password=next_secret, new_password=current_secret)
        require(rotated_identity["algorithm"] == "pq2025", "Rotation silently downgraded the algorithm")
        require(rotated_identity["agent_id"] == identity["agent_id"], "Rotation changed the identity")
        require(rotated_identity["agent_version"] != identity["agent_version"], "Rotation did not version the identity")
        require(rotated_identity["public_key"] != identity["public_key"], "Rotation did not change the key")
        require("jacsKeyRotationProof" in json.loads(rotated.read_text())["agent"], "Rotation proof missing")
        signed = result(binary, ["sign", "--agent", rotated, "--input", "-"], password=current_secret, data="{}")
        require(result(binary, ["verify", "--agent", rotated, "--input", "-"], data=json.dumps(signed))["valid"], "Rotated PQ key could not sign")
        require(result(binary, ["verify", "--public-identity", public, "--input", "-"], data=json.dumps(signed), ok=False)["valid"] is False, "Old key accepted new-key signature")
        print("PASS: real PQ create/sign/verify, private permissions, re-encryption, wrong-password rejection, rotation")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Avoid dumping subprocess state, environment, or fixture contents.
        raise SystemExit(f"FAIL: portable CLI smoke ({type(error).__name__}): {error}") from None
