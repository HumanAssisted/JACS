#!/usr/bin/env python3
"""Local MCP -> MIME -> separate JACS recipient; Python standard library only.

Supply a source-matched jacs binary explicitly. No mail is sent. This signs the
JSON attachment, not the email; both peers use the same JACS implementation.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import signal
import subprocess
import sys
import tempfile
import time
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser

PROTOCOL = "2025-11-25"  # Explicit supported initialize/initialized contract.
FILENAME = "signed-report.jacs.json"
MAX_FRAME = 1024 * 1024
RPC_TIMEOUT = 30
CLAIMS = ("humanApproval", "policyAccepted", "contactAuthorized")


class DemoError(Exception):
    """Only fixed, non-sensitive diagnostics are emitted by the driver."""


def require(condition, message):
    if not condition:
        raise DemoError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def isolated_env(directory, password_file=None):
    # Allowlist: no ambient JACS config/password/legacy flags, proxies, Python
    # paths or loader overrides. Each process has its own home and trust path.
    home = directory / "home"
    home.mkdir(exist_ok=True, mode=0o700)
    env = {
        "PATH": os.defpath,
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / "config"),
        "XDG_DATA_HOME": str(home / "data"),
        "TMPDIR": str(directory),
        "PYTHONDONTWRITEBYTECODE": "1",
        "JACS_KEYCHAIN_BACKEND": "disabled",
        "JACS_ALLOW_NETWORK": "false",
        "JACS_TRUST_STORE_DIR": str(directory / "trusted"),
        "RUST_LOG": "warn",
    }
    if password_file is not None:
        env["JACS_PASSWORD_FILE"] = str(password_file)
    return env


def run_process(command, directory, env, timeout=90):
    # A separate group lets timeout cleanup stop a recipient and its MCP child.
    process = subprocess.Popen(
        command,
        cwd=directory,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        stdout, _ = process.communicate(timeout=timeout)
        require(process.returncode == 0, "CLI or recipient process failed")
        require(len(stdout) <= MAX_FRAME, "Child output exceeds the demo limit")
        return stdout
    except BaseException:
        # Also stop descendants if the recipient exited before its MCP child.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise


class McpSession:
    """One request at a time, bounded newline frames and wallclock-independent I/O."""

    def __init__(self, binary, directory, env, profile, config=None):
        self.command = [str(binary), "mcp", "--profile", profile]
        if config is not None:
            self.command += ["--config", str(config)]
        self.directory, self.env = directory, env
        self.pending = bytearray()
        self.request_id = 0

    def __enter__(self):
        self.process = subprocess.Popen(
            self.command,
            cwd=self.directory,
            env=self.env,
            bufsize=0,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        os.set_blocking(self.process.stdin.fileno(), False)
        os.set_blocking(self.process.stdout.fileno(), False)
        try:
            opened = self.request(
                "initialize",
                {
                    "protocolVersion": PROTOCOL,
                    "capabilities": {},
                    "clientInfo": {"name": "jacs-mcp-mime-demo", "version": "1"},
                },
            )
            result = self.result(opened)
            require(result.get("protocolVersion") == PROTOCOL, "MCP protocol mismatch")
            require(
                result.get("serverInfo", {}).get("name") == "jacs-mcp",
                "Unexpected MCP server",
            )
            self.send(
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                time.monotonic() + RPC_TIMEOUT,
            )
            return self
        except BaseException:
            self.close(check=False)
            raise

    def send(self, message, deadline):
        data = json.dumps(message, separators=(",", ":")).encode() + b"\n"
        require(len(data) <= MAX_FRAME, "MCP request exceeds frame limit")
        while data:
            remaining = deadline - time.monotonic()
            require(remaining > 0, "MCP write timeout")
            require(
                select.select([], [self.process.stdin], [], remaining)[1],
                "MCP write timeout",
            )
            count = os.write(self.process.stdin.fileno(), data)
            require(count > 0, "MCP stdin closed")
            data = data[count:]

    def frame(self, deadline):
        while b"\n" not in self.pending:
            remaining = deadline - time.monotonic()
            require(remaining > 0, "MCP response timeout")
            require(
                select.select([self.process.stdout], [], [], remaining)[0],
                "MCP response timeout",
            )
            chunk = os.read(self.process.stdout.fileno(), 65536)
            require(chunk, "MCP stdout closed before response")
            self.pending.extend(chunk)
            require(len(self.pending) <= MAX_FRAME, "MCP response exceeds frame limit")
        line, _, rest = self.pending.partition(b"\n")
        self.pending = bytearray(rest)
        value = json.loads(line)
        require(
            isinstance(value, dict) and value.get("jsonrpc") == "2.0",
            "Invalid JSON-RPC frame",
        )
        return value

    def request(self, method, params):
        self.request_id += 1
        deadline = time.monotonic() + RPC_TIMEOUT
        self.send(
            {
                "jsonrpc": "2.0",
                "id": self.request_id,
                "method": method,
                "params": params,
            },
            deadline,
        )
        for _ in range(16):
            value = self.frame(deadline)
            if "id" not in value:  # Bounded allowance for server notifications.
                continue
            require(value["id"] == self.request_id, "Unexpected MCP response id")
            require(
                ("result" in value) != ("error" in value),
                "Invalid JSON-RPC result/error envelope",
            )
            return value
        raise DemoError("Too many MCP notifications")

    @staticmethod
    def result(response):
        require("error" not in response, "JSON-RPC operation rejected")
        return response["result"]

    def tools(self):
        result = self.result(self.request("tools/list", {}))
        return {tool["name"] for tool in result["tools"]}

    def call(self, name, arguments):
        result = self.result(
            self.request("tools/call", {"name": name, "arguments": arguments})
        )
        require(result.get("isError") is False, "MCP tool envelope rejected operation")
        texts = [
            part["text"] for part in result["content"] if part.get("type") == "text"
        ]
        require(len(texts) == 1, "Expected one JACS text payload")
        value = json.loads(texts[0])
        require(isinstance(value, dict), "Invalid JACS tool payload")
        return value

    def close(self, check=True):
        self.process.stdin.close()  # EOF is the stdio shutdown boundary.
        graceful = True
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            graceful = False
            self.process.kill()
            self.process.wait(timeout=5)
        self.process.stdout.close()
        if check:
            require(
                graceful and self.process.returncode == 0,
                "MCP did not shut down cleanly",
            )

    def __exit__(self, exc_type, *_):
        self.close(check=exc_type is None)


def create_identity(binary, directory):
    directory.mkdir(mode=0o700)
    password = directory / "password.txt"
    password.write_text("Demo!9aA" + secrets.token_urlsafe(32), encoding="utf-8")
    password.chmod(0o600)
    env = isolated_env(directory, password)
    run_process(
        [
            str(binary),
            "quickstart",
            "--name",
            "mime-demo",
            "--domain",
            "example.test",
            "--algorithm",
            "ed25519",
        ],
        directory,
        env,
    )
    config = directory / "jacs.config.json"
    settings = json.loads(config.read_bytes())
    key_dir = (directory / settings["jacs_key_directory"]).resolve()
    require(key_dir.is_relative_to(directory), "Unexpected key directory")
    public = key_dir / settings["jacs_agent_public_key_filename"]
    private = key_dir / settings["jacs_agent_private_key_filename"]
    require(
        private.name.endswith(".enc") and private.is_file(),
        "Expected encrypted private key",
    )
    require(
        private.stat().st_mode & 0o077 == 0,
        "Private key permissions are not owner-only",
    )
    key = (
        public.read_bytes()
    )  # CLI's Ed25519 public file contains raw 32-byte key bytes.
    require(len(key) == 32, "Unexpected Ed25519 public-key format")
    return config, key, env


def mime_message(document, copies=1):
    message = EmailMessage(policy=policy.SMTP)
    message["From"] = "sender@example.test"
    message["To"] = "recipient@example.test"
    message["Subject"] = "Local synthetic report; attachment signature only"
    message.set_content("Illustrative unsigned outer email body.")
    for _ in range(copies):
        message.add_attachment(
            document,
            maintype="application",
            subtype="json",
            filename=FILENAME,
            cte="base64",
        )
    return message.as_bytes()


def extract_report(raw):
    require(len(raw) <= MAX_FRAME, "MIME message exceeds the demo limit")
    message = BytesParser(policy=policy.default).parsebytes(raw)
    matches = [part for part in message.walk() if part.get_filename() == FILENAME]
    require(len(matches) == 1, "Expected exactly one signed-report attachment")
    part = matches[0]
    require(
        part.get_content_type() == "application/json"
        and part.get_content_disposition() == "attachment",
        "Invalid signed-report MIME type",
    )
    content = part.get_payload(decode=True)
    require(
        isinstance(content, bytes) and not part.defects,
        "Invalid MIME attachment encoding",
    )
    return content


def recipient(binary, directory):
    # Only public out-of-band test inputs exist here. Sender keys were deleted
    # before this interpreter was spawned, not merely hidden from its argv.
    expected = (directory / "expected.json").read_bytes()
    trusted_key = (directory / "trusted-public.key").read_bytes()
    unrelated_key = (directory / "unrelated-public.key").read_bytes()
    raw = (directory / "message.eml").read_bytes()
    extracted = extract_report(raw)
    require(
        extracted == expected and digest(extracted) == digest(expected),
        "MIME changed the signed document bytes",
    )
    require(
        not list(directory.rglob("*.enc"))
        and not list(directory.rglob("jacs.config.json")),
        "Recipient received private identity material",
    )
    with McpSession(
        binary, directory, isolated_env(directory), "verify-only"
    ) as session:
        require(
            session.tools() == {"jacs_verify_document"},
            "Recipient inventory is not verification-only",
        )

        def verify(document, key):
            return session.call(
                "jacs_verify_document",
                {
                    "document": document.decode("utf-8"),
                    "public_key": list(key),
                    "algorithm": "ed25519",
                },
            )

        checked = verify(extracted, trusted_key)
        require(
            checked.get("success") is True and checked.get("valid") is True,
            "Recipient verification failed",
        )
        require(
            all(name not in checked for name in CLAIMS),
            "Verification projected an authority claim",
        )
        changed = json.loads(extracted)
        changed["content"]["score"] += 1
        corrupt = json.loads(extracted)
        signature = bytearray(
            base64.b64decode(corrupt["jacsSignature"]["signature"], validate=True)
        )
        require(signature, "Missing signature bytes")
        signature[0] ^= 1
        corrupt["jacsSignature"]["signature"] = base64.b64encode(signature).decode(
            "ascii"
        )
        for document, key in [
            (json.dumps(changed).encode(), trusted_key),
            (json.dumps(corrupt).encode(), trusted_key),
            (extracted, unrelated_key),
        ]:
            rejected = verify(document, key)
            require(
                rejected.get("valid") is False,
                "Invalid attachment or unrelated key was accepted",
            )
        for copies in (0, 2):
            try:
                extract_report(mime_message(expected, copies))
            except DemoError:
                pass
            else:
                raise DemoError("Missing or duplicate attachment was accepted")
        denied = session.request(
            "tools/call", {"name": "jacs_sign_document", "arguments": {"content": "{}"}}
        )
        require(
            denied.get("error", {}).get("code") == -32602 and "result" not in denied,
            "Verify-only admitted signing",
        )
        outer_edit = BytesParser(policy=policy.default).parsebytes(raw)
        outer_edit.replace_header("From", "changed@example.test")
        outer_edit.replace_header("Subject", "Changed unsigned subject")
        outer_edit.get_body(preferencelist=("plain",)).set_content(
            "Changed unsigned body."
        )
        unchanged = extract_report(outer_edit.as_bytes(policy=policy.SMTP))
        require(unchanged == extracted, "Outer edit changed attachment bytes")
        require(
            verify(unchanged, trusted_key).get("valid") is True,
            "Unchanged attachment failed after outer edit/refusals",
        )
        mcp_pid = session.process.pid
    return {
        "recipient_pid": os.getpid(),
        "recipient_mcp_pid": mcp_pid,
        "mime_bytes_preserved": True,
        "attachment_sha256": digest(extracted),
        "attachment_size": len(extracted),
        "signature_verified": True,
        "refused": [
            "modified_payload",
            "corrupted_signature",
            "unrelated_key",
            "missing_attachment",
            "duplicate_attachment",
            "verify_only_signing",
        ],
        "outer_email_edit_preserves_attachment_verification": True,
        "human_approval_inferred": False,
        "agreement_policy_acceptance_inferred": False,
        "contact_authority_inferred": False,
        "mailbox_identity_inferred": False,
        "recipient_has_no_private_identity": True,
        "recipient_shutdown_clean": True,
    }


def demo(binary, temp_root):
    with tempfile.TemporaryDirectory(
        prefix="jacs-mcp-mime-", dir=temp_root
    ) as temporary:
        workspace = Path(temporary).resolve()
        receiving = workspace / "recipient"
        receiving.mkdir(mode=0o700)
        version = (
            run_process([str(binary), "--version"], receiving, isolated_env(receiving))
            .decode()
            .strip()
        )
        with tempfile.TemporaryDirectory(
            prefix="identities-", dir=workspace
        ) as identities:
            config, key, env = create_identity(binary, Path(identities) / "sender")
            _, unrelated, _ = create_identity(binary, Path(identities) / "unrelated")
            require(key != unrelated, "Disposable keys unexpectedly match")
            with McpSession(binary, config.parent, env, "local-sign", config) as sender:
                allowed = {
                    "jacs_sign_document",
                    "jacs_verify_document",
                    "jacs_create_agreement_v2",
                    "jacs_apply_agreement_v2",
                    "jacs_sign_agreement_v2",
                    "jacs_verify_agreement_v2",
                    "jacs_detect_agreement_v2_branch_conflict",
                    "jacs_merge_agreement_v2_transcript_branches",
                    "jacs_resolve_agreement_v2_branch_conflict",
                }
                inventory = sender.tools()
                require(
                    {"jacs_sign_document", "jacs_verify_document"}
                    <= inventory
                    <= allowed,
                    "Unexpected sender inventory",
                )
                report = {
                    "report": "synthetic-local-baseline",
                    "score": 7,
                    **dict.fromkeys(CLAIMS, True),
                }
                signed = sender.call(
                    "jacs_sign_document",
                    {"content": json.dumps(report), "content_type": "application/json"},
                )
                require(signed.get("success") is True, "Sender signing failed")
                document = signed["signed_document"].encode(
                    "utf-8"
                )  # Never reserialize this positive path.
                parsed = json.loads(document)
                require(
                    parsed["content"] == report
                    and all(name not in parsed for name in CLAIMS),
                    "Caller claims escaped the signed content",
                )
                require(
                    parsed["jacsSignature"].get("signatureContentVersion")
                    == "jacs-signature-v2",
                    "Expected a normal portable-v2 signature",
                )
                sender_pid = sender.process.pid
            (receiving / "expected.json").write_bytes(document)
            (receiving / "message.eml").write_bytes(mime_message(document))
            (receiving / "trusted-public.key").write_bytes(key)
            (receiving / "unrelated-public.key").write_bytes(unrelated)
        require(not Path(identities).exists(), "Sender identity cleanup failed")
        output = run_process(
            [
                sys.executable,
                "-I",
                str(Path(__file__).resolve()),
                "--jacs-bin",
                str(binary),
                "--recipient",
            ],
            receiving,
            isolated_env(receiving),
            timeout=180,
        )
        result = json.loads(output)
        require(
            result["recipient_pid"] != os.getpid(),
            "Recipient was not a separate process",
        )
        result.update(
            {
                "sender_mcp_pid": sender_pid,
                "driver_pid": os.getpid(),
                "sender_shutdown_clean": True,
                "sender_keys_deleted_before_recipient": True,
                "protocol": PROTOCOL,
                "jacs_version": version,
                "binary_sha256": digest(binary.read_bytes()),
                "harness_sha256": digest(Path(__file__).read_bytes()),
            }
        )
    require(not workspace.exists(), "Temporary workspace cleanup failed")
    result["temporary_files_cleaned"] = True
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jacs-bin", type=Path, required=True)
    parser.add_argument(
        "--expected-bin-sha256", help="Optional pinned build-artifact digest"
    )
    parser.add_argument("--temp-root", type=Path)
    parser.add_argument(
        "--json", action="store_true", help="Print the compact evidence object"
    )
    parser.add_argument("--recipient", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    require(os.name == "posix", "This isolated pipe demo requires a POSIX host")
    binary = args.jacs_bin.resolve(strict=True)
    require(
        binary.is_file() and os.access(binary, os.X_OK),
        "--jacs-bin must be an executable file",
    )
    if args.expected_bin_sha256:
        require(
            digest(binary.read_bytes()) == args.expected_bin_sha256,
            "Binary digest does not match the pinned build",
        )

    def interrupted(*_):
        raise DemoError("Demo interrupted or exceeded its total time budget")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGALRM, interrupted)
    signal.alarm(300)  # Leave time for cleanup before the regression's outer timeout.
    previous_umask = os.umask(0o077)
    try:
        result = (
            recipient(binary, Path.cwd())
            if args.recipient
            else demo(binary, args.temp_root)
        )
    finally:
        signal.alarm(0)
        os.umask(previous_umask)
    if args.json or args.recipient:
        print(json.dumps(result, sort_keys=True))
    else:
        print(
            f"MIME preserved {result['attachment_size']} signed bytes; SHA256 {result['attachment_sha256']}"
        )
        print(
            "Separate keyless JACS recipient verified; all six rejection checks passed; processes/files cleaned."
        )
        print(
            "Outer email edits remain outside the attachment signature. No human approval, policy acceptance, contact authority or mailbox identity inferred."
        )
        print(
            f"Binary {result['jacs_version']}; SHA256 {result['binary_sha256']}; protocol {PROTOCOL}"
        )


if __name__ == "__main__":
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        print(
            f"MCP/MIME demo failed: {error if isinstance(error, DemoError) else type(error).__name__}",
            file=sys.stderr,
        )
        sys.exit(1)
