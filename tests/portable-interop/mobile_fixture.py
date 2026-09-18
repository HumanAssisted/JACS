#!/usr/bin/env python3
"""Real jacs-mobile UniFFI side of the temporary PQ interoperability fixture."""
import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import sys

# These passwords protect disposable test keys only. Never use them for real identities.
RECOVERY = os.environ.get("JACS_INTEROP_RECOVERY") == "1"
TO_BROWSER_PASSWORD = "JacsInterop-MobileToBrowser-TestOnly-7pQ!"
TO_MOBILE_PASSWORD = "JacsInterop-BrowserToMobile-TestOnly-9rS!"


def require(condition, phase):
    if not condition:
        raise AssertionError(phase)


def load_binding(path):
    spec = importlib.util.spec_from_file_location("jacs_mobile", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_private_json(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(value, output)


def create_fixture(binding, path):
    agent = binding.MobileAgent.create_human() if RECOVERY else binding.MobileAgent.create(binding.MobileAlgorithm.PQ2025)
    try:
        require(agent.algorithm() == binding.MobileAlgorithm.PQ2025, "source algorithm")
        document = json.loads(agent.export_agent_json())
        challenge = {"test": "jacs-portable-pq-interop", "direction": "mobile-to-browser", "nonce": document["jacsId"]}
        signed_challenge = agent.sign_message_json(json.dumps(challenge))
        if RECOVERY:
            require(document["jacsAgentType"] == "human", "human first version")
            require(document["jacsVersion"] == document["jacsOriginalVersion"], "no AI predecessor")
            recovery = agent.export_recovery()
            material_json = binding.material_to_json(recovery.material)
        else:
            material_json = binding.material_to_json(agent.export_encrypted_agent(TO_BROWSER_PASSWORD))
        write_private_json(path, {
            "algorithm": "pq2025",
            "agent_id": document["jacsId"],
            "agent_version": document["jacsVersion"],
            "public_key_base64": agent.get_public_key_base64(),
            "public_key_hash": agent.get_public_key_hash(),
            "material_json": material_json,
            "signed_challenge": signed_challenge,
            "challenge": challenge,
            "recovery": RECOVERY,
            "transfer_password": recovery.code if RECOVERY else TO_BROWSER_PASSWORD,
            "return_password": TO_MOBILE_PASSWORD,
        })
    finally:
        agent.clear_secrets()
    require(not agent.is_unlocked(), "source clear")
    print("PASS: mobile UniFFI created, encrypted, and signed PQ material")


def verify_return(binding, fixture_path, returned_path):
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    returned = json.loads(returned_path.read_text(encoding="utf-8"))
    require(returned["algorithm"] == "pq2025", "returned algorithm")
    require(returned["agent_id"] == fixture["agent_id"], "returned identity")
    require(returned["public_key_base64"] == fixture["public_key_base64"], "returned public key")
    require(returned["verified_mobile"] is True, "browser verified source")
    material = binding.material_from_json(returned["material_json"])
    public_key = base64.b64decode(fixture["public_key_base64"], validate=True)
    if RECOVERY:
        agent = binding.MobileAgent.import_recovery(material, returned["recovery_code"], fixture["agent_id"], public_key, binding.MobileAlgorithm.PQ2025)
        for document in returned["created_humans"]:
            key = base64.b64decode(document["public_key_base64"], validate=True)
            outcome = binding.verify_with_key(document["signed_identity"], key, binding.MobileAlgorithm.PQ2025)
            require(outcome.valid, "native verifies web and worker human constructors")
            require(json.loads(document["signed_identity"])["jacsAgentType"] == "human", "created human type")
    else:
        agent = binding.MobileAgent.import_pinned(material, fixture["return_password"], fixture["agent_id"], public_key, binding.MobileAlgorithm.PQ2025)
    try:
        require(agent.is_unlocked(), "mobile return unlock")
        require(agent.algorithm() == binding.MobileAlgorithm.PQ2025, "mobile return algorithm")
        require(agent.get_public_key_base64() == fixture["public_key_base64"], "mobile return pin")
        require(json.loads(agent.export_agent_json())["jacsVersion"] == fixture["agent_version"], "mobile return version")
        outcome = agent.verify_json(returned["signed_response"])
        require(outcome.valid, "mobile verifies browser signature")
        require(outcome.signer_id == fixture["agent_id"], "mobile verifies browser signer")
        content = json.loads(outcome.document_json)["content"]
        require(content == {
            "test": "jacs-portable-pq-interop",
            "direction": "browser-to-mobile",
            "reply_to": fixture["challenge"]["nonce"],
        }, "mobile verifies browser response content")
    finally:
        agent.clear_secrets()
    require(not agent.is_unlocked(), "mobile return clear")
    print("PASS: mobile UniFFI unlocked browser export and verified browser PQ signature")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=["create", "verify"])
    parser.add_argument("--binding", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--returned", type=Path)
    args = parser.parse_args()
    try:
        binding = load_binding(args.binding)
        if args.operation == "create":
            create_fixture(binding, args.fixture)
        else:
            if args.returned is None:
                raise ValueError("returned fixture required")
            verify_return(binding, args.fixture, args.returned)
    except Exception as error:
        # Do not echo key material, passwords, or binding exceptions containing inputs.
        print(f"FAIL: mobile {args.operation} ({type(error).__name__})", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
