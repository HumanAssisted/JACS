"""
Method enumeration parity test for the Python binding.

Validates that all methods listed in
binding-core/tests/fixtures/method_parity.json are exposed in the Python
binding (via SimpleAgent PyO3 class), with documented exclusions and
name mappings.

This is a *structural* test (method names), not a *behavioral* test.
It complements, not duplicates, test_parity.py.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

# Skip all tests if the native jacs module is not built
jacs = pytest.importorskip("jacs")

from jacs import SimpleAgent

FIXTURE_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "binding-core"
    / "tests"
    / "fixtures"
    / "method_parity.json"
)

# Methods that are intentionally Rust-only and not exposed in Python.
# Each exclusion has a comment explaining why.
EXCLUDED_FROM_PYTHON = {
    # inner_ref returns a raw Rust reference; not meaningful across FFI
    "inner_ref",
    # from_agent wraps a Rust SimpleAgent; not callable from Python
    "from_agent",
    # load_with_info is an internal Rust helper; Python uses load() directly
    "load_with_info",
}

# Rust method name -> Python attribute name mapping.
# When the Python binding uses a different name than Rust, document it here.
#
# Suffix-stripping convention (matches sign_file_json -> sign_file etc.):
# the `_json` / `_base64` suffixes on SimpleAgentWrapper are FFI-internal
# and dropped on the language-side surface.
PYTHON_NAME_MAP = {
    "create": "create",
    "load": "load",
    "ephemeral": "ephemeral",
    "create_with_params": "create_with_params",
    "get_agent_id": "get_agent_id",
    "key_id": "key_id",
    "is_strict": "is_strict",
    "config_path": "config_path",
    "export_agent": "export_agent",
    "get_public_key_pem": "get_public_key_pem",
    "get_public_key_base64": "get_public_key_base64",
    "diagnostics": "diagnostics",
    "verify_self": "verify_self",
    "verify_json": "verify",
    "verify_with_key_json": "verify_with_key",
    "verify_by_id_json": "verify_by_id",
    "sign_message_json": "sign_message",
    "sign_raw_bytes_base64": "sign_string",
    "sign_file_json": "sign_file",
    "build_auth_header": "build_auth_header",
    "build_request_auth_header": "build_request_auth_header",
    "canonicalize_json": "canonicalize_json",
    "sign_response": "sign_response",
    "encode_verify_payload": "encode_verify_payload",
    "decode_verify_payload": "decode_verify_payload",
    "extract_document_id": "extract_document_id",
    "prepare_signed_event_replay_json": "prepare_signed_event_replay",
    "unwrap_signed_event": "unwrap_signed_event",
    "to_yaml": "to_yaml",
    "from_yaml": "from_yaml",
    "to_html": "to_html",
    "from_html": "from_html",
    "rotate_keys": "rotate_keys",
    "export_w3c_did": "export_w3c_did",
    "export_w3c_did_document_json": "export_w3c_did_document",
    "export_w3c_agent_description_json": "export_w3c_agent_description",
    "generate_w3c_well_known_json": "generate_w3c_well_known",
    "sign_w3c_request_json": "sign_w3c_request",
    "verify_w3c_request_json": "verify_w3c_request",
    # Inline text + media (Task 05 + 06; Task 10 ships PyO3 surface).
    "sign_text_file_json": "sign_text_file",
    "verify_text_file_json": "verify_text_file",
    "sign_image_json": "sign_image",
    "verify_image_json": "verify_image",
    "extract_media_signature_json": "extract_media_signature",
    # Agreement v2 (feature-gated in Rust, exposed by the Python extension
    # when built with the `agreements` feature).
    "create_agreement_v2_json": "create_agreement_v2",
    "apply_agreement_v2_json": "apply_agreement_v2",
    "sign_agreement_v2_json": "sign_agreement_v2",
    "verify_agreement_v2_json": "verify_agreement_v2",
    "detect_agreement_v2_branch_conflict_json": "detect_agreement_v2_branch_conflict",
    "merge_agreement_v2_transcript_branches_json": "merge_agreement_v2_transcript_branches",
    "resolve_agreement_v2_branch_conflict_json": "resolve_agreement_v2_branch_conflict",
    # ES256 compatibility key + ecosystem exports (P2 Tasks 002 / 004).
    "add_compat_key_json": "add_compat_key",
    "issue_compat_binding_json": "issue_compat_binding",
    "export_compatibility_jwks_json": "export_compatibility_jwks",
    "export_compatibility_key_binding_json": "export_compatibility_key_binding",
    "export_ap2_mandate_json": "export_ap2_mandate",
    "export_a2a_agent_card_json": "export_a2a_agent_card",
    "export_agreement_v2_as_vc_json": "export_agreement_v2_as_vc",
}

# Feature-gated fixture groups are only present on SimpleAgent when the
# native extension was compiled with the matching cargo feature. The default
# maturin build (see pyproject.toml [tool.maturin] features) enables
# `agreements` but not `a2a`. Detect each feature via a pre-existing gated
# method so the presence check for NEW gated methods stays meaningful.
FEATURE_BUILT = {
    "a2a": hasattr(jacs.JacsAgent, "export_agent_card"),
    "agreements": hasattr(SimpleAgent, "create_agreement_v2"),
}


@pytest.fixture(scope="module")
def method_parity() -> dict:
    """Load the shared method parity fixture file."""
    assert FIXTURE_PATH.exists(), (
        f"Method parity fixture not found at {FIXTURE_PATH}. "
        "Ensure binding-core/tests/fixtures/method_parity.json exists."
    )
    with open(FIXTURE_PATH) as f:
        return json.load(f)


def parity_methods(method_parity: dict) -> list[str]:
    """Return the full language-surface contract, including feature-gated groups."""
    methods = list(method_parity["all_methods_flat"])
    for gated in method_parity.get("feature_gated_methods", {}).values():
        methods.extend(gated)
    return methods


def built_parity_methods(method_parity: dict) -> list[str]:
    """Return the contract for THIS build: gated groups whose cargo feature
    was not compiled in (see FEATURE_BUILT) are excluded from presence checks."""
    methods = list(method_parity["all_methods_flat"])
    for feature, gated in method_parity.get("feature_gated_methods", {}).items():
        if FEATURE_BUILT.get(feature, True):
            methods.extend(gated)
    return methods


def test_python_method_parity_against_fixture(method_parity: dict):
    """All non-excluded methods from the fixture must exist on SimpleAgent."""
    all_methods = built_parity_methods(method_parity)

    missing = []
    for rust_name in all_methods:
        if rust_name in EXCLUDED_FROM_PYTHON:
            continue

        python_name = PYTHON_NAME_MAP.get(rust_name, rust_name)
        if not hasattr(SimpleAgent, python_name):
            missing.append(f"{rust_name} (expected as '{python_name}')")

    assert not missing, (
        f"Python SimpleAgent is missing {len(missing)} methods from method_parity.json:\n"
        + "\n".join(f"  - {m}" for m in missing)
        + "\n\nIf a method was intentionally excluded, add it to EXCLUDED_FROM_PYTHON. "
        + "If it has a different name in Python, add it to PYTHON_NAME_MAP."
    )


def test_public_simple_protocol_roundtrip(monkeypatch):
    """Protocol helpers must be functional on the public SimpleAgent class."""
    monkeypatch.delenv("JACS_REJECT_UNBOUND_AUTH_HEADER", raising=False)
    agent, _ = SimpleAgent.ephemeral("ed25519")
    legacy = agent.build_auth_header()
    assert legacy.startswith("JACS ")
    body = '{"include_test":false}'
    header = agent.build_request_auth_header(
        "POST", "https://hai.ai/api/v1/agents/hello", body, "hai.ai"
    )
    assert header.startswith("JACS v2.")

    envelope = agent.sign_response('{"type":"connected"}')
    parsed = json.loads(envelope)
    signer_id = parsed["jacsSignature"]["agentID"]
    verified = json.loads(
        agent.unwrap_signed_event(
            envelope, json.dumps({signer_id: agent.get_public_key_pem()})
        )
    )
    assert verified["verified"] is True
    assert verified["data"]["type"] == "connected"


def test_request_auth_hashes_exact_binary_body_bytes():
    agent, _ = SimpleAgent.ephemeral("ed25519")
    body = b"\x00\xffbinary\x00body"
    for bytes_like in (body, bytearray(body), memoryview(body)):
        header = agent.build_request_auth_header(
            "POST", "https://hai.ai/api/v1/jobs", bytes_like, "hai.ai"
        )
        claims_segment = header.removeprefix("JACS v2.").split(".", 1)[0]
        claims = json.loads(
            base64.urlsafe_b64decode(
                claims_segment + "=" * (-len(claims_segment) % 4)
            )
        )
        expected = base64.b64encode(hashlib.sha256(body).digest()).decode()
        assert claims["contentDigest"] == f"sha-256=:{expected}:"

    with pytest.raises(TypeError, match="contiguous"):
        agent.build_request_auth_header(
            "POST", "https://hai.ai/api/v1/jobs", memoryview(body)[::2], "hai.ai"
        )

    with pytest.raises(TypeError, match="str or a contiguous bytes-like object"):
        agent.build_request_auth_header(
            "POST", "https://hai.ai/api/v1/jobs", 123, "hai.ai"
        )


def test_python_exclusions_are_valid(method_parity: dict):
    """Every excluded method must actually exist in the fixture."""
    all_methods = set(parity_methods(method_parity))

    invalid_exclusions = EXCLUDED_FROM_PYTHON - all_methods
    assert not invalid_exclusions, (
        f"EXCLUDED_FROM_PYTHON contains methods not in the fixture: {invalid_exclusions}. "
        "Remove stale exclusions."
    )


def test_python_name_map_covers_all_non_excluded(method_parity: dict):
    """Every non-excluded method should have a mapping (even if identity)."""
    all_methods = parity_methods(method_parity)

    unmapped = []
    for rust_name in all_methods:
        if rust_name in EXCLUDED_FROM_PYTHON:
            continue
        if rust_name not in PYTHON_NAME_MAP:
            unmapped.append(rust_name)

    assert not unmapped, (
        f"Methods without PYTHON_NAME_MAP entry: {unmapped}. "
        "Add a mapping (even rust_name -> rust_name if the name is the same)."
    )


def test_python_name_map_has_no_stale_entries(method_parity: dict):
    """PYTHON_NAME_MAP should not contain methods that don't exist in the fixture."""
    all_methods = set(parity_methods(method_parity))

    stale = set(PYTHON_NAME_MAP.keys()) - all_methods
    assert not stale, (
        f"PYTHON_NAME_MAP contains methods not in the fixture: {stale}. "
        "Remove stale mappings."
    )


def test_python_exclusions_are_still_needed():
    """Check if excluded methods now exist on SimpleAgent.

    If an excluded method becomes available at runtime (e.g., after
    rebuilding the native module), this test fails to prompt removal
    of the exclusion. This turns the TODO in EXCLUDED_FROM_PYTHON
    into an automated check.
    """
    newly_available = []
    for method_name in EXCLUDED_FROM_PYTHON:
        # Skip internal-only exclusions that will never appear on the class
        if method_name in ("inner_ref", "from_agent", "load_with_info"):
            continue
        # Check if the method is now available on SimpleAgent
        python_name = PYTHON_NAME_MAP.get(method_name, method_name)
        if hasattr(SimpleAgent, python_name):
            newly_available.append(
                f"{method_name} (as '{python_name}') is now available on SimpleAgent"
            )

    assert not newly_available, (
        "The following excluded methods are now available on SimpleAgent. "
        "Remove them from EXCLUDED_FROM_PYTHON and add them to PYTHON_NAME_MAP:\n"
        + "\n".join(f"  - {m}" for m in newly_available)
    )
