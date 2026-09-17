"""Public-only compound verification through the actual native binding.

Run with the extension's ``human-approval`` feature enabled and
``JACS_TEST_HUMAN_APPROVAL=1``. That gate fails rather than skips if the build
omits the verifier. The fixture contains public
evidence, caller-selected expectations and separate authority/provenance pins.
"""

import copy
import json
import os
from pathlib import Path

import pytest
from jacs import SimpleAgent

FIXTURES = Path(__file__).resolve().parents[2] / "binding-core/tests/fixtures"
ERROR_KIND_PREFIX = json.loads((FIXTURES / "parity_inputs.json").read_text())[
    "portable_error_contract"
]["message_prefix"]

pytestmark = pytest.mark.skipif(
    os.environ.get("JACS_TEST_HUMAN_APPROVAL") != "1"
    and not hasattr(SimpleAgent, "verify_human_approved_document"),
    reason="requires an opt-in human-approval native build",
)


@pytest.fixture
def fixture():
    return json.loads(
        (FIXTURES / "human_approved_document_v1.json").read_text(encoding="utf-8")
    )


def verify(fixture):
    # Static invocation intentionally creates no agent or signing key.
    return SimpleAgent.verify_human_approved_document(
        *(json.dumps(fixture[name]) for name in ("bundle", "expected", "authority", "provenance"))
    )


def test_public_evidence_preserves_the_complete_report_without_an_agent(fixture, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("JACS_PRIVATE_KEY_PASSWORD", raising=False)
    report = verify(fixture)
    assert isinstance(report, dict)
    assert report == fixture["report"]
    assert report["provenanceSignatureValid"] is True
    assert report["approval"]["proofValid"] is True
    assert report["approval"]["userVerified"] is True
    assert report["current"] == report["approval"]["current"] == "not_evaluated"
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("field", ["expected", "authority", "provenance"])
def test_public_evidence_requires_independently_selected_context_and_pins(fixture, field):
    changed = copy.deepcopy(fixture)
    if field == "expected":
        changed[field]["humanId"] += "-other"
    else:
        changed[field]["agentId"] += "-other"
    with pytest.raises(RuntimeError) as error:
        verify(changed)
    assert f"{ERROR_KIND_PREFIX}VerificationFailed:" in str(error.value)


@pytest.mark.parametrize("position", range(4))
def test_public_evidence_rejects_malformed_json_in_each_argument(fixture, position):
    args = [json.dumps(fixture[name]) for name in ("bundle", "expected", "authority", "provenance")]
    args[position] = "{"
    with pytest.raises(RuntimeError) as error:
        SimpleAgent.verify_human_approved_document(*args)
    kind = "VerificationFailed" if position == 0 else "InvalidArgument"
    assert f"{ERROR_KIND_PREFIX}{kind}:" in str(error.value)
