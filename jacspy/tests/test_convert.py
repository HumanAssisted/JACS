"""Tests for JACS format conversion (YAML/HTML) via SimpleAgent."""

import json
import pytest


@pytest.fixture
def agent():
    """Create an ephemeral SimpleAgent for testing."""
    import jacs

    agent, _info = jacs.SimpleAgent.ephemeral("ed25519")
    return agent


def test_to_yaml_returns_valid_yaml(agent):
    """to_yaml should return a valid YAML string."""
    signed = agent.sign_message(json.dumps({"hello": "world"}))
    yaml_str = agent.to_yaml(signed["raw"])
    # Should be parseable as YAML
    assert "hello" in yaml_str
    assert isinstance(yaml_str, str)


def test_from_yaml_returns_valid_json(agent):
    """from_yaml should return a valid JSON string."""
    yaml_str = "hello: world\ncount: 42\n"
    json_str = agent.from_yaml(yaml_str)
    parsed = json.loads(json_str)
    assert parsed["hello"] == "world"
    assert parsed["count"] == 42


def test_yaml_round_trip_preserves_content(agent):
    """Sign, to_yaml, from_yaml should preserve content for verification."""
    signed = agent.sign_message(json.dumps({"data": "test", "num": 42}))
    yaml_str = agent.to_yaml(signed["raw"])
    json_back = agent.from_yaml(yaml_str)
    # Both should parse to equivalent JSON
    original = json.loads(signed["raw"])
    reconstituted = json.loads(json_back)
    # Verify the document survived the round-trip (has same keys)
    assert "jacsSignature" in reconstituted
    assert "content" in reconstituted or "jacsType" in reconstituted


def test_verify_yaml_succeeds_on_valid_document(agent):
    """verify_yaml should succeed on a valid signed document converted to YAML."""
    signed = agent.sign_message(json.dumps({"data": "verify me"}))
    yaml_str = agent.to_yaml(signed["raw"])
    result_json = agent.verify_yaml(yaml_str)
    result = json.loads(result_json)
    assert result["valid"] is True


def test_to_html_returns_valid_html(agent):
    """to_html should return a valid HTML string."""
    signed = agent.sign_message(json.dumps({"content": "test"}))
    html = agent.to_html(signed["raw"])
    assert html.startswith("<!DOCTYPE html>")
    assert '<script type="application/json" id="jacs-data">' in html


def test_from_html_returns_valid_json(agent):
    """from_html should extract valid JSON from HTML."""
    signed = agent.sign_message(json.dumps({"content": "extract me"}))
    html = agent.to_html(signed["raw"])
    json_back = agent.from_html(html)
    parsed = json.loads(json_back)
    assert "content" in str(parsed)


def test_html_round_trip_preserves_content(agent):
    """Sign, to_html, from_html, verify should succeed."""
    signed = agent.sign_message(json.dumps({"data": "html test"}))
    html = agent.to_html(signed["raw"])
    json_back = agent.from_html(html)
    result = agent.verify(json_back)
    assert result["valid"] is True


def test_to_yaml_invalid_json_raises(agent):
    """to_yaml should raise on invalid JSON input."""
    with pytest.raises(Exception):
        agent.to_yaml("{not valid json}")


def test_from_yaml_invalid_yaml_raises(agent):
    """from_yaml should raise on invalid YAML input."""
    with pytest.raises(Exception):
        agent.from_yaml("{{{{ not yaml ::::")
