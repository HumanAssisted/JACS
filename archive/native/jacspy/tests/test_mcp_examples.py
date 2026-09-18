"""Preflight behavior for the authenticated MCP examples."""

import runpy
from pathlib import Path

import pytest


EXAMPLE_DIR = Path(__file__).parents[1] / "examples" / "mcp"


@pytest.mark.parametrize("script", ["server.py", "client.py"])
def test_examples_require_caller_generated_config(monkeypatch, script):
    monkeypatch.delenv("JACS_CONFIG_PATH", raising=False)
    monkeypatch.delenv("JACS_PRIVATE_KEY_PASSWORD", raising=False)

    with pytest.raises(RuntimeError, match="generate fresh JACS identities"):
        runpy.run_path(str(EXAMPLE_DIR / script))


def test_server_example_requires_explicit_client_allowlist(monkeypatch, tmp_path):
    config = tmp_path / "jacs.config.json"
    config.write_text("{}")
    monkeypatch.setenv("JACS_CONFIG_PATH", str(config))
    monkeypatch.delenv("JACS_MCP_ALLOWED_CLIENT_AGENT_ID", raising=False)

    with pytest.raises(RuntimeError, match="JACS_MCP_ALLOWED_CLIENT_AGENT_ID"):
        runpy.run_path(str(EXAMPLE_DIR / "server.py"))
