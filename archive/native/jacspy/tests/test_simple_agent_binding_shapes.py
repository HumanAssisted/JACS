import json

import pytest

jacs = pytest.importorskip("jacs")

from jacs import SimpleAgent


def _ephemeral(algorithm: str = "ed25519") -> SimpleAgent:
    agent, _info = SimpleAgent.ephemeral(algorithm=algorithm)
    return agent


def _created_agent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return SimpleAgent.create("binding-shape-agent", None, "ed25519")


def _persistent_agent(tmp_path, name: str):
    password = "ShapePass123!#"
    data_directory = tmp_path / f"{name}-data"
    key_directory = tmp_path / f"{name}-keys"
    config_path = tmp_path / f"{name}.config.json"
    agent, info = SimpleAgent.create_agent(
        name=name,
        password=password,
        algorithm="ring-Ed25519",
        data_directory=str(data_directory),
        key_directory=str(key_directory),
        config_path=str(config_path),
    )
    return agent, info


def test_create_returns_exact_info_shape(tmp_path, monkeypatch):
    _agent, info = _created_agent(tmp_path, monkeypatch)

    assert set(info.keys()) == {
        "agent_id",
        "name",
        "public_key_path",
        "config_path",
    }
    assert all(isinstance(info[key], str) for key in info)


def test_ephemeral_returns_exact_info_shape():
    _agent, info = SimpleAgent.ephemeral(algorithm="ed25519")

    assert set(info.keys()) == {"agent_id", "name", "algorithm", "version"}
    assert all(isinstance(info[key], str) for key in info)


def test_create_agent_returns_exact_info_shape(tmp_path):
    _agent, info = _persistent_agent(tmp_path, "shape-create-agent")

    assert set(info.keys()) == {
        "agent_id",
        "name",
        "public_key_path",
        "config_path",
        "version",
        "algorithm",
        "private_key_path",
        "data_directory",
        "key_directory",
        "domain",
        "dns_record",
    }
    assert all(isinstance(info[key], str) for key in info)


def test_create_with_params_returns_exact_info_shape(tmp_path):
    params_json = json.dumps(
        {
            "name": "shape-create-with-params",
            "password": "ShapePass123!#",
            "algorithm": "ring-Ed25519",
            "data_directory": str(tmp_path / "params-data"),
            "key_directory": str(tmp_path / "params-keys"),
            "config_path": str(tmp_path / "params.config.json"),
            "agent_type": "ai",
            "description": "binding shape test",
            "domain": "",
            "default_storage": "fs",
        }
    )

    _agent, info = SimpleAgent.create_with_params(params_json)

    assert set(info.keys()) == {
        "agent_id",
        "name",
        "public_key_path",
        "config_path",
        "version",
        "algorithm",
        "private_key_path",
        "data_directory",
        "key_directory",
        "domain",
        "dns_record",
    }
    assert all(isinstance(info[key], str) for key in info)


def test_sign_message_returns_exact_shape():
    agent = _ephemeral()

    signed = agent.sign_message({"binding_shape": True})

    assert set(signed.keys()) == {"raw", "document_id", "agent_id", "timestamp"}
    assert all(isinstance(signed[key], str) for key in signed)


def test_sign_file_returns_exact_shape(tmp_path):
    agent = _ephemeral()
    file_path = tmp_path / "binding-shape.txt"
    file_path.write_text("shape", encoding="utf-8")

    signed = agent.sign_file(str(file_path), embed=False)

    assert set(signed.keys()) == {"raw", "document_id", "agent_id", "timestamp"}
    assert all(isinstance(signed[key], str) for key in signed)


def test_verify_returns_exact_shape_and_types():
    agent = _ephemeral()
    signed = agent.sign_message({"binding_shape": "verify"})

    result = agent.verify(signed["raw"])

    assert set(result.keys()) == {
        "valid",
        "signer_id",
        "timestamp",
        "errors",
        "data",
        "attachments",
    }
    assert isinstance(result["valid"], bool)
    assert isinstance(result["signer_id"], str)
    assert isinstance(result["timestamp"], str)
    assert isinstance(result["errors"], list)
    assert isinstance(result["attachments"], list)


def test_verify_by_id_returns_exact_shape_and_types(tmp_path):
    agent, _info = _persistent_agent(tmp_path, "shape-verify-by-id")
    signed = agent.sign_message({"binding_shape": "verify_by_id"})
    raw = json.loads(signed["raw"])
    document_key = f"{raw['jacsId']}:{raw['jacsVersion']}"

    result = agent.verify_by_id(document_key)

    assert set(result.keys()) == {"valid", "signer_id", "timestamp", "errors", "data"}
    assert isinstance(result["valid"], bool)
    assert isinstance(result["signer_id"], str)
    assert isinstance(result["timestamp"], str)
    assert isinstance(result["errors"], list)


def test_verify_with_key_returns_exact_shape_and_types():
    agent = _ephemeral()
    signed = agent.sign_message({"binding_shape": "verify_with_key"})
    key_b64 = agent.get_public_key_base64()

    result = agent.verify_with_key(signed["raw"], key_b64)

    assert set(result.keys()) == {"valid", "signer_id", "timestamp", "errors", "data"}
    assert isinstance(result["valid"], bool)
    assert isinstance(result["signer_id"], str)
    assert isinstance(result["timestamp"], str)
    assert isinstance(result["errors"], list)
