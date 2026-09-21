"""Exercise an installed wheel, isolated from checkout and PYTHONPATH."""
import importlib.metadata
import json
from pathlib import Path
import sys

import jacs
from jacs import SimpleAgent
from jacs.client import JacsClient

assert Path(jacs.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
assert importlib.metadata.version("jacs") == sys.argv[1]
agent, _ = SimpleAgent.ephemeral()
signed = agent.sign_message({"message": "binding-smoke-original"})
assert agent.verify(signed["raw"])["valid"] is True
assert json.loads(signed["raw"])["jacsSignature"]["signingAlgorithm"] == "pq2025"
tampered = signed["raw"].replace("binding-smoke-original", "binding-smoke-tampered")
assert tampered != signed["raw"]
try:
    accepted = agent.verify(tampered)["valid"]
except Exception:
    accepted = False
assert accepted is False, "tampered document accepted"
client = JacsClient.ephemeral()
assert client.verify(client.sign_message({"client": True})).valid is True
print("PYTHON-CANDIDATE-OK: installed wheel, PQ signing, tamper rejection, client API")
