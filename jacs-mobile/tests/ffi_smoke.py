"""Host UniFFI smoke test. See README for generation and PYTHONPATH setup.

This executes the actual cdylib through generated foreign bindings, including
an independent Python/cryptography ES256 callback. It does not simulate iOS or
Android biometric behavior. Requires the `cryptography` Python package.
"""
import base64
import hashlib
import json

import jacs_mobile as jacs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


class ExternalP256:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cleared = False
        self.cancelled = False

    def algorithm(self):
        return jacs.MobileAlgorithm.ES256

    def public_key(self):
        return self.key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )

    def sign(self, message):
        if self.cancelled:
            raise jacs.PlatformSignerError.Cancelled()
        der = self.key.sign(message, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def clear_secrets(self):
        self.cleared = True


default_agent = jacs.MobileAgent.create_default()
assert default_agent.algorithm() == jacs.MobileAlgorithm.PQ2025
default_agent.clear_secrets()

# These explicit algorithm selections check compatibility, not application defaults.
for algorithm in jacs.MobileAlgorithm:
    agent = jacs.MobileAgent.create(algorithm)
    code = jacs.generate_transfer_code()
    wire = jacs.material_to_json(agent.export_encrypted_agent(code))
    restored = jacs.MobileAgent.import_encrypted_agent(jacs.material_from_json(wire), code)
    assert restored.public_key() == agent.public_key()
    signed = restored.sign_message_json('{"hello":"foreign FFI"}')
    assert agent.verify_json(signed).valid
    restored.clear_secrets()
    assert not restored.is_unlocked()
    try:
        restored.sign_message_json("{}")
        raise AssertionError("cleared agent signed")
    except jacs.MobileError.Core as error:
        assert error.code == "Locked"
    agent.clear_secrets()

callback = ExternalP256()
hardware = jacs.MobileAgent.from_platform_signer(callback, "{}")
assert hardware.verify_json(hardware.sign_message_json("{}")).valid
original_identity = hardware.export_agent_json()
candidate = hardware.prepare_agent_update_json('{"jacsName":"Phone"}')
assert hardware.export_agent_json() == original_identity
assert hardware.commit_agent_update_json(candidate) == candidate
body = b'\x00exact transmitted bytes\xff'
header = hardware.build_request_auth_header("POST", "https://example.com/api?x=1", body, "test-audience")
claims_token, signature_token = header.removeprefix("JACS v2.").split(".")
decode = lambda token: base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
canonical, signature = decode(claims_token), decode(signature_token)
claims = json.loads(canonical)
assert claims["contentDigest"] == "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"
assert claims["audience"] == "test-audience"
assert claims["method"] == "POST" and claims["target"] == "/api?x=1"
der = utils.encode_dss_signature(int.from_bytes(signature[:32]), int.from_bytes(signature[32:]))
callback.key.public_key().verify(der, b"JACS-REQUEST-AUTH-V2\n" + canonical, ec.ECDSA(hashes.SHA256()))
try:
    hardware.export_encrypted_agent("not exportable")
    raise AssertionError("hardware export succeeded")
except jacs.MobileError.Core as error:
    assert error.code == "NotExportable"
callback.cancelled = True
try:
    hardware.sign_message_json("{}")
    raise AssertionError("cancelled callback succeeded")
except jacs.MobileError.Core as error:
    assert error.code == "Locked"
hardware.clear_secrets()
assert callback.cleared
print("PASS: generated UniFFI FFI for all algorithms, independent ES256 callback, export denial and relocking")
