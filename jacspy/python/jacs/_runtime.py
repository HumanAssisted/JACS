import json
import logging
import os

from .types import JacsError

logger = logging.getLogger("jacs")


def write_key_directory_ignore_files(key_dir: str):
    """Write ignore files in the key directory to keep secrets out of artifacts."""
    ignore_content = (
        "# JACS private key material -- do NOT commit or ship\n"
        "*.pem\n"
        "*.pem.enc\n"
        ".jacs_password\n"
        "*.key\n"
        "*.key.enc\n"
    )
    os.makedirs(key_dir, exist_ok=True)
    gitignore = os.path.join(key_dir, ".gitignore")
    if not os.path.exists(gitignore):
        try:
            with open(gitignore, "w", encoding="utf-8") as f:
                f.write(ignore_content)
        except OSError as e:
            logger.warning("Could not write %s: %s", gitignore, e)
    dockerignore = os.path.join(key_dir, ".dockerignore")
    if not os.path.exists(dockerignore):
        try:
            with open(dockerignore, "w", encoding="utf-8") as f:
                f.write(ignore_content)
        except OSError as e:
            logger.warning("Could not write %s: %s", dockerignore, e)


class EphemeralAgentAdapter:
    """Adapter that wraps a native SimpleAgent to match the JacsAgent interface."""

    def __init__(self, native_agent):
        self._native = native_agent

    def sign_string(self, data):
        return self._native.sign_string(data)

    def verify_agent(self, agentfile=None):
        result = self._native.verify_self()
        if not result.get("valid", False):
            errors = result.get("errors", [])
            raise RuntimeError(f"Agent verification failed: {errors}")
        return True

    def create_document(
        self,
        document_string,
        custom_schema=None,
        outputfilename=None,
        no_save=None,
        attachments=None,
        embed=None,
    ):
        if attachments:
            result = self._native.sign_file(attachments, embed or False)
        else:
            data = json.loads(document_string)
            result = self._native.sign_message(data)
        return result.get("raw", "")

    @staticmethod
    def _unwrap_jacs_payload(data):
        if not isinstance(data, dict):
            return data
        if "jacs_payload" in data:
            return data.get("jacs_payload")
        jacs_document = data.get("jacsDocument")
        if isinstance(jacs_document, dict) and "jacs_payload" in jacs_document:
            return jacs_document.get("jacs_payload")
        payload = data.get("payload")
        if isinstance(payload, dict) and "jacs_payload" in payload:
            return payload.get("jacs_payload")
        return data

    def sign_request(self, payload):
        result = self._native.sign_message({"jacs_payload": payload})
        if isinstance(result, str):
            return result
        if isinstance(result, dict):
            raw = result.get("raw") or result.get("raw_json")
            if isinstance(raw, str):
                return raw
        raise RuntimeError("Ephemeral sign_request returned an unexpected result shape")

    def verify_response(self, document_string):
        result = self._native.verify(document_string)
        if not isinstance(result, dict):
            raise RuntimeError("Ephemeral verify_response returned an unexpected result shape")
        if not result.get("valid", False):
            errors = result.get("errors")
            if isinstance(errors, list) and errors:
                message = "; ".join(str(e) for e in errors)
            elif errors:
                message = str(errors)
            else:
                message = "signature verification failed"
            raise RuntimeError(message)
        return self._unwrap_jacs_payload(result.get("data"))

    def verify_document(self, document_string):
        result = self._native.verify(document_string)
        return result.get("valid", False)

    def get_agent_json(self):
        return self._native.export_agent()

    def update_agent(self, new_agent_string):
        raise JacsError(
            "update_agent() is not supported on ephemeral agents. "
            "Use jacs.create() or jacs.load() for a persistent agent."
        )

    def update_document(
        self,
        document_key,
        new_document_string,
        attachments=None,
        embed=None,
    ):
        raise JacsError(
            "update_document() is not supported on ephemeral agents. "
            "Use jacs.create() or jacs.load() for a persistent agent."
        )

    def create_agreement(
        self,
        document_string,
        agentids,
        question=None,
        context=None,
        agreement_fieldname=None,
    ):
        raise JacsError(
            "create_agreement() is not supported on ephemeral agents. "
            "Use jacs.create() or jacs.load() for a persistent agent."
        )

    def sign_agreement(self, document_string, agreement_fieldname=None):
        raise JacsError(
            "sign_agreement() is not supported on ephemeral agents. "
            "Use jacs.create() or jacs.load() for a persistent agent."
        )

    def check_agreement(self, document_string, agreement_fieldname=None):
        raise JacsError(
            "check_agreement() is not supported on ephemeral agents. "
            "Use jacs.create() or jacs.load() for a persistent agent."
        )

    def verify_document_by_id(self, document_id):
        result = self._native.verify_by_id(document_id)
        return result.get("valid", False)

    def reencrypt_key(self, old_password, new_password):
        return self._native.reencrypt_key(old_password, new_password)

    def diagnostics(self):
        return json.dumps({"agent_loaded": True, "ephemeral": True})

    def get_setup_instructions(self, domain, ttl=3600):
        raise JacsError(
            "get_setup_instructions() is not supported on ephemeral agents. "
            "Use jacs.create() or jacs.load() for a persistent agent."
        )

    def create_attestation(self, params_json):
        return self._native.create_attestation(params_json)

    def verify_attestation(self, document_key):
        return self._native.verify_attestation(document_key)

    def verify_attestation_full(self, document_key):
        return self._native.verify_attestation_full(document_key)

    def lift_to_attestation(self, signed_doc_json, claims_json):
        return self._native.lift_to_attestation(signed_doc_json, claims_json)

    def export_attestation_dsse(self, attestation_json):
        return self._native.export_dsse(attestation_json)
