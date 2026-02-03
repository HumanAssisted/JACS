"""
Tests for the async JACS Python API.

These tests require pytest-asyncio and a valid jacs.config.json.
"""

import json
import os
import pytest

# Skip all tests if jacs module or pytest-asyncio is not available
pytest.importorskip("jacs")
pytest.importorskip("pytest_asyncio")

from jacs import async_simple
from jacs.types import (
    AgentInfo,
    SignedDocument,
    VerificationResult,
    AgreementStatus,
    JacsError,
    AgentNotLoadedError,
)


# Fixtures


@pytest.fixture
def config_path(in_fixtures_dir, shared_config_path):
    """Get path to JACS config from shared fixtures."""
    path = os.environ.get("JACS_CONFIG_PATH", shared_config_path)
    if not os.path.exists(path):
        pytest.skip(f"JACS config not found at {path}")
    return path


@pytest.fixture
async def loaded_agent(config_path):
    """Load agent for tests that need it."""
    # Reload sync module to ensure clean state
    import importlib
    from jacs import simple
    importlib.reload(simple)

    info = await async_simple.load(config_path)
    assert info is not None
    return info


# Test async load()


class TestAsyncLoad:
    @pytest.mark.asyncio
    async def test_load_returns_agent_info(self, config_path):
        """async load() should return AgentInfo with valid fields."""
        info = await async_simple.load(config_path)

        assert isinstance(info, AgentInfo)
        assert info.agent_id
        assert info.config_path == config_path

    @pytest.mark.asyncio
    async def test_load_nonexistent_raises(self):
        """async load() with nonexistent path should raise error."""
        with pytest.raises(JacsError):
            await async_simple.load("/nonexistent/path/config.json")


# Test async verify_self()


class TestAsyncVerifySelf:
    @pytest.mark.asyncio
    async def test_verify_self_valid(self, loaded_agent):
        """async verify_self() should return valid=True for loaded agent."""
        result = await async_simple.verify_self()

        assert isinstance(result, VerificationResult)
        assert result.valid is True
        assert len(result.errors) == 0


# Test async sign_message()


class TestAsyncSignMessage:
    @pytest.mark.asyncio
    async def test_sign_dict(self, loaded_agent):
        """async sign_message() should sign a dictionary."""
        data = {"action": "test", "value": 42}
        signed = await async_simple.sign_message(data)

        assert isinstance(signed, SignedDocument)
        assert signed.document_id
        assert signed.agent_id
        assert signed.timestamp
        assert signed.raw

    @pytest.mark.asyncio
    async def test_sign_string(self, loaded_agent):
        """async sign_message() should sign a string."""
        data = "Hello, Async JACS!"
        signed = await async_simple.sign_message(data)

        assert isinstance(signed, SignedDocument)

    @pytest.mark.asyncio
    async def test_sign_produces_valid_json(self, loaded_agent):
        """async sign_message() should produce valid JSON in raw field."""
        data = {"test": True}
        signed = await async_simple.sign_message(data)

        parsed = json.loads(signed.raw)
        assert "jacsSignature" in parsed


# Test async verify()


class TestAsyncVerify:
    @pytest.mark.asyncio
    async def test_verify_own_signature(self, loaded_agent):
        """async verify() should validate documents we signed."""
        data = {"verified": True}
        signed = await async_simple.sign_message(data)

        result = await async_simple.verify(signed.raw)

        assert isinstance(result, VerificationResult)
        assert result.valid is True
        assert result.signer_id == signed.agent_id

    @pytest.mark.asyncio
    async def test_verify_invalid_json(self, loaded_agent):
        """async verify() should handle invalid JSON gracefully."""
        result = await async_simple.verify("not valid json")

        assert result.valid is False
        assert len(result.errors) > 0


# Test async sign_file()


class TestAsyncSignFile:
    @pytest.mark.asyncio
    async def test_sign_file_reference(self, loaded_agent, tmp_path):
        """async sign_file() should sign a file in reference mode."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello, World!")

        signed = await async_simple.sign_file(str(test_file), embed=False)

        assert isinstance(signed, SignedDocument)
        assert signed.document_id

    @pytest.mark.asyncio
    async def test_sign_file_embed(self, loaded_agent, tmp_path):
        """async sign_file() should sign a file with embedding."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("Embedded content")

        signed = await async_simple.sign_file(str(test_file), embed=True)

        assert isinstance(signed, SignedDocument)
        doc = json.loads(signed.raw)
        assert "jacsSignature" in doc


# Test async agreement functions


class TestAsyncAgreement:
    @pytest.mark.asyncio
    async def test_create_agreement(self, loaded_agent):
        """async create_agreement() should return SignedDocument."""
        agreement = await async_simple.create_agreement(
            document={"proposal": "Async test proposal"},
            agent_ids=[loaded_agent.agent_id],
            question="Do you approve?",
        )

        assert isinstance(agreement, SignedDocument)
        assert agreement.document_id

    @pytest.mark.asyncio
    async def test_sign_agreement(self, loaded_agent):
        """async sign_agreement() should add signature."""
        agreement = await async_simple.create_agreement(
            document={"proposal": "Sign async"},
            agent_ids=[loaded_agent.agent_id],
        )

        signed = await async_simple.sign_agreement(agreement)

        assert isinstance(signed, SignedDocument)
        assert signed.document_id

    @pytest.mark.asyncio
    async def test_check_agreement(self, loaded_agent):
        """async check_agreement() should return AgreementStatus."""
        agreement = await async_simple.create_agreement(
            document={"proposal": "Check async"},
            agent_ids=[loaded_agent.agent_id],
        )
        signed = await async_simple.sign_agreement(agreement)

        status = await async_simple.check_agreement(signed)

        assert isinstance(status, AgreementStatus)
        assert status.complete is True


# Test sync utility functions


class TestSyncUtilities:
    @pytest.mark.asyncio
    async def test_is_loaded(self, loaded_agent):
        """is_loaded() should work synchronously."""
        assert async_simple.is_loaded() is True

    @pytest.mark.asyncio
    async def test_get_agent_info(self, loaded_agent):
        """get_agent_info() should work synchronously."""
        info = async_simple.get_agent_info()
        assert isinstance(info, AgentInfo)
        assert info.agent_id


# Test async utility functions


class TestAsyncUtilities:
    @pytest.mark.asyncio
    async def test_get_public_key(self, loaded_agent):
        """async get_public_key() should return PEM formatted key."""
        pem = await async_simple.get_public_key()

        assert pem.startswith("-----BEGIN")
        assert "KEY" in pem

    @pytest.mark.asyncio
    async def test_export_agent(self, loaded_agent):
        """async export_agent() should return valid JSON."""
        agent_json = await async_simple.export_agent()

        data = json.loads(agent_json)
        assert "jacsId" in data


# Integration test


class TestAsyncIntegration:
    @pytest.mark.asyncio
    async def test_full_async_workflow(self, config_path):
        """Test complete async sign-verify workflow."""
        # Load
        info = await async_simple.load(config_path)
        assert info is not None

        # Verify self
        self_check = await async_simple.verify_self()
        assert self_check.valid

        # Sign
        data = {
            "transaction_id": "async-tx-001",
            "amount": 100.50,
            "currency": "USD",
            "approved": True
        }
        signed = await async_simple.sign_message(data)
        assert signed.document_id

        # Verify
        result = await async_simple.verify(signed.raw)
        assert result.valid
        assert result.signer_id == info.agent_id

    @pytest.mark.asyncio
    async def test_concurrent_operations(self, loaded_agent):
        """Test multiple async operations running concurrently."""
        import asyncio

        # Create multiple signing tasks
        tasks = [
            async_simple.sign_message({"task": i})
            for i in range(5)
        ]

        # Run them concurrently
        results = await asyncio.gather(*tasks)

        # Verify all succeeded
        assert len(results) == 5
        for i, signed in enumerate(results):
            assert isinstance(signed, SignedDocument)
            assert signed.document_id

            # Verify each one
            result = await async_simple.verify(signed.raw)
            assert result.valid
