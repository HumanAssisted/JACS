"""
Pytest configuration for jacspy tests.

Uses jacs/tests/scratch/ as the single source of truth for test fixtures.
This avoids duplication and ensures all packages use the same test data.
"""

import os
import pathlib
import shutil
import pytest

# Default algorithm for tests. Override via JACS_TEST_ALGORITHM env var.
# Ed25519 is ~100x faster than pq2025/RSA-PSS for key generation and signing.
TEST_ALGORITHM = os.environ.get("JACS_TEST_ALGORITHM", "ed25519")

# The internal Rust name for the test algorithm (used by simple.create / quickstart).
TEST_ALGORITHM_INTERNAL = {
    "ed25519": "ring-Ed25519",
    "rsa-pss": "RSA-PSS",
    "pq2025": "pq2025",
}.get(TEST_ALGORITHM, TEST_ALGORITHM)

_JACS_PATH_ENV_VARS = (
    "JACS_DATA_DIRECTORY",
    "JACS_KEY_DIRECTORY",
    "JACS_DEFAULT_STORAGE",
    "JACS_KEY_RESOLUTION",
    "JACS_AGENT_PRIVATE_KEY_FILENAME",
    "JACS_AGENT_PUBLIC_KEY_FILENAME",
    "JACS_AGENT_ID_AND_VERSION",
    "JACS_AGENT_KEY_ALGORITHM",
    "JACS_TRUST_STORE_DIR",
)


def get_shared_fixtures_path():
    """Get path to shared test fixtures in jacs/tests/scratch/."""
    # Navigate from jacspy/tests/ to jacs/tests/scratch/
    current_dir = pathlib.Path(__file__).parent.absolute()
    # jacspy/tests -> jacspy -> JACS -> jacs -> tests -> scratch
    return current_dir.parent.parent / "jacs" / "tests" / "scratch"


def _ensure_loadable_agent_fixture(fixtures_dir: pathlib.Path) -> None:
    """Ensure fixtures contain a loadable agent for Python tests.

    The shared repository fixture can be mutated by other language test suites.
    For jacspy, we require a valid, loadable agent fixture every run.
    """
    config_path = fixtures_dir / "jacs.config.json"
    password = os.environ.get("JACS_PRIVATE_KEY_PASSWORD", "TestP@ss123!#")
    original_cwd = os.getcwd()

    try:
        os.chdir(fixtures_dir)
        from jacs import simple
        import importlib

        # Try existing fixture first.
        if config_path.exists():
            try:
                importlib.reload(simple)
                simple.load(str(config_path))
                simple.reset()
                return
            except Exception:
                pass

        # Rebuild a known-good fixture if missing/invalid.
        for rel in ("jacs.config.json", "jacs_data", "jacs_keys"):
            target = fixtures_dir / rel
            if target.is_file():
                target.unlink()
            elif target.is_dir():
                shutil.rmtree(target)

        importlib.reload(simple)
        simple.create(
            name="jacspy-test-agent",
            password=password,
            algorithm=TEST_ALGORITHM_INTERNAL,
            data_directory="jacs_data",
            key_directory="jacs_keys",
            config_path="jacs.config.json",
        )
        simple.reset()
    finally:
        os.chdir(original_cwd)


@pytest.fixture(scope="session")
def shared_fixtures_path(tmp_path_factory, ensure_private_key_password):
    """Isolated copy of shared fixtures for this pytest session.

    This avoids cross-suite mutation from other languages/tests and keeps
    jacspy runs deterministic in CI.
    """
    source = get_shared_fixtures_path()
    if not source.exists():
        pytest.skip(f"Shared fixtures not found at {source}")

    isolated_root = tmp_path_factory.mktemp("jacspy-shared-fixtures")
    path = isolated_root / "scratch"
    shutil.copytree(source, path, dirs_exist_ok=True)
    _ensure_loadable_agent_fixture(path)
    return path


@pytest.fixture(scope="session")
def shared_config_path(shared_fixtures_path):
    """Path to shared jacs.config.json."""
    config = shared_fixtures_path / "jacs.config.json"
    if not config.exists():
        pytest.skip(f"Config not found at {config}")
    return str(config)


@pytest.fixture(scope="session", autouse=True)
def ensure_private_key_password():
    """Ensure a default private key password is available for shared scratch fixtures.

    If JACS_PRIVATE_KEY_PASSWORD is already set, keep it unchanged.
    Otherwise set the password used by the CLI scratch fixture flow.
    """
    password_env = "JACS_PRIVATE_KEY_PASSWORD"
    if os.environ.get(password_env):
        yield
        return

    os.environ[password_env] = "TestP@ss123!#"
    try:
        yield
    finally:
        os.environ.pop(password_env, None)


@pytest.fixture(scope="session", autouse=True)
def ensure_iat_skew_window():
    """Avoid flaky age-based signature checks in long-running test sessions."""
    skew_env = "JACS_MAX_IAT_SKEW_SECONDS"
    if os.environ.get(skew_env):
        yield
        return

    # Keep a bounded check, but wide enough for full suite duration.
    os.environ[skew_env] = "7200"
    try:
        yield
    finally:
        os.environ.pop(skew_env, None)


@pytest.fixture(autouse=True)
def isolate_jacs_path_env(monkeypatch, tmp_path):
    """Prevent leaked path/config env vars from changing fixture resolution."""
    for key in _JACS_PATH_ENV_VARS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("JACS_TRUST_STORE_DIR", str(tmp_path / "jacs_trust_store"))
    if not os.environ.get("JACS_MAX_IAT_SKEW_SECONDS"):
        monkeypatch.setenv("JACS_MAX_IAT_SKEW_SECONDS", "7200")
    yield


@pytest.fixture
def in_fixtures_dir(shared_fixtures_path):
    """Context manager fixture that changes to fixtures directory and restores CWD on cleanup.

    This ensures the working directory is always restored, even if a test fails.
    Use this fixture for tests that need relative path resolution from the fixtures dir.
    """
    original_cwd = os.getcwd()
    os.chdir(shared_fixtures_path)
    yield shared_fixtures_path
    os.chdir(original_cwd)
