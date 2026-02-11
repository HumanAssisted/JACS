"""
Pytest configuration for jacspy tests.

Uses jacs/tests/scratch/ as the single source of truth for test fixtures.
This avoids duplication and ensures all packages use the same test data.
"""

import os
import pathlib
import pytest

_JACS_PATH_ENV_VARS = (
    "JACS_DATA_DIRECTORY",
    "JACS_KEY_DIRECTORY",
    "JACS_DEFAULT_STORAGE",
    "JACS_KEY_RESOLUTION",
    "JACS_AGENT_PRIVATE_KEY_FILENAME",
    "JACS_AGENT_PUBLIC_KEY_FILENAME",
    "JACS_AGENT_ID_AND_VERSION",
    "JACS_AGENT_KEY_ALGORITHM",
)


def get_shared_fixtures_path():
    """Get path to shared test fixtures in jacs/tests/scratch/."""
    # Navigate from jacspy/tests/ to jacs/tests/scratch/
    current_dir = pathlib.Path(__file__).parent.absolute()
    # jacspy/tests -> jacspy -> JACS -> jacs -> tests -> scratch
    return current_dir.parent.parent / "jacs" / "tests" / "scratch"


@pytest.fixture(scope="session")
def shared_fixtures_path():
    """Path to shared test fixtures."""
    path = get_shared_fixtures_path()
    if not path.exists():
        pytest.skip(f"Shared fixtures not found at {path}")
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


@pytest.fixture(autouse=True)
def isolate_jacs_path_env(monkeypatch):
    """Prevent leaked path/config env vars from changing fixture resolution."""
    for key in _JACS_PATH_ENV_VARS:
        monkeypatch.delenv(key, raising=False)
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
