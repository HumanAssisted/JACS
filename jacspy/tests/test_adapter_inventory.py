"""
Adapter inventory parity test for the Python binding.

Validates that all Python adapters listed in
binding-core/tests/fixtures/adapter_inventory.json are importable
and expose the documented public functions.

This test complements (does not duplicate) the MCP contract drift test
or behavioral adapter tests. It validates API surface existence only.

NOTE: Some adapter tests are skipped when optional dependencies are not
installed (e.g., langchain, crewai). In CI, install with `pip install
jacs[all]` to test all 5 adapters. The test_skip_count_guard test below
warns if too many adapters are skipped.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

FIXTURE_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "binding-core"
    / "tests"
    / "fixtures"
    / "adapter_inventory.json"
)


@pytest.fixture(scope="module")
def adapter_inventory() -> dict:
    """Load the shared adapter inventory fixture file."""
    assert FIXTURE_PATH.exists(), (
        f"Adapter inventory fixture not found at {FIXTURE_PATH}. "
        "Ensure binding-core/tests/fixtures/adapter_inventory.json exists."
    )
    with open(FIXTURE_PATH) as f:
        return json.load(f)


@pytest.fixture(scope="module")
def python_adapters(adapter_inventory: dict) -> dict:
    """Get the Python adapter definitions from the inventory."""
    adapters = adapter_inventory.get("adapters", {}).get("python", {})
    assert adapters, "adapter_inventory.json should have Python adapters"
    return adapters


def test_python_adapter_count(python_adapters: dict):
    """Python should have exactly 5 adapters."""
    assert len(python_adapters) == 5, (
        f"Expected 5 Python adapters, found {len(python_adapters)}. "
        f"Adapters: {list(python_adapters.keys())}"
    )


@pytest.mark.parametrize(
    "adapter_name",
    ["mcp", "langchain", "crewai", "fastapi", "anthropic"],
)
def test_python_adapter_module_importable(
    python_adapters: dict, adapter_name: str
):
    """Each Python adapter module should be importable."""
    adapter = python_adapters[adapter_name]
    module_name = adapter["module"]

    # Some adapters have optional dependencies; we test that the module
    # itself exists (importlib.util.find_spec) rather than forcing import
    # of all framework dependencies.
    spec = importlib.util.find_spec(module_name)
    assert spec is not None, (
        f"Python adapter module '{module_name}' is not importable. "
        f"Ensure the module exists at the expected path."
    )


@pytest.mark.parametrize(
    "adapter_name",
    ["mcp", "langchain", "crewai", "fastapi", "anthropic"],
)
def test_python_adapter_public_functions_exist(
    python_adapters: dict, adapter_name: str
):
    """Each listed public function should exist in the adapter module."""
    adapter = python_adapters[adapter_name]
    module_name = adapter["module"]
    expected_functions = adapter["public_functions"]

    try:
        mod = importlib.import_module(module_name)
    except ImportError as e:
        # Framework dependency not installed (e.g., langchain, crewai).
        # Skip rather than fail -- the module importability test above
        # already verifies the module file exists.
        pytest.skip(
            f"Cannot import {module_name} (missing dependency: {e}). "
            f"Install optional deps to fully test."
        )
        return

    missing = []
    for func_name in expected_functions:
        if not hasattr(mod, func_name):
            missing.append(func_name)

    assert not missing, (
        f"Adapter '{adapter_name}' ({module_name}) is missing public functions: {missing}. "
        f"Expected: {expected_functions}"
    )


def test_skip_count_guard(python_adapters: dict):
    """Warn if too many adapters are skipped due to missing dependencies.

    If more than 1 adapter cannot be imported, it likely means optional
    dependencies are not installed. In CI, ensure `pip install jacs[all]`
    is used to fully test all adapters.
    """
    skipped = []
    for adapter_name, adapter in python_adapters.items():
        module_name = adapter["module"]
        try:
            importlib.import_module(module_name)
        except ImportError:
            skipped.append(adapter_name)

    # Allow at most 1 skip (some environments may not have one framework)
    if len(skipped) > 1:
        import warnings

        warnings.warn(
            f"{len(skipped)} of {len(python_adapters)} Python adapters could not "
            f"be imported: {skipped}. Install optional dependencies with "
            f"`pip install jacs[all]` to fully test all adapters.",
            stacklevel=1,
        )
