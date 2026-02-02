"""Tests for the register_new_agent convenience function.

These tests verify the function signature and docstring without
actually calling HAI.ai.
"""

import inspect


def test_register_new_agent_is_importable():
    """Verify the function can be imported from jacs.hai."""
    from jacs.hai import register_new_agent

    assert callable(register_new_agent)
    assert register_new_agent.__name__ == "register_new_agent"


def test_register_new_agent_in_all():
    """Verify the function is exported in __all__."""
    from jacs import hai

    assert "register_new_agent" in hai.__all__


def test_register_new_agent_signature():
    """Verify the function has the expected parameters."""
    from jacs.hai import register_new_agent

    sig = inspect.signature(register_new_agent)
    params = list(sig.parameters.keys())

    # Check required parameters
    assert "name" in params

    # Check optional parameters with defaults
    assert "hai_url" in params
    assert "api_key" in params
    assert "key_algorithm" in params
    assert "output_dir" in params

    # Check default values
    assert sig.parameters["hai_url"].default == "https://hai.ai"
    assert sig.parameters["api_key"].default is None
    assert sig.parameters["key_algorithm"].default == "ed25519"
    assert sig.parameters["output_dir"].default == "."


def test_register_new_agent_return_annotation():
    """Verify the function has proper return type annotation."""
    from jacs.hai import register_new_agent, HaiRegistrationResult

    sig = inspect.signature(register_new_agent)
    assert sig.return_annotation == HaiRegistrationResult


def test_register_new_agent_docstring():
    """Verify the docstring is present and well-formed."""
    from jacs.hai import register_new_agent

    docstring = register_new_agent.__doc__
    assert docstring is not None
    assert len(docstring) > 100  # Should be a substantial docstring

    # Check key sections are present
    assert "Args:" in docstring
    assert "Returns:" in docstring
    assert "Raises:" in docstring
    assert "Example:" in docstring

    # Check key information is documented
    assert "name:" in docstring.lower() or "name" in docstring
    assert "HAI.ai" in docstring
    assert "HaiRegistrationResult" in docstring


def test_docstring_renders_properly():
    """Verify the docstring can be parsed by help()."""
    from jacs.hai import register_new_agent
    import io
    import contextlib

    # Capture help() output
    f = io.StringIO()
    with contextlib.redirect_stdout(f):
        help(register_new_agent)

    help_output = f.getvalue()

    # Verify it includes function name and key content
    assert "register_new_agent" in help_output
    assert "Create a new JACS agent" in help_output


if __name__ == "__main__":
    # Run tests when executed directly
    test_register_new_agent_is_importable()
    print("PASS: test_register_new_agent_is_importable")

    test_register_new_agent_in_all()
    print("PASS: test_register_new_agent_in_all")

    test_register_new_agent_signature()
    print("PASS: test_register_new_agent_signature")

    test_register_new_agent_return_annotation()
    print("PASS: test_register_new_agent_return_annotation")

    test_register_new_agent_docstring()
    print("PASS: test_register_new_agent_docstring")

    test_docstring_renders_properly()
    print("PASS: test_docstring_renders_properly")

    print("\nAll tests passed!")
