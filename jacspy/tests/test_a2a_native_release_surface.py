"""The Python release build must include native A2A trust-boundary methods."""

import jacs


def test_native_a2a_methods_are_present_in_default_release_build():
    assert hasattr(jacs.JacsAgent, "generate_well_known_documents")
    assert hasattr(jacs.JacsAgent, "assess_a2a_agent")
