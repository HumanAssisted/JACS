#!/usr/bin/env python3
"""Check an installed wheel's public verifier; missing support is a failure."""

import copy
import json
import sys
from pathlib import Path

from jacs import SimpleAgent


def main():
    fixture = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))

    def verify(value):
        return SimpleAgent.verify_human_approved_document(
            *(json.dumps(value[name]) for name in ("bundle", "expected", "authority", "provenance"))
        )

    assert verify(fixture) == fixture["report"], "incomplete or incorrect public proof report"
    assert fixture["report"]["current"] == "not_evaluated"
    assert fixture["report"]["approval"]["current"] == "not_evaluated"
    wrong = copy.deepcopy(fixture)
    wrong["expected"]["humanId"] += "-other"
    try:
        verify(wrong)
    except RuntimeError as error:
        assert "VerificationFailed:" in str(error), str(error)
    else:
        raise AssertionError("wrong independently selected human was accepted")
    print("PUBLIC-HUMAN-PROOF-OK (archival evidence; current status not evaluated)")


if __name__ == "__main__":
    main()
