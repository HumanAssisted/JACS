#!/usr/bin/env python3
"""Permit the one-time WASM npm bootstrap only while its package is absent."""

from __future__ import annotations

import sys
import urllib.error
import urllib.request

try:
    from http_policy import open_no_redirect
except ModuleNotFoundError:
    from scripts.http_policy import open_no_redirect


PACKAGE_URL = "https://registry.npmjs.org/@hai.ai%2Fjacs-wasm"


def require_absent(*, open_url=open_no_redirect):
    request = urllib.request.Request(
        PACKAGE_URL,
        headers={"Accept": "application/json", "User-Agent": "jacs-release-bootstrap/1"},
    )
    try:
        with open_url(request, timeout=20):
            pass
    except urllib.error.HTTPError as error:
        error.close()
        if error.code == 404:
            return
        raise RuntimeError(f"npm bootstrap registry check failed: HTTP {error.code}") from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise RuntimeError("npm bootstrap registry check failed") from error
    raise RuntimeError("WASM npm package already exists; disable bootstrap and configure its trusted publisher")


if __name__ == "__main__":
    try:
        require_absent()
    except RuntimeError as error:
        sys.exit(str(error))
