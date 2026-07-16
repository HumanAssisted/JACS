#!/usr/bin/env python3
"""Shared fail-closed HTTP opener for authoritative registry metadata probes."""

from __future__ import annotations

import urllib.request
from typing import Any


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Return the original 3xx response without contacting its target."""

    def redirect_request(
        self,
        request: Any,
        fp: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        del request, fp, code, message, headers, new_url
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(NoRedirectHandler())


def open_no_redirect(request: urllib.request.Request, *, timeout: int):
    """Open one URL with a deadline and never follow an HTTP redirect."""

    return _NO_REDIRECT_OPENER.open(request, timeout=timeout)
