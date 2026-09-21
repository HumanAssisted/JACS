#!/usr/bin/env python3
"""Build the current MCP-first guide and label the preserved native reference."""

import argparse
import html
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "target/jacsbook"
NATIVE = ROOT / "archive/native/jacs/docs/jacsbook"
NOTICE = (
    "> **Supported library reference.** Rust, Node.js, Python and Go "
    "remain supported in a separate workspace. This chapter can contain historical "
    "version or installation text; use the [current package guide]"
    "(https://humanassisted.github.io/JACS/packages.html). "
    "Extended CLI examples use `jacs-compat` in 0.15. See the "
    "[current MCP guide](https://humanassisted.github.io/JACS/native-mcp.html) "
    "for actual runtime profiles and the "
    "[release inventory](https://github.com/HumanAssisted/JACS/blob/main/docs/release-status.md) "
    "for published versions.\n\n"
)


def preserve_reference_urls():
    """Keep existing deep links while the current guide owns the landing page."""
    count = 0
    for chapter in (OUTPUT / "native").rglob("*.html"):
        previous = OUTPUT / chapter.relative_to(OUTPUT / "native")
        if previous.exists():
            # Current guide pages, including index/print/404, take precedence.
            continue
        target = quote(Path(os.path.relpath(chapter, previous.parent)).as_posix(), safe="/.")
        link = html.escape(target, quote=True)
        previous.parent.mkdir(parents=True, exist_ok=True)
        previous.write_text(
            '<!doctype html><html lang="en"><meta charset="utf-8">'
            '<title>JACS library documentation</title>'
            f'<link rel="canonical" href="{link}">'
            f'<meta http-equiv="refresh" content="0; url={link}">'
            '<script>location.replace(' + json.dumps(target) +
            '+location.search+location.hash);</script>'
            f'<p><a href="{link}">Continue to the JACS library documentation</a>.</p>'
            '</html>\n'
        )
        count += 1
    print(f"Preserved {count} existing reference URLs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-only", action="store_true")
    args = parser.parse_args()
    if not shutil.which("mdbook"):
        raise SystemExit("mdbook is required; CI uses mdbook 0.4.52")
    if not args.native_only:
        subprocess.run(["mdbook", "build", str(ROOT / "docs/book"), "--dest-dir", str(OUTPUT)], check=True)
    # Add context to every rendered historical chapter without rewriting or
    # moving the preserved compatibility source, licenses, or commands.
    with tempfile.TemporaryDirectory(prefix="jacs-native-book-") as temporary:
        staged = Path(temporary) / "book"
        shutil.copytree(NATIVE, staged, ignore=shutil.ignore_patterns("book", "target"))
        for page in (staged / "src").rglob("*.md"):
            original = NATIVE / page.relative_to(staged)

            def resolve_include(match):
                filename, separator, selection = match[1].partition(":")
                source = (original.parent / filename).resolve()
                if not source.is_relative_to(ROOT) or not source.is_file():
                    raise ValueError(f"Documentation include must be a repository file: {filename}")
                if source.is_relative_to(NATIVE):
                    return match[0]
                # The email example lives outside the book. Retain its actual
                # reviewed source after staging the book in a temporary folder.
                return "{{#include " + str(source) + (separator + selection if separator else "") + "}}"

            content = re.sub(r"\{\{#include\s+([^}\s]+)\s*\}\}", resolve_include, page.read_text())
            if page.name != "SUMMARY.md" and "_snippets" not in page.parts:
                content = NOTICE + content
            page.write_text(content)
        subprocess.run(["mdbook", "build", str(staged), "--dest-dir", str(OUTPUT / "native")], check=True)
    preserve_reference_urls()
    print(f"Built documentation at {OUTPUT}")


if __name__ == "__main__":
    main()
