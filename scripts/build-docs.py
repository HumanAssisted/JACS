#!/usr/bin/env python3
"""Build the current MCP-first guide and label the preserved native reference."""

import argparse
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "target/jacsbook"
NATIVE = ROOT / "archive/native/jacs/docs/jacsbook"
NOTICE = (
    "> **Native compatibility reference.** This chapter preserves the native APIs. "
    "Native CLI examples use the separate `jacs-compat` executable in 0.15; "
    "the portable `jacs` CLI has a focused surface. See the "
    "[current MCP guide](https://humanassisted.github.io/JACS/native-mcp.html) "
    "for actual runtime profiles and the "
    "[release inventory](https://github.com/HumanAssisted/JACS/blob/main/docs/release-status.md) "
    "for published versions.\n\n"
)


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
    print(f"Built documentation at {OUTPUT}")


if __name__ == "__main__":
    main()
