"""Small dependency-free parsers shared by workflow policy tests."""


def checkout_step_blocks(text: str) -> list[str]:
    """Return complete ``actions/checkout`` step blocks from a workflow."""

    lines = text.splitlines()
    blocks: list[str] = []
    for index, line in enumerate(lines):
        if "uses: actions/checkout@" not in line:
            continue
        step_indent = len(line) - len(line.lstrip())
        if not line.lstrip().startswith("- uses:"):
            # Named steps put ``uses`` one indentation level below the dash.
            step_indent -= 2
        start = index
        while start > 0:
            candidate = lines[start]
            if (
                len(candidate) - len(candidate.lstrip()) == step_indent
                and candidate.lstrip().startswith("- ")
            ):
                break
            start -= 1
        end = index + 1
        while end < len(lines):
            candidate = lines[end]
            if (
                candidate.strip()
                and len(candidate) - len(candidate.lstrip()) == step_indent
                and candidate.lstrip().startswith("- ")
            ):
                break
            end += 1
        blocks.append("\n".join(lines[start:end]))
    return blocks
