"""Check that every paragraph of an old README is in one of the new files.

Usage: python scripts/check_readme_moved.py OLD_README NEW_FILE [NEW_FILE ...]

A paragraph is a run of lines between blank lines; a fenced code block is one paragraph however
many blank lines it holds. Whitespace is normalised on both sides. A paragraph counts as moved
when its normalised text is a substring of the normalised concatenation of the new files.
Exit 1 when any paragraph is missing, and each missing one is printed.
"""

from __future__ import annotations

import pathlib
import sys


def paragraphs(text: str) -> list[str]:
    out: list[str] = []
    current: list[str] = []
    fenced = False
    for line in text.split("\n"):
        if line.lstrip().startswith("```"):
            fenced = not fenced
        if not line.strip() and not fenced:
            if current:
                out.append("\n".join(current))
                current = []
            continue
        current.append(line)
    if current:
        out.append("\n".join(current))
    return out


def norm(text: str) -> str:
    return " ".join(text.split())


def main(argv: list[str]) -> int:
    old = pathlib.Path(argv[1]).read_text(encoding="utf-8")
    new = norm("\n\n".join(pathlib.Path(p).read_text(encoding="utf-8") for p in argv[2:]))
    found = paragraphs(old)
    missing = [p for p in found if norm(p) not in new]
    for p in missing:
        print("MISSING:", p[:200].replace("\n", " "))
    print(f"{len(found) - len(missing)} of {len(found)} paragraphs found in the new files")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
