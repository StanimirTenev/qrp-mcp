"""S3 of the 0.50.0 review (PREGLED.md, 18.11, fixture v2-b): setup.py invented a dependency.
`setup(install_requires=["requests"], description="cryptography")` gave a `dependencies` row
`cryptography`: every string literal after `install_requires=[` on that line was read, the bracket
closing on the same line notwithstanding. Only the values of `install_requires` and
`extras_require` count (setuptools, "Dependencies Management"); the list ends at its bracket.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from qrp_mcp.assets import _setuptools_requests
from qrp_mcp.scan import scan_directory


def _names(text: str) -> list[tuple[str, int]]:
    return [(p, n) for p, n, _ in _setuptools_requests("setup.py", text.splitlines())]


def test_the_review_reproduction_gives_no_row(tmp_path):
    (tmp_path / "setup.py").write_text(
        'from setuptools import setup\nsetup(install_requires=["requests"], description="cryptography")\n')
    rows = scan_directory(tmp_path)["evidence"]["dependencies"]
    assert [r["package"] for r in rows] == []
    assert _names((tmp_path / "setup.py").read_text()) == [("requests", 2)]


@pytest.mark.parametrize("text, expected", [
    ('setup(install_requires=["requests"], description="cryptography")', [("requests", 1)]),
    ('setup(install_requires=["a"], name="paramiko", extras_require={"ssh": ["paramiko"]})',
     [("a", 1), ("paramiko", 1)]),
    ('setup(extras_require={"x": ["b", "c"]}, long_description="pyopenssl", install_requires=["d"])',
     [("b", 1), ("c", 1), ("d", 1)]),
    ('setup(\n    install_requires=[\n        "e",\n    ], version="cryptography",\n)',
     [("e", 3)]),
    ('setup(tests_require=["cryptography"], install_requires=["f"])', [("f", 1)]),
    ('setup(install_requires=["g[extra]>=1", "h"]); x = "cryptography"', [("g", 1), ("h", 1)]),
])
def test_only_the_argument_values_count(text, expected):
    assert _names(text) == expected


def test_a_multi_line_list_is_read_as_before(tmp_path):
    text = ('from setuptools import setup\nsetup(\n    name="x",\n    install_requires=[\n'
            '        "cryptography>=42",\n        "paramiko",\n    ],\n'
            '    extras_require={\n        "ssh": ["pynacl"],\n    },\n)\n')
    assert _names(text) == [("cryptography", 5), ("paramiko", 6), ("pynacl", 9)]
