"""ZA-OPRAVYANE row 533, N7 (fifth review of 0.50.0, 18.11): a subscript on the next line inside
brackets was not seen. Python joins the lines inside brackets, so `["requests", "paramiko"]` and
`[:1]` on the line below are one expression; the lexer reset what it had read at the newline even
there, read the list as the literal and gave a paramiko row. Outside brackets a newline still ends
the statement.
"""

from __future__ import annotations

import pytest

from qrp_mcp.assets import _setuptools_requests
from qrp_mcp.scan import scan_directory


def _names(text: str) -> list[str]:
    return [p for p, _, _ in _setuptools_requests("setup.py", text.splitlines())]


@pytest.mark.parametrize("text", [
    'setup(install_requires=["requests", "paramiko"]\n[:1])',
    'setup(\n    install_requires=["requests", "paramiko"]\n    [:1],\n)',
    'setup(install_requires=(["paramiko"]\n)[0])',
    'setup(extras_require={"a": ["paramiko"]}\n["a"])',
])
def test_a_subscript_on_the_next_line_inside_brackets_is_a_subscript(text):
    assert "paramiko" not in _names(text)


def test_through_the_scan(tmp_path):
    (tmp_path / "setup.py").write_text('from setuptools import setup\nsetup(name="x",\n'
                                       '      install_requires=["requests", "paramiko"]\n'
                                       '      [:1])\n')
    assert [r["package"] for r in scan_directory(tmp_path)["evidence"]["dependencies"]] == []


@pytest.mark.parametrize("text, expected", [
    # Outside brackets the newline ends the statement: the list is the value.
    ('install_requires = ["paramiko"]\n[1, 2]\nsetup()', ["paramiko"]),
    # Lines inside brackets that are not subscripts read as before.
    ('setup(\n    install_requires=[\n        "paramiko",\n        "ecdsa"\n    ],\n    extras_require={"a": ["pyopenssl"]},\n)',
     ["paramiko", "ecdsa", "pyopenssl"]),
    ('setup(install_requires=["a"]\n    + ["paramiko"])', ["a", "paramiko"]),
    ('setup(install_requires=[\n    "paramiko"\n    "-ng"\n])', ["paramiko-ng"]),
])
def test_what_is_not_a_subscript_is_unchanged(text, expected):
    assert _names(text) == expected
