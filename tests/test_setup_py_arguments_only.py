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


# Second review of 0.50.0 (18.11): the S3 fix ended the list at its first closing bracket, so a
# concatenated list (`["paramiko"] + ["ecdsa"]`, which 829add5 read whole) lost its second half,
# and the line scanner cut a line at the first `#`, inside a string, so the strings of the next
# lines (`description=`, `long_description=`) were read as dependencies. setup.py is now parsed
# as Python: literal lists and `+` of them, dict values of extras_require, the leading literal
# name of an f-string; anything else is skipped, never guessed.
@pytest.mark.parametrize("text, expected", [
    ('setup(name="x", install_requires=["paramiko"] + ["ecdsa"], description="pycryptodome")',
     [("paramiko", 1), ("ecdsa", 1)]),
    ('setup(\n    install_requires=(\n        ["a"]\n        + ["b"]\n    ),\n    description="c",\n)',
     [("a", 3), ("b", 4)]),
    ('setup(\n    install_requires=["foo @ git+https://h.example/x.git#egg=foo"],\n'
     '    description="paramiko",\n    long_description="ecdsa",\n)', [("foo", 2)]),
    ('setup(install_requires=["a"]  # "zzcomment"\n, description="b")', [("a", 1)]),
    ('install_requires = ["cryptography"]\nsetup(install_requires=install_requires)',
     [("cryptography", 1)]),
    ('deps = ["zzvardep"]\nsetup(install_requires=deps + ["requests"], description="x")',
     [("requests", 2)]),
    ('setup(extras_require={"ssh": "paramiko", "x": ["a"] + ["b"]})',
     [("paramiko", 1), ("a", 1), ("b", 1)]),
    ('setup(install_requires=[f"cryptography>={v}", f"x{v}", f"{p}>=1", "pkg[extra]>=1"])',
     [("cryptography", 1), ("pkg", 1)]),
    ('setup(install_requires=("a", "b"))', []),
    ('﻿setup(install_requires=["a"])', [("a", 1)]),
])
def test_setup_py_is_read_as_python(text, expected):
    assert _names(text) == expected


def test_an_f_string_keeps_its_request_as_written():
    assert _setuptools_requests("setup.py", ['setup(install_requires=[f"acme>={version}"])']) == [
        ("acme", 1, ">={version}")]


def test_the_second_review_reproductions_give_no_invented_row(tmp_path):
    (tmp_path / "setup.py").write_text(
        'from setuptools import setup\nsetup(\n'
        '    install_requires=["foo @ git+https://h.example/x.git#egg=foo"],\n'
        '    description="paramiko",\n    long_description="ecdsa",\n)\n')
    assert [r["package"] for r in scan_directory(tmp_path)["evidence"]["dependencies"]] == []
    (tmp_path / "setup.py").write_text(
        'from setuptools import setup\n'
        'setup(name="x", install_requires=["paramiko"] + ["ecdsa"], description="pycryptodome")\n')
    rows = scan_directory(tmp_path)["evidence"]["dependencies"]
    assert sorted(r["package"] for r in rows) == ["ecdsa", "paramiko"]


@pytest.mark.parametrize("text, expected", [
    ('print "python 2"\nsetup(install_requires=["cryptography"])', []),
    ('setup(install_requires=["cryptography"]\x00)', []),
    ("x = " + "(" * 5000 + "1" + ")" * 5000, []),
    ('setup(install_requires=["\\d", "a"])', [("a", 1)]),
])
def test_a_setup_py_python_cannot_parse_gives_no_row_and_no_error(tmp_path, text, expected):
    # A Python 2 setup.py is not read (said in CHANGELOG 0.50.0); nothing in it ends the scan.
    assert _names(text) == expected
    (tmp_path / "setup.py").write_text(text)
    scan_directory(tmp_path)


def test_a_very_long_concatenation_ends_nothing(tmp_path):
    text = "setup(install_requires=" + " + ".join(['["a"]'] * 100000) + ")"
    assert _names(text) in ([], [("a", 1)] * 100000)
    (tmp_path / "setup.py").write_text(text)
    scan_directory(tmp_path)
