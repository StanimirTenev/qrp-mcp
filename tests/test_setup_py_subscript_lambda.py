"""Fourth review of 0.50.0 (18.11): the lexer read a subscript on a literal as the literal, and a
lambda in a dict value as a string. `install_requires=["requests", "paramiko"][:1]` gave a
paramiko row although only requests is installed; `{"a": lambda: "cryptography"}` gave a
cryptography row. Both compute a value, so both are skipped, as the CHANGELOG says.
"""

from __future__ import annotations

import pytest

from qrp_mcp.assets import _setuptools_requests
from qrp_mcp.scan import scan_directory


def _names(text: str) -> list[str]:
    return [p for p, _, _ in _setuptools_requests("setup.py", text.splitlines())]


@pytest.mark.parametrize("text", [
    'setup(install_requires=["requests", "paramiko"][:1])',
    'setup(install_requires=["cryptography"[0:3], "x"])',
    'setup(install_requires=(["cryptography"])[0])',
    'setup(install_requires={"a": ["cryptography"]}["a"])',
    'setup(extras_require={"a": lambda: "cryptography"})',
])
def test_a_computed_value_gives_no_crypto_row(text):
    assert "cryptography" not in _names(text) and "paramiko" not in _names(text)


def test_the_review_reproduction_through_the_scan(tmp_path):
    (tmp_path / "setup.py").write_text(
        'from setuptools import setup\nsetup(name="x", install_requires=["requests", "paramiko"][:1])\n')
    rows = scan_directory(tmp_path)["evidence"]["dependencies"]
    assert [r["package"] for r in rows] == []


@pytest.mark.parametrize("text, expected", [
    ('setup(install_requires=["paramiko"], extras_require={"a": ["ecdsa"]})', ["paramiko", "ecdsa"]),
    ('setup(install_requires=["a"] + ["paramiko"])', ["a", "paramiko"]),
    ('setup(install_requires=["ecdsa" if X else "paramiko"])', ["ecdsa", "paramiko"]),
    ('setup(extras_require={"a": ["ecdsa"], "b": ["paramiko"]})', ["ecdsa", "paramiko"]),
    # A call beside a literal drops only the call (fifth review: 720f5c4 dropped these too).
    ('setup(install_requires=["cryptography>=41", "paramiko"] + read_requirements("x.txt"))',
     ["cryptography", "paramiko"]),
    ('setup(install_requires=["cryptography"] + get_reqs())', ["cryptography"]),
    ('setup(install_requires=get_reqs() + ["cryptography"])', ["cryptography"]),
    ('setup(install_requires=get_reqs()[0] + ["cryptography"])', ["cryptography"]),
    ('setup(install_requires=["cryptography>=" + str(v), "paramiko"])', ["cryptography", "paramiko"]),
    ('setup(extras_require={"a": ["pyopenssl"] + extra("a"), "b": ["paramiko"]})',
     ["pyopenssl", "paramiko"]),
    ('setup(install_requires=["cryptography"] if x else get())', ["cryptography"]),
    ('setup(install_requires=["a"] + ["paramiko"][:1] + ["ecdsa"])', ["a", "ecdsa"]),
])
def test_literal_values_are_still_read(text, expected):
    assert _names(text) == expected
