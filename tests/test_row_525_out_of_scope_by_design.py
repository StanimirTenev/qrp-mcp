"""ZA-OPRAVYANE row 525 (Tooba Qasim, 17.11; probe linkedin-postove/2026-11-17/tooba-proba, 0.48.0):
SecureRandom/DRBG, os.urandom, secrets, `random` for a token and a remote entropy API gave nothing
in the output, which is the scope (docs/measurement.md), but README's "What it is not" did not say
so, nor did the output: a file with only these read as "read, nothing found".

Decided 17.11 (Stanimir): randomness and KDFs stay out of scope; it is said in README and in
`coverage.claims`, which reaches the scan JSON, the MCP tools and the CBOM's coverage properties.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from qrp_mcp import cyclonedx
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import main

ROOT = Path(__file__).resolve().parent.parent

RNG = """import os, random, secrets, hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
token = ''.join(random.choice('abcdef0123456789') for _ in range(32))
nonce = secrets.token_bytes(16)
seed = os.urandom(32)
kdf = PBKDF2HMAC(algorithm=None, length=32, salt=seed, iterations=600000)
"""


def _claims(result):
    return result["coverage"]["claims"]["out_of_scope_by_design"]


def test_the_scan_says_randomness_and_kdfs_are_not_read(tmp_path):
    (tmp_path / "rng.py").write_text(RNG)
    result = scan_directory(str(tmp_path))
    assert result["findings"] == []
    said = _claims(result)
    text = json.dumps(said).lower()
    for word in ("random number generation", "key derivation", "symmetric", "hash"):
        assert word in text, word
    assert "not read" in said["meaning"]


def test_it_reaches_the_cbom(tmp_path):
    (tmp_path / "rng.py").write_text(RNG)
    bom = cyclonedx.build(scan_directory(str(tmp_path)))
    names = {p["name"] for p in bom["properties"]}
    assert any(n.startswith("qrp:coverage:claims:out_of_scope_by_design") for n in names), names


def test_it_reaches_the_command_line_output(tmp_path):
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / "rng.py").write_text(RNG)
    out = tmp_path / "r.json"
    with pytest.raises(SystemExit):
        main(["scan", str(tree), "--no-config", "--out", str(out)])
    assert "random number generation" in json.dumps(_claims(json.loads(out.read_text())))


def test_readme_what_it_is_not_says_it():
    readme = (ROOT / "README.md").read_text()
    section = readme.split("## What it is not", 1)[1].split("\n## ", 1)[0]
    for words in ("random number generation", "key derivation", "symmetric"):
        assert words in section, words


def test_it_reaches_the_mcp_tools(tmp_path):
    from qrp_mcp.server import export_cbom, scan_repo
    (tmp_path / "rng.py").write_text(RNG)
    assert "key derivation" in json.dumps(_claims(scan_repo(str(tmp_path))))
    bom = export_cbom(str(tmp_path))
    bom = bom.get("cbom", bom) if isinstance(bom, dict) else json.loads(bom)
    assert "out_of_scope_by_design" in json.dumps(bom)
