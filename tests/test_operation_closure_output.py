"""`operation_closure`: the (operation, ecosystem) pairs whose documented spellings this version
tests one by one (data/operations, tests/test_operation_closure.py). It says what the version
was tested against, never what the scanned code holds, so it must not move the findings, their
fingerprint, a mandate's gate or the exit code: the same tree scanned with the catalogue and
with it emptied gives the same of all four.
"""

from __future__ import annotations

import json

import pytest

from qrp_mcp import operations
from qrp_mcp.scan import findings_fingerprint, scan_directory
from qrp_mcp.server import main, scan_repo

TREE = {
    "sign.py": 'import os\nfrom cryptography.hazmat.primitives.asymmetric import rsa\n'
               'k = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n'
               'alg = os.getenv("SIGN_ALG", "RSA-PSS")\n',
    "swanctl.conf": "connections {\n  gw {\n    proposals = aes256-sha256-ecp256bp\n  }\n}\n",
}


def _tree(tmp_path):
    for name, text in TREE.items():
        (tmp_path / name).write_text(text)
    return tmp_path


def _run(tmp_path, tag):
    out = tmp_path / f"{tag}.json"
    with pytest.raises(SystemExit) as code:
        main(["scan", str(tmp_path / "src"), "--out", str(out), "--no-config", "--level", "full",
              "--mandate", "cnsa-2.0", "--lead-months", "120", "--as-of", "2026-11-18"])
    return json.loads(out.read_text()), code.value.code


def test_the_section_lists_each_catalogue_family():
    section = operations.closure_section()
    assert "does not affect the findings" in section["meaning"]
    pairs = {(f["operation"], f["ecosystem"]) for f in section["families"]}
    assert {("ike", "IPsec"), ("apiname", "C"), ("keyfile", "PKI"), ("tlsend", "nginx"),
            ("external", "Py")} <= pairs
    for family in section["families"]:
        assert set(family) == {"operation", "ecosystem", "spellings_count", "catalogue_version"}
        assert family["spellings_count"] > 0


def test_every_exit_carries_it(tmp_path):
    (tmp_path / "src").mkdir()
    src = _tree(tmp_path / "src")
    expected = operations.closure_section()
    assert scan_directory(src)["operation_closure"] == expected
    assert getattr(scan_repo, "fn", scan_repo)(str(src))["operation_closure"] == expected
    result, _code = _run(tmp_path, "cli")
    assert result["operation_closure"] == expected


def test_it_moves_neither_findings_nor_fingerprint_nor_gate_nor_exit_code(tmp_path, monkeypatch):
    (tmp_path / "src").mkdir()
    _tree(tmp_path / "src")
    with_catalogue, code_with = _run(tmp_path, "with")
    monkeypatch.setattr(operations, "_load", lambda: ())
    without, code_without = _run(tmp_path, "without")
    assert without["operation_closure"]["families"] == []
    assert with_catalogue["operation_closure"]["families"]
    for key in ("findings", "findings_fingerprint", "evidence", "summary", "mandates"):
        assert with_catalogue[key] == without[key], key
    # RSA-1024, and CNSA 2.0's deadlines within ten years: the gate fails in both.
    assert code_with == code_without == 1
    # And the fingerprint is computed without it, whatever it holds.
    altered = dict(with_catalogue, operation_closure={"families": [{"operation": "x"}]})
    assert findings_fingerprint(altered) == findings_fingerprint(with_catalogue)
