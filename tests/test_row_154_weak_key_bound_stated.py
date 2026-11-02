"""ZA-OPRAVYANE row 154 (LinkedIn, Jaime Gomez Garcia, 27.10.2026; decided by Stanimir on
2 Nov 2026): a P-384 key with private scalar 4 is found from its public key, one with scalar
300 gives nothing and `weak_count 0`, because the check compares with k*G for k <= 256 only.
The bound stays; the output says it where the check ran, found or not, in the scan file, the
scan_repo tool and the CBOM. No new setting."""

import json
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from qrp_mcp.server import scan_repo


def _tree(tmp_path, scalar):
    tree = tmp_path / "t"
    tree.mkdir()
    key = ec.derive_private_key(scalar, ec.SECP384R1())
    (tree / "ca.pem").write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return tree


def _cli(tmp_path, tree, command):
    out = tmp_path / f"{command}.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", command, str(tree),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return json.loads(out.read_text())


@pytest.mark.parametrize("scalar, weak", [(4, 1), (300, 0)])
def test_the_bound_is_stated_found_or_not(tmp_path, scalar, weak):
    tree = _tree(tmp_path, scalar)
    result = _cli(tmp_path, tree, "scan")
    assert len(result["evidence"]["weak_keys"]) == weak
    check = result["weak_key_check"]
    assert check["bound"] == 256 and check["ec_public_keys_checked"] == 1
    assert "checked up to 256" in check["statement"]
    assert scan_repo(str(tree))["weak_key_check"] == check
    props = {p["name"]: p["value"] for p in _cli(tmp_path, tree, "cbom")["properties"]}
    assert props["qrp:weak_key_check:bound"] == "256"
    assert props["qrp:weak_key_check:ec_public_keys_checked"] == "1"


def test_nothing_is_said_where_no_ec_key_was_read(tmp_path):
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / "a.py").write_text("print(1)\n")
    assert scan_repo(str(tree))["weak_key_check"] is None
