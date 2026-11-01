"""ZA-OPRAVYANE row 184 (01.11.2026): the role each RSA and EC line shows (signature, key
establishment, undetermined) was read for every occurrence and stopped at the scan JSON; in
the CBOM, RSA arrived as `primitive: pke` and nothing else, so a reader of only the CBOM had
to count it against both signatures and key establishment.

The CBOM now carries `qrp:role`: one value per occurrence, in the order of
`evidence.occurrences`, like `qrp:confidence`. Roles are read before any level masks a line,
so all three levels carry the same roles."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

ROLES_PY = ("from cryptography.hazmat.primitives.asymmetric import rsa, padding\n"
            "sig = key.sign(data, padding.PSS(mgf=padding.MGF1(h), salt_length=32), h)  # RSA\n"
            "ct = rsa_pub.encrypt(k, padding.OAEP(mgf=padding.MGF1(h), algorithm=h, label=None))\n"
            "key = rsa.generate_private_key(public_exponent=65537, key_size=3072)\n")


def _role_of(path, level):
    out = path.parent / f"cbom-{level}.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "cbom", str(path),
                        "--out", str(out), "--level", level], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    doc = json.loads(out.read_text())
    got = {}
    for c in doc["components"]:
        props = {p["name"]: p["value"] for p in c.get("properties", [])}
        if "qrp:role" in props:
            roles = json.loads(props["qrp:role"])
            assert len(roles) == len(c["evidence"]["occurrences"])
            for o, role in zip(c["evidence"]["occurrences"], roles):
                got[(c["name"], o["line"])] = role
    return got


@pytest.mark.parametrize("level", ["full", "masked", "trimmed"])
def test_role_reaches_the_cbom_at_every_level(tmp_path, level):
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / "r.py").write_text(ROLES_PY)
    from qrp_mcp.scan import scan_directory
    expected = {e["line"]: e["role"] for e in scan_directory(tree)["evidence"]["source_code"]
                if e["algorithm"] == "RSA" and e.get("role")}
    got = _role_of(tree, level)
    assert {line: role for (_, line), role in got.items()} == expected
    assert "signature" in expected.values() and "key_establishment" in expected.values()


def test_role_through_the_mcp_tool(tmp_path):
    from qrp_mcp.server import export_cbom
    (tmp_path / "r.py").write_text(ROLES_PY)
    roles = []
    for c in export_cbom(str(tmp_path))["components"]:
        props = {p["name"]: p["value"] for p in c.get("properties", [])}
        if "qrp:role" in props:
            roles += json.loads(props["qrp:role"])
    assert "signature" in roles and "key_establishment" in roles


def test_no_role_on_a_family_whose_name_says_it(tmp_path):
    from qrp_mcp.server import export_cbom
    (tmp_path / "d.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import dh\n"
        "params = dh.generate_parameters(generator=2, key_size=2048)\n")
    for c in export_cbom(str(tmp_path))["components"]:
        assert "qrp:role" not in {p["name"] for p in c.get("properties", [])}, c["name"]
