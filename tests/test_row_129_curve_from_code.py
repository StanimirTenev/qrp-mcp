"""ZA-OPRAVYANE row 129 (CryptoScan, qScan comparison, 23.10.2026): the CBOM lacked `oid`,
the security levels, `cryptoFunctions`, hybrid -> `dependencies` and `curve`. Release A
(0.36/0.37, tests/test_cbom_m4_fields.py and test_cbom_hybrid_dependencies.py) filled the
first four from tables with sources; `curve` came only from DNSSEC records and the fixed
curves of X25519/X448. An EC line that names its curve in code (`ec.SECP256R1()`,
`prime256v1`, `NIST_P384`) left the field empty. It is read now where the line names exactly
one NIST prime curve, and reaches the CBOM's `algorithmProperties.curve`."""

import json
import subprocess
import sys
import pytest

from qrp_mcp.scan import scan_directory

def _cbom(tmp_path, name, text):
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / name).write_text(text, encoding="utf-8")
    out = tmp_path / "cbom.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "cbom", str(tree),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return json.loads(out.read_text())


def _curves(doc):
    out = set()
    stack = list(doc["components"])
    while stack:
        c = stack.pop()
        stack.extend(c.get("components", []))
        curve = c.get("cryptoProperties", {}).get("algorithmProperties", {}).get("curve")
        if curve:
            out.add(curve)
    return out


@pytest.mark.parametrize("name, text, curve", [
    ("a.py", "e = ec.generate_private_key(ec.SECP256R1())\n", "P-256"),
    ("a.c", "EC_KEY *k = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);\n", "P-256"),
    ("a.go", "k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)\n", "P-384"),
    ("a.js", "crypto.generateKeyPairSync('ec', { namedCurve: 'secp521r1' })\n", "P-521"),
])
def test_the_curve_named_on_the_line_reaches_the_cbom(tmp_path, name, text, curve):
    assert curve in _curves(_cbom(tmp_path, name, text))


def test_two_curves_on_one_line_name_none(tmp_path):
    (tmp_path / "a.py").write_text("c = ec.SECP256R1() if big is False else ec.SECP384R1()\n")
    result = scan_directory(str(tmp_path))
    assert not [e for e in result["evidence"]["source_code"] if e.get("curve")]


def test_secp256k1_is_not_p256(tmp_path):
    (tmp_path / "a.py").write_text("k = ec.generate_private_key(ec.SECP256K1())\n")
    result = scan_directory(str(tmp_path))
    assert not [e for e in result["evidence"]["source_code"] if e.get("curve") == "P-256"]
