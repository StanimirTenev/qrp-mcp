"""Row 458 (14.11.2026, a CBOM-for-blockchain probe on qrp-mcp 0.44.0): pyca's
`ec.generate_private_key(ec.SECP256K1())` gave an EC row with no curve and key size
undetermined, and "secp256k1" was absent from the CBOM; `ec.SECP256R1()` gave P-256, and
python-ecdsa's `curve=SECP256k1` gave secp256k1 (the control). The dotted pyca name now
carries its curve and size on every exit, as python-ecdsa's already did.
"""

import json
import subprocess
import sys

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import export_cbom, scan_repo

PYCA = ("from cryptography.hazmat.primitives.asymmetric import ec\n"
        "k = ec.generate_private_key(ec.SECP256K1())\n"
        "r = ec.generate_private_key(ec.SECP256R1())\n")


def _ec_rows(result, line):
    return [o for o in result["evidence"]["source_code"]
            if o["line"] == line and o["algorithm"] in ("EC", "ECDSA", "ECDH")]


def _check(result):
    rows = _ec_rows(result, 2)
    assert rows and all(o.get("curve") == "secp256k1" and o.get("key_size") == 256
                        for o in rows), rows
    assert all(o.get("curve") == "P-256" for o in _ec_rows(result, 3))


def _cbom_curves(bom):
    return {c["cryptoProperties"].get("algorithmProperties", {}).get("curve")
            for c in bom["components"] if c.get("type") == "cryptographic-asset"}


def test_pyca_secp256k1_carries_its_curve(tmp_path):
    (tmp_path / "w.py").write_text(PYCA)
    result = scan_directory(tmp_path)
    _check(result)
    assert "secp256k1" in _cbom_curves(build(result))


def test_python_ecdsa_control_unchanged(tmp_path):
    (tmp_path / "e.py").write_text("from ecdsa import SigningKey, SECP256k1\n"
                                   "sk = SigningKey.generate(curve=SECP256k1)\n")
    rows = _ec_rows(scan_directory(tmp_path), 2)
    assert rows and all(o.get("curve") == "secp256k1" for o in rows)


def test_two_curves_on_a_line_name_none(tmp_path):
    (tmp_path / "t.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "CURVES = [ec.SECP256K1(), ec.SECP384R1()]\n")
    assert all(not o.get("curve") for o in _ec_rows(scan_directory(tmp_path), 2))


def test_secp256k1_leaves_by_the_cli_and_mcp_tools(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "w.py").write_text(PYCA)
    out, bom = tmp_path / "scan.json", tmp_path / "bom.json"
    for args in (("scan", str(src), "--out", str(out), "--no-config"),
                 ("cbom", str(src), "--out", str(bom), "--no-config")):
        done = subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()",
                               *args], capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
    _check(json.loads(out.read_text()))
    assert "secp256k1" in _cbom_curves(json.loads(bom.read_text()))
    _check(getattr(scan_repo, "fn", scan_repo)(str(src)))
    tool_bom = getattr(export_cbom, "fn", export_cbom)(str(src))
    assert "secp256k1" in _cbom_curves(tool_bom if isinstance(tool_bom, dict) else json.loads(tool_bom))
