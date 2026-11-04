"""Row 413 (04.11.2026): Node's `crypto.createECDH('secp256k1')` read as ECDSA.

"Creates an Elliptic Curve Diffie-Hellman (ECDH) key exchange object using a predefined curve
specified by the curveName string" (https://nodejs.org/api/crypto.html): key agreement on
secp256k1, no signature. The curve name inside createECDH no longer gives ECDSA."""

from __future__ import annotations


def test_create_ecdh_on_secp256k1(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "k.js").write_text("const e = crypto.createECDH('secp256k1');\n")
    found = {e["algorithm"] for e in scan_directory(tmp_path)["evidence"]["source_code"]}
    assert "ECDSA" not in found and "ECDH" in found


def test_secp256k1_signing_stays_ecdsa(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "s.js").write_text("const k = ec.keyFromPrivate(p, 'secp256k1'); // secp256k1\n"
                                   "const sig = secp256k1.sign(msg, priv);\n")
    found = {e["algorithm"] for e in scan_directory(tmp_path)["evidence"]["source_code"]}
    assert "ECDSA" in found
