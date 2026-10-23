"""Node's key types and RSA-only calls (ZA-OPRAVYANE row 69, swarm A of 22.10.2026,
`roy-2026-10-22/a-pravopisi/test_r9`).

Key types 'rsa-pss', 'dsa', 'dh' and crypto.publicEncrypt from Node's doc/api/crypto.md;
forge.pki.rsa from node-forge lib/rsa.js (both read 23.10.2026). Node passes the cipher
name to OpenSSL, where DES-CBC is single DES.
"""

import pytest

from qrp_mcp.scan import scan_directory


@pytest.mark.parametrize("family, line", [
    ("RSA", "crypto.generateKeyPairSync('rsa-pss', { modulusLength: 2048 });"),
    ("DSA", "crypto.generateKeyPairSync('dsa', { modulusLength: 2048 });"),
    ("DH", "crypto.generateKeyPairSync('dh', { group: 'modp14' });"),
    ("DES", "const c = crypto.createCipheriv('des-cbc', key, iv);"),
    ("RSA", "const enc = crypto.publicEncrypt(publicKey, buf);"),
    ("RSA", "const keys = forge.pki.rsa.generateKeyPair(2048);"),
])
def test_node_name(tmp_path, family, line):
    (tmp_path / "a.js").write_text(line + "\n", encoding="utf-8")
    assert family in scan_directory(tmp_path)["detected_algorithms"]


def test_triple_des_is_not_single_des(tmp_path):
    (tmp_path / "a.js").write_text(
        "const c = crypto.createCipheriv('des-ede3-cbc', key, iv);\n", encoding="utf-8")
    found = set(scan_directory(tmp_path)["detected_algorithms"])
    assert "3DES" in found and "DES" not in found, found
