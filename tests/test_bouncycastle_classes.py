"""Bouncy Castle's lightweight API (ZA-OPRAVYANE row 74, swarm A of 22.10.2026,
`roy-2026-10-22/a-pravopisi/test_r7`). Classes checked in bc-java
core/src/main/java/org/bouncycastle (read 23.10.2026)."""

import pytest

from qrp_mcp.scan import scan_directory


@pytest.mark.parametrize("family, line", [
    ("RSA", "AsymmetricBlockCipher e = new OAEPEncoding(new RSAEngine());"),
    ("RSA", "RSAKeyPairGenerator gen = new RSAKeyPairGenerator();"),
    ("DES", "BlockCipher e = new DESEngine();"),
    ("RC4", "StreamCipher c = new RC4Engine();"),
    ("MD5", "Digest d = new MD5Digest();"),
    ("SHA1", "Digest d = new SHA1Digest();"),
    ("Falcon", "FalconSigner signer = new FalconSigner();"),
])
def test_bouncy_castle_class(tmp_path, family, line):
    (tmp_path / "B.java").write_text(line + "\n", encoding="utf-8")
    assert family in scan_directory(tmp_path)["detected_algorithms"]


def test_desede_engine_is_not_single_des(tmp_path):
    (tmp_path / "B.java").write_text("BlockCipher e = new DESedeEngine();\n", encoding="utf-8")
    found = set(scan_directory(tmp_path)["detected_algorithms"])
    assert "3DES" in found and "DES" not in found, found
