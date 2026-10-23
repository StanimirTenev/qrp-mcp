"""JCA algorithm names, by a table (ZA-OPRAVYANE rows 68 and 86, swarm A and C of
22.10.2026: `roy-2026-10-22/a-pravopisi/test_r6`, `c-korpus` test_c8).

Names and aliases checked against the JDK sources (SunJCE.java, SunEC.java, KnownOIDs.java,
XDHKeyPairGenerator.java) and Bouncy Castle's BCPQC Falcon.java; the EC types against
java.security.spec / java.security.interfaces in the JDK tree (all read 23.10.2026).
"""

import pytest

from qrp_mcp.scan import scan_directory


@pytest.mark.parametrize("family, line", [
    ("RSA", 'KeyFactory kf = KeyFactory.getInstance("RSA");'),
    ("EC", 'KeyFactory kf = KeyFactory.getInstance("EC");'),
    ("DH", 'KeyAgreement ka = KeyAgreement.getInstance("DH");'),
    ("DH", 'KeyPairGenerator g = KeyPairGenerator.getInstance("DiffieHellman");'),
    ("X25519", 'KeyPairGenerator g = KeyPairGenerator.getInstance("XDH");'),
    ("DES", 'Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");'),
    ("3DES", 'Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");'),
    ("RC4", 'Cipher c = Cipher.getInstance("ARCFOUR");'),
    ("SHA1", 'MessageDigest md = MessageDigest.getInstance("SHA");'),
    ("Falcon", 'KeyPairGenerator g = KeyPairGenerator.getInstance("Falcon", "BCPQC");'),
])
def test_jca_name(tmp_path, family, line):
    (tmp_path / "A.java").write_text(line + "\n", encoding="utf-8")
    assert family in scan_directory(tmp_path)["detected_algorithms"]


def test_xdh_says_what_it_defaults_to(tmp_path):
    (tmp_path / "A.java").write_text(
        'KeyPairGenerator g = KeyPairGenerator.getInstance("XDH");\n', encoding="utf-8")
    items = scan_directory(tmp_path)["evidence"]["source_code"]
    assert any("X448" in i["description"] for i in items if i["algorithm"] == "X25519")


def test_ec_types_when_the_curve_is_a_constant(tmp_path):
    (tmp_path / "KeyGen.kt").write_text(
        "import java.security.interfaces.ECPublicKey\n"
        "import java.security.spec.ECGenParameterSpec\n"
        "fun generate(algo: String, curve: String): KeyPair {\n"
        "    val gen = KeyPairGenerator.getInstance(algo)\n"
        "    gen.initialize(ECGenParameterSpec(curve))\n"
        "    return gen.genKeyPair()\n"
        "}\n", encoding="utf-8")
    assert "EC" in scan_directory(tmp_path)["detected_algorithms"]


@pytest.mark.parametrize("line", [
    'MessageDigest md = MessageDigest.getInstance("SHA-256");',
    'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");',
    "val ecPublicKey = loadKey()",
])
def test_not_a_classical_family(tmp_path, line):
    (tmp_path / "A.java").write_text(line + "\n", encoding="utf-8")
    found = set(scan_directory(tmp_path)["detected_algorithms"])
    assert not found & {"SHA1", "EC", "DES", "RSA"}, found
