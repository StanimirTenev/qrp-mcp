"""strongSwan's RSA and DH constants (ZA-OPRAVYANE row 80, swarm C of 22.10.2026,
`roy-2026-10-22/c-korpus` test_c2_strongswan_key_rsa). Names from strongSwan
src/libstrongswan/credentials/keys/*.h, crypto/key_exchange.h and plugins/ (corpus copy)."""

import pytest

from qrp_mcp.scan import scan_directory


def test_key_rsa_and_its_signature_scheme(tmp_path):
    (tmp_path / "keys.c").write_text(
        "key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_RSA,\n"
        "                         BUILD_KEY_SIZE, 3072, BUILD_END);\n"
        "return key->sign(key, SIGN_RSA_EMSA_PKCS1_SHA2_256, NULL, data, sig);\n",
        encoding="utf-8")
    assert "RSA" in scan_directory(tmp_path)["detected_algorithms"]


@pytest.mark.parametrize("family, line", [
    ("RSA", "enc = pub->encrypt(pub, ENCRYPT_RSA_OAEP_SHA256, NULL, plain, &crypt);"),
    ("RSA", "this = gmp_rsa_private_key_gen(type, args);"),
    ("DH", "ke = lib->crypto->create_ke(lib->crypto, MODP_2048_BIT);"),
    ("DH", "case MODP_1024_160:"),
])
def test_strongswan_constant(tmp_path, family, line):
    (tmp_path / "a.c").write_text(line + "\n", encoding="utf-8")
    assert family in scan_directory(tmp_path)["detected_algorithms"]


def test_modp_null_is_no_group(tmp_path):
    (tmp_path / "a.c").write_text("if (group == MODP_NULL) return FALSE;\n", encoding="utf-8")
    assert "DH" not in scan_directory(tmp_path)["detected_algorithms"]
