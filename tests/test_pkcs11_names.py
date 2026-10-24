"""PKCS#11 key types and mechanisms name the algorithm (ZA-OPRAVYANE row 135).

`CKK_RSA`, `CKK_DH`, `CKK_EC` and the `CKM_*` mechanisms were 85 of 247 in NSS's headers
(`qrp-kachestvo/imena-2026-10-23/a-c-biblioteki`, class E); only `CKM_RSA_*` and `CKM_DSA_*`
had a rule. An HSM integration names its keys this way and nothing else. Names from the
PKCS#11 header OpenSSH carries (pkcs11.h) and NSS's pkcs11t.h, as measured.
"""

import pytest

from qrp_mcp.scan import scan_directory


@pytest.mark.parametrize("family, name", [
    ("RSA", "CKK_RSA"), ("DH", "CKK_DH"), ("DH", "CKK_X9_42_DH"), ("EC", "CKK_EC"),
    ("DSA", "CKK_DSA"), ("DES", "CKK_DES"), ("3DES", "CKK_DES3"), ("3DES", "CKK_DES2"),
    ("RC4", "CKK_RC4"), ("EC", "CKK_EC_EDWARDS"), ("EC", "CKA_EC_PARAMS"),
    ("DH", "CKM_DH_PKCS_DERIVE"), ("DH", "CKM_X9_42_DH_KEY_PAIR_GEN"),
    ("EC", "CKM_EC_KEY_PAIR_GEN"), ("RSA", "CKM_SHA256_RSA_PKCS"), ("SHA1", "CKM_SHA1_RSA_PKCS"),
    ("MD5", "CKM_MD5"), ("SHA1", "CKM_SHA_1"), ("SHA224", "CKM_SHA224"),
    ("SHA3-224", "CKM_SHA3_224"), ("DES", "CKM_DES_CBC"), ("3DES", "CKM_DES3_CBC"),
    ("RC4", "CKM_RC4"), ("SHA224", "CKM_ECDSA_SHA224"),
])
def test_pkcs11_name(tmp_path, family, name):
    (tmp_path / "p.c").write_text(f"#define X {name}\nmech.mechanism = {name};\n",
                                  encoding="utf-8")
    assert family in scan_directory(tmp_path)["detected_algorithms"]


def test_single_des_mechanism_is_not_triple_des(tmp_path):
    (tmp_path / "p.c").write_text("mech.mechanism = CKM_DES_CBC;\n", encoding="utf-8")
    assert "3DES" not in scan_directory(tmp_path)["detected_algorithms"]


def test_ml_dsa_mechanism_is_not_dsa(tmp_path):
    (tmp_path / "p.c").write_text("mech.mechanism = CKM_ML_DSA_KEY_PAIR_GEN;\n", encoding="utf-8")
    assert "DSA" not in scan_directory(tmp_path)["detected_algorithms"]
