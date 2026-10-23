"""Mbed TLS and PSA names outside mbedtls_rsa_/ecdsa/ecdh (ZA-OPRAVYANE row 73, swarm A of
22.10.2026, `roy-2026-10-22/a-pravopisi/test_r4`).

Checked against Mbed-TLS mbedtls-3.6: include/mbedtls/dhm.h, ecp.h, md5.h, sha1.h, des.h,
md.h and include/psa/crypto_values.h (read 23.10.2026).
"""

import pytest

from qrp_mcp.scan import scan_directory


@pytest.mark.parametrize("family, line", [
    ("DH", "mbedtls_dhm_make_public(&dhm, x_size, out, olen, f_rng, p_rng);"),
    ("DH", "psa_set_key_algorithm(&attr, PSA_ALG_FFDH);"),
    ("RSA", "psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_KEY_PAIR);"),
    ("EC", "mbedtls_ecp_gen_key(grp_id, &kp, f_rng, p_rng);"),
    ("MD5", "mbedtls_md5_update(&ctx, buf, len);"),
    ("SHA1", "mbedtls_sha1_update(&ctx, buf, len);"),
    ("DES", "mbedtls_des_setkey_enc(&ctx, key);"),
    ("3DES", "mbedtls_des3_set3key_enc(&ctx, key);"),
    ("SHA1", "md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);"),
])
def test_mbedtls_name(tmp_path, family, line):
    (tmp_path / "a.c").write_text(line + "\n", encoding="utf-8")
    assert family in scan_directory(tmp_path)["detected_algorithms"]


def test_des3_is_not_single_des(tmp_path):
    (tmp_path / "a.c").write_text("mbedtls_des3_set3key_enc(&ctx, key);\n", encoding="utf-8")
    assert "DES" not in scan_directory(tmp_path)["detected_algorithms"]
