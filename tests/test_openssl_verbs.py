"""OpenSSL calls, constants and headers outside the listed ones (ZA-OPRAVYANE row 65, swarm A
of 22.10.2026, `qrp-kachestvo/roy-2026-10-22/a-pravopisi/test_r5`).

Every name checked against OpenSSL's own headers in the corpus copy: include/openssl/rsa.h,
dsa.h, dh.h, md5.h, sha.h, des.h; `NID_ffdhe2048` against crypto/objects/objects.txt (the
header obj_mac.h is generated from it).
"""

import pytest

from qrp_mcp.scan import scan_directory


@pytest.mark.parametrize("family, line", [
    ("RSA", "EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);"),
    ("RSA", "EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);"),
    ("RSA", "int n = RSA_size(rsa);"),
    ("DSA", "DSA_sign(0, dgst, dlen, sig, &siglen, dsa);"),
    ("DSA", "DSA_SIG *s = DSA_do_sign(dgst, dlen, dsa);"),
    ("DH", "int n = DH_compute_key(secret, peer_pub, dh);"),
    ("DH", "DH *dh = DH_new_by_nid(NID_ffdhe2048);"),
    ("MD5", "MD5(data, len, digest);"),
    ("SHA1", "SHA1(data, len, digest);"),
    ("3DES", "DES_ecb3_encrypt(&in, &out, &ks1, &ks2, &ks3, DES_ENCRYPT);"),
    ("RSA", "#include <openssl/rsa.h>"),
    ("DSA", "#include <openssl/dsa.h>"),
    ("DH", "#include <openssl/dh.h>"),
    ("MD5", "#include <openssl/md5.h>"),
])
def test_openssl_name_is_found(tmp_path, family, line):
    (tmp_path / "a.c").write_text(line + "\n", encoding="utf-8")
    assert family in scan_directory(tmp_path)["detected_algorithms"]


@pytest.mark.parametrize("line", [
    "ECDSA_sign(0, dgst, dlen, sig, &siglen, eckey);",
    "#include <openssl/sha.h>",
])
def test_neighbours_are_not_dsa_or_sha1(tmp_path, line):
    (tmp_path / "a.c").write_text(line + "\n", encoding="utf-8")
    found = set(scan_directory(tmp_path)["detected_algorithms"])
    assert not found & {"DSA", "SHA1"}, found
