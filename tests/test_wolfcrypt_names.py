"""wolfCrypt's classical API (ZA-OPRAVYANE row 72, swarm A of 22.10.2026,
`roy-2026-10-22/a-pravopisi/test_r3`): a whole wolfSSL RSA signer scanned as empty.

Every name checked against wolfssl/wolfcrypt/*.h in the corpus copy
(~/qrp-evidence/corpus/wolfssl).
"""

import pytest

from qrp_mcp.scan import scan_directory


@pytest.mark.parametrize("family, line", [
    ("RSA", "wc_InitRsaKey(&key, NULL);"),
    ("RSA", "ret = wc_RsaPublicEncrypt(in, inLen, out, outLen, &key, &rng);"),
    ("RSA", "ret = wc_MakeRsaKey(&key, 2048, WC_RSA_EXPONENT, &rng);"),
    ("EC", "wc_ecc_make_key(&rng, 32, &key);"),
    ("ECDSA", "wc_ecc_sign_hash(hash, hashSz, sig, &sigSz, &rng, &key);"),
    ("ECDH", "wc_ecc_shared_secret(&priv, &pub, out, &outSz);"),
    ("DH", "wc_DhGenerateKeyPair(&key, &rng, priv, &privSz, pub, &pubSz);"),
    ("MD5", "wc_Md5Update(&md5, data, len);"),
    ("SHA1", "wc_ShaUpdate(&sha, data, len);"),
    ("3DES", "wc_Des3_CbcEncrypt(&des3, out, in, sz);"),
    ("DES", "wc_Des_CbcEncrypt(&des, out, in, sz);"),
    ("Falcon", "wc_falcon_sign_msg(msg, msgSz, sig, &sigSz, &key, &rng);"),
    ("RSA", "#include <wolfssl/wolfcrypt/rsa.h>"),
])
def test_wolfcrypt_name(tmp_path, family, line):
    (tmp_path / "a.c").write_text(line + "\n", encoding="utf-8")
    assert family in scan_directory(tmp_path)["detected_algorithms"]


def test_whole_wolfssl_rsa_signer(tmp_path):
    (tmp_path / "sign.c").write_text(
        "#include <wolfssl/options.h>\n"
        "int sign_fw(const byte* in, word32 inLen, byte* out, word32 outLen) {\n"
        "    RsaKey key; WC_RNG rng;\n"
        "    wc_InitRng(&rng);\n"
        "    return wc_RsaSSL_Sign(in, inLen, out, outLen, &key, &rng);\n"
        "}\n", encoding="utf-8")
    assert "RSA" in scan_directory(tmp_path)["detected_algorithms"]


@pytest.mark.parametrize("line", [
    "wc_Sha256Update(&sha, data, len);",
    "wc_Sha3_256_Update(&sha3, data, len);",
    "wc_Shake128_Update(&shake, data, len);",
])
def test_other_hashes_are_not_sha1(tmp_path, line):
    (tmp_path / "a.c").write_text(line + "\n", encoding="utf-8")
    assert "SHA1" not in scan_directory(tmp_path)["detected_algorithms"]
