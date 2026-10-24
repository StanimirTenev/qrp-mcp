"""Headers and types named after the algorithm (ZA-OPRAVYANE row 137).

Measured 23.10.2026 (`qrp-kachestvo/imena-2026-10-23`, A-C classes G and H, B class C25):
`#include <openssl/ec.h>`, `<openssl/des.h>`, `<mbedtls/dhm.h>`, `<wolfssl/wolfcrypt/dsa.h>`
and the types a C program declares its keys with -- `DSA_SIG *`, `EC_GROUP *`, `MD5_CTX`,
`RC4_KEY`, `curve448_key` -- gave nothing, nor did the Java and Bouncy Castle classes with an
API suffix (`DSASigner`, `ECDHBasicAgreement`, `RSAKeyGenParameterSpec`, `DHParameterSpec`)
or pyca's key classes reached through their module (`dsa.DSAPublicNumbers`).
"""

from pathlib import Path

import pytest

from qrp_mcp import detectors


def _families(line: str, name: str = "a.c") -> set[str]:
    found = detectors.scan_source_file(Path(name), name, lines=[line])
    return {f["algorithm"] for f in found if f["evidence_kind"] not in ("ban", "comment")}


@pytest.mark.parametrize("header,family", [
    ("openssl/ec.h", "EC"), ("openssl/ec_key.h", "EC"), ("openssl/des.h", "DES"),
    ("openssl/rsaerr.h", "RSA"), ("openssl/dsaerr.h", "DSA"), ("openssl/dherr.h", "DH"),
    ("mbedtls/dhm.h", "DH"), ("mbedtls/rsa.h", "RSA"), ("mbedtls/ecp.h", "EC"),
    ("mbedtls/des.h", "DES"), ("mbedtls/md5.h", "MD5"), ("mbedtls/sha1.h", "SHA1"),
    ("mbedtls/lms.h", "HSS/LMS"), ("wolfssl/wolfcrypt/dsa.h", "DSA"),
    ("wolfssl/wolfcrypt/curve448.h", "X448"), ("wolfssl/wolfcrypt/md4.h", "MD4"),
    ("wolfssl/wolfcrypt/rc2.h", "RC2"), ("wolfssl/wolfcrypt/sm2.h", "SM2"),
    ("wolfssl/wolfcrypt/wc_lms.h", "HSS/LMS"), ("oqs/kem_bike.h", "BIKE"),
    ("oqs/sig_falcon.h", "Falcon"), ("oqs/sig_stfl_lms.h", "HSS/LMS"),
])
def test_headers(header, family):
    assert family in _families(f"#include <{header}>")
    assert family in _families(f'#include "{header}"')


def test_a_header_that_names_no_algorithm_stays_silent():
    for header in ("openssl/evp.h", "openssl/ecdsa_extra.h", "mbedtls/des_alt.h",
                   "openssl/err.h", "wolfssl/wolfcrypt/hash.h"):
        assert _families(f"#include <{header}>") - {"ECDSA"} == set(), header


@pytest.mark.parametrize("line,family", [
    ("DSA_SIG *k = NULL;", "DSA"), ("EC_GROUP *k = NULL;", "EC"), ("EC_KEY *k = NULL;", "EC"),
    ("MD5_CTX *k = NULL;", "MD5"), ("RC4_KEY *k = NULL;", "RC4"), ("RSA *k = NULL;", "RSA"),
    ("DH *k = NULL;", "DH"), ("const DSA *k = d;", "DSA"), ("RSA_METHOD *k = NULL;", "RSA"),
    ("curve448_key *k = NULL;", "X448"), ("DES_cblock *k = NULL;", "DES"),
    ("SHA_CTX *k = NULL;", "SHA1"), ("MD4_CTX *k = NULL;", "MD4"), ("RC2_KEY *k = NULL;", "RC2"),
    ("struct rsa_st *k = NULL;", "RSA"), ("struct dsa_st *k = NULL;", "DSA"),
    ("RSAPublicKeyStr *k = NULL;", "RSA"), ("DHParams *k = NULL;", "DH"),
    ("falcon_key *k = NULL;", "Falcon"), ("LmsKey *k = NULL;", "HSS/LMS"),
    ("WOLFSSL_EC_GROUP *k = NULL;", "EC"), ("psa_dh_family_t *k = NULL;", "DH"),
])
def test_c_types(line, family):
    assert family in _families(line)


@pytest.mark.parametrize("line,family", [
    ("use(new DSASigner());", "DSA"), ("use(new DSADigestSigner());", "DSA"),
    ("use(new DSAKeyPairGenerator());", "DSA"), ("use((DSAParameterSpec) params);", "DSA"),
    ("use(new ECDHBasicAgreement());", "ECDH"), ("use(new ECDHRawAgreement());", "ECDH"),
    ("use(new ECKeyPairGenerator());", "EC"), ("use((ECKey) params);", "EC"),
    ("use((RSAKeyGenParameterSpec) params);", "RSA"), ("use((RSAPrivateCrtKey) params);", "RSA"),
    ("use(new RSADigestSigner());", "RSA"), ("use(new PSSSigner());", "RSA"),
    ("use(new OAEPEncoding());", "RSA"), ("use(new PKCS1Encoding());", "RSA"),
    ("use((PSSParameterSpec) params);", "RSA"), ("use(new ISO9796d2Signer());", "RSA"),
    ("use((DHParameterSpec) params);", "DH"), ("use((DHPublicKey) params);", "DH"),
    ("use((DESKeySpec) params);", "DES"), ("use(new DESKeyGenerator());", "DES"),
    ("use((EdECPublicKey) params);", "EdDSA"), ("use((EdDSAParameterSpec) params);", "EdDSA"),
    ("use((XECPublicKey) params);", "X25519"),
    ("use(new BLSSigner());", "BLS"), ("use(new BIP340Signer());", "Schnorr"),
])
def test_java_classes(line, family):
    assert family in _families(line, "A.java")


@pytest.mark.parametrize("line,name,family", [
    ("x = dsa.DSAPublicNumbers", "a.py", "DSA"), ("x = dh.DHParameterNumbers", "a.py", "DH"),
    ("ec.EllipticCurvePublicKey()", "a.py", "EC"), ("ec.BrainpoolP256R1()", "a.py", "EC"),
    ("x = rsa.RSAPrivateNumbers", "a.py", "RSA"), ("let _ = des::TdesEde3;", "a.rs", "3DES"),
    ("forge.pki.wrapRsaPrivateKey();", "a.js", "RSA"),
    ("forge.des.createEncryptionCipher();", "a.js", "DES"),
])
def test_other_languages(line, name, family):
    assert family in _families(line, name)


@pytest.mark.parametrize("line,name", [
    ("int DH = height - base;", "a.c"), ("x = DH * 2;", "a.c"), ("RSAVE *k = NULL;", "a.c"),
    ("DESCRIPTION *d = NULL;", "a.c"), ("DHCP_OPTION_ROUTER *o = NULL;", "a.c"),
    ("rsa_logo_draw(k);", "a.c"), ("ECHO *e = NULL;", "a.c"), ("ECKeyboard k;", "A.java"),
    ("use(new PSSManager());", "A.java"), ("x = ec.ECHO", "a.py"),
])
def test_lookalikes_stay_silent(line, name):
    assert _families(line, name) == set(), line
