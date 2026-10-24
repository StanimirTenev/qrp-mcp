"""Narrow gaps (ZA-OPRAVYANE row 143).

Measured 23.10.2026 (`qrp-kachestvo/imena-2026-10-23`, A-C sections 4-5): SHA-1 was found
for 29 of 535 library names, because the SHA-1 rule knew a list of calls and no name where
SHA1 is glued to something else -- `sha1WithRSAEncryption`, `ecdsa-with-SHA1`,
`DSAwithSHA1`, `PKCS1WithSHA1`, `MGF1SHA1`, `TripleDesSha1`, `hmac-sha1`. X448 in camel case
(`SetX448KeyGenCb`) and in `curve448`; every `efrodokem_*` (liboqs's ephemeral FrodoKEM);
libsodium's `crypto_sign_edwards25519sha512batch*`; and the LMS names of wolfSSL
(`WC_LMS_PARM_*`), liboqs (`OQS_LMS_ID_*`) and Mbed TLS (`mbedtls_lms_*`). SHA-1 as a MAC
or KDF is reported (the owner's policy).
"""

from pathlib import Path

import pytest

from qrp_mcp import detectors


def _families(line: str, name: str = "a.c") -> set[str]:
    found = detectors.scan_source_file(Path(name), name, lines=[line])
    return {f["algorithm"] for f in found if f["evidence_kind"] not in ("ban", "comment")}


@pytest.mark.parametrize("line,name", [
    ('x = "sha1WithRSAEncryption"', "a.py"), ('x = "ecdsa-with-SHA1"', "a.py"),
    ('x = "DSA-SHA1"', "a.py"), ('use(Signature.getInstance("DSAwithSHA1"));', "A.java"),
    ('use(Signature.getInstance("SHA1withECDSAinP1363Format"));', "A.java"),
    ('use(Signature.getInstance("SHA/DSA", "BC"));', "A.java"),
    ('use(Signature.getInstance("SHAwithDSA", "BC"));', "A.java"),
    ("_ = tls.PKCS1WithSHA1", "a.go"), ("SignatureAlgorithms = rsa_pkcs1_sha1", "openssl.cnf"),
    ("let _ = &aws_lc_rs::rsa::OAEP_SHA1_MGF1SHA1;", "a.rs"),
    ("var a = Pkcs12ExportPbeParameters.Pkcs12TripleDesSha1;", "a.cs"),
    ("MACs hmac-sha1", "sshd_config"), ('Mac.getInstance("HmacSHA1");', "A.java"),
    ('use(KeyAgreement.getInstance("ECCDHWITHSHA1KDF", "BC"));', "A.java"),
    ("EVP_md5_sha1();", "a.c"), ("#define CKM_SHA_1 0x220", "a.h"),
    ("x = digest(SHA1Context *c);", "a.c"), ("_ = ssh.InsecureKeyExchangeDH14SHA1", "a.go"), ("x = 'dhSinglePass-stdDH-sha1kdf-scheme'", "a.py"),
    ('{"kid": "k1", "alg": "SHA-1"}', "cose.json"),
])
def test_sha1_glued_and_component_forms(line, name):
    assert "SHA1" in _families(line, name)


@pytest.mark.parametrize("line,name", [
    ("x = sha256(data)", "a.py"), ('x = "SHA-256"', "a.py"), ("SHA256_Init(&c);", "a.c"),
    ("x = sha_384", "a.py"), ("SHA3_512_Init(&c);", "a.c"), ("pasha1 = 1", "a.py"),
    ("shasum = 1", "a.py"), ("x = SHA1024", "a.c"), ("int sha12 = 0;", "a.c"),
    ("x = sha512_224", "a.py"), ("sha1sum file.tar", "a.sh"),   # a tool's name, one word
    # Prose in a string: the A-C measurement's hand-written negative control.
    ('log_msg("legacy SHA1 path removed");', "a.c"), ('fail "keygen fingerprint sha1"', "a.sh"),
])
def test_other_hashes_are_not_sha1(line, name):
    assert "SHA1" not in _families(line, name), line


@pytest.mark.parametrize("line,family", [
    ("wolfSSL_CTX_SetX448KeyGenCb(ctx, cb);", "X448"), ("CallbackX448SharedSecret cb;", "X448"),
    ("HpkeDhKemX448Sha512 k;", "X448"), ("wc_curve448_make_key(rng, 56, &k);", "X448"),
    ("#define HAVE_CURVE448", "X448"), ("x = MBEDTLS_ECP_DP_CURVE448;", "X448"),
    ("OQS_KEM_efrodokem_640_aes_keypair(pk, sk);", "FrodoKEM"),
    ('x = "eFrodoKEM-976-SHAKE";', "FrodoKEM"), ("x = EFRODOKEM_1344_AESk;", "FrodoKEM"),
    ("crypto_sign_edwards25519sha512batch_keypair(pk, sk);", "Ed25519"),
    ("#include <sodium/crypto_sign_edwards25519sha512batch.h>", "Ed25519"),
    ("wolfSSL_CTX_SetEd25519SignCb(ctx, cb);", "Ed25519"),
    ("x = WC_LMS_PARM_L1_H5_W1;", "HSS/LMS"), ("x = OQS_LMS_ID_sha256_h10_w1;", "HSS/LMS"),
    ("mbedtls_lms_sign(&ctx, f, r, m, l, s, n, &o);", "HSS/LMS"),
    ("mbedtls_lms_public_t pub;", "HSS/LMS"), ("x = MBEDTLS_LMS_SIG_LEN(h, o);", "HSS/LMS"),
    ("x = MBEDTLS_LMOTS_SHA256_N32_W8;", "HSS/LMS"), ("x = LMOTS_SHA256_N32_W8;", "HSS/LMS"),
])
def test_narrow_names(line, family):
    assert family in _families(line)


@pytest.mark.parametrize("line", [
    "x = hex448;", "int boX448ed = 0;", "x = frodo_baggins;", "int lms_course = 1;",
    "x = LMS_SHARED_SECRET;", "x = edwards_curve;",
])
def test_lookalikes_stay_silent(line):
    assert _families(line) == set(), line
