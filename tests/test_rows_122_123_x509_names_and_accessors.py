"""X.509 algorithm names and OpenSSL's old accessors (ZA-OPRAVYANE rows 122, 123).

Both were open on 23.10 and were closed by rows 133-134 in 0.36.0 (component names, the
OID table); 01-tablo re-judged mbedtls x509_oid.c and curl x509asn1.c / openssl.c FOUND.
These tests passed before release B and pin the forms the two rows list.
"""

from pathlib import Path

import pytest

from qrp_mcp import detectors


def _families(line: str, name: str = "a.c") -> set[str]:
    found = detectors.scan_source_file(Path(name), name, lines=[line])
    return {f["algorithm"] for f in found if f["evidence_kind"] not in ("ban", "comment")}


@pytest.mark.parametrize("line,family", [
    ('static const char *n = "sha256WithRSAEncryption";', "RSA"),
    ('static const char *n = "RSASSA-PSS";', "RSA"),
    ('static const char *n = "ecdsa-with-SHA256";', "ECDSA"),
    ('static const char *n = "id-ecPublicKey";', "EC"),
    ('static const char *n = "dsaWithSHA1";', "DSA"),
    ('static const char *o = "1.2.840.113549.1.1.11";', "RSA"),
    ('static const char *o = "1.2.840.10045.4.3.2";', "ECDSA"),
])
def test_row_122_x509_names_and_dotted_oids(line, family):
    assert family in _families(line)


@pytest.mark.parametrize("line,family", [
    ("DSA_get0_pqg(dsa, &p, &q, &g);", "DSA"), ("DH_get0_key(dh, &pub, NULL);", "DH"),
    ("RSA_free(rsa);", "RSA"), ("RSA_up_ref(rsa);", "RSA"), ("DSA_free(d);", "DSA"),
    ("EVP_PKEY_get1_RSA(pkey);", "RSA"), ("EVP_PKEY_get0_DSA(pkey);", "DSA"),
    ("EVP_PKEY_get1_EC_KEY(pkey);", "EC"), ("EVP_PKEY_get0_DH(pkey);", "DH"),
    ("x = OSSL_PKEY_PARAM_RSA_E;", "RSA"), ("x = OSSL_PKEY_PARAM_DH_GENERATOR;", "DH"),
    ("x = OSSL_PKEY_PARAM_EC_PUB_X;", "EC"),
])
def test_row_123_old_openssl_accessors(line, family):
    assert family in _families(line)
