"""Algorithm words inside C identifiers, the strict form only (ZA-OPRAVYANE row 120).

The words count only behind a prefix that marks the identifier as cryptographic (rows
132-135 built that rule; 0.36.0 already reads PSA_WANT_*, MBEDTLS_PK_SIGALG_*, OSSL_PKEY_PARAM_*,
LIBSSH2_HOSTKEY_HASH_*). What row 120 still missed is curl's own crypto API: `Curl_MD5_*`,
`curl_md5.h` -- lib/vauth/digest.c, HTTP Digest over MD5, had 0 rows.

The guard is what makes the strict form safe: a naive split put 2 208 DSA rows on
`libcrux_ml_dsa_*` lines in OpenSSH (qrp-pokazateli 04-advokat A1). A post-quantum or an
Edwards signature must never be reported as classical DSA, ML-KEM or ECDH never as DH. The
guard tests below passed on 0.36.0 already; they pin it.
"""

from pathlib import Path

import pytest

from qrp_mcp import detectors


def _families(line: str, name: str = "a.c") -> set[str]:
    found = detectors.scan_source_file(Path(name), name, lines=[line])
    return {f["algorithm"] for f in found if f["evidence_kind"] not in ("ban", "comment")}


@pytest.mark.parametrize("line", [
    "typedef void (*Curl_MD5_update_func)(void *context, const unsigned char *data);",
    'Curl_MD5_update(ctxt, (const unsigned char *)":", 1);',
    '#include "curl_md5.h"',
    "result = Curl_HMAC_MD5(key, n);",
])
def test_curl_md5_api(line):
    assert "MD5" in _families(line)


def test_curl_des_and_ed25519_api():
    assert "DES" in _families("curl_des_set_odd_parity(key, sizeof(key));")
    assert "Ed25519" in _families("rc = Curl_ed25519_sign(k, m, n);")


@pytest.mark.parametrize("line", [
    "libcrux_ml_dsa_ml_dsa_65_sign(a, b);",
    "libcrux_ml_dsa_generic_verify_internal(x);",
    "slh_dsa_sha2_128s_sign(x);",
    "fn_dsa_512_keygen(x);",
    "PSA_ALG_PURE_EDDSA;",
    "OSSL_SIGALG_ED25519;",
    "PSA_ALG_ECDSA_ANY;",
    "PSA_ALG_ML_DSA;",
    "mbedtls_ecdsa_sign(a);",
    "MBEDTLS_PK_SIGALG_ECDSA;",
    "GNUTLS_SIGN_EDDSA_ED25519;",
])
def test_no_post_quantum_or_edwards_or_ec_signature_becomes_dsa(line):
    assert "DSA" not in _families(line)


@pytest.mark.parametrize("line", [
    "MBEDTLS_SSL_IANA_TLS_GROUP_ML_KEM_768;",
    "OSSL_KEM_ML_KEM_768;",
    "PSA_ALG_ECDH;",
    "mbedtls_ecdh_compute_shared(a);",
    "GNUTLS_GROUP_X25519_MLKEM768;",
])
def test_no_ml_kem_or_ecdh_becomes_dh(line):
    assert "DH" not in _families(line)


def test_libcrux_ml_dsa_stays_ml_dsa():
    assert _families("libcrux_ml_dsa_ml_dsa_65_sign(a, b);") == {"ML-DSA"}


def test_trailing_comment_prose_is_not_a_use():
    assert _families('static const char *x = "abc"; /**< e.g. sha1RSA */') == set()


@pytest.mark.parametrize("line,name", [
    ("rsa_enabled = False", "a.py"),
    ("rsa_enabled: false", "a.yaml"),
    ("dsa_support = off", "a.ini"),
])
def test_configuration_key_names_stay_silent(line, name):
    # Owner's decision 25.10: a configuration key's name is not a finding.
    assert _families(line, name) == set()


def test_words_without_a_crypto_prefix_stay_silent():
    assert _families("DHCP_STATUS_OK = rsa_logo_draw(ECHO);") == set()
    assert _families("int DSA_COUNTY_CODE = 3;") == set()
