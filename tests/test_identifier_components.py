"""An algorithm name as a whole component of a library identifier is a finding (ZA-OPRAVYANE
rows 132 and 133, decided 24.10.2026).

Measured over the public headers of ten C libraries (`qrp-kachestvo/imena-2026-10-23/
a-c-biblioteki`, 23.10.2026): 35 % of the classical names were found, GnuTLS's `gnutls_`
0 of 91, Mbed TLS's `PSA_WANT_` 4 of 55, OpenSSL's `DH_` 4 of 145. Every name below is
from that measurement's tables, which read them from the libraries' own headers.

The negatives come from the measurement's own control: identifiers that contain the letters
without naming the algorithm -- its 36 hand-written lines, 100 of its 218 library names, and
four lines from the Linux kernel's headers. They were all silent before and must stay
silent; the control itself (all 218) is re-run with the measurement's scripts.
"""

import re

import pytest

from qrp_mcp import detectors
from qrp_mcp.scan import scan_directory


def _families(line: str) -> set[str]:
    from pathlib import Path
    return {f["algorithm"] for f in detectors.scan_source_file(Path("a.c"), "a.c", lines=[line])}


@pytest.mark.parametrize("family, name", [
    # Row 132's three.
    ("DSA", "GNUTLS_SIGN_DSA_SHA256"), ("DSA", "d2i_DSAPublicKey"), ("X448", "wc_curve448_make_key"),
    # Row 133: after a vendor prefix ...
    ("DSA", "GNUTLS_PK_DSA"), ("DH", "gnutls_dh_params_init"), ("SHA1", "GCRY_MD_SHA1"),
    ("RSA", "GCRY_PK_RSA"), ("MD5", "LIBSSH2_HOSTKEY_HASH_MD5"), ("MD5", "PSA_WANT_ALG_MD5"),
    ("DES", "MBEDTLS_DES_C"), ("DES", "MBEDTLS_CIPHER_ID_DES"), ("DSA", "OPENSSL_NO_DSA"),
    ("EC", "OPENSSL_NO_EC"), ("RSA", "MBEDTLS_ERR_RSA_BAD_INPUT_DATA"),
    ("RSA", "OSSL_PKEY_PARAM_RSA_EXPONENT4"), ("DH", "WOLFSSL_STATIC_DH"),
    ("DH", "GNUTLS_GROUP_FFDHE6144"),
    # ... OpenSSL's module API and error codes ...
    ("DH", "DH_set0_key"), ("DSA", "DSA_free"), ("RSA", "RSA_blinding_on"),
    ("DES", "DES_ecb2_encrypt"), ("EC", "EC_KEY_get0_group"), ("DSA", "DSA_SIG_get0"),
    ("RSA", "RSA_R_UNKNOWN_DIGEST"), ("DH", "DH_F_DH_PUB_ENCODE"), ("SHA224", "SHA224_Init"),
    ("DH", "DHparams_print"), ("DH", "X509_R_CANT_CHECK_DH_KEY"),
    # ... CamelCase and snake_case components.
    ("RSA", "PEM_write_bio_RSAPrivateKey"), ("EC", "PEM_write_bio_ECPrivateKey"),
    ("RC4", "wc_Arc4Process"), ("RSA", "gnutls_pubkey_export_rsa_raw"),
    ("MD5", "mbedtls_internal_md5_process"), ("RSA", "EVP_PKEY_CTX_get0_rsa_oaep_label"),
    ("RSA", "SSL_use_RSAPrivateKey"), ("DH", "SSL_CTX_set_tmp_dh_callback"),
    ("ECDSA", "CTC_SHA224wECDSA"), ("3DES", "wc_Des3Init"), ("RC4", "GNUTLS_CIPHER_ARCFOUR_128"),
])
def test_algorithm_as_a_component(tmp_path, family, name):
    # The measurement's usage lines: a function is called, a constant is assigned.
    line = f"x = {name}(a, b);" if re.search("[a-z]", name) else f"int id = {name};"
    (tmp_path / "a.c").write_text(f"    {line}\n", encoding="utf-8")
    result = scan_directory(tmp_path)
    assert family in result["detected_algorithms"]
    said = [f["description"] for f in result["evidence"]["source_code"] if f["algorithm"] == family]
    assert said and any(name in s or "usage" in s or "API" in s for s in said)


@pytest.mark.parametrize("name, family", [
    ("DES_ede3_cbc_encrypt", "DES"),          # triple DES, which its own rule reports
    ("MBEDTLS_DES3_CRYPT_ECB_ALT", "DES"),
    ("CKM_ML_DSA_KEY_PAIR_GEN", "DSA"),       # the post-quantum replacement is not DSA
    ("LN_ML_DSA_44", "DSA"), ("NID_ML_DSA_65", "DSA"), ("wc_MlDsaKey_Init", "DSA"),
    ("OQS_SIG_alg_ml_dsa_65", "DSA"), ("wc_IsSlhDsaOid", "DSA"), ("CTC_SLH_DSA_SHA2_128S", "DSA"),
    ("CKM_HASH_SLH_DSA_SHA3_256", "DSA"),
    ("OBJ_dhSinglePass_stdDH_sha1kdf_scheme", "DH"),    # RFC 5753: ECDH
    ("wolfSSL_CTX_SetTmpEC_DHE_Sz", "DH"),
])
def test_a_component_that_is_part_of_another_name(name, family):
    assert family not in _families(f"    x = {name};")


HANDWRITTEN = [
    "int DESCRIPTION = 1;", "x = destroy_window(a, b);", "int id = DESKTOP_MODE;",
    "x = universal_handler(a, b);", "x = traversal_next(a, b);", "int id = CONVERSATION_ID;",
    "x = adversary_model(a, b);", "int id = REVERSAL_FLAG;", "x = adhoc_mode(a, b);",
    "int id = DHCP_OPTION_ROUTER;", "x = dhcp_client_start(a, b);", "int id = SHADOW_PASSWD;",
    "x = decision_tree(a, b);", "int id = ECHO_REQUEST;", "x = ecology_index(a, b);",
    "int id = SECTION_HEADER;", "x = codes_lookup(a, b);", "int id = MODES_COUNT;",
    "x = cmd5_parse(a, b);", "int id = PRC4_SLOT;", "x = src2_buffer(a, b);",
    "int id = ARC2D_LAYOUT;", "x = threadsafe_queue(a, b);", "int id = UNTRUSTED_INPUT;",
    "x = hsspec_lookup(a, b);", "int id = ELMS_COUNT;", "x = bikeshed(a, b);",
    "int id = FALCONRY_TEAM;", "x = mayonnaise(a, b);", "int id = CROSSFADE_MS;",
    "x = desc_alloc(a, b);", "int id = SHA_TIMEOUT;", "x = rsa_logo_draw(a, b);",
    "int id = DSA_COUNTY_CODE;", "x = ec_window(a, b);", "int id = DH_STATUS_OK;",
    "#define RSA_LEGACY_TEXT \"text\"",
    # The Linux kernel's DSA (distributed switch architecture) and embedded controllers.
    "struct dsa_switch *ds = dp->ds;", "ret = cros_ec_cmd(ec, 0, EC_CMD_GET_VERSION, NULL, 0);",
    "__u8   DH_length;", "uint16_t flags;\t\t/* EC_FP_FLAG_xxx */",
]
LIBRARY = """
ACCESS_DESCRIPTION_free ASN1_R_INVALID_UNIVERSALSTRING BIO_CTRL_GET_WPOLL_DESCRIPTOR
BIO_DGRAM_CAP_PROVIDES_DST_ADDR BIO_meth_set_destroy CBS_ASN1_UNIVERSAL CERT_DestroyName
CERT_EncodeSubjectKeyID CKA_DESTROYABLE CKA_X2RATCHET_DHR CKA_X2RATCHET_DHS CK_DESTROYMUTEX
CMMF_DestroyCertifiedKeyPair CP_IDENTRUST_PIVI_HW_ENC_OID CRMF_POPOPrivKeyGetDHMAC
CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION CT_R_LOG_CONF_MISSING_DESCRIPTION DESb
ENGINE_get_destroy_function EVP_KDF_get0_description EVP_MD_CTX_destroy GCRY_KDF_ITERSALTED_S2K
GNUTLS_OCSP_VERIFY_UNTRUSTED_SIGNER HPKE_Ndh_MAX LN_description LN_destinationIndicator
MBEDTLS_KEY_EXCHANGE_SOME_XXDH_PSA_ANY_ENABLED NID_attribute_descriptor NID_cades NID_description
NID_destinationIndicator NID_id_smime_aa_mlExpandHistory NSSLOWKEYDHKey NSS_INIT_PK11THREADSAFE
OBJ_cades_attributes OPENSSL_SYS_VMS_DECC OPENSSL_SYS_VMS_DECCXX OSSL_CMP_CTX_set1_untrusted
OSSL_CRMF_POPOPRIVKEY_DHMAC OSSL_DIGEST_NAME_KECCAK_KMAC128 OSSL_DYNAMIC_OLDEST
OSSL_SELF_TEST_DESC_CIPHER_AES_ECB OSSL_SELF_TEST_DESC_DRBG_HMAC OSSL_SELF_TEST_DESC_KDF_SSKDF
OSSL_SELF_TEST_DESC_KDF_X942KDF OSSL_SELF_TEST_DESC_KEM OSSL_SELF_TEST_DESC_MD_SHA2
OSSL_STORE_F_OSSL_STORE_INFO_GET1_NAME_DESCRIPTION OSSL_STORE_INFO_set0_NAME_description
PERSAKeyHeader PERSA_Issuer PERSA_Key PK11URI_PATTR_LIBRARY_DESCRIPTION PK11_HPKE_DestroyContext
PROV_DESCS_HKDF_SHA256_SIGN PROV_NAMES_KECCAK_384 PROV_NAMES_KECCAK_KMAC_256 SECCertificateUsage
SECOID_FindOIDTagDescription SEC_ASN1_OBJECT_DESCRIPTOR SEC_ERROR_UNTRUSTED_CERT
SEC_ERROR_UNTRUSTED_ISSUER SEC_PKCS12CreateUnencryptedSafe SN_attribute_descriptor SN_cades
SSL_CIPHER_description SSL_DestroyMaskingContext SSL_ERROR_MISSING_PSK_KEY_EXCHANGE_MODES
SSL_F_TLS_PARSE_CTOS_PSK_KEX_MODES SSL_TXT_kDHd SSL_alert_desc_string SSL_error_description
SSL_net_write_desired TLSEXT_TYPE_psk_kex_modes TS_R_TSA_UNTRUSTED UI_destroy_method
V_ASN1_OBJECT_DESCRIPTOR WC_ECCSET_TYPE_DEFINED WC_HASH_SHA3_KECCAK256 WC_NAME_DESCRIPTION_OID
WOLFSSL_ACCESS_DESCRIPTION WOLFSSL_ATECC_DEBUG X509_STORE_CTX_get_num_untrusted
X509_TRUST_UNTRUSTED X509_V_ERR_CERT_UNTRUSTED d2i_ASN1_UNIVERSALSTRING kDHd kDHr
mbedtls_oid_get_sig_alg_desc mbedtls_oid_descriptor_t mbedtls_ssl_conf_tls13_key_exchange_modes
psa_drv_se_destroy_key_t wc_EncodeSignature wc_HpkeDeserializePublicKey
wc_PKCS7_DecodeSymmetricKeyPackageAttribute wc_Poly1305_EncodeSizes64 wolfSSL_CIPHER_description
wolfSSL_CTX_UseTruncatedHMAC wolfSSL_alert_desc_string wolfSSL_sk_ACCESS_DESCRIPTION_pop_free
""".split()


@pytest.mark.parametrize("line", HANDWRITTEN + [f"    x = {n};" for n in LIBRARY])
def test_letters_inside_another_word_stay_silent(line):
    assert _families(line) == set()


def test_every_new_pattern_keeps_the_prefilter():
    # One pattern without derivable literals turns the line gate off for all of them.
    assert detectors._ANY_LITERAL.pattern != ""
    assert all(literals for *_, literals in detectors._FILTERED_PATTERNS)
