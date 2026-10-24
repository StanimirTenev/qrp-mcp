"""Cipher suites that left out a family they name (ZA-OPRAVYANE row 136).

The library-header measurement of 23.10.2026 (`qrp-kachestvo/imena-2026-10-23`, class C
and C06/C07/C36) found suites read only in part: OpenSSL's own constants
`TLS1_CK_DHE_RSA_WITH_AES_128_SHA` and `SSL3_CK_RSA_RC4_40_MD5` gave nothing, because only
an IANA `TLS_` name was read as a suite; JSSE's `SSL_RSA_WITH_RC4_128_MD5` gave RC4 alone
(0 of 27); `DES-CBC-SHA` and `EXP-RC4-MD5` are RSA key exchange and gave no RSA; the
SHA-1 record MAC (`_SHA`, `-SHA`) was never a finding; ARIA, RC2 and ECCPWD suites were not
recognised. MD5 and SHA-1 used as a MAC are reported (the owner's policy, row 136).
"""

from pathlib import Path

from qrp_mcp import detectors


def _families(line: str, name: str = "suites.c") -> set[str]:
    found = detectors.scan_source_file(Path(name), name, lines=[line],
                                       cipher_exclusions=not name.endswith(".c"))
    return {f["algorithm"] for f in found if f["evidence_kind"] != "ban"}


def test_openssl_suite_constants_are_suites():
    assert _families("#define TLS1_CK_DHE_RSA_WITH_AES_128_SHA 0x03000033") == {"DH", "RSA", "SHA1"}
    assert _families("#define SSL3_CK_RSA_RC4_40_MD5 0x03000003") == {"RSA", "RC4", "MD5"}
    assert _families("#define TLS1_3_CK_AES_128_GCM_SHA256 0x03001301") == set()


def test_jsse_ssl_names_are_suites():
    line = 'sock.setEnabledCipherSuites(new String[] {"SSL_RSA_WITH_RC4_128_MD5"});'
    assert _families(line, "A.java") == {"RSA", "RC4", "MD5"}
    line = 'sock.setEnabledCipherSuites(new String[] {"SSL_DH_anon_WITH_3DES_EDE_CBC_SHA"});'
    assert _families(line, "A.java") == {"DH", "3DES", "SHA1"}
    assert _families("var s = TlsCipherSuite.TLS_DH_anon_WITH_DES_CBC_SHA;", "A.cs") == {
        "DH", "DES", "SHA1"}


def test_sha1_record_mac_and_weak_ciphers_in_psk_krb5_srp_suites():
    assert _families("server.ssl.ciphers=TLS_PSK_WITH_AES_128_CBC_SHA",
                     "application.properties") == {"SHA1"}
    assert _families("server.ssl.ciphers=TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5",
                     "application.properties") == {"RC2", "MD5"}
    assert _families("ssl_ciphers PSK-RC4-SHA;", "nginx.conf") == {"RC4", "SHA1"}
    assert _families("CipherString = SRP-3DES-EDE-CBC-SHA", "openssl.cnf") == {"3DES", "SHA1"}
    # SHA-256 is not SHA-1.
    assert _families("ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256;", "nginx.conf") == {"ECDH", "RSA"}


def test_suites_whose_name_omits_rsa():
    assert _families("ssl_ciphers EXP-RC4-MD5;", "nginx.conf") == {"RSA", "RC4", "MD5"}
    assert _families("CipherString = DES-CBC-SHA", "openssl.cnf") == {"RSA", "DES", "SHA1"}
    assert _families("ssl_ciphers EXP-RC2-CBC-MD5;", "nginx.conf") == {"RSA", "RC2", "MD5"}
    # OpenSSL's names for TLS_ECDHE_RSA_WITH_ARIA_*: the RSA is not in the string.
    assert _families("ssl_ciphers ECDHE-ARIA128-GCM-SHA256;", "nginx.conf") == {"ECDH", "RSA"}


def test_aria_and_eccpwd_suites():
    assert _families("ssl_ciphers DHE-DSS-ARIA128-GCM-SHA256;", "nginx.conf") == {"DH", "DSA"}
    assert _families("server.ssl.ciphers=TLS_ECCPWD_WITH_AES_128_GCM_SHA256",
                     "application.properties") == {"EC"}


def test_words_that_are_not_suites_stay_silent():
    for line in ("SSL_CTX_set_cipher_list(ctx, list);", "#define SSL_OP_NO_SSLv3 0x02000000",
                 "int r = SSL_read(ssl, buf, n);", "#define TLS1_FLAGS_SKIP_CERT_VERIFY 0x0010",
                 "DESCRIPTION = 'sha-based-cache'", "x = rsa-sha-thing;"):
        assert _families(line) == set(), line
