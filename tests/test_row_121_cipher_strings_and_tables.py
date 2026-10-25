"""Cipher strings joined with `+` and cipher-suite tables in C (ZA-OPRAVYANE row 121).

Suites were split only at `-`: `RC4+RSA` gave RC4 and no RSA, `EECDH+aRSA:EDH+aRSA` gave
nothing, a GnuTLS priority string `+SIGN-RSA-SHA512` gave nothing, and curl's
`lib/vtls/cipher_suite.c`, the table of every TLS suite curl knows, gave 0 RSA and 0 DH
(`CS_ENTRY(0x009E, DHE,RSA,AES128,GCM,SHA256,,,)`; 12 of the 37 TRUE misses left of the
60 judged on 23.10).
"""

from pathlib import Path

import pytest

from qrp_mcp import detectors


def _families(line: str, name: str = "nginx.conf", use_only: bool = True) -> set[str]:
    cfg = Path(name).suffix in detectors.CONFIG_EXTENSIONS
    found = detectors.scan_source_file(Path(name), name, lines=[line], cipher_exclusions=cfg)
    return {f["algorithm"] for f in found
            if not use_only or f["evidence_kind"] not in ("ban", "comment")}


@pytest.mark.parametrize("line,expected", [
    ("ssl_ciphers  ALL:!ADH:!EXPORT56:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP;", {"RC4", "RSA"}),
    ("SSLCipherSuite EECDH+aRSA:EDH+aRSA:!aNULL", {"ECDH", "RSA", "DH"}),
    ("ssl_ciphers 'EECDH+AESGCM:EDH+AESGCM';", {"ECDH", "DH"}),
])
def test_plus_joined_selectors(line, expected):
    assert expected <= _families(line)


def test_struck_out_selectors_are_not_uses():
    found = _families("ssl_ciphers HIGH:!aNULL:!EDH+aRSA:-kRSA:EECDH+AESGCM;")
    assert "ECDH" in found and "DH" not in found and "RSA" not in found


def test_dash_suites_are_left_to_the_suite_reader():
    # DES-CBC3-SHA is triple DES; reading its parts again must not add a single DES.
    assert "DES" not in _families("ssl_ciphers DES-CBC3-SHA:RC4+RSA;")


def test_a_plus_outside_a_cipher_setting_is_not_read():
    assert "RSA" not in _families("total = RC4+RSA", "a.py")


def test_gnutls_priority_string():
    line = ('--priority=NORMAL:-SIGN-ALL:+SIGN-RSA-SHA512:+SIGN-RSA-PSS-RSAE-SHA512:'
            '+SIGN-ECDSA-SECP521R1-SHA512" \\')
    assert {"RSA", "ECDSA"} <= _families(line, "ssl-opt.sh")
    assert "RSA" in _families('--priority=NORMAL:-VERS-ALL:+VERS-TLS1.2:-SIGN-ALL:'
                              '+SIGN-RSA-PSS-RSAE-SHA256" \\', "ssl-opt.sh")


def test_gnutls_removal_is_not_a_use_and_pqc_is_not_dsa():
    assert "RSA" not in _families("--priority=NORMAL:-SIGN-RSA-SHA1", "a.sh")
    assert "DSA" not in _families("--priority=NORMAL:+SIGN-ML-DSA-65", "a.sh")


@pytest.mark.parametrize("line,expected", [
    ("CS_ENTRY(0x009E, DHE,RSA,AES128,GCM,SHA256,,,),", {"DH", "RSA"}),
    ("CS_ENTRY(0xC02F, ECDHE,RSA,AES128,GCM,SHA256,,,),", {"ECDH", "RSA"}),
    ("CS_ENTRY(0x00C0, TLS,RSA,WITH,CAMELLIA,256,CBC,SHA256,),", {"RSA"}),
    ("CS_ENTRY(0xC06F, RSA,PSK,ARIA256,GCM,SHA384,,,),", {"RSA"}),
    ("CS_ENTRY(0xC02A, TLS,ECDH,RSA,WITH,AES,256,CBC,SHA384),", {"ECDH", "RSA"}),
    ("CS_ENTRY(0xC013, TLS,ECDHE,RSA,WITH,AES,128,CBC,SHA),", {"ECDH", "RSA", "SHA1"}),
    ("CS_ENTRY(0x000A, TLS,RSA,WITH,3DES,EDE,CBC,SHA),", {"RSA", "3DES", "SHA1"}),
])
def test_c_cipher_suite_table(line, expected):
    assert expected <= _families(line, "cipher_suite.c")


def test_c_table_without_classical_parts_and_other_macros():
    assert _families("CS_ENTRY(0x1301, TLS,AES,128,GCM,SHA256,,,),", "cipher_suite.c") == set()
    # A hex first argument alone is not a suite table.
    assert _families("SET(0x0010, RSA, x, y);", "a.c") == set()
