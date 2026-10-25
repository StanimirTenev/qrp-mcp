"""TLS groups set from C, and the RFC 7919 FFDHE groups (ZA-OPRAVYANE row 124).

curl lib/vtls/openssl.c:3896 `SSL_CTX_set1_curves_list(octx->ssl_ctx, ...)` had no EC row:
the list is a variable, and the group reader reads names only. The curves API names its
family by itself, so the call is EC key agreement. The groups API does not (a group list
can hold FFDHE and ML-KEM hybrids): with a literal it is read as before, without one it
invents nothing. `groups=ffdhe6144` (mbedtls tests/ssl-opt.sh:14195) was not read: an
FFDHE group name is DH wherever it stands, as a word of its own.
"""

from pathlib import Path

import pytest

from qrp_mcp import detectors


def _families(line: str, name: str = "a.c") -> set[str]:
    found = detectors.scan_source_file(Path(name), name, lines=[line])
    return {f["algorithm"] for f in found if f["evidence_kind"] not in ("ban", "comment")}


@pytest.mark.parametrize("line", [
    "if(!SSL_CTX_set1_curves_list(octx->ssl_ctx, OSSL_CURVE_CAST(curves))) {",
    "SSL_set1_curves_list(ssl, list);",
    "SSL_CTX_set1_curves(ctx, nids, n);",
])
def test_curves_api_is_ec_key_agreement(line):
    assert "ECDH" in _families(line)


def test_groups_api_reads_the_literal_and_invents_nothing_without_one():
    assert {"ECDH", "X25519"} <= _families('SSL_CTX_set1_groups_list(ctx, "P-256:X25519");')
    assert _families("SSL_set1_groups(ssl, groups, n);") == set()
    assert _families("SSL_CTX_set1_groups_list(ctx, list);") == set()


@pytest.mark.parametrize("line,name", [
    ('"$P_CLI ca_file=x debug_level=4 sig_algs=rsa_pss_rsae_sha256 groups=ffdhe6144" \\',
     "ssl-opt.sh"),
    ("groups = ['ffdhe2048', 'ffdhe3072']", "a.py"),
    ("openssl s_client -groups ffdhe8192 -connect h:443", "run.sh"),
    ("#define G MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE4096", "a.h"),
])
def test_ffdhe_groups_are_dh(line, name):
    assert "DH" in _families(line, name)


def test_ffdhe_inside_another_word_or_a_removal():
    assert "DH" not in _families("x = myffdhe2048tool", "a.py")
    assert "DH" not in _families("Groups = X25519MLKEM768:-ffdhe2048", "openssl.cnf")
