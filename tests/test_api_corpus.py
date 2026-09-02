"""What cryptography looks like in C and in .NET, pinned as a contract.

The scanner has three layers -- which file is opened, what is extracted from it,
what the extraction means -- and a gap in any one of them is invisible from the
other two. Teaching it to open .h and .ps1 fixed the first layer and left this
one untouched: the patterns were written for import statements in scripting
languages (crypto/rsa, hazmat.primitives, Crypto.PublicKey), so the platform's
own Windows agent could read RSA and ECDSA public keys off X.509 certificates in
a file that was now being read and still reported nothing.

Each line below is the shape the real API takes, not a paraphrase of it.
"""

from __future__ import annotations

import pytest

from qrp_mcp.detectors import ALGORITHM_PATTERNS

# (source line, the algorithm it must be reported as)
C_OPENSSL = [
    ("RSA *rsa = RSA_new();", "RSA"),
    ("RSA_generate_key_ex(rsa, 2048, e, NULL);", "RSA"),
    ("EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);", "RSA"),
    ("PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);", "RSA"),
    ("DSA *dsa = DSA_new();", "DSA"),
    ("EC_KEY *k = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);", "EC"),
    ("ECDSA_do_sign(digest, dlen, eckey);", "ECDSA"),
    ("DH *dh = DH_new();", "DH"),
    ("SHA1_Init(&ctx);", "SHA1"),
    ("md = EVP_md5();", "MD5"),
    ("DES_set_key_unchecked(&key, &schedule);", "DES"),
    ("EVP_rc4()", "RC4"),
]

DOTNET_POWERSHELL = [
    # The exact call in agents/windows-host-agent/collect.ps1.
    ("[System.Security.Cryptography.X509Certificates.RSACertificateExtensions]"
     "::GetRSAPublicKey($c)", "RSA"),
    ("[System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]"
     "::GetECDsaPublicKey($c)", "ECDSA"),
    ("$rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider(2048)", "RSA"),
    ("New-SelfSignedCertificate -KeyAlgorithm RSA -KeyLength 2048", "RSA"),
    # .NET spells it ECDsa, and names the curve with an underscore suffix. A word
    # boundary refused both halves of that.
    ("New-SelfSignedCertificate -KeyAlgorithm ECDSA_nistP256", "ECDSA"),
    ("$k = [System.Security.Cryptography.ECDsaCng]::new()", "ECDSA"),
    ("$dh = [System.Security.Cryptography.ECDiffieHellmanCng]::new()", "DH"),
    ("$h = [System.Security.Cryptography.SHA1Managed]::new()", "SHA1"),
    ("$m = [System.Security.Cryptography.MD5CryptoServiceProvider]::new()", "MD5"),
]


def _algorithms(line: str) -> set[str]:
    return {name for name, _, pattern in ALGORITHM_PATTERNS if pattern.search(line)}


@pytest.mark.parametrize("line,expected", C_OPENSSL)
def test_c_and_openssl_api_is_recognised(line, expected):
    assert expected in _algorithms(line), f"{expected} not found in: {line}"


@pytest.mark.parametrize("line,expected", DOTNET_POWERSHELL)
def test_dotnet_and_powershell_api_is_recognised(line, expected):
    assert expected in _algorithms(line), f"{expected} not found in: {line}"


# Widening a pattern is how false positives arrive, so the guards are pinned too.
NOT_CRYPTOGRAPHY = [
    "FECDSA_thing = 1",           # the letter lookbehind still protects
    "# a note about the rsa building on Main Street",
    "int des_moines_population = 0;",
    "New-SelfSignedCertificate -Subject cn=test",   # algorithm not stated: claim nothing
]


@pytest.mark.parametrize("line", NOT_CRYPTOGRAPHY)
def test_ordinary_lines_are_not_read_as_algorithms(line):
    assert _algorithms(line) == set(), f"false positive on: {line}"
