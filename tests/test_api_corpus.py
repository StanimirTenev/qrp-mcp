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

from pathlib import Path

from qrp_mcp.detectors import ALGORITHM_PATTERNS, _is_excluded

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
    found = set()
    for name, _, pattern in ALGORITHM_PATTERNS:
        match = pattern.search(line)
        if match and not _is_excluded(line, match.start()):
            found.add(name)
    return found


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


# --- caught in the wild -----------------------------------------------------
# Every line below is copied from a well-known repository, where the scanner
# reported an algorithm that is not there. They are kept verbatim because a
# paraphrase would not have reproduced any of them.
WILD_FALSE_POSITIVES = [
    # Bitcoin Core, src/tinyformat.h: "n truncated", matched NTRU 22 times.
    ("// Format at most ntrunc characters to the given stream.", "NTRU"),
    ("inline void formatTruncated(std::ostream& out, const T& v, int ntrunc)", "NTRU"),
    # Bitcoin Core, src/qt/locale/bitcoin_ve.ts: "sike" is a word in Venda. This
    # one would have reported the single broken scheme in the list as present in
    # Bitcoin.
    ('<translation type="unfinished">Kha vha sike Tshipatshi</translation>', "SIKE"),
    # Bitcoin Core, src/kernel/chainparams.cpp: node service flags in hex.
    ('vSeeds.emplace_back("seed.mainnet.achownodes.xyz."); '
     '// only supports x1, x5, x9, x408, x448, xc08', "X448"),
    # Certbot, Apache fixtures: an OpenSSL cipher string names what it BANS.
    # Reporting these does not pad the answer, it inverts it.
    ('SSLCipherSuite "EECDH+aRSA+AESGCM EECDH !aNULL !eNULL !LOW !3DES !MD5 !EXP"', "DES"),
    ('SSLCipherSuite "EECDH+aRSA+AESGCM EECDH !aNULL !eNULL !LOW !3DES !MD5 !EXP"', "MD5"),
]


def _scan_line(tmp_path, line, *, as_config=False):
    from qrp_mcp.detectors import scan_source_file
    f = tmp_path / ("t.conf" if as_config else "t.c")
    f.write_text(line + "\n", encoding="utf-8")
    found = scan_source_file(f, f.name, cipher_exclusions=as_config)
    return {r["algorithm"] for r in found}


@pytest.mark.parametrize("line,must_not_report", WILD_FALSE_POSITIVES)
def test_lines_from_real_repositories_are_not_misread(tmp_path, line, must_not_report):
    as_config = "SSLCipherSuite" in line
    assert must_not_report not in _scan_line(tmp_path, line, as_config=as_config), line


# "!" is a cipher exclusion in configuration and logical negation in C. Applying
# the config rule to source deleted 190 real findings in OpenSSL alone.
C_NEGATION = [
    ("if (!MD5_Init(&c))", "MD5"),
    ("if (!EC_POINT_set_affine_coordinates(group, point, x, y, ctx))", "EC"),
    ("if (!ml_kem_has(key, selection))", "ML-KEM"),
    ("if (!slh_dsa_key_hash_init(ret))", "SLH-DSA"),
    ("if (!DH_generate_key(dh))", "DH"),
    ("if (!ecdsa_sign_setup(eckey, NULL, &kinv, &r, dgst, dlen,", "ECDSA"),
]


@pytest.mark.parametrize("line,expected", C_NEGATION)
def test_logical_not_in_c_is_not_a_cipher_exclusion(tmp_path, line, expected):
    assert expected in _scan_line(tmp_path, line), f"{expected} hidden by '!' in: {line}"


def test_cipher_exclusion_still_applies_in_configuration(tmp_path):
    line = 'SSLCipherSuite "EECDH+aRSA !aNULL !eNULL !LOW !3DES !MD5 !EXP"'
    assert "DES" not in _scan_line(tmp_path, line, as_config=True)


# The same fixes must not cost the true positives they sit next to.
WILD_TRUE_POSITIVES = [
    ("KexAlgorithms sntrup761x25519-sha512@openssh.com", "NTRU"),   # OpenSSH
    ("crypto_kem_ntruhrss701_keypair(pk, sk);", "NTRU"),
    ("static const char *sikep434_name = \"SIKEp434\";", "SIKE"),
    ("SIKE was broken by Castryck-Decru in 2022", "SIKE"),
    ("EVP_PKEY_X448", "X448"),                                       # OpenSSL
    ("static int ossl_x448_keygen(void)", "X448"),                    # OpenSSL
    ("from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey", "X448"),
    ("SSLCipherSuite EECDH+aRSA+RC4 RC4", "RC4"),   # allowed, not banned: real
    ("hasher = hashlib.md5()", "MD5"),
    # Certbot again: the exclusion guard must not eat the name it sits beside.
    ("'X25519PublicKey', 'X448PublicKey'],", "X448"),
    ("'X25519PublicKey', 'X448PublicKey'],", "X25519"),
]


@pytest.mark.parametrize("line,expected", WILD_TRUE_POSITIVES)
def test_the_guards_do_not_cost_the_true_positives(line, expected):
    assert expected in _algorithms(line), f"{expected} lost on: {line}"


def test_one_line_yields_one_finding_per_algorithm(tmp_path):
    """Several patterns carry the same name -- ECDSA is matched by its own name and
    by secp256k1, X448 by its upper and lower case forms. Counting each separately
    inflates the headline number by how many ways the line could be spotted, which
    is not a property of the code being scanned."""
    from qrp_mcp.detectors import scan_source_file
    f = tmp_path / "a.c"
    f.write_text("secp256k1_ecdsa_sign(ctx, &sig, msg, key);\n", encoding="utf-8")
    found = scan_source_file(f, "a.c")
    assert [r["algorithm"] for r in found].count("ECDSA") == 1
