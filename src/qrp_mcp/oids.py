"""Algorithm OIDs written as numbers in code (ZA-OPRAVYANE row 134).

`new ASN1ObjectIdentifier("1.2.840.113549.1.1.5")`, Go's `asn1.ObjectIdentifier{1, 2, 840,
113549, 1, 1, 5}`, node-forge's `'1.2.840.10045.2.1'`: the algorithm is named by its number
and by nothing else, and 0 of 470 such literals were found (qrp-kachestvo/imena-2026-10-23,
registries and languages, 23.10.2026). Only well-known OIDs, each from the RFC that assigns
or registers it; an OID not in the table is left alone rather than guessed at. A hash or a
cipher named inside a signature or PBE OID is a second family, as in the name it stands for.
"""

from __future__ import annotations

import re

# OID -> (families, name). Sources: RFC 8017 App. C and RFC 4055 (PKCS #1), RFC 3279
# (MD5, SHA-1, DSA, DH, ECDSA with SHA-1), RFC 5480 (EC public keys and named curves),
# RFC 5758 (DSA and ECDSA with SHA-2), RFC 8410 (X25519, X448, Ed25519, Ed448), RFC 8018
# (PBES1, DES-CBC, 3DES, HMAC-SHA-1), RFC 7292 App. C (PKCS #12 PBE), RFC 3370 (ESDH, 3DES
# key wrap).
OIDS: dict[str, tuple[tuple[str, ...], str]] = {
    "1.2.840.113549.1.1.1": (("RSA",), "rsaEncryption"),
    "1.2.840.113549.1.1.2": (("RSA",), "md2WithRSAEncryption"),
    "1.2.840.113549.1.1.3": (("RSA",), "md4WithRSAEncryption"),
    "1.2.840.113549.1.1.4": (("RSA", "MD5"), "md5WithRSAEncryption"),
    "1.2.840.113549.1.1.5": (("RSA", "SHA1"), "sha1WithRSAEncryption"),
    "1.2.840.113549.1.1.7": (("RSA",), "id-RSAES-OAEP"),
    "1.2.840.113549.1.1.10": (("RSA",), "id-RSASSA-PSS"),
    "1.2.840.113549.1.1.11": (("RSA",), "sha256WithRSAEncryption"),
    "1.2.840.113549.1.1.12": (("RSA",), "sha384WithRSAEncryption"),
    "1.2.840.113549.1.1.13": (("RSA",), "sha512WithRSAEncryption"),
    "1.2.840.113549.1.1.14": (("RSA", "SHA224"), "sha224WithRSAEncryption"),
    "1.2.840.113549.1.1.15": (("RSA",), "sha512-224WithRSAEncryption"),
    "1.2.840.113549.1.1.16": (("RSA",), "sha512-256WithRSAEncryption"),
    "1.2.840.113549.2.5": (("MD5",), "md5"),
    "1.3.14.3.2.26": (("SHA1",), "sha1"),
    "1.2.840.113549.2.7": (("SHA1",), "hmacWithSHA1"),
    "1.2.840.10040.4.1": (("DSA",), "id-dsa"),
    "1.2.840.10040.4.3": (("DSA", "SHA1"), "id-dsa-with-sha1"),
    "2.16.840.1.101.3.4.3.1": (("DSA", "SHA224"), "dsa-with-sha224"),
    "2.16.840.1.101.3.4.3.2": (("DSA",), "dsa-with-sha256"),
    "1.2.840.10046.2.1": (("DH",), "dhpublicnumber"),
    "1.2.840.10045.2.1": (("EC",), "id-ecPublicKey"),
    "1.2.840.10045.3.1.7": (("EC",), "secp256r1"),
    "1.3.132.0.34": (("EC",), "secp384r1"),
    "1.3.132.0.35": (("EC",), "secp521r1"),
    "1.2.840.10045.4.1": (("ECDSA", "SHA1"), "ecdsa-with-SHA1"),
    "1.2.840.10045.4.3.1": (("ECDSA", "SHA224"), "ecdsa-with-SHA224"),
    "1.2.840.10045.4.3.2": (("ECDSA",), "ecdsa-with-SHA256"),
    "1.2.840.10045.4.3.3": (("ECDSA",), "ecdsa-with-SHA384"),
    "1.2.840.10045.4.3.4": (("ECDSA",), "ecdsa-with-SHA512"),
    "1.3.101.110": (("X25519",), "id-X25519"),
    "1.3.101.111": (("X448",), "id-X448"),
    "1.3.101.112": (("Ed25519",), "id-Ed25519"),
    "1.3.101.113": (("Ed448",), "id-Ed448"),
    "1.3.14.3.2.7": (("DES",), "desCBC"),
    "1.2.840.113549.3.7": (("3DES",), "des-ede3-cbc"),
    "1.2.840.113549.1.5.3": (("MD5", "DES"), "pbeWithMD5AndDES-CBC"),
    "1.2.840.113549.1.5.10": (("SHA1", "DES"), "pbeWithSHA1AndDES-CBC"),
    "1.2.840.113549.1.12.1.1": (("SHA1", "RC4"), "pbeWithSHAAnd128BitRC4"),
    "1.2.840.113549.1.12.1.2": (("SHA1", "RC4"), "pbeWithSHAAnd40BitRC4"),
    "1.2.840.113549.1.12.1.3": (("SHA1", "3DES"), "pbeWithSHAAnd3-KeyTripleDES-CBC"),
    "1.2.840.113549.1.12.1.4": (("SHA1", "3DES"), "pbeWithSHAAnd2-KeyTripleDES-CBC"),
    "1.2.840.113549.1.9.16.3.5": (("DH",), "id-alg-ESDH"),
    "1.2.840.113549.1.9.16.3.6": (("3DES",), "id-alg-CMS3DESwrap"),
}

# Dotted, or comma-separated inside braces (Go's asn1.ObjectIdentifier, Java int arrays).
# The whole dotted run (a longer OID is another OID), not the tail of a version number.
_DOTTED = re.compile(r"(?<![\d.])[12]\.\d+(?:\.\d+){2,}")
_BRACED = re.compile(r"\{\s*([12](?:\s*,\s*\d+){3,})\s*\}")


def scan(line: str) -> list[tuple[str, int, str]]:
    """(family, position, description) for each family a well-known OID in the line names."""
    # Every OID in the table has one of these in it; most lines have none.
    if "840" not in line and "1.3.1" not in line and "3, 1" not in line:
        return []
    found = [(m.group(0), m.start()) for m in _DOTTED.finditer(line)]
    found += [(re.sub(r"\s*,\s*", ".", m.group(1)), m.start(1)) for m in _BRACED.finditer(line)]
    out: list[tuple[str, int, str]] = []
    for oid, pos in found:
        entry = OIDS.get(oid)
        if entry:
            out += [(family, pos, f"{family} named by the OID {oid} ({entry[1]})")
                    for family in entry[0]]
    return out
