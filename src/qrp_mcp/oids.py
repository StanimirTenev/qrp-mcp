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

# Rows 477, 478: the 18 composite ML-DSA signatures of RFC 10073 section 7 (read 15.11.2026 from
# the RFC text): OID -> (name, label, (ML-DSA half, traditional half), pre-hash). A half is
# (family, parameter set, curve or RSA size, or None). The certificate parser reads the same
# table (certificates.COMPOSITE_SIGNATURES).
COMPOSITE_ML_DSA: dict[str, tuple[str, str, tuple[tuple[str, str | None], ...], str]] = {
    f"1.3.6.1.5.5.7.6.{arc}": (name, label, (("ML-DSA", mldsa), (family, param)), prehash)
    for arc, name, label, mldsa, family, param, prehash in (
        (37, "id-MLDSA44-RSA2048-PSS-SHA256", "COMPSIG-MLDSA44-RSA2048-PSS-SHA256", "44", "RSA", "2048", "SHA256"),
        (38, "id-MLDSA44-RSA2048-PKCS15-SHA256", "COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256", "44", "RSA", "2048", "SHA256"),
        (39, "id-MLDSA44-Ed25519-SHA512", "COMPSIG-MLDSA44-Ed25519-SHA512", "44", "Ed25519", None, "SHA512"),
        (40, "id-MLDSA44-ECDSA-P256-SHA256", "COMPSIG-MLDSA44-ECDSA-P256-SHA256", "44", "ECDSA", "P-256", "SHA256"),
        (41, "id-MLDSA65-RSA3072-PSS-SHA512", "COMPSIG-MLDSA65-RSA3072-PSS-SHA512", "65", "RSA", "3072", "SHA512"),
        (42, "id-MLDSA65-RSA3072-PKCS15-SHA512", "COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512", "65", "RSA", "3072", "SHA512"),
        (43, "id-MLDSA65-RSA4096-PSS-SHA512", "COMPSIG-MLDSA65-RSA4096-PSS-SHA512", "65", "RSA", "4096", "SHA512"),
        (44, "id-MLDSA65-RSA4096-PKCS15-SHA512", "COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512", "65", "RSA", "4096", "SHA512"),
        (45, "id-MLDSA65-ECDSA-P256-SHA512", "COMPSIG-MLDSA65-ECDSA-P256-SHA512", "65", "ECDSA", "P-256", "SHA512"),
        (46, "id-MLDSA65-ECDSA-P384-SHA512", "COMPSIG-MLDSA65-ECDSA-P384-SHA512", "65", "ECDSA", "P-384", "SHA512"),
        (47, "id-MLDSA65-ECDSA-brainpoolP256r1-SHA512", "COMPSIG-MLDSA65-ECDSA-BP256-SHA512", "65", "ECDSA", "brainpoolP256r1", "SHA512"),
        (48, "id-MLDSA65-Ed25519-SHA512", "COMPSIG-MLDSA65-Ed25519-SHA512", "65", "Ed25519", None, "SHA512"),
        (49, "id-MLDSA87-ECDSA-P384-SHA512", "COMPSIG-MLDSA87-ECDSA-P384-SHA512", "87", "ECDSA", "P-384", "SHA512"),
        (50, "id-MLDSA87-ECDSA-brainpoolP384r1-SHA512", "COMPSIG-MLDSA87-ECDSA-BP384-SHA512", "87", "ECDSA", "brainpoolP384r1", "SHA512"),
        (51, "id-MLDSA87-Ed448-SHAKE256", "COMPSIG-MLDSA87-Ed448-SHAKE256", "87", "Ed448", None, "SHAKE256/64"),
        (52, "id-MLDSA87-RSA3072-PSS-SHA512", "COMPSIG-MLDSA87-RSA3072-PSS-SHA512", "87", "RSA", "3072", "SHA512"),
        (53, "id-MLDSA87-RSA4096-PSS-SHA512", "COMPSIG-MLDSA87-RSA4096-PSS-SHA512", "87", "RSA", "4096", "SHA512"),
        (54, "id-MLDSA87-ECDSA-P521-SHA512", "COMPSIG-MLDSA87-ECDSA-P521-SHA512", "87", "ECDSA", "P-521", "SHA512"),
    )}
OIDS.update({oid: (tuple(family for family, _ in halves), name)
             for oid, (name, _, halves, _) in COMPOSITE_ML_DSA.items()})

# Row 477: the post-quantum OIDs of the NIST CSOR arcs (as classifier._OID_FAMILIES and
# cyclonedx._PQC_OID): sigAlgs 2.16.840.1.101.3.4.3.17-19 ML-DSA and .32-.34 HashML-DSA
# (FIPS 204, RFC 9881),
# .20-.31 SLH-DSA and .35-.46 HashSLH-DSA (FIPS 205, RFC 9909), kems 2.16.840.1.101.3.4.4.1-3
# ML-KEM (FIPS 203). Until 0.46.0 a number among them, alone in code, gave nothing.
OIDS.update({
    **{f"2.16.840.1.101.3.4.3.{17 + i}": (("ML-DSA",), f"id-ml-dsa-{n}")
       for i, n in enumerate((44, 65, 87))},
    # HashML-DSA, FIPS 204 section 5.4 (NIST CSOR sigAlgs .32-.34).
    **{f"2.16.840.1.101.3.4.3.{32 + i}": (("ML-DSA",), f"id-hash-ml-dsa-{n}-with-sha512")
       for i, n in enumerate((44, 65, 87))},
    **{f"2.16.840.1.101.3.4.3.{20 + i}": (("SLH-DSA",), f"id-slh-dsa-{h}-{n}{v}")
       for i, (h, n, v) in enumerate((h, n, v) for h in ("sha2", "shake")
                                     for n in (128, 192, 256) for v in "sf")},
    **{f"2.16.840.1.101.3.4.3.{n}": (("SLH-DSA",), "id-hash-slh-dsa") for n in range(35, 47)},
    **{f"2.16.840.1.101.3.4.4.{1 + i}": (("ML-KEM",), f"id-alg-ml-kem-{n}")
       for i, n in enumerate((512, 768, 1024))},
})

# The classical rest of the NIST CSOR sigAlgs arc, which the watched-arc rule below would
# otherwise call unknown (asn1crypto's algos.py lists them; read on the corpus, 15.11.2026):
# .3/.4 dsa-with-sha384/512, .5-.8 DSA, .9-.12 ECDSA and .13-.16 RSA PKCS #1 v1.5, with SHA3-224,
# -256, -384 and -512, as the NIST CSOR sigAlgs arc assigns them.
OIDS.update({
    "2.16.840.1.101.3.4.3.3": (("DSA",), "dsa-with-sha384"),
    "2.16.840.1.101.3.4.3.4": (("DSA",), "dsa-with-sha512"),
    **{f"2.16.840.1.101.3.4.3.{base + i}": ((family,), f"{name}-with-sha3-{bits}")
       for base, family, name in ((5, "DSA", "id-dsa"), (9, "ECDSA", "id-ecdsa"),
                                  (13, "RSA", "id-rsassa-pkcs1-v1_5"))
       for i, bits in enumerate((224, 256, 384, 512))},
})

# Row 477: an arc where new algorithm OIDs are assigned. An OID one component below it that
# this version has no entry for is said ("an OID this version does not know"), not passed over.
WATCHED_ARCS = ("1.3.6.1.5.5.7.6", "2.16.840.1.101.3.4.3")
NOT_KNOWN = "an OID this version does not know"
_WATCHED = re.compile(r"(?<![\d.])(1\.3\.6\.1\.5\.5\.7\.6|2\.16\.840\.1\.101\.3\.4\.3)"
                      r"\.(\d+)(?![\d.])")


def not_known(line: str) -> list[tuple[str, str]]:
    """(OID, arc) for each OID one component under a watched arc that the table does not hold."""
    if "5.5.7.6." not in line and "101.3.4.3." not in line:
        return []
    return [(m.group(0), m.group(1)) for m in _WATCHED.finditer(line) if m.group(0) not in OIDS]


# Dotted, or comma-separated inside braces (Go's asn1.ObjectIdentifier, Java int arrays).
# The whole dotted run (a longer OID is another OID), not the tail of a version number.
_DOTTED = re.compile(r"(?<![\d.])[12]\.\d+(?:\.\d+){2,}")
_BRACED = re.compile(r"\{\s*([12](?:\s*,\s*\d+){3,})\s*\}")


def scan(line: str) -> list[tuple[str, int, str]]:
    """(family, position, description) for each family a well-known OID in the line names."""
    # Every OID in the table has one of these in it; most lines have none.
    if ("840" not in line and "1.3.1" not in line and "3, 1" not in line
            and "5.5.7.6." not in line):
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
