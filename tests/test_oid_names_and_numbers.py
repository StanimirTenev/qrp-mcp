"""OIDs name the algorithm: by OpenSSL's NID_/SN_/LN_/OBJ_ and NSS's SEC_OID_ names, by the
X.509 name strings, and by number (ZA-OPRAVYANE row 134).

Measured 23.10.2026 (`qrp-kachestvo/imena-2026-10-23`): OpenSSL/NSS OID names 1,430 rows
missed (class D), X.509 name strings 131 of 484 (class F, C02), and numeric OIDs in Java and
Go code 0 of 470 (C01). The usage lines are the measurement's own shapes.
"""

import pytest

from qrp_mcp import oids
from qrp_mcp.scan import scan_directory


def _scan(tmp_path, name, line):
    (tmp_path / name).write_text(line + "\n", encoding="utf-8")
    return scan_directory(tmp_path)


@pytest.mark.parametrize("families, line", [
    ({"MD5"}, "int id = NID_md5;"), ({"DSA"}, "int id = SN_dsa;"),
    ({"RSA", "SHA1"}, "int id = OBJ_sha1WithRSAEncryption;"), ({"SHA1"}, "int id = SEC_OID_SHA1;"),
    ({"RSA"}, "int id = NID_rsaEncryption;"), ({"EC"}, "int id = NID_X9_62_id_ecPublicKey;"),
    ({"DH"}, "int id = LN_dhKeyAgreement;"), ({"DSA", "SHA224"}, "int id = NID_dsa_with_SHA224;"),
    ({"DSA", "SHA1"}, "int id = SEC_OID_ANSIX9_DSA_SIGNATURE_WITH_SHA1_DIGEST;"),
    ({"RC4"}, "int id = NID_rc4_40;"), ({"DES"}, "int id = LN_des_ecb;"),
])
def test_oid_name_constant(tmp_path, families, line):
    assert families <= set(_scan(tmp_path, "o.c", line)["detected_algorithms"])


@pytest.mark.parametrize("families, name", [
    ({"RSA"}, "rsaEncryption"), ({"RSA", "SHA1"}, "sha1WithRSAEncryption"),
    ({"DSA", "SHA1"}, "dsaWithSHA1"), ({"EC"}, "id-ecPublicKey"),
    ({"ECDSA", "SHA224"}, "ecdsa-with-SHA224"), ({"RSA", "SHA1"}, "RSA-SHA1"),
    ({"DSA"}, "dsaEncryption"), ({"MD5", "RSA"}, "md5WithRSAEncryption"),
])
def test_x509_name_string(tmp_path, families, name):
    line = f'    if cert.signature_algorithm_oid._name == "{name}": return'
    assert families <= set(_scan(tmp_path, "o.py", line)["detected_algorithms"])


@pytest.mark.parametrize("families, name, line", [
    ({"RSA", "SHA1"}, "o.java", 'use(new ASN1ObjectIdentifier("1.2.840.113549.1.1.5"));'),
    ({"ECDSA", "SHA1"}, "o.go", "\tvar _ = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}"),
    ({"EC"}, "o.js", "if (cert.siginfo.algorithmOid === '1.2.840.10045.2.1') {}"),
    ({"Ed25519"}, "o.js", "if (oid === '1.3.101.112') {}"),
    ({"DSA", "SHA1"}, "o.java", 'use(new ASN1ObjectIdentifier("1.2.840.10040.4.3"));'),
    ({"SHA1", "3DES"}, "o.js", "if (oid === '1.2.840.113549.1.12.1.3') {}"),
    ({"MD5"}, "o.go", "\tvar _ = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}"),
])
def test_numeric_oid(tmp_path, families, name, line):
    assert families <= set(_scan(tmp_path, name, line)["detected_algorithms"])


@pytest.mark.parametrize("name, line", [
    ("o.py", 'x = "rsa-logo"'), ("o.py", 'x = "ec-window"'), ("o.py", 'x = "EC-Council"'),
    ("o.py", 'x = "rsa"'),                              # a bare value is row 126, not this
    ("o.py", 'version = "1.2.840.113549.1.1.5.3"'),     # a longer OID is another OID
    ("o.py", 'v = "21.2.840.10045.2.1"'),
    ("o.c", "int id = NID_description;"), ("o.c", "int id = NID_destinationIndicator;"),
])
def test_not_an_algorithm_name(tmp_path, name, line):
    assert _scan(tmp_path, name, line)["detected_algorithms"] == []


def test_every_oid_in_the_table_is_dotted_and_named():
    for oid, (families, name) in oids.OIDS.items():
        assert oids._DOTTED.fullmatch(oid) and families and name
