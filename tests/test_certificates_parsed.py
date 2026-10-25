"""Every certificate in a bundle, read with `cryptography`, on its own line (release C).

ZA-OPRAVYANE row 127: a PEM bundle was reported once, at line 1, as object identifiers
"observed in the file; the file was not decoded as a certificate". certbot's
fullchain1.pem:30 (the second certificate) and li-trust-store's ca-bundle.pem:29 were
PostShor's rows, not ours. The probe of 01-tablo M6 is a three-certificate bundle
(RSA-2048/sha256WithRSA, P-256/ecdsa-with-SHA384, Ed25519); this file builds the same
three and asks for three lines, each with key, signature and validity.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa, rsa
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from cryptography.x509.oid import NameOID

from qrp_mcp import certificates, cyclonedx
from qrp_mcp.certificates import scan_certificate_file
from qrp_mcp.scan import scan_directory

UTC = datetime.timezone.utc
START = datetime.datetime(2026, 10, 25, 2, 29, 20, tzinfo=UTC)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(key, cn: str, days: int, digest, issuer_key=None, issuer_cn: str | None = None):
    builder = (x509.CertificateBuilder()
               .subject_name(_name(cn))
               .issuer_name(_name(issuer_cn or cn))
               .public_key(key.public_key())
               .serial_number(1000 + days)
               .not_valid_before(START)
               .not_valid_after(START + datetime.timedelta(days=days)))
    return builder.sign(issuer_key or key, digest)


def _pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture(scope="module")
def three():
    """The 01-tablo M6 bundle: RSA-2048/sha256, P-256/ecdsa-with-SHA384, Ed25519."""
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ed_key = ed25519.Ed25519PrivateKey.generate()
    return [
        _cert(rsa_key, "probe-rsa", 365, hashes.SHA256()),
        _cert(ec_key, "probe-ecdsa", 730, hashes.SHA384()),
        _cert(ed_key, "probe-ed25519", 1095, None),
    ], (rsa_key, ec_key, ed_key)


def _bundle(tmp_path: Path, certs) -> tuple[Path, list[int]]:
    text, lines = "", []
    for cert in certs:
        lines.append(text.count("\n") + 1)
        text += _pem(cert)
    path = tmp_path / "bundle.pem"
    path.write_text(text)
    return path, lines


def _cert_rows(algorithms):
    return [a for a in algorithms if a.get("certificate")]


def test_each_certificate_of_a_bundle_on_its_own_begin_line(tmp_path, three):
    path, lines = _bundle(tmp_path, three[0])
    algorithms, _ = scan_certificate_file(path, "bundle.pem")
    rows = _cert_rows(algorithms)
    assert sorted({r["line"] for r in rows}) == lines
    by_line = {}
    for row in rows:
        by_line.setdefault(row["line"], set()).add(row["algorithm"])
    assert by_line[lines[0]] == {"RSA"}
    assert by_line[lines[1]] == {"EC", "ECDSA"}
    assert by_line[lines[2]] == {"Ed25519"}
    # Nothing from this file is the old line-1 sentence: every block was decoded.
    assert not [a for a in algorithms if "not decoded" in a["description"]]


def test_each_row_carries_key_signature_and_validity(tmp_path, three):
    path, lines = _bundle(tmp_path, three[0])
    algorithms, _ = scan_certificate_file(path, "bundle.pem")
    certs = {r["line"]: r["certificate"] for r in _cert_rows(algorithms)}
    rsa_c, ec_c, ed_c = (certs[n] for n in lines)
    assert rsa_c["public_key"] == {"algorithm": "RSA", "size": 2048,
                                   "oid": "1.2.840.113549.1.1.1"}
    assert rsa_c["signature_algorithm"]["name"] == "sha256WithRSAEncryption"
    assert rsa_c["signature_algorithm"]["oid"] == "1.2.840.113549.1.1.11"
    assert rsa_c["not_before"] == "2026-10-25T02:29:20Z"
    assert rsa_c["not_after"] == "2027-10-25T02:29:20Z"
    assert ec_c["public_key"]["curve"] == "P-256" and ec_c["public_key"]["size"] == 256
    assert ec_c["signature_algorithm"]["name"] == "ecdsa-with-SHA384"
    assert ed_c["public_key"]["algorithm"] == "Ed25519"
    assert ed_c["signature_algorithm"]["name"] == "ed25519"
    for c, cn in ((rsa_c, "probe-rsa"), (ec_c, "probe-ecdsa"), (ed_c, "probe-ed25519")):
        assert c["subject_cn"] == cn and c["issuer_cn"] == cn
        assert c["subject"] == f"CN={cn}"
        assert c["self_signed"] is True
        assert c["format"] == "PEM"
        assert len(c["sha256"]) == 64
    # The row's own size and curve are the certificate's, not the file's.
    ec_row = next(r for r in _cert_rows(algorithms) if r["line"] == lines[1]
                  and r["algorithm"] == "EC")
    assert ec_row["curve"] == "P-256" and ec_row["key_size"] == 256
    rsa_row = next(r for r in _cert_rows(algorithms) if r["line"] == lines[0])
    assert rsa_row["key_size"] == 2048


def test_expiry_is_relative_to_source_date_epoch(tmp_path, three, monkeypatch):
    path, lines = _bundle(tmp_path, three[0])
    # 2028-01-01: the RSA certificate (to 2027-10-25) has expired, the other two have not.
    monkeypatch.setenv("SOURCE_DATE_EPOCH", str(int(datetime.datetime(
        2028, 1, 1, tzinfo=UTC).timestamp())))
    algorithms, _ = scan_certificate_file(path, "bundle.pem")
    certs = {r["line"]: r["certificate"] for r in _cert_rows(algorithms)}
    assert [certs[n]["expired"] for n in lines] == [True, False, False]
    assert certs[lines[0]]["expired_as_of"] == "2028-01-01T00:00:00Z"
    assert certs[lines[0]]["expired_basis"] == "SOURCE_DATE_EPOCH"


def test_expiry_without_source_date_epoch_is_the_scan_clock(tmp_path, three, monkeypatch):
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    path, _ = _bundle(tmp_path, three[0][:1])
    algorithms, _ = scan_certificate_file(path, "bundle.pem")
    cert = _cert_rows(algorithms)[0]["certificate"]
    assert cert["expired_basis"] == "scan time"
    assert cert["expired"] is (datetime.datetime.now(UTC) > START + datetime.timedelta(days=365))


def test_a_certificate_signed_by_another_is_not_self_signed(tmp_path, three):
    _, (rsa_key, ec_key, _) = three
    leaf = _cert(ec_key, "leaf.example", 90, hashes.SHA256(), issuer_key=rsa_key,
                 issuer_cn="probe-rsa")
    path, lines = _bundle(tmp_path, [leaf, three[0][0]])
    algorithms, _ = scan_certificate_file(path, "bundle.pem")
    rows = _cert_rows(algorithms)
    first = {r["algorithm"] for r in rows if r["line"] == lines[0]}
    # An EC key signed with RSA: both families, at the leaf's line.
    assert first == {"EC", "RSA"}
    cert = next(r["certificate"] for r in rows if r["line"] == lines[0])
    assert cert["self_signed"] is False
    assert cert["issuer_cn"] == "probe-rsa" and cert["subject_cn"] == "leaf.example"


def test_sha1_in_the_signature_is_named(tmp_path, three):
    # This `cryptography` will not sign with SHA-1, so the identifier is swapped in the DER:
    # sha256WithRSAEncryption (...1.1.11) and sha1WithRSAEncryption (...1.1.5) are the
    # same length. The signature no longer verifies; what is read is the identifier.
    der = three[0][0].public_bytes(serialization.Encoding.DER)
    sha256_rsa = bytes.fromhex("06092a864886f70d01010b")
    assert der.count(sha256_rsa) == 2
    (tmp_path / "old.der").write_bytes(der.replace(sha256_rsa, sha256_rsa[:-1] + b"\x05"))
    algorithms, _ = scan_certificate_file(tmp_path / "old.der", "old.der")
    rows = _cert_rows(algorithms)
    assert {r["algorithm"] for r in rows} == {"RSA", "SHA1"}
    assert rows[0]["certificate"]["signature_algorithm"]["name"] == "sha1WithRSAEncryption"
    # Issuer is subject; the swapped signature is not verified as one.
    assert rows[0]["certificate"]["self_signature_verified"] is not True


def test_an_ml_dsa_certificate(tmp_path):
    key = mldsa.MLDSA65PrivateKey.generate()
    path, _ = _bundle(tmp_path, [_cert(key, "pq", 365, None)])
    algorithms, _ = scan_certificate_file(path, "bundle.pem")
    rows = _cert_rows(algorithms)
    assert {r["algorithm"] for r in rows} == {"ML-DSA"}
    cert = rows[0]["certificate"]
    assert cert["public_key"]["algorithm"] == "ML-DSA"
    assert cert["public_key"]["parameter_set"] == "ML-DSA-65"
    assert cert["signature_algorithm"]["oid"] == "2.16.840.1.101.3.4.3.18"


# -- A composite certificate, by hand ----------------------------------------------------
# `cryptography` cannot sign with a composite, so the DER is assembled here: the structure
# of a certificate whose key and signature are id-MLDSA65-ECDSA-P256-SHA512
# (draft-ietf-lamps-pq-composite-sigs-19, 1.3.6.1.5.5.7.6.45). The bytes of the key and of
# the signature are filler: what is read is the identifiers.

def _tlv(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        size = bytes([n])
    elif n < 0x100:
        size = bytes([0x81, n])
    else:
        size = bytes([0x82]) + n.to_bytes(2, "big")
    return bytes([tag]) + size + body


def _oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    out = bytes([parts[0] * 40 + parts[1]])
    for value in parts[2:]:
        chunk = [value & 0x7F]
        value >>= 7
        while value:
            chunk.append(0x80 | (value & 0x7F))
            value >>= 7
        out += bytes(reversed(chunk))
    return _tlv(0x06, out)


def _composite_der(oid: str) -> bytes:
    alg = _tlv(0x30, _oid(oid))
    name = _tlv(0x30, _tlv(0x31, _tlv(0x30, _oid("2.5.4.3") + _tlv(0x0C, b"composite"))))
    validity = _tlv(0x30, _tlv(0x17, b"261025022920Z") + _tlv(0x17, b"271025022920Z"))
    spki = _tlv(0x30, alg + _tlv(0x03, b"\x00" + b"\x11" * 64))
    tbs = _tlv(0x30, _tlv(0xA0, _tlv(0x02, b"\x02")) + _tlv(0x02, b"\x07") + alg + name
               + validity + name + spki)
    return _tlv(0x30, tbs + alg + _tlv(0x03, b"\x00" + b"\x22" * 64))


def test_a_composite_certificate_names_both_halves(tmp_path):
    der = _composite_der("1.3.6.1.5.5.7.6.45")
    (tmp_path / "composite.der").write_bytes(der)
    algorithms, _ = scan_certificate_file(tmp_path / "composite.der", "composite.der")
    rows = _cert_rows(algorithms)
    assert {r["algorithm"] for r in rows} == {"ML-DSA", "ECDSA"}
    cert = rows[0]["certificate"]
    assert cert["signature_algorithm"]["name"] == "id-MLDSA65-ECDSA-P256-SHA512"
    assert cert["public_key"]["algorithm"] == "id-MLDSA65-ECDSA-P256-SHA512"
    assert cert["format"] == "DER"
    assert {r["line"] for r in rows} == {1}


def test_composite_table_is_draft_19():
    table = certificates.COMPOSITE_SIGNATURES
    assert len(table) == 18
    assert table["1.3.6.1.5.5.7.6.37"] == ("id-MLDSA44-RSA2048-PSS-SHA256", ("ML-DSA", "RSA"))
    assert table["1.3.6.1.5.5.7.6.51"] == ("id-MLDSA87-Ed448-SHAKE256", ("ML-DSA", "Ed448"))
    assert table["1.3.6.1.5.5.7.6.54"][1] == ("ML-DSA", "ECDSA")


# -- Other containers ----------------------------------------------------------------------

def test_a_der_certificate(tmp_path, three):
    (tmp_path / "a.der").write_bytes(three[0][0].public_bytes(serialization.Encoding.DER))
    algorithms, _ = scan_certificate_file(tmp_path / "a.der", "a.der")
    rows = _cert_rows(algorithms)
    assert {r["algorithm"] for r in rows} == {"RSA"}
    assert rows[0]["certificate"]["format"] == "DER" and rows[0]["line"] == 1


def test_a_pkcs7_bundle_reads_every_certificate(tmp_path, three):
    p7 = pkcs7.serialize_certificates(three[0], serialization.Encoding.PEM)
    (tmp_path / "chain.p7b").write_bytes(b"# chain\n" + p7)
    algorithms, _ = scan_certificate_file(tmp_path / "chain.p7b", "chain.p7b")
    rows = _cert_rows(algorithms)
    assert {r["certificate"]["subject_cn"] for r in rows} == {
        "probe-rsa", "probe-ecdsa", "probe-ed25519"}
    # One BEGIN line for the whole bundle: that is where each of them is.
    assert {r["line"] for r in rows} == {2}
    assert {r["certificate"]["format"] for r in rows} == {"PKCS#7"}
    assert sorted({r["certificate"]["index"] for r in rows}) == [1, 2, 3]


def test_p7b_is_a_claimed_extension():
    assert ".p7b" in certificates.CERTIFICATE_EXTENSIONS
    assert ".p7c" in certificates.CERTIFICATE_EXTENSIONS


def test_a_pkcs12_without_a_password_is_read(tmp_path, three):
    certs, (rsa_key, _, _) = three
    blob = pkcs12.serialize_key_and_certificates(
        b"x", rsa_key, certs[0], None, serialization.NoEncryption())
    (tmp_path / "a.p12").write_bytes(blob)
    algorithms, keys = scan_certificate_file(tmp_path / "a.p12", "a.p12")
    rows = _cert_rows(algorithms)
    assert {r["algorithm"] for r in rows} == {"RSA"}
    assert rows[0]["certificate"]["format"] == "PKCS#12"


def test_a_pkcs12_with_a_password_is_named_unread_with_its_reason(tmp_path, three):
    certs, (rsa_key, _, _) = three
    blob = pkcs12.serialize_key_and_certificates(
        b"x", rsa_key, certs[0], None, serialization.BestAvailableEncryption(b"pw"))
    (tmp_path / "a.p12").write_bytes(blob)
    problems = certificates.unparsed_material(tmp_path / "a.p12", "a.p12", blob)
    assert problems == [{"path": "a.p12", "line": 1, "label": "PKCS#12",
                         "reason": "password_protected"}]


def test_a_jks_keystore_is_named_unread(tmp_path):
    blob = b"\xfe\xed\xfe\xed\x00\x00\x00\x02" + b"\x00" * 40
    problems = certificates.unparsed_material(tmp_path / "a.jks", "a.jks", blob)
    assert problems == [{"path": "a.jks", "line": 1, "label": "JKS",
                         "reason": "format_not_parsed"}]


def test_a_truncated_block_is_named_and_the_good_one_still_read(tmp_path, three):
    good = _pem(three[0][0])
    bad = _pem(three[0][1]).splitlines()
    text = good + "\n".join(bad[:5] + bad[-1:]) + "\n"
    path = tmp_path / "mixed.pem"
    path.write_text(text)
    raw = path.read_bytes()
    algorithms, _ = scan_certificate_file(path, "mixed.pem", raw)
    assert {r["line"] for r in _cert_rows(algorithms)} == {1}
    second = good.count("\n") + 1
    assert certificates.unparsed_material(path, "mixed.pem", raw) == [
        {"path": "mixed.pem", "line": second, "label": "CERTIFICATE",
         "reason": "not_parsed_as_certificate"}]


def test_a_malformed_file_never_raises(tmp_path):
    for blob in (b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
                 b"\x30\x82\xff\xff\x30", b"", b"-----BEGIN PKCS7-----\n!!\n-----END PKCS7-----\n"):
        (tmp_path / "x.pem").write_bytes(blob)
        scan_certificate_file(tmp_path / "x.pem", "x.pem", blob)
        certificates.unparsed_material(tmp_path / "x.pem", "x.pem", blob)


# -- Embedded keys -------------------------------------------------------------------------

def test_a_pkcs8_key_names_its_family_and_size(tmp_path, three):
    _, (rsa_key, ec_key, _) = three
    pk8 = rsa_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
    sec1 = ec_key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption()).decode()
    (tmp_path / "k.pem").write_text(pk8 + sec1)
    _, keys = scan_certificate_file(tmp_path / "k.pem", "k.pem")
    assert [(k["line"], k["key_algorithm"], k["key_size"]) for k in keys] == [
        (1, "RSA", 2048), (pk8.count("\n") + 1, "EC", 256)]
    assert keys[1]["curve"] == "P-256"


def test_an_encrypted_key_is_named_with_its_reason(tmp_path, three):
    _, (rsa_key, _, _) = three
    enc = rsa_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.BestAvailableEncryption(b"pw"))
    (tmp_path / "k.pem").write_bytes(enc)
    _, keys = scan_certificate_file(tmp_path / "k.pem", "k.pem", enc)
    assert "key_algorithm" not in keys[0]
    assert keys[0]["key_unread"] == "password_protected"


def test_a_key_in_c_string_literals_names_its_family(tmp_path, three):
    from qrp_mcp.detectors import scan_embedded_keys
    _, (_, ec_key, _) = three
    pk8 = ec_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption()).decode()
    lines = ["static const char mykey[] ="]
    lines += [f'    "{line}\\n"' for line in pk8.splitlines()]
    lines[-1] += ";"
    found = scan_embedded_keys("a.c", lines)
    assert [(k["line"], k["key_algorithm"], k["curve"]) for k in found] == [(2, "EC", "P-256")]


def test_a_placeholder_key_body_is_not_given_a_family(tmp_path):
    """curl docs/examples/usercertinmem.c:67: the body is `XXXX...`, base64 alphabet and
    no key. Named as unread, not guessed (PostShor reports RSA there)."""
    from qrp_mcp.detectors import scan_embedded_keys
    lines = ["  static const char mykey[] =", '    "-----BEGIN PRIVATE KEY-----\\n"']
    lines += ['    "' + "X" * 64 + '\\n"'] * 3
    lines += ['    "-----END PRIVATE KEY-----\\n";']
    found = scan_embedded_keys("a.c", lines)
    assert len(found) == 1 and "key_algorithm" not in found[0]
    assert found[0]["key_unread"] == "body_not_a_key"
    # The description, which other tools and the diff key on, is unchanged.
    assert found[0]["description"] == "Embedded private key material"


# -- Through the scan and into the CBOM ------------------------------------------------------

def test_the_scan_names_unparsed_blocks_in_coverage(tmp_path, three):
    good = _pem(three[0][0])
    (tmp_path / "mixed.pem").write_text(good + "-----BEGIN CERTIFICATE-----\nMIIB\n"
                                        "-----END CERTIFICATE-----\n")
    result = scan_directory(tmp_path)
    block = result["coverage"]["examined_partly"]
    assert block["reason"] == "material_not_parsed"
    assert block["count"] == 1
    assert block["items"] == [{"path": "mixed.pem", "line": good.count("\n") + 1,
                               "label": "CERTIFICATE", "reason": "not_parsed_as_certificate"}]


def test_the_cbom_carries_each_certificate(tmp_path, three, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1798761600")
    jsonschema = pytest.importorskip("jsonschema")
    _bundle(tmp_path, three[0])
    doc = cyclonedx.build(scan_directory(tmp_path))
    certs = [c for c in doc["components"]
             if c.get("cryptoProperties", {}).get("assetType") == "certificate"]
    assert len(certs) == 3
    refs = {c["bom-ref"]: c for c in doc["components"]}
    by_name = {c["name"]: c for c in certs}
    rsa_c = by_name["CN=probe-rsa"]["cryptoProperties"]["certificateProperties"]
    assert rsa_c["subjectName"] == "CN=probe-rsa" and rsa_c["issuerName"] == "CN=probe-rsa"
    assert rsa_c["notValidBefore"] == "2026-10-25T02:29:20Z"
    assert rsa_c["notValidAfter"] == "2027-10-25T02:29:20Z"
    assert rsa_c["certificateFormat"] == "X.509"
    assert refs[rsa_c["signatureAlgorithmRef"]]["name"] == "RSA"
    key = refs[rsa_c["subjectPublicKeyRef"]]
    assert key["cryptoProperties"]["assetType"] == "related-crypto-material"
    material = key["cryptoProperties"]["relatedCryptoMaterialProperties"]
    assert material["type"] == "public-key" and material["size"] == 2048
    assert refs[material["algorithmRef"]]["name"] == "RSA"
    ec_c = by_name["CN=probe-ecdsa"]["cryptoProperties"]["certificateProperties"]
    assert refs[ec_c["signatureAlgorithmRef"]]["name"] == "ECDSA"
    assert refs[refs[ec_c["subjectPublicKeyRef"]]["cryptoProperties"][
        "relatedCryptoMaterialProperties"]["algorithmRef"]]["name"] == "EC"
    # Validity is data; nothing about the clock is in the document.
    assert "expired" not in json.dumps(certs)
    schema_dir = Path(__file__).parent / "schema"
    schema = json.loads((schema_dir / "bom-1.6.schema.json").read_text())
    store = {
        "http://cyclonedx.org/schema/spdx.SNAPSHOT.schema.json":
            json.loads((schema_dir / "spdx.schema.json").read_text()),
        "http://cyclonedx.org/schema/jsf-0.82.SNAPSHOT.schema.json":
            json.loads((schema_dir / "jsf-0.82.schema.json").read_text()),
    }
    validator = jsonschema.Draft7Validator(
        schema, resolver=jsonschema.RefResolver.from_schema(schema, store=store),
        format_checker=jsonschema.FormatChecker())
    assert not list(validator.iter_errors(doc))


def test_the_same_certificate_in_two_files_is_one_component(tmp_path, three):
    (tmp_path / "a.pem").write_text(_pem(three[0][0]))
    (tmp_path / "b.pem").write_text(_pem(three[0][1]) + _pem(three[0][0]))
    doc = cyclonedx.build(scan_directory(tmp_path))
    certs = [c for c in doc["components"]
             if c.get("cryptoProperties", {}).get("assetType") == "certificate"]
    rsa_c = next(c for c in certs if c["name"] == "CN=probe-rsa")
    assert sorted((o["location"], o["line"]) for o in rsa_c["evidence"]["occurrences"]) == [
        ("a.pem", 1), ("b.pem", _pem(three[0][1]).count("\n") + 1)]
    assert len(certs) == 2


def test_the_cbom_is_byte_identical_across_runs_and_clocks(tmp_path, three, monkeypatch):
    _bundle(tmp_path, three[0])
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1798761600")
    first = cyclonedx.build(scan_directory(tmp_path))
    again = cyclonedx.build(scan_directory(tmp_path))
    assert json.dumps(first, sort_keys=True) == json.dumps(again, sort_keys=True)
    # Ten years on every certificate has expired; only the stated timestamp may move.
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "2114380800")
    later = cyclonedx.build(scan_directory(tmp_path))
    assert first["components"] == later["components"]
    assert first["serialNumber"] == later["serialNumber"]
