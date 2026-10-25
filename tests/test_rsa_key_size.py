"""The size of an RSA key, read from its public key (ZA-OPRAVYANE row 46).

In the network-vs-code probe of 22.10.2026 four RSA files under deploy/ read as RSA
with `key_size: None` -- certificates of 2048 and 3072 bits among them -- because the
certificate was walked for object identifiers only. The size is now read from the
SubjectPublicKeyInfo (rsaEncryption, BIT STRING, RSAPublicKey modulus) and from an
`RSA PUBLIC KEY` block, so it reaches `algorithm_key_sizes`, the findings and the CBOM.

No key file is committed: certificates and keys are made at test time with
pyca/cryptography, and only public material is written to the tree.
"""

import datetime

import pytest

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory

crypto = pytest.importorskip("cryptography")
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402


def _cert(public_key, signer, name="t"):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(public_key).serial_number(1).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=30))
            .sign(signer, hashes.SHA256()))


def _rsa(bits):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def test_rsa_certificates_carry_their_size(tmp_path):
    k2048, k3072 = _rsa(2048), _rsa(3072)
    pem = serialization.Encoding.PEM
    (tmp_path / "a.crt").write_bytes(_cert(k2048.public_key(), k2048).public_bytes(pem))
    (tmp_path / "b.der").write_bytes(
        _cert(k3072.public_key(), k3072).public_bytes(serialization.Encoding.DER))
    (tmp_path / "c.pub").write_bytes(k3072.public_key().public_bytes(
        pem, serialization.PublicFormat.PKCS1))
    result = scan_directory(tmp_path)
    sizes = {f["path"]: f.get("key_size") for f in result["evidence"]["source_code"]
             if f["algorithm"] == "RSA"}
    assert sizes == {"a.crt": 2048, "b.der": 3072, "c.pub": 3072}
    assert result["algorithm_key_sizes"]["RSA"] == 2048
    assert result["algorithm_key_sizes_observed"]["RSA"] == [2048, 3072]
    names = {c["name"] for c in build(result)["components"]}
    assert {"RSA-2048", "RSA-3072"} <= names      # release 3b: one per size (M4c)
    assert "RSA" not in names                     # release 3d: no sizeless sighting


def test_an_ec_key_signed_by_rsa_gets_no_rsa_size(tmp_path):
    """The issuer's RSA signature is in the certificate; the issuer's key is not."""
    issuer = _rsa(2048)
    subject = ec.generate_private_key(ec.SECP256R1())
    (tmp_path / "ec.crt").write_bytes(
        _cert(subject.public_key(), issuer).public_bytes(serialization.Encoding.PEM))
    found = scan_directory(tmp_path)["evidence"]["source_code"]
    assert [f.get("key_size") for f in found if f["algorithm"] == "RSA"] == [None]
