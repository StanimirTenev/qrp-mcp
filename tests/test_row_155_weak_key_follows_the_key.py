"""ZA-OPRAVYANE row 155: a self-signed P-384 certificate whose private scalar is 4 gave two
findings for one key: `EC-384` with `weak_key: true` (critical) and `ECDSA-384` with
`weak_key: false` (high). The ECDSA signature on a self-signed certificate whose signature
verifies is made by that same key, so the flag goes with it. A certificate signed by another
key keeps the issuer's signature unflagged: that is a different key."""

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from qrp_mcp.scan import scan_directory


def _cert(subject_key, signing_key, subject, issuer):
    now = datetime.datetime(2026, 10, 27, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
            .public_key(subject_key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365))
            .sign(signing_key, hashes.SHA384()))
    return cert.public_bytes(serialization.Encoding.PEM)


def _findings(tmp_path, pem):
    t = tmp_path / "repo"
    t.mkdir()
    (t / "ca.pem").write_bytes(pem)
    return {f["algorithm_family"]: f for f in scan_directory(t)["findings"]}


def test_self_signed_weak_key_flags_its_signature_too(tmp_path):
    weak = ec.derive_private_key(4, ec.SECP384R1())
    f = _findings(tmp_path, _cert(weak, weak, "Weak CA", "Weak CA"))
    assert f["EC"]["weak_key"] is True
    assert f["ECDSA"]["weak_key"] is True and f["ECDSA"]["severity"] == "critical"
    assert "same key" in f["ECDSA"]["reason"]


def test_issuer_signature_is_another_key(tmp_path):
    weak = ec.derive_private_key(4, ec.SECP384R1())
    issuer = ec.generate_private_key(ec.SECP384R1())
    f = _findings(tmp_path, _cert(weak, issuer, "Weak leaf", "Strong CA"))
    assert f["EC"]["weak_key"] is True
    assert f["ECDSA"]["weak_key"] is False
