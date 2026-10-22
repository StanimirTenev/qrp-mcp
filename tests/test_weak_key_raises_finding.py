"""A recoverable private key raises the finding it belongs to (ZA-OPRAVYANE row 51,
raised in public by Sagar A., 22.10.2026).

`evidence.weak_keys` said "the public point is 4*G on P-384, so the private scalar is 4",
and the EC finding beside it stayed `weak_key: false`, severity high, with
`summary.weak_count` 0. The evidence and the finding now say the same thing.
The key is generated here, never committed.
"""

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from qrp_mcp.scan import scan_directory


def _cert(scalar):
    key = ec.derive_private_key(scalar, ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "weak ca")])
    now = datetime.datetime(2026, 10, 22, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA384()))
    return cert.public_bytes(serialization.Encoding.PEM)


def test_recoverable_key_raises_the_finding(tmp_path):
    (tmp_path / "ca_weak4.pem").write_bytes(_cert(4))
    result = scan_directory(tmp_path)
    assert result["evidence"]["weak_keys"][0]["scalar"] == 4
    ec_finding = next(f for f in result["findings"] if f["algorithm_family"] == "EC")
    assert ec_finding["weak_key"] is True
    assert ec_finding["severity"] == "critical"
    assert "Private key recoverable" in ec_finding["reason"]
    assert result["summary"]["weak_count"] >= 1
    assert result["summary"]["highest_severity"] == "critical"


def test_random_key_is_not_raised(tmp_path):
    (tmp_path / "ca.pem").write_bytes(_cert(0x1234567890ABCDEF1234567890ABCDEF))
    result = scan_directory(tmp_path)
    assert result["evidence"]["weak_keys"] == []
    ec_finding = next(f for f in result["findings"] if f["algorithm_family"] == "EC")
    assert ec_finding["weak_key"] is False
    assert result["summary"]["weak_count"] == 0
