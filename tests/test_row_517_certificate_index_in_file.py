"""Row 517 (17.11.2026, Georgi Ivanov; probe `linkedin-postove/2026-11-17/stai-qrp/proba-ivanov/`).

In a PEM bundle every certificate was `index: 1`: the index was counted inside each PEM block, and
a block holds one certificate. `tls_listeners` reads `index == 1` as the leaf, so in a
`fullchain.pem` (leaf, then root) the root's RSA-2048 signature entered the listener's
certificate as a second "signature on the certificate". The index is now the certificate's
place in the file: 1 for the first, 2 for the next, across blocks.

Not claimed: that the file's order is the chain's order. The first certificate in the file is
taken as the leaf, as nginx takes it (`ssl_certificate`: "the primary certificate comes first").
"""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from qrp_mcp.scan import scan_directory

UTC = datetime.timezone.utc
START = datetime.datetime(2026, 10, 25, tzinfo=UTC)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(key, cn: str, issuer_key, issuer_cn: str, digest) -> str:
    cert = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(issuer_cn))
            .public_key(key.public_key()).serial_number(517 + len(cn))
            .not_valid_before(START).not_valid_after(START + datetime.timedelta(days=365))
            .sign(issuer_key, digest))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _tree(tmp_path: Path) -> Path:
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    (tmp_path / "tls").mkdir()
    (tmp_path / "tls" / "fullchain.pem").write_text(
        _cert(leaf_key, "www.example.test", root_key, "Test Root", hashes.SHA256())
        + _cert(root_key, "Test Root", root_key, "Test Root", hashes.SHA256()))
    (tmp_path / "nginx.conf").write_text(
        "server {\n    listen 443 ssl;\n    ssl_certificate tls/fullchain.pem;\n}\n")
    return tmp_path


def test_each_certificate_has_its_place_in_the_file(tmp_path):
    result = scan_directory(_tree(tmp_path))
    rows = [r for r in result["evidence"]["source_code"] if r.get("certificate")]
    by_line = {}
    for r in rows:
        by_line.setdefault(r["line"], set()).add(r["certificate"]["index"])
    assert by_line == {1: {1}, by_line and max(by_line): {2}}
    root = [r for r in rows if r["certificate"]["self_signed"]]
    assert root and all("in certificate 2 " in r["description"] for r in root)


def test_the_root_of_a_fullchain_is_not_the_listeners_certificate(tmp_path):
    result = scan_directory(_tree(tmp_path))
    [place] = result["tls_listeners"]["places"]
    [cert] = [c for c in place["certificates"] if c["setting"] == "ssl_certificate"]
    parts = [(a["family"], a.get("key_size"), a["part"]) for a in cert["algorithms"]]
    # The leaf's EC P-256 key and its RSA signature (by the root); not the root's own RSA-2048.
    assert ("EC", 256, "public key") in parts
    assert not any(size == 2048 for _family, size, _part in parts), parts
    assert len(parts) == 2, parts
