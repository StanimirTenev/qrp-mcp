"""ZA-OPRAVYANE row 431 (the W2 cross-OS round, 04.11.2026): `expired` is relative to `--as-of`,
and no scan carries the time of day.

55 X.509 rows of certbot carried `expired_as_of` = the scan's wall-clock time, so two scans of
one tree were never byte-equal, and `expired` flips the day a certificate expires between runs
-- a date-dependent finding `--as-of` did not pin (it applied only with `--mandate`). Now
`--as-of YYYY-MM-DD` pins it on every scan; without it SOURCE_DATE_EPOCH, else the scan's date
at 00:00 UTC (`scan date`), never the clock.
"""

from __future__ import annotations

import datetime
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from qrp_mcp.server import main

UTC = datetime.timezone.utc


def _tree(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "probe")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(7)
            .not_valid_before(datetime.datetime(2025, 1, 1, tzinfo=UTC))
            .not_valid_after(datetime.datetime(2027, 1, 1, tzinfo=UTC))
            .sign(key, hashes.SHA256()))
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return tree


def _certs(tmp_path, tree, *extra):
    out = tmp_path / f"s{len(list(tmp_path.iterdir()))}.json"
    with pytest.raises(SystemExit) as done:
        main(["scan", str(tree), "--no-config", "--level", "full", "--out", str(out), *extra])
    assert done.value.code == 0
    result = json.loads(out.read_text())
    return result, [r["certificate"] for rows in result["evidence"].values() for r in rows
                    if isinstance(r, dict) and r.get("certificate")]


def test_as_of_pins_expiry_without_a_mandate(tmp_path, monkeypatch):
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    tree = _tree(tmp_path)
    _, before = _certs(tmp_path, tree, "--as-of", "2026-06-01")
    _, after = _certs(tmp_path, tree, "--as-of", "2027-06-01")
    assert before and {c["expired"] for c in before} == {False}
    assert {c["expired"] for c in after} == {True}
    assert {c["expired_as_of"] for c in before} == {"2026-06-01T00:00:00Z"}
    assert {c["expired_basis"] for c in before} == {"--as-of"}


def test_two_scans_carry_the_same_certificate_rows(tmp_path, monkeypatch):
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    tree = _tree(tmp_path)
    first, certs = _certs(tmp_path, tree)
    second, _ = _certs(tmp_path, tree)
    assert first["evidence"] == second["evidence"]
    # Without --as-of: the date of the scan, never the time of day.
    assert {c["expired_basis"] for c in certs} == {"scan date"}
    assert all(c["expired_as_of"].endswith("T00:00:00Z") for c in certs)
