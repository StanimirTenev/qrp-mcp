"""A post-quantum key or certificate names its parameter set in its identifier.

ML-KEM-768 is 2.16.840.1.101.3.4.4.2 and ML-DSA-65 is 2.16.840.1.101.3.4.3.18: each NIST arc
names one set. A source line that writes `MLKEM768PrivateKey` carried `parameter_set: 768` and
got the CNSA 2.0 clause (row 210); a key file holding that same key, or a certificate whose
`public_key` said ML-DSA-65, did not. The row the profiles, the mandates and the CBOM read had
the family alone, so `--mandate cnsa-2.0` said nothing of three ML-KEM-768 / ML-DSA-65 files
on a host image, and the CBOM's ML-DSA component had no parameterSetIdentifier, OID or
nistQuantumSecurityLevel.

The keys here are built the way `openssl genpkey` 3.6 writes them by default: a PKCS#8
PrivateKeyInfo whose privateKey holds the seed and the expanded key together, which
`cryptography` 50 does not load. The bytes are random; the identifier and the lengths are the
standard's (seed 64 / expanded 2400 for ML-KEM-768, seed 32 / expanded 4032 for ML-DSA-65).
"""

from __future__ import annotations

import base64
import datetime
import json
import os
import subprocess
import sys

from qrp_mcp import cyclonedx
from qrp_mcp.certificates import scan_certificate_file
from qrp_mcp.scan import scan_directory

ML_KEM_768 = "2.16.840.1.101.3.4.4.2"
ML_KEM_1024 = "2.16.840.1.101.3.4.4.3"
ML_DSA_65 = "2.16.840.1.101.3.4.3.18"


def _der(tag: int, body: bytes) -> bytes:
    n = len(body)
    length = bytes([n]) if n < 0x80 else (lambda b: bytes([0x80 | len(b)]) + b)(
        n.to_bytes((n.bit_length() + 7) // 8, "big"))
    return bytes([tag]) + length + body


def _oid(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.split(".")]
    out = bytes([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.insert(0, 0x80 | (arc & 0x7F))
            arc >>= 7
        out += bytes(chunk)
    return _der(0x06, out)


def _seed_and_expanded(oid: str, seed: int, expanded: int) -> str:
    inner = _der(0x30, _der(0x04, os.urandom(seed)) + _der(0x04, os.urandom(expanded)))
    info = _der(0x30, _der(0x02, b"\x00") + _der(0x30, _oid(oid)) + _der(0x04, inner))
    body = base64.encodebytes(info).decode().replace("\n", "")
    lines = "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
    return f"-----BEGIN PRIVATE KEY-----\n{lines}\n-----END PRIVATE KEY-----\n"


def _rows(path, rel):
    algorithms, _ = scan_certificate_file(path, rel)
    return algorithms


def test_every_nist_arc_names_one_set():
    from qrp_mcp.certificates import pqc_set
    assert pqc_set(ML_KEM_768) == ("ML-KEM", "768")
    assert pqc_set(ML_DSA_65) == ("ML-DSA", "65")
    assert pqc_set("2.16.840.1.101.3.4.3.20") == ("SLH-DSA", "SHA2-128s")
    assert pqc_set("2.16.840.1.101.3.4.3.31") == ("SLH-DSA", "SHAKE-256f")
    # Not a set: RSA, and an arc past the twelve SLH-DSA sets.
    assert pqc_set("1.2.840.113549.1.1.1") is None
    assert pqc_set("2.16.840.1.101.3.4.3.32") is None


def test_a_key_file_that_does_not_parse_still_names_its_set(tmp_path):
    (tmp_path / "mlkem768.key").write_text(_seed_and_expanded(ML_KEM_768, 64, 2400))
    (tmp_path / "mldsa65.key").write_text(_seed_and_expanded(ML_DSA_65, 32, 4032))
    kem = _rows(tmp_path / "mlkem768.key", "mlkem768.key")
    dsa = _rows(tmp_path / "mldsa65.key", "mldsa65.key")
    assert [(r["algorithm"], r.get("parameter_set")) for r in kem] == [("ML-KEM", "768")]
    assert [(r["algorithm"], r.get("parameter_set")) for r in dsa] == [("ML-DSA", "65")]
    assert "parameter set ML-KEM-768 from its object identifier" in kem[0]["description"]


def test_two_sets_of_one_family_in_a_file_give_none(tmp_path):
    (tmp_path / "both.pem").write_text(_seed_and_expanded(ML_KEM_768, 64, 2400)
                                       + _seed_and_expanded(ML_KEM_1024, 64, 3168))
    rows = _rows(tmp_path / "both.pem", "both.pem")
    assert [r["algorithm"] for r in rows] == ["ML-KEM"]
    assert "parameter_set" not in rows[0]


def test_an_ml_dsa_certificate_row_carries_the_set(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import mldsa
    from cryptography.x509.oid import NameOID
    key = mldsa.MLDSA65PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pq")])
    start = datetime.datetime(2026, 11, 9, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(start).not_valid_after(start + datetime.timedelta(days=365))
            .sign(key, None))
    (tmp_path / "mldsa65.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    rows = [r for r in _rows(tmp_path / "mldsa65.crt", "mldsa65.crt") if r.get("certificate")]
    assert [(r["algorithm"], r.get("parameter_set")) for r in rows] == [("ML-DSA", "65")]
    # What `public_key` already said, unchanged.
    assert rows[0]["certificate"]["public_key"]["parameter_set"] == "ML-DSA-65"


def test_the_set_reaches_the_mandate_through_the_cli(tmp_path):
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / "mlkem768.key").write_text(_seed_and_expanded(ML_KEM_768, 64, 2400))
    out = tmp_path / "r.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree),
                        "--mandate", "cnsa-2.0", "--as-of", "2026-11-09", "--out", str(out)],
                       capture_output=True, text=True)
    result = json.loads(out.read_text())
    row = [e for e in result["evidence"]["source_code"] if e["algorithm"] == "ML-KEM"][0]
    assert row["mandates"]["cnsa-2.0"]["status"] == "parameter_set_not_in_mandate"
    assert result["mandates"]["cnsa-2.0"]["by_status"]["parameter_set_not_in_mandate"] == 1
    # Not a deadline: the gate is unchanged by it.
    assert r.returncode == 0


def test_the_set_reaches_the_cbom(tmp_path):
    (tmp_path / "mldsa65.key").write_text(_seed_and_expanded(ML_DSA_65, 32, 4032))
    document = cyclonedx.build(scan_directory(tmp_path))
    component = next(c for c in document["components"]
                     if c.get("cryptoProperties", {}).get("assetType") == "algorithm"
                     and c["name"].startswith("ML-DSA"))
    properties = component["cryptoProperties"]
    assert properties["algorithmProperties"]["parameterSetIdentifier"] == "65"
    assert properties["algorithmProperties"]["nistQuantumSecurityLevel"] == 3
    assert properties["oid"] == ML_DSA_65
