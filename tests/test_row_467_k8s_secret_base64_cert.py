"""Row 467 (15.11.2026, QCI CBOM-Benchmark 2.6.6 cross-run): a Kubernetes TLS Secret carries its
certificate as base64 of the PEM text under `tls.crt:`, and the file was read and gave
nothing, so an EC P-384 key was missed. The certificate is now decoded at the line of the
run. The certificate is made here with `cryptography`; no file is copied, no key is committed.
"""

import base64
import datetime
import json
import subprocess
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import export_cbom, scan_repo


def _cert_pem() -> bytes:
    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "edge.example.internal")])
    start = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(start).not_valid_after(start + datetime.timedelta(days=365))
            .sign(key, hashes.SHA384()))
    return cert.public_bytes(serialization.Encoding.PEM)


def _secret(tmp_path):
    crt = base64.b64encode(_cert_pem()).decode()
    (tmp_path / "ingress-tls-secret.yaml").write_text(
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: ingress-tls\n"
        "type: kubernetes.io/tls\ndata:\n"
        f"  tls.crt: {crt}\n")


def _check(result):
    rows = [o for o in result["evidence"]["source_code"]
            if o["path"] == "ingress-tls-secret.yaml" and o["line"] == 7]
    families = {o["algorithm"] for o in rows}
    assert {"EC", "ECDSA"} <= families, rows
    assert all(o.get("curve") == "P-384" for o in rows if o["algorithm"] == "EC")


def test_base64_certificate_in_a_secret_is_decoded(tmp_path):
    _secret(tmp_path)
    _check(scan_directory(tmp_path))


def test_base64_that_is_not_a_certificate_gives_nothing(tmp_path):
    other = base64.b64encode(b"-----BEGIN NOTHING-----\nhello\n-----END NOTHING-----\n").decode()
    (tmp_path / "s.yaml").write_text(f"data:\n  blob: {other}\n  junk: LS0tLS1CRUdJTiBub3Q$$$\n")
    result = scan_directory(tmp_path)
    assert result["evidence"]["source_code"] == []


def test_the_certificate_leaves_by_every_exit(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _secret(src)
    out, bom = tmp_path / "scan.json", tmp_path / "bom.json"
    for args in (("scan", str(src), "--out", str(out), "--no-config"),
                 ("cbom", str(src), "--out", str(bom), "--no-config")):
        done = subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()",
                               *args], capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
    _check(json.loads(out.read_text()))
    _check(getattr(scan_repo, "fn", scan_repo)(str(src)))
    for b in (json.loads(bom.read_text()), build(scan_directory(src)),
              getattr(export_cbom, "fn", export_cbom)(str(src))):
        b = b if isinstance(b, dict) else json.loads(b)
        curves = {c["cryptoProperties"].get("algorithmProperties", {}).get("curve")
                  for c in b["components"] if c.get("type") == "cryptographic-asset"}
        assert "P-384" in curves, curves
