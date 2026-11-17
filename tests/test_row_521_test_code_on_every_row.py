"""Row 521 (17.11.2026, Abid Hussain Mohammed; probe
`linkedin-postove/2026-11-17/stai-qrp/proba-nielson/certbot-noasof.json`, certbot 56ee049).

`in_test_code` was set on rows found in source text and missing on certificate, configuration
and embedded-key rows. `test_code.findings_in_other_code` counts every row without the flag as
other code, so on certbot 162 of the 365 "other" rows had no flag, and 88 of those sat under
tests/testdata by the rule's own words. Every evidence row with a path now carries the flag, by
the same rule (`test_code.rule`), and the counts follow it.

Not claimed: anything about the rule itself -- a path convention, said beside the counts.
"""

import json
import os
import subprocess
import sys
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from qrp_mcp.detectors import in_test_code
from qrp_mcp.scan import scan_directory


def _pem_cert() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture")])
    start = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(521).not_valid_before(start)
            .not_valid_after(start + datetime.timedelta(days=30)).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _key_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def _tree(root):
    cert = _pem_cert()
    files = {
        "tests/testdata/cert.pem": cert,
        "tests/testdata/key.pem": _key_pem(),
        "tests/testdata/nginx.conf": ("server {\n    listen 443 ssl;\n"
                                      "    ssl_protocols TLSv1 TLSv1.2;\n"
                                      "    ssl_ecdh_curve X25519MLKEM768:X25519;\n}\n"),
        "deploy/cert.pem": cert,
        "deploy/nginx.conf": ("server {\n    listen 443 ssl;\n"
                              "    ssl_ecdh_curve X25519MLKEM768:X25519;\n}\n"),
    }
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    return root


def _rows(result):
    return [(category, r) for category, items in result["evidence"].items()
            for r in items if isinstance(r, dict) and isinstance(r.get("path"), str)]


def _check(result):
    rows = _rows(result)
    categories = {c for c, _ in rows}
    assert {"source_code", "embedded_keys", "protocols", "tls_groups"} <= categories, categories
    unflagged = [(c, r["path"], r.get("line")) for c, r in rows if "in_test_code" not in r]
    assert unflagged == []
    wrong = [(c, r["path"]) for c, r in rows if r["in_test_code"] is not in_test_code(r["path"])]
    assert wrong == []
    certs = [r for c, r in rows if c == "source_code" and r.get("certificate")]
    assert {r["path"]: r["in_test_code"] for r in certs} == {
        "tests/testdata/cert.pem": True, "deploy/cert.pem": False}
    counted = result["test_code"]
    source = result["evidence"]["source_code"] + result["evidence"]["iac"]
    assert counted["findings_in_test_code"] == sum(1 for r in source if r["in_test_code"])
    assert counted["findings_in_other_code"] == sum(1 for r in source if not r["in_test_code"])


def test_every_row_with_a_path_says_whether_it_is_test_code(tmp_path):
    _check(scan_directory(_tree(tmp_path)))


def test_the_command_line_carries_it(tmp_path):
    root = _tree(tmp_path / "t")
    out = tmp_path / "s.json"
    subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", "scan",
                    str(root), "--out", str(out), "--level", "full"],
                   check=True, capture_output=True, env=dict(os.environ))
    _check(json.loads(out.read_text()))


def _composite_fixture() -> str:
    import base64
    import struct
    blob = b"".join(struct.pack(">I", len(b)) + b for b in (b"ssh-mldsa44-ed25519",
                                                            bytes(1312 + 32)))
    return "ssh-mldsa44-ed25519 " + base64.b64encode(blob).decode() + " fixture\n"


def test_a_test_only_name_does_not_make_its_family_test_only(tmp_path):
    """OpenSSH 7fe3b24: once `regress/unittests/sshkey/testdata/*.pub` carried the flag, the
    composite ML-DSA-44-Ed25519 there marked the whole ML-DSA family test-only, and ML-DSA used
    outside tests was set aside. A family is test-only when every name of it is."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        "from pqcrypto.sign import ml_dsa_65\npk, sk = ml_dsa_65.generate_keypair()\n")
    (tmp_path / "tests" / "testdata").mkdir(parents=True)
    (tmp_path / "tests" / "testdata" / "k.pub").write_text(_composite_fixture())
    result = scan_directory(tmp_path)
    assert {f["raw_value"]: f.get("in_test_code") for f in result["findings"]} == {
        "ML-DSA": None, "ML-DSA-44-Ed25519": None}
    assert result["summary"]["pqc_ready_count"] == 2
    assert result["summary"]["by_role"]["signature"]["pqc_readiness"] == "pqc_ready"
