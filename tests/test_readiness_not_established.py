"""The summary does not reassure past what the scan did not read or determine
(ZA-OPRAVYANE rows 52 and 62, the second half).

Row 52 (raised in public, Chandra Devadass, 22.10.2026): a module using ML-KEM-768 and a
Caddyfile terminating TLS with x25519 only. The scan read 1 of 2 files, named the Caddyfile
as a type it does not read, and the summary said `pqc_ready` -- "nothing classical is" --
about the one file it had not opened, which was the classical terminator.

Row 62: a private key whose algorithm the scan did not determine (PKCS#8 embedded in a
.py, an encrypted PKCS#8 file) sat beside ML-KEM, and the summary said `pqc_ready`.

A value that says nothing classical is present -- `pqc_ready`, `pqc_pre_standard`,
`mechanism_protected`, `no_quantum_vulnerable_detected` -- is now `not_established` when
either holds, and `readiness_not_established` says what it would have read and why not.
A value that warns is never withheld.
"""

from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric import ec

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory

KEM = "from pqcrypto.kem.ml_kem_768 import generate_keypair\npk, sk = generate_keypair()\n"
CADDY = ("api.example.com {\n    tls {\n        protocols tls1.2 tls1.3\n"
         "        curves x25519\n    }\n    reverse_proxy app:8000\n}\n")


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def test_unread_terminator_withholds_pqc_ready(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "kem.py").write_text(KEM)
    (tmp_path / "Caddyfile").write_text(CADDY)
    result = scan_directory(tmp_path)
    summary = result["summary"]
    assert summary["pqc_readiness"] == "not_established"
    assert summary["readiness_not_established"]["would_read"] == "pqc_ready"
    assert summary["readiness_not_established"]["because"] == [
        "1 of 2 files were not read (50.0% read); see coverage.not_examined"]
    # The CBOM is built from the same result and does not restate the readiness.
    assert build(result)["components"]


def test_every_file_read_still_says_pqc_ready(tmp_path):
    (tmp_path / "kem.py").write_text(KEM)
    summary = scan_directory(tmp_path)["summary"]
    assert summary["pqc_readiness"] == "pqc_ready"
    assert summary["readiness_not_established"] is None


def test_a_warning_is_not_withheld(tmp_path):
    (tmp_path / "kem.py").write_text(KEM + "from cryptography.hazmat.primitives.asymmetric "
                                     "import ec\nk = ec.generate_private_key(ec.SECP256R1())\n")
    (tmp_path / "Caddyfile").write_text(CADDY)
    summary = scan_directory(tmp_path)["summary"]
    assert summary["pqc_readiness"] == "hybrid_partial"
    assert summary["readiness_not_established"] is None


def test_embedded_key_of_undetermined_algorithm(tmp_path):
    pem = _key().private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8,
                               s.NoEncryption()).decode()
    (tmp_path / "kem.py").write_text(KEM + "KEY = '''" + pem + "'''\n")
    summary = scan_directory(tmp_path)["summary"]
    assert summary["pqc_readiness"] == "not_established"
    assert summary["readiness_not_established"]["because"] == [
        "a private key at kem.py:3 whose algorithm was not determined"]


def test_encrypted_key_beside_mlkem(tmp_path):
    (tmp_path / "server.key").write_bytes(_key().private_bytes(
        s.Encoding.PEM, s.PrivateFormat.PKCS8, s.BestAvailableEncryption(b"pw")))
    (tmp_path / "kem.py").write_text(KEM)
    summary = scan_directory(tmp_path)["summary"]
    assert summary["pqc_readiness"] == "not_established"
    assert summary["readiness_not_established"]["because"] == [
        "a private key at server.key:1 whose algorithm was not determined"]
