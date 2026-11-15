"""Row 469 (15.11.2026, QCI CBOM-Benchmark 2.6.6 cross-run): an OpenSSH private key
(`deploy_id_ed25519`) gave "Embedded private key material" with no family, so Ed25519 was
never named. The key type is now read from the openssh-key-v1 header (OpenSSH PROTOCOL.key),
which keeps the public key in the clear, so a passphrase does not hide it. Keys are made here
with `cryptography`; none is committed.
"""

import json
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import export_cbom, scan_repo


def _openssh(key, encryption=None) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                             encryption or serialization.NoEncryption())


KEYS = {
    "deploy_id_ed25519": (lambda: ed25519.Ed25519PrivateKey.generate(), "Ed25519", 256, None),
    "id_ecdsa": (lambda: ec.generate_private_key(ec.SECP384R1()), "EC", 384, "P-384"),
    "id_rsa": (lambda: rsa.generate_private_key(public_exponent=65537, key_size=3072),
               "RSA", 3072, None),
}


def _check(result, name, family, size, curve):
    keys = [k for k in result["evidence"]["embedded_keys"] if k["path"] == name]
    assert keys and keys[0].get("key_algorithm") == family, keys
    assert keys[0].get("key_size") == size
    rows = [o for o in result["evidence"]["source_code"]
            if o["path"] == name and o["algorithm"] == family]
    assert rows and rows[0].get("key_size") == size and rows[0].get("curve") == curve, rows
    assert family in {f["algorithm_family"] for f in result["findings"]}


@pytest.mark.parametrize("name", sorted(KEYS))
def test_openssh_key_family_from_its_header(tmp_path, name):
    make, family, size, curve = KEYS[name]
    (tmp_path / name).write_bytes(_openssh(make()))
    _check(scan_directory(tmp_path), name, family, size, curve)


def test_a_passphrase_does_not_hide_the_type(tmp_path):
    # Built by hand in the layout PROTOCOL.key gives (cryptography needs bcrypt to encrypt
    # one): an aes256-ctr / bcrypt header, the public key in the clear, then bytes nobody
    # without the passphrase can read.
    import base64
    import os

    def string(b: bytes) -> bytes:
        return len(b).to_bytes(4, "big") + b

    public = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    blob = (b"openssh-key-v1\0" + string(b"aes256-ctr") + string(b"bcrypt")
            + string(string(os.urandom(16)) + (16).to_bytes(4, "big")) + (1).to_bytes(4, "big")
            + string(string(b"ssh-ed25519") + string(public)) + string(os.urandom(160)))
    body = base64.b64encode(blob).decode()
    lines = "\n".join(body[i:i + 70] for i in range(0, len(body), 70))
    (tmp_path / "id_ed25519").write_text(
        f"-----BEGIN OPENSSH PRIVATE KEY-----\n{lines}\n-----END OPENSSH PRIVATE KEY-----\n")
    _check(scan_directory(tmp_path), "id_ed25519", "Ed25519", 256, None)


def test_a_broken_body_names_no_family(tmp_path):
    import base64
    body = base64.b64encode(b"openssh-key-v1\0" + b"\0\0\0\x04none" + b"\xff" * 60).decode()
    (tmp_path / "id_ed25519").write_text(
        f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----\n")
    result = scan_directory(tmp_path)
    assert result["evidence"]["embedded_keys"]
    assert not result["evidence"]["embedded_keys"][0].get("key_algorithm")


def test_the_family_leaves_by_every_exit(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "deploy_id_ed25519").write_bytes(_openssh(ed25519.Ed25519PrivateKey.generate()))
    out, bom = tmp_path / "scan.json", tmp_path / "bom.json"
    for args in (("scan", str(src), "--out", str(out), "--no-config"),
                 ("cbom", str(src), "--out", str(bom), "--no-config")):
        done = subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()",
                               *args], capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
    _check(json.loads(out.read_text()), "deploy_id_ed25519", "Ed25519", 256, None)
    _check(getattr(scan_repo, "fn", scan_repo)(str(src)), "deploy_id_ed25519", "Ed25519", 256, None)
    for b in (json.loads(bom.read_text()), build(scan_directory(src)),
              getattr(export_cbom, "fn", export_cbom)(str(src))):
        b = b if isinstance(b, dict) else json.loads(b)
        assert any(c["name"].startswith("Ed25519") for c in b["components"]), [
            c["name"] for c in b["components"]]
