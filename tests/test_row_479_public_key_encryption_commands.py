"""Row 479 (15.11.2026, Edwin Weijdema on HNDL and backups; probe
`linkedin-postove/2026-11-15/backup-proba/`): encryption to a public key in a script was invisible.

`gpg --batch --encrypt --recipient ...` and `openssl smime -encrypt ... vault-rsa4096.crt` gave 0
findings and the verdict said every file was read, while `openssl dgst -sign` already gave a
`ci_pipeline` row. Exactly the archives kept longest dropped out. Now each such command is a
`ci_pipeline` row with `operation: public_key_encryption`, role key_establishment and
`hndl_exposed: true`: "public-key encryption to a key not in these files", unless the recipient
certificate or key is a file the scan read, whose families it then names. Symmetric
`openssl enc -aes-256-gcm -pbkdf2` stays silent.
"""

import json
import subprocess
import sys
from pathlib import Path

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import export_cbom, scan_repo

NIGHTLY = ("#!/bin/sh\ntar czf - /srv/data | openssl enc -aes-256-gcm -pbkdf2 -iter 600000 "
           "-pass file:/etc/backup/pass -out /backup/data.tgz.enc\n")
OFFSITE = ("#!/bin/sh\n"
           "tar czf - /srv/data | gpg --batch --encrypt --recipient offsite-vault@example.com "
           "-o /backup/offsite.tgz.gpg\n"
           "openssl smime -encrypt -aes256 -binary -in /backup/db.dump -out /backup/db.dump.p7m "
           "-outform DER /etc/backup/vault-rsa4096.crt\n"
           "openssl pkeyutl -encrypt -pubin -inkey keys/archive_pub.pem -in k.bin -out k.enc\n"
           "age -r age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p -o x.age x.tar\n"
           "gpg -er ops@example.com notes.txt\n")


def _pub_pem() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _tree(tmp_path: Path) -> Path:
    root = tmp_path / "r"
    (root / "keys").mkdir(parents=True)
    (root / "nightly_backup.sh").write_text(NIGHTLY)
    (root / "offsite_backup.sh").write_text(OFFSITE)
    (root / "keys" / "archive_pub.pem").write_text(_pub_pem())
    return root


def _cli(args):
    subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", *args],
                   check=True, capture_output=True)


def _rows(result):
    return [r for r in result["evidence"]["ci_pipeline"]
            if r.get("operation") == "public_key_encryption"]


def test_each_command_is_a_key_establishment_row(tmp_path):
    root = _tree(tmp_path)
    out = tmp_path / "s.json"
    _cli(["scan", str(root), "--out", str(out)])
    for result in (json.loads(out.read_text()), scan_repo(str(root)), scan_directory(root)):
        rows = {(r["path"], r["line"]): r for r in _rows(result)}
        assert set(rows) == {("offsite_backup.sh", n) for n in (2, 3, 4, 5, 6)}
        # The finding beside the row: not a signing command, and not an algorithm component.
        encrypting = [f for f in result["findings"]
                      if f["algorithm_family"] == "public_key_encryption"]
        assert len(encrypting) == 5 and all("harvest now" in f["reason"] for f in encrypting)
        assert not [f for f in result["findings"] if f["algorithm_family"] == "signing_command"]
        assert {r["command_type"] for r in rows.values()} == {
            "gpg_encrypt", "openssl_smime_encrypt", "openssl_pkeyutl_encrypt", "age_encrypt"}
        for r in rows.values():
            assert r["role"] == "key_establishment" and r["hndl_exposed"] is True
        smime = rows[("offsite_backup.sh", 3)]
        assert smime["description"] == "public-key encryption to a key not in these files"
        assert smime["recipient_key"] == {"path": "/etc/backup/vault-rsa4096.crt",
                                          "in_tree": False}
        # The key is in the tree: its family is named, from the file the scan read.
        pkey = rows[("offsite_backup.sh", 4)]
        assert pkey["recipient_key"]["in_tree"] is True
        assert pkey["recipient_key"]["algorithms"] == ["RSA"]
        assert "keys/archive_pub.pem" in pkey["description"]
        # Symmetric encryption with a passphrase is not public-key encryption.
        assert not [r for r in result["evidence"]["ci_pipeline"]
                    if r["path"] == "nightly_backup.sh"]


def test_the_cbom_counts_them_apart_from_signing(tmp_path):
    root = _tree(tmp_path)
    out = tmp_path / "c.json"
    _cli(["cbom", str(root), "--out", str(out)])
    for doc in (json.loads(out.read_text()), export_cbom(str(root)), build(scan_directory(root))):
        props = {p["name"]: p["value"] for p in doc["properties"]}
        assert props["qrp:evidence:ci_signing_commands"] == "0"
        rows = json.loads(props["qrp:evidence:public_key_encryption_commands"])
        assert len(rows) == 5 and all(r["hndl_exposed"] is True for r in rows)
        assert not [c for c in doc["components"] if c["name"] == "public_key_encryption"]


def test_a_mandate_does_not_read_them_as_signatures(tmp_path):
    root = _tree(tmp_path)
    out = tmp_path / "m.json"
    subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", "scan",
                    str(root), "--mandate", "nist-ir-8547", "--mandate", "cnsa-2.0",
                    "--out", str(out)],
                   capture_output=True)
    rows = _rows(json.loads(out.read_text()))
    assert len(rows) == 5
    for r in rows:
        # CNSA 2.0 dates every signing step; an encryption step is not one.
        assert r["hndl_exposed"] is True and "mandates" not in r
