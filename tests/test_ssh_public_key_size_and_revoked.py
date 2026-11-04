"""Rows 338 and 353 (04.11.2026): SSH public keys in authorized_keys and known_hosts.

338: an `ssh-rsa` entry gave RSA with no size, so a 1024-bit key was not weak. The blob is
"string "ssh-rsa", mpint e, mpint n" (RFC 4253 §6.6,
https://www.rfc-editor.org/rfc/rfc4253#section-6.6); the size is the bit length of n.
353: "Revoked keys are specified by including the "@revoked" marker ... Revoked keys are never
accepted" (sshd(8), https://man.openbsd.org/sshd.8#SSH_KNOWN_HOSTS_FILE_FORMAT): a ban, not a key
in use. Not done: `ssh-mldsa44-ed25519` in `hybrid_names`."""

from __future__ import annotations

import base64


def _ssh_rsa(bits: int) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                         serialization.PublicFormat.OpenSSH).decode()


def _ed25519() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    return ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()


def test_ssh_rsa_size_from_the_blob(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "authorized_keys").write_text(
        f'restrict,command="dump /home" {_ssh_rsa(1024)} a@b\n{_ssh_rsa(3072)} c@d\n')
    result = scan_directory(tmp_path)
    sizes = {e["line"]: e.get("key_size") for e in result["evidence"]["source_code"]
             if e["algorithm"] == "RSA"}
    assert sizes == {1: 1024, 2: 3072}
    assert any(f["raw_value"] == "RSA-1024" and f["weak_key"] for f in result["findings"])


def test_a_damaged_blob_gives_no_size(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "authorized_keys").write_text("ssh-rsa AAAAB3NzaC1yc2EAAAAD a@b\n")
    [row] = [e for e in scan_directory(tmp_path)["evidence"]["source_code"]
             if e["algorithm"] == "RSA"]
    assert not isinstance(row.get("key_size"), int)


def test_revoked_key_is_not_in_use(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "known_hosts").write_text(f"@revoked * {_ed25519()}\n")
    rows = [e for e in scan_directory(tmp_path)["evidence"]["source_code"]
            if e["algorithm"] == "Ed25519"]
    assert rows and {e["evidence_kind"] for e in rows} == {"ban"}
