"""A claimed file type that yields nothing has to say so.

Found on Cryben: benchmark-server.p12 is a file extension this scanner claims,
counted as read, and it produced no finding and no note. That is the silent skip
this scanner exists to argue against, committed by this scanner.

The PKCS#12 wrapper itself is not encrypted. It names its bags, so a shrouded
key bag says a private key is in there even when the key cannot be decoded, and
the encryptedData bag says why the certificates did not come out.
"""
from __future__ import annotations

import base64
from pathlib import Path

from qrp_mcp.scan import scan_directory

FIXTURE = Path(__file__).parent / "fixtures" / "shrouded.p12.b64"


def test_shrouded_key_bag_is_reported_as_key_material(tmp_path):
    (tmp_path / "server.p12").write_bytes(base64.b64decode(FIXTURE.read_text()))
    result = scan_directory(tmp_path)
    keys = result["evidence"]["embedded_keys"]
    assert keys, "a PKCS#12 shrouded key bag holds a private key"
    assert "not decoded" in keys[0]["description"].lower()


def test_the_file_is_named_as_claimed_but_not_decoded(tmp_path):
    (tmp_path / "server.p12").write_bytes(base64.b64decode(FIXTURE.read_text()))
    result = scan_directory(tmp_path)
    assert "server.p12" in result["coverage"]["examined_without_result"]["paths"]


def test_a_readable_key_is_not_listed_as_undecoded(tmp_path):
    body = "MIIEpAIBAAKCAQEAvZ3kP1hQ2tXcR8mN4bK7wY6uL0sJ9fD5gH3aT1nE8rV2cX7y"
    (tmp_path / "a.key").write_text(
        f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n{body}\n-----END RSA PRIVATE KEY-----\n")
    result = scan_directory(tmp_path)
    assert result["coverage"]["examined_without_result"]["paths"] == []
    assert result["evidence"]["embedded_keys"]


# --- SSH certificates -------------------------------------------------------

def test_ssh_certificate_names_its_key_type(tmp_path):
    """openssh keeps 41 of these; every one read as nothing.

    An SSH certificate is a public key line whose type carries the suffix
    -cert-v01@openssh.com. The key type in front of it is the algorithm, and it
    is the same algorithm whether the key is certified or not.
    """
    (tmp_path / "id_rsa-cert.pub").write_text(
        "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20A\n")
    result = scan_directory(tmp_path)
    assert "RSA" in result["detected_algorithms"]
    assert result["coverage"]["examined_without_result"]["paths"] == []


def test_ssh_certificate_ed25519(tmp_path):
    (tmp_path / "a.cert").write_text(
        "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9w\n")
    assert "Ed25519" in scan_directory(tmp_path)["detected_algorithms"]


def test_openssh_hybrid_key_type_with_the_domain_suffix(tmp_path):
    """ssh-mldsa44-ed25519@openssh.com -- the hybrid, missed for the suffix.

    The bare spelling was known and the one OpenSSH actually writes was not, so
    three post-quantum host keys read as nothing. Post-quantum detection is this
    scanner's strongest claim, which makes this the worst place to have a gap.
    """
    (tmp_path / "hybrid.pub").write_text(
        "ssh-mldsa44-ed25519@openssh.com AAAAH3NzaC1tbGRzYTQ0LWVkMjU1MTlAb3Blbn\n")
    families = scan_directory(tmp_path)["detected_algorithms"]
    assert "ML-DSA" in families


def test_ssh_protocol_1_public_key(tmp_path):
    """`bits exponent modulus` -- an RSA key, and the size is the first field."""
    (tmp_path / "rsa1.pub").write_text(
        "1024 65537 1538954316036770739258903145485667049484467769583341952800\n")
    result = scan_directory(tmp_path)
    assert "RSA" in result["detected_algorithms"]
    assert result["algorithm_key_sizes"].get("RSA") == 1024  # weak, and named as such


def test_ssh_protocol_1_key_with_a_trailing_comment(tmp_path):
    """The real files carry one; the first pattern anchored to end of line."""
    (tmp_path / "rsa1.pub").write_text(
        "1024 65537 " + "1" * 60 + " RSA1 #1\n")
    assert "RSA" in scan_directory(tmp_path)["detected_algorithms"]
