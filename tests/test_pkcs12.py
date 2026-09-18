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
