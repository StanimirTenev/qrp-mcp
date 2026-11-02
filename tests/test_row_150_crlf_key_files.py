"""ZA-OPRAVYANE row 150 (first test run on windows-latest, 26.10.2026): four tests of keys in
files without a claimed extension failed there (test_remaining_gaps x3, test_group2's id_key).
`write_text` writes CRLF on Windows, and the sniff for key material in an unclaimed file
counted only base64 lines ending in `\\n`: a key saved with Windows line endings -- an
`id_rsa` copied from a Windows machine, on any OS -- was never opened. A product defect, not
a test one; reproduced here on Linux by writing the bytes with CRLF."""

import json
import subprocess
import sys

import pytest

KEY = ("-----BEGIN RSA PRIVATE KEY-----\n"
       + "MIIEpAIBAAKCAQEAvZ3kP1hQ2tXcR8mN4bK7wY6uL0sJ9fD5gH3aT1nE8rV2cX7y\n" * 2
       + "-----END RSA PRIVATE KEY-----\n")


@pytest.mark.parametrize("name", ["id_rsa", "rsa_openssh.prv"])
def test_a_crlf_key_without_an_extension_is_read(tmp_path, name):
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / name).write_bytes(KEY.replace("\n", "\r\n").encode())
    out = tmp_path / "scan.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    result = json.loads(out.read_text())
    assert name in result["files_read"]
    assert result["evidence"]["embedded_keys"]
    assert "RSA" in result["detected_algorithms"]
