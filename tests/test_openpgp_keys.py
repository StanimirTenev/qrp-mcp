"""OpenPGP keys (ZA-OPRAVYANE row 337). `.asc` and `.gpg` were skipped by type on 0.41.0. The
fixtures are L2/19-gpg: three signing keys made with `gpg --quick-gen-key`, which gpg itself
lists (`gpg --show-keys --with-colons`) as RSA 2048 (algorithm 1), DSA 1024 (17) and EdDSA
(22) on Ed25519. The packet grammar is RFC 9580's (https://www.rfc-editor.org/rfc/rfc9580):
4.2 packet headers, Table 3 packet types (5, 6, 7, 14), 5.5.2.2 the version 4 key ("A 1-octet
number denoting the public key algorithm"), 3.2 MPIs ("a 2-octet scalar that is the length of
the MPI in bits"), 9.1 algorithm IDs, 9.2 curve OIDs.
"""

import shutil
from pathlib import Path

import pytest

from qrp_mcp.scan import scan_directory

FIXTURES = Path(__file__).parent / "fixtures" / "openpgp"
EXPECTED = [("DSA", 1024), ("Ed25519", None), ("RSA", 2048)]


@pytest.mark.parametrize("name", ["release-keys.asc", "keyring.gpg"])
def test_keys_from_armored_and_binary(tmp_path, name):
    shutil.copy(FIXTURES / name, tmp_path / name)
    result = scan_directory(tmp_path)
    assert result["files_read"] == [name]
    rows = sorted((f["algorithm"], f.get("key_size")) for f in result["evidence"]["source_code"])
    assert rows == EXPECTED
    assert 1024 in result["algorithm_key_sizes_observed"]["DSA"]
    assert result["claimed_but_not_decoded"] == []


def test_apache_keys_file(tmp_path):
    shutil.copy(FIXTURES / "release-keys.asc", tmp_path / "KEYS")
    result = scan_directory(tmp_path)
    assert sorted((f["algorithm"], f.get("key_size")) for f in result["evidence"]["source_code"]) == EXPECTED


def test_not_openpgp_is_named_not_decoded(tmp_path):
    (tmp_path / "notes.asc").write_text("just some ascii text\n")
    result = scan_directory(tmp_path)
    assert result["evidence"]["source_code"] == []
    assert result["claimed_but_not_decoded"] == ["notes.asc"]


@pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg not installed")
def test_secret_key_export(tmp_path):
    import subprocess
    home = tmp_path / "gnupg"
    home.mkdir(mode=0o700)
    env = {"GNUPGHOME": str(home), "PATH": "/usr/bin:/bin"}
    subprocess.run(["gpg", "--batch", "--passphrase", "", "--quick-gen-key", "t@example.org",
                    "rsa3072", "sign", "never"], env=env, check=True, capture_output=True)
    out = subprocess.run(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
                          "--armor", "--export-secret-keys", "t@example.org"],
                         env=env, check=True, capture_output=True).stdout
    scan_dir = tmp_path / "repo"
    scan_dir.mkdir()
    (scan_dir / "secret.asc").write_bytes(out)
    result = scan_directory(scan_dir)
    assert [(f["algorithm"], f.get("key_size")) for f in result["evidence"]["source_code"]] == [("RSA", 3072)]
    [key] = result["evidence"]["embedded_keys"]
    assert (key["key_algorithm"], key["key_size"]) == ("RSA", 3072)
