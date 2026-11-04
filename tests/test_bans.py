"""A ban is not a use, wherever it is written.

This scanner already refused to count `!MD5` in a cipher list and `-SSLv3` in an
SSLProtocol line. A negative corpus written for this release -- 198 files with no
quantum-vulnerable cryptography and 100 where it is named but not used -- showed
the same idea in a dozen other shapes, and the scanner counted every one of them
as a use: an SSH directive removing an algorithm with a minus, a policy file
listing what is forbidden, `jdk.tls.disabledAlgorithms`, a lint rule whose whole
purpose is to forbid the pattern it quotes, a `BANNED_CIPHERS` set.

Reporting a ban as a use is the defect this project points at in a rival over
`!MD5`. So a banned algorithm is reported, marked as a ban, and kept out of the
inventory -- the same treatment a comment gets.
"""
from __future__ import annotations

import pytest

from qrp_mcp.scan import scan_directory


def scan(tmp_path, name: str, body: str):
    (tmp_path / name).write_text(body)
    return scan_directory(tmp_path)


@pytest.mark.parametrize("name,line,family", [
    # SSH removes an algorithm with a leading minus, exactly as a cipher list uses !
    ("sshd_config", "HostKeyAlgorithms -ssh-rsa,-ssh-dss", "DSA"),
    ("sshd_config", "PubkeyAcceptedAlgorithms -ssh-rsa,-ssh-dss", "RSA"),
    ("ssh_config", "KexAlgorithms -diffie-hellman-group14-sha1", "DH"),
    # the setting names itself
    ("java.security", "jdk.tls.disabledAlgorithms=RC4, DES, DESede, MD5withRSA", "RC4"),
    ("app.properties", "crypto.banned.algorithms=3DES,RC4", "3DES"),
    ("policy.yaml", "  forbiddenAlgorithms:\n    - RC4\n", "RC4"),
    ("a.py", 'BANNED_CIPHERS = frozenset({"rc4", "des", "3des"})', "RC4"),
    ("a.go", 'var blockedAlgorithms = []string{"crypto/md5", "crypto/des"}', "MD5"),
    ("a.ts", "const rejectedSuites = ['RC4-SHA'];", "RC4"),
])
def test_a_banned_algorithm_is_not_in_the_inventory(tmp_path, name, line, family):
    result = scan(tmp_path, name, line + "\n")
    assert family not in result["detected_algorithms"], result["detected_algorithms"]
    assert family in result["named_but_not_used"]


def test_the_ban_is_still_reported_and_says_what_it_is(tmp_path):
    """Not dropped: a list of what a deployment forbids is worth reading. The
    report says it is a ban rather than filing it as a use."""
    result = scan(tmp_path, "sshd_config", "HostKeyAlgorithms -ssh-dss\n")
    rows = [e for e in result["evidence"]["source_code"] if e["algorithm"] == "DSA"]
    assert rows and rows[0]["evidence_kind"] == "ban"


def test_an_openssh_removal_list_removes_every_name_on_it(tmp_path):
    """Row 420 corrects what this test used to say. In OpenSSH the `-` opens the list, not
    an entry: sshd_config(5), "If the specified list begins with a '-' character, then the
    specified algorithms (including wildcards) will be removed from the default set", and
    kex_assemble_names applies it to the whole list. `-ssh-dss,rsa-sha2-512` removes both;
    the line names nothing live. A list without the prefix still offers what it names
    (test_sshd_removal_lists.py)."""
    result = scan(tmp_path, "sshd_config",
                  "HostKeyAlgorithms -ssh-dss,rsa-sha2-512\n")
    assert result["detected_algorithms"] == []
    assert {"DSA", "RSA"} <= set(result["named_but_not_used"])


def test_a_comment_only_family_lands_in_the_same_place(tmp_path):
    """One field for both: named, and not used."""
    result = scan(tmp_path, "a.py", "# drop ecdsa before 2030\n")
    assert result["detected_algorithms"] == []
    assert result["named_but_not_used"] == ["ECDSA"]


def test_an_ordinary_setting_is_not_read_as_a_ban(tmp_path):
    """The guard keys on words that mean denial, not on any word near an
    algorithm. `tls.enabledAlgorithms` must stay a use."""
    result = scan(tmp_path, "app.properties",
                  "tls.enabledAlgorithms=ssh-rsa,ecdsa-sha2-nistp256\n")
    assert "RSA" in result["detected_algorithms"]
