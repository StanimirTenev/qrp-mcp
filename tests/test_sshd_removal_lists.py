"""ZA-OPRAVYANE row 420 (the L1 self-seeded control, 04.11.2026): an OpenSSH list that begins
with `-` removes every algorithm it names from the default set.

`HostKeyAlgorithms -ssh-rsa,ssh-dss` read `ssh-rsa` as a ban and `ssh-dss`, on the same removal
line, as a DSA reference at medium; `KexAlgorithms -diffie-hellman-group14-sha1,...` was a DH
reference with key size 2048. 14 of 14 planted lines.

The prefix governs the whole list. sshd_config(5) at OpenSSH 7fe3b24, for Ciphers, MACs,
KexAlgorithms, PubkeyAcceptedAlgorithms, HostbasedAcceptedAlgorithms, CASignatureAlgorithms:
"If the specified list begins with a '-' character, then the specified algorithms (including
wildcards) will be removed from the default set instead of replacing them." HostKeyAlgorithms
goes through the same code in sshd: servconf.c `assemble_algorithms` passes
`hostkeyalgorithms` to `kex_assemble_names`, whose `*list == '-'` branch removes (kex-names.c);
ssh_config(5) documents the `-` for HostKeyAlgorithms in words. `+` appends and `^` places at
the head: both still offer what they name.
"""

from __future__ import annotations

from qrp_mcp.scan import scan_directory


def _rows(tmp_path, text):
    (tmp_path / "sshd_config").write_text(text)
    result = scan_directory(tmp_path, settings=None)
    return [r for r in result["evidence"]["source_code"] if r["path"] == "sshd_config"]


def test_a_removal_list_names_nothing_it_uses(tmp_path):
    rows = _rows(tmp_path, "HostKeyAlgorithms -ssh-rsa,ssh-dss\n"
                           "PubkeyAcceptedAlgorithms -ssh-rsa,ssh-dss\n"
                           "KexAlgorithms -diffie-hellman-group14-sha1,diffie-hellman-group1-sha1\n"
                           "Ciphers -3des-cbc,aes128-cbc\n"
                           "CASignatureAlgorithms=-ssh-rsa,ssh-dss\n")
    assert rows
    used = [(r["line"], r["algorithm"], r["evidence_kind"]) for r in rows
            if r["evidence_kind"] not in {"ban", "comment"}]
    assert used == []
    # The size of a removed group stays on the ban row; nothing counts it as a size in use.
    result = scan_directory(tmp_path, settings=None)
    assert result["algorithm_key_sizes"] == {} and result["detected_algorithms"] == []


def test_an_appended_or_headed_list_still_offers(tmp_path):
    rows = _rows(tmp_path, "HostKeyAlgorithms +ssh-dss\n"
                           "KexAlgorithms ^diffie-hellman-group14-sha256\n"
                           "PubkeyAcceptedAlgorithms ssh-dss\n")
    used = {(r["line"], r["algorithm"]) for r in rows if r["evidence_kind"] not in {"ban", "comment"}}
    assert (1, "DSA") in used
    assert (2, "DH") in used
    assert (3, "DSA") in used
