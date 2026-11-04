"""Rows 229 and 333 (04.11.2026): "read" on a file whose grammar is not understood.

A FortiOS backup, a Cisco IOS configuration and a Junos configuration hold a tunnel's key
exchange and authentication in sections and values the scan does not parse; the verdict
still said "This scan read every one of the N files it was given". Each such file is now in
`examined_partly` with the reason `grammar_not_parsed`, and the verdict says so. The forms
are taken from the vendors' documentation:
- FortiOS `#config-version=` header:
  https://community.fortinet.com/t5/FortiGate/Technical-Tip-How-to-backup-FortiGate-configurations-using-Kiwi/ta-p/198720
- Cisco IOS `crypto ikev2 proposal`:
  https://www.cisco.com/en/US/docs/ios-xml/ios/sec_conn_ike2vpn/configuration/15-2mt/sec-cfg-ikev2-flex.html
- Junos `[edit security ike]`:
  https://juniper.net/documentation/en_US/junos12.2/topics/reference/configuration-statement/proposal-edit-security-ike.html
`coverage_pct` is not changed: it is a reading claim, and the file was read."""

from __future__ import annotations

import shutil
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "b042"


def _partly(result):
    return [(i["path"], i["line"], i["label"], i["reason"])
            for i in result["coverage"]["examined_partly"]["items"]]


def test_fortios_backup_is_read_in_part(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "fw.conf").write_text(
        "#config-version=FGT60F-7.6.6-FW-build3652-251020:opmode=0:vdom=0:user=admin\n"
        "config vpn ipsec phase1-interface\n    edit \"t1\"\n        set dhgrp 14 5\n"
        "    next\nend\n")
    result = scan_directory(tmp_path)
    assert _partly(result) == [("fw.conf", 1, "FortiOS configuration", "grammar_not_parsed")]
    assert "grammar_not_parsed" in result["coverage"]["examined_partly"]["reasons"]
    assert result["verdict"] == ("This scan opened every one of the 1 files it was given; 1 of "
                                 "them was read only in part or gave nothing it could decode, "
                                 "named with a reason (0.0% of the files given were read in "
                                 "full).")
    assert result["coverage"]["scope"]["coverage_pct"] == 100.0


def test_cisco_ios_and_junos_are_read_in_part(tmp_path):
    from qrp_mcp.scan import scan_directory
    for name in ("router.cfg", "srx.conf", "srx-hier.conf"):
        shutil.copy(FIXTURES / name, tmp_path / name)
    assert sorted(_partly(scan_directory(tmp_path))) == [
        ("router.cfg", 3, "Cisco IOS configuration", "grammar_not_parsed"),
        ("srx-hier.conf", 2, "Junos configuration", "grammar_not_parsed"),
        ("srx.conf", 1, "Junos configuration", "grammar_not_parsed"),
    ]


def test_other_configuration_stays_read(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "nginx.conf").write_text("server {\n    ssl_protocols TLSv1.2;\n}\n")
    (tmp_path / "wg0.conf").write_text("[Interface]\nListenPort = 51820\n")
    result = scan_directory(tmp_path)
    assert _partly(result) == []
    assert result["verdict"] == "This scan read every one of the 2 files it was given."


def test_partly_read_is_named_when_some_files_were_not_read(tmp_path):
    from qrp_mcp.scan import scan_directory
    shutil.copy(FIXTURES / "srx.conf", tmp_path / "srx.conf")
    (tmp_path / "notes.docx").write_bytes(b"x")
    assert scan_directory(tmp_path)["verdict"].endswith(
        "; of those read, 1 was read only in part or gave nothing it could decode, named "
        "with a reason (0.0% of the files given were read in full).")


def test_each_entry_says_what_was_read_and_what_was_not(tmp_path):
    """After the formats batch (rows 225-228, 334) part of each grammar is read: FortiOS
    `set dhgrp` and three firmware defaults, Cisco IOS XE `group` in a `crypto ikev2 proposal`,
    Junos `dh-group`. The meaning said "group numbers ... are not parsed", which was no longer
    true; each entry now says what was read and what was not."""
    from qrp_mcp.scan import scan_directory
    (tmp_path / "fw.conf").write_text(
        "#config-version=FGT60F-7.6.6-FW-build3652-251020:opmode=0:vdom=0:user=admin\n"
        "config vpn ipsec phase1-interface\n    edit \"t1\"\n        set dhgrp 14 5\n"
        "    next\nend\n")
    (tmp_path / "router.cfg").write_text("crypto ikev2 proposal P1\n group 14\n")
    (tmp_path / "srx.conf").write_text("set security ike proposal p1 dh-group group14\n")
    result = scan_directory(tmp_path)
    block = result["coverage"]["examined_partly"]
    items = {i["path"]: i for i in block["items"]}
    assert "set dhgrp" in items["fw.conf"]["read"]
    assert "which proposal" in items["fw.conf"]["not_read"]
    assert "crypto ikev2 proposal" in items["router.cfg"]["read"]
    assert "crypto isakmp policy" in items["router.cfg"]["not_read"]
    assert "dh-group" in items["srx.conf"]["read"]
    assert "group numbers" not in block["reasons"]["grammar_not_parsed"]
