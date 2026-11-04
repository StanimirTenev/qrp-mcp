"""FortiOS firmware defaults for settings a backup leaves out (ZA-OPRAVYANE row 228).

A backup holds only what differs from the default -- Fortinet's technical tip, "the
"full-config" will also include all default values within the saved file",
https://community.fortinet.com/fortigate-3/technical-tip-differences-between-fortigate-cli-commands-execute-backup-config-and-execute-backup-full-config-98533

Each default applied here is quoted from the FortiOS 7.6.4 CLI reference (read 04.11.2026):

* https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/339914554/config-system-global
  -- `ssl-static-key-ciphers` "Enable/disable static key ciphers in SSL/TLS connections (e.g.
  AES128-SHA, AES256-SHA, AES128-SHA256, AES256-SHA256)." default `enable`.
  `strong-crypto` default "enable **", `ssl-min-proto-version` "TLSv1-2 **",
  `admin-https-ssl-versions` "tlsv1-2 tlsv1-3 **", and the page's footnote: "** Values may
  differ between models." Those three are therefore NOT applied: "defaults not evaluated".
* https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/114404382/config-vpn-ssl-settings
  -- `ssl-min-proto-ver` "SSL minimum protocol version." default `tls1-2`;
  `ssl-max-proto-ver` "SSL maximum protocol version." default `tls1-3`.
* https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/305883427/config-vpn-ipsec-phase1-interface
  -- `dhgrp` "DH group." default `14`.
"""

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory

BACKUP = """#config-version=FGT60F-7.6.6-FW-build3652-251020:opmode=0:vdom=0:user=admin
#conf_file_ver=1
config system global
    set hostname "fw"
end
config vpn ssl settings
    set ssl-min-proto-ver tls1-1
end
config vpn ipsec phase1-interface
    edit "no-group"
        set ike-version 2
    next
    edit "with-group"
        set dhgrp 20
    next
end
"""


def _scan(tmp_path, text=BACKUP):
    (tmp_path / "fw.conf").write_text(text)
    return scan_directory(tmp_path)


def test_dh_group_default_per_tunnel(tmp_path):
    result = _scan(tmp_path)
    rows = [(f["line"], f["algorithm"], f.get("key_size"), f.get("evidence_kind"), f.get("basis"))
            for f in result["evidence"]["source_code"] if "ike_group" in f]
    assert rows == [(14, "ECDH", 384, "declaration", None),
                    (10, "DH", 2048, "default", "firmware_default")]


def test_static_key_ciphers_default_is_enable(tmp_path):
    result = _scan(tmp_path)
    [static] = result["evidence"]["static_rsa_kex"]
    assert (static["line"], static["basis"], static["default_value"]) == (3, "firmware_default",
                                                                         "enable")
    assert "7.6.4 CLI reference" in static["description"]
    assert "FGT60F 7.6.6" in static["description"]


def test_ssl_vpn_max_default_and_configured_min(tmp_path):
    result = _scan(tmp_path)
    versions = sorted((p["line"], p["version"], p["basis"]) for p in result["evidence"]["protocols"]
                      if p.get("version"))
    assert versions == [(6, "TLSv1.3", "firmware_default"), (7, "TLSv1.1", "configured_protocol")]


def test_model_dependent_defaults_are_named_not_evaluated(tmp_path):
    result = _scan(tmp_path)
    [note] = [p for p in result["evidence"]["protocols"] if p["basis"] == "firmware_defaults"]
    assert note["firmware"] == "FGT60F 7.6.6"
    assert [s.split()[0] for s in note["defaults_not_evaluated"]] == [
        "strong-crypto", "ssl-min-proto-version", "admin-https-ssl-versions"]
    assert "every other setting this backup omits" in note["description"]
    names = {c["name"] for c in build(result)["components"]}
    assert "FortiOS firmware defaults (FGT60F 7.6.6)" in names


def test_multi_vdom_backup(tmp_path):
    text = """#config-version=FGVMH6-7.6.7-FW-build3704-260601:opmode=0:vdom=1:user=admin
config vdom
edit root
next
end
config global
config system global
    set strong-crypto enable
    set ssl-static-key-ciphers disable
    set ssl-min-proto-version TLSv1-2
    set admin-https-ssl-versions tlsv1-3
end
end
config vdom
edit root
config vpn ipsec phase1-interface
    edit "to-dc"
        set ike-version 2
    next
end
end
"""
    result = _scan(tmp_path, text)
    rows = [(f["line"], f["key_size"]) for f in result["evidence"]["source_code"]
            if f.get("basis") == "firmware_default"]
    assert rows == [(17, 2048)]
    assert result["evidence"]["static_rsa_kex"] == []
    [note] = [p for p in result["evidence"]["protocols"] if p["basis"] == "firmware_defaults"]
    assert note["defaults_not_evaluated"] == []


def test_not_a_fortios_backup(tmp_path):
    result = _scan(tmp_path, "config system global\n    set hostname x\nend\n")
    assert [p for p in result["evidence"]["protocols"] if p.get("basis") == "firmware_defaults"] == []
