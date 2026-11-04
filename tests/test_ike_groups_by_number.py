"""IKE key exchange groups named by number (ZA-OPRAVYANE rows 225 and 334). FortiOS `set dhgrp
14 5`, Cisco IOS XE `group 2 14 19` in a `crypto ikev2 proposal` and Junos `dh-group group2`
gave no evidence on 0.41.0, although they are the key exchange of every tunnel.

The number means the IANA "Transform Type 4 - Key Exchange Method Transform IDs" entry,
https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml (read 04.11.2026):
"2 | 1024-bit MODP Group", "5 | 1536-bit MODP Group", "14 | 2048-bit MODP Group",
"19 | 256-bit random ECP group", "20 | 384-bit random ECP group", "21 | 521-bit random ECP group".

That the vendors use that numbering:
* FortiOS 7.6.4 CLI reference, config vpn ipsec phase1-interface,
  https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/305883427/config-vpn-ipsec-phase1-interface
  -- "dhgrp  DH group." options "1 DH Group 1." ... "14 DH Group 14." ... "21 DH Group 21.".
* Cisco IOS XE 17 IKEv2, https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/sec-vpn/b-security-vpn/m_sec-cfg-ikev2-flex.html
  -- "2 --1024-bit DH (No longer recommended).", "14 --Specifies the 2048-bit DH group.",
  "19 --Specifies the 256-bit elliptic curve DH (ECDH) group."
* Junos, https://networkingdocs.hpe.com/documentation/us/en/software/junos/interfaces-adaptive-services/topics/topic-map/dynamic-security-associations.html
  -- "group2: Specifies that IKE uses the 1024-bit Diffie-Hellman prime modulus group",
  "group14: ... the 2048-bit Diffie-Hellman prime modulus group".
"""

from qrp_mcp.scan import scan_directory

FORTIOS = """#config-version=FGT60F-7.6.6-FW-build3652-251020:opmode=0:vdom=0:user=admin
config vpn ipsec phase1-interface
    edit "to-branch"
        set ike-version 2
        set dhgrp 14 5
    next
    edit "to-dc"
        set dhgrp 21
    next
end
"""

CISCO = """hostname edge1
!
crypto ikev2 proposal PROP1
 encryption aes-cbc-128
 integrity sha1
 group 2 14 19
!
router ospf 1
 group 5
"""

JUNOS = """set security ike proposal P1 dh-group group2
set security ike proposal P2 dh-group group19
set security ipsec policy POL1 perfect-forward-secrecy keys group14
"""

JUNOS_HIER = """security {
    ike {
        proposal P1 {
            dh-group group5;
        }
    }
}
"""


def _groups(tmp_path, name, text):
    (tmp_path / name).write_text(text)
    result = scan_directory(tmp_path)
    rows = [(f["line"], f["algorithm"], f.get("key_size"), f.get("curve"))
            for f in result["evidence"]["source_code"] if "ike_group" in f]
    return result, rows


def test_fortios_dhgrp(tmp_path):
    result, rows = _groups(tmp_path, "fw.conf", FORTIOS)
    assert rows == [(5, "DH", 2048, None), (5, "DH", 1536, None), (8, "ECDH", 521, "P-521")]


def test_cisco_ikev2_proposal_group_only_inside_the_proposal(tmp_path):
    result, rows = _groups(tmp_path, "router.cfg", CISCO)
    assert rows == [(6, "DH", 1024, None), (6, "DH", 2048, None), (6, "ECDH", 256, "P-256")]


def test_junos_dh_group_and_pfs(tmp_path):
    result, rows = _groups(tmp_path, "srx.conf", JUNOS)
    assert rows == [(1, "DH", 1024, None), (2, "ECDH", 256, "P-256"), (3, "DH", 2048, None)]
    assert 1024 in result["algorithm_key_sizes_observed"]["DH"]


def test_junos_hierarchical(tmp_path):
    _result, rows = _groups(tmp_path, "srx-hier.conf", JUNOS_HIER)
    assert rows == [(4, "DH", 1536, None)]


def test_a_commented_or_unknown_group_is_not_read(tmp_path):
    _result, rows = _groups(tmp_path, "fw.conf", "#    set dhgrp 2\n    set dhgrp 3 99\n")
    assert rows == []
