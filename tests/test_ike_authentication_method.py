"""IKE peer authentication by signature (ZA-OPRAVYANE row 342; fixtures L2/01-cisco-ios,
L2/02-junos). `authentication remote rsa-sig` and `authentication-method rsa-signatures` gave
nothing; `ecdsa-signatures-256` gave ECDSA with the size undetermined.

* Cisco IOS XE 17 IKEv2, https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/sec-vpn/b-security-vpn/m_sec-cfg-ikev2-flex.html
  -- "authentication remote rsa-sig", "pki trustpoint trustpoint-remote verify".
* Junos proposal (Security IKE), https://networkingdocs.hpe.com/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-proposal.html
  -- `dsa-signatures` "Specifies that the Digital Signature Algorithm (DSA) is used",
  `ecdsa-signatures-384` "the ECDSA using the 384-bit elliptic curve secp384r1",
  `rsa-signatures` "a public key algorithm, which supports encryption and digital signatures".
"""

from qrp_mcp import remediation
from qrp_mcp.scan import scan_directory


def _rows(tmp_path, name, text):
    (tmp_path / name).write_text(text)
    result = scan_directory(tmp_path)
    return result, sorted((f["line"], f["algorithm"], f.get("key_size"), f.get("role"))
                          for f in result["evidence"]["source_code"] if "authentication" in f["description"])


def test_junos_methods(tmp_path):
    result, rows = _rows(tmp_path, "srx.conf", (
        "set security ike proposal P1 authentication-method rsa-signatures\n"
        "set security ike proposal P2 authentication-method ecdsa-signatures-384\n"
        "set security ike proposal P3 authentication-method dsa-signatures\n"
        "set security ike proposal P4 authentication-method pre-shared-keys\n"))
    assert [(l, a, s) for l, a, s, _ in rows] == [(1, "RSA", "undetermined"), (2, "ECDSA", 384),
                                                  (3, "DSA", "undetermined")]
    assert {remediation.role_of(f) for f in result["evidence"]["source_code"]
            if "authentication" in f["description"] and f["algorithm"] == "RSA"} == {"signature"}


def test_cisco_profile_rsa_sig_only_in_the_profile(tmp_path):
    _result, rows = _rows(tmp_path, "router.cfg", (
        "crypto ikev2 profile PROF1\n authentication remote rsa-sig\n authentication local pre-share\n"
        "!\naaa new-model\n authentication remote rsa-sig\n"))
    assert [(l, a) for l, a, _, _ in rows] == [(2, "RSA")]
