"""Row 307 (04.11.2026): `SecurityAlgorithms.RsaSha256` read as a DNSSEC algorithm.

The DNSSEC mnemonics are upper case in the IANA registry (RSASHA256 = 8,
https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml) and lower case
in BIND's configuration (`algorithm rsasha256;`,
https://bind9.readthedocs.io/en/latest/reference.html#dnssec-policy-block-definition-and-usage).
The camelCase `RsaSha256` is Microsoft.IdentityModel's JOSE constant for RS256
(https://learn.microsoft.com/en-us/dotnet/api/microsoft.identitymodel.tokens.securityalgorithms.rsasha256)
or a Rust type: RSA, but not DNSSEC."""

from __future__ import annotations


def _descriptions(tmp_path, name, text):
    from qrp_mcp.scan import scan_directory
    tmp_path = tmp_path / name.replace(".", "_")
    tmp_path.mkdir()
    (tmp_path / name).write_text(text)
    return {e["description"] for e in scan_directory(tmp_path)["evidence"]["source_code"]
            if e["algorithm"] == "RSA"}


DNSSEC = "RSA named by a DNSSEC algorithm (1, 5, 7, 8 or 10)"


def test_camel_case_is_not_dnssec(tmp_path):
    said = _descriptions(tmp_path, "S.cs",
                         "var a = SecurityAlgorithms.RsaSha256;\npub struct RsaSha256;\n")
    assert DNSSEC not in said


def test_upper_and_lower_case_stay_dnssec(tmp_path):
    assert DNSSEC in _descriptions(tmp_path, "keygen.sh", "dnssec-keygen -a RSASHA256 -b 2048 example.\n")
    assert DNSSEC in _descriptions(tmp_path, "named.conf",
                                   "dnssec-policy p { keys { ksk lifetime unlimited algorithm rsasha256; }; };\n")
