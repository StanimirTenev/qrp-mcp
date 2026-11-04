"""Row 310 (04.11.2026): the MODP group size in an IKE proposal was not read.

`ike=aes256-sha2;modp2048,aes128-sha1;modp1024` gave "Diffie-Hellman usage" with no size, so the
1024-bit group was not weak. Libreswan ipsec.conf(5) names `modp2048` as DH14 and "the very
weak modp1024 (DH2)" (https://libreswan.org/man/ipsec.conf.5.html); the number is the group's
size in bits (RFC 3526, https://www.rfc-editor.org/rfc/rfc3526). A line offering several
groups is as weak as the smallest. Not done here: `ecp384` as a curve."""

from __future__ import annotations


def test_modp_group_size_and_the_smallest_offered(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "ipsec.conf").write_text(
        "conn l2tp\n  ike=aes256-sha2;modp2048,aes128-sha1;modp1024\n"
        "conn swan\n  ike=aes256-sha256-modp3072!\n")
    result = scan_directory(tmp_path)
    sizes = {e["line"]: e.get("key_size") for e in result["evidence"]["source_code"]
             if e["algorithm"] == "DH"}
    assert sizes == {2: 1024, 4: 3072}
    [weak] = [f for f in result["findings"] if f["raw_value"] == "DH-1024"]
    assert weak["weak_key"] is True
