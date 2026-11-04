"""Rows 310 and 345 (04.11.2026): IKE's `ecp256` named no curve.

`proposals = aes256-sha256-ecp256-ke1_mlkem768` (strongSwan) and `esp=aes256-sha256-ecp384!`
(Libreswan) gave "Elliptic curve usage" with no curve. ECP groups 19, 20 and 21 are the NIST
curves P-256, P-384 and P-521 (RFC 5903 §3, https://www.rfc-editor.org/rfc/rfc5903#section-3).
Not done: listing `ecp256-ke1_mlkem768` in `hybrid_names`."""

from __future__ import annotations


def test_ecp_group_names_its_curve(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "swanctl.conf").write_text(
        "connections {\n  pq {\n    proposals = aes256-sha256-ecp256-ke1_mlkem768\n  }\n}\n")
    (tmp_path / "ipsec.conf").write_text("conn swan\n  esp=aes256-sha256-ecp384!\n")
    curves = {(e["path"], e.get("curve")) for e in scan_directory(tmp_path)["evidence"]["source_code"]
              if e["algorithm"] == "EC"}
    assert curves == {("swanctl.conf", "P-256"), ("ipsec.conf", "P-384")}
