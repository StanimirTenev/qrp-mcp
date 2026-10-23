"""RFC 8784 preshared keys: strongSwan's default and the scope of what one protects
(ZA-OPRAVYANE rows 89 and 92; both raised by the 0.34.0 agent as А and reproduced 23.10.2026).

Row 89: strongSwan's `connections.<conn>.ppk_required` defaults to `no` (swanctl.opt in the
strongSwan tree: "ppk_required = no -- Whether a Postquantum Preshared Key (PPK) is required
for this connection"). A `ppk_id` without `ppk_required = yes` is an optional PPK, and 0.34.0
still read `mechanism_protected`.

Row 92: a family was protected if ANY of its uses sat in a file with a required PPK, so EC
in a second, PPK-less tunnel was counted protected too. It now has to be every use.
"""

from qrp_mcp.scan import scan_directory

TUNNEL = "connections {{\n  {name} {{\n    proposals = aes256-sha256-ecp384\n{extra}  }}\n}}\n"


def _ppk(result):
    return next(f for f in result["findings"] if f["algorithm_family"] == "PPK (RFC 8784)")


def test_ppk_id_alone_is_optional(tmp_path):
    (tmp_path / "swanctl.conf").write_text(
        TUNNEL.format(name="home", extra="    ppk_id = home-ppk\n"))
    result = scan_directory(tmp_path)
    assert result["summary"]["pqc_readiness"] == "classical_only"
    assert _ppk(result)["protects"] == []


def test_ppk_id_with_required_yes_still_protects(tmp_path):
    (tmp_path / "swanctl.conf").write_text(TUNNEL.format(
        name="home", extra="    ppk_id = home-ppk\n    ppk_required = yes\n"))
    result = scan_directory(tmp_path)
    assert result["summary"]["pqc_readiness"] == "mechanism_protected"
    assert _ppk(result)["protects"] == ["EC"]


def test_a_second_tunnel_without_ppk_is_not_protected(tmp_path):
    (tmp_path / "vpn1").mkdir()
    (tmp_path / "vpn2").mkdir()
    (tmp_path / "vpn1" / "swanctl.conf").write_text(TUNNEL.format(
        name="home", extra="    ppk_id = home-ppk\n    ppk_required = yes\n"))
    (tmp_path / "vpn2" / "swanctl.conf").write_text(TUNNEL.format(name="office", extra=""))
    result = scan_directory(tmp_path)
    assert result["summary"]["pqc_readiness"] == "classical_only"
    assert "EC" not in _ppk(result)["protects"]
