"""Row 14 (Saqib Ahmad, 6 Oct 2026): the algorithm was named, the setting that has to
carry it was not.

Reproduced on 0.28.0 + 178dcf2: a strongSwan swanctl.conf proposing
`x25519-ke1_mlkem768` scanned as ML-KEM, pqc-ready, and nothing was said about IKE
fragmentation (RFC 7383). draft-ietf-ipsecme-ikev2-pqc-auth-12 makes fragmentation
support a MUST for PQ authentication; RFC 9370 puts additional key exchanges in
IKE_INTERMEDIATE precisely so they can be fragmented.

So where an IKE configuration carries a post-quantum algorithm, the fragmentation
setting is named: enabled, disabled, or not found in the files read -- with the
documented default for the product where the research confirmed one (strongSwan,
Libreswan, FortiOS, Junos, OpenBSD iked), and "default not confirmed" for Cisco, whose
IOS XE and ASA document opposite defaults.
"""

import json
import subprocess
import sys
from pathlib import Path

from qrp_mcp.server import export_cbom, scan_repo


def _tool(obj):
    return getattr(obj, "fn", obj)


def _tree(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    return root


def _cli(tree: Path, out: Path) -> dict:
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return json.loads(out.read_text())


def _both(tmp_path: Path, files: dict[str, str]) -> list[dict]:
    tree = _tree(tmp_path / "tree", files)
    return [_cli(tree, tmp_path / "out.json"), _tool(scan_repo)(str(tree))]


def _ike(result: dict) -> list[dict]:
    return [p for p in result["evidence"]["protocols"] if p.get("protocol") == "ike"]


SWANCTL = """connections {
  pq {
    version = 2
    proposals = aes256gcm16-sha384-x25519-ke1_mlkem768
%s  }
}
"""


def test_strongswan_without_the_setting_names_the_documented_default(tmp_path):
    for result in _both(tmp_path, {"swanctl.conf": SWANCTL % ""}):
        [ike] = _ike(result)
        assert ike["product"] == "strongSwan"
        assert ike["fragmentation"] == "not_found"
        assert ike["fragmentation_default"] == "yes (strongSwan, default since 5.5.1)"
        assert ike["post_quantum"] == ["ML-KEM"]
        assert ike["line"] == 4


def test_strongswan_disabled(tmp_path):
    result = _tool(scan_repo)(str(_tree(tmp_path, {
        "swanctl.conf": SWANCTL % "    fragmentation = no\n"})))
    [ike] = _ike(result)
    assert ike["fragmentation"] == "disabled"
    assert ike["fragmentation_setting"] == {"line": 5, "value": "no"}


def test_libreswan_enabled(tmp_path):
    text = ("conn pq\n  intermediate=yes\n  ike=aes128-sha2-dh31;addke1=ml_kem_768\n"
            "  fragmentation=yes\n")
    [ike] = _ike(_tool(scan_repo)(str(_tree(tmp_path, {"ipsec.conf": text}))))
    assert (ike["product"], ike["fragmentation"]) == ("Libreswan", "enabled")


def test_cisco_default_is_not_asserted(tmp_path):
    text = ("crypto ikev2 proposal PQ\n encryption aes-gcm-256\n group 21\n"
            " pqc mlkem768 mlkem1024 optional\n")
    for result in _both(tmp_path, {"router.cfg": text}):
        [ike] = _ike(result)
        assert ike["product"] == "Cisco"
        assert ike["fragmentation"] == "not_found"
        assert ike["fragmentation_default"] == "default not confirmed"
        assert "IOS XE" in ike["description"] and "ASA" in ike["description"]


def test_cisco_enabled(tmp_path):
    text = ("crypto ikev2 fragmentation mtu 1280\ncrypto ikev2 proposal PQ\n"
            " pqc mlkem768 optional\n")
    [ike] = _ike(_tool(scan_repo)(str(_tree(tmp_path, {"router.cfg": text}))))
    assert ike["fragmentation"] == "enabled"


def test_fortios_numeric_addke_is_ml_kem(tmp_path):
    text = ("config vpn ipsec phase1-interface\n    edit \"pq\"\n"
            "        set addke1 36\n    next\nend\n")
    for result in _both(tmp_path, {"fgt_backup.conf": text}):
        assert {f["algorithm_family"] for f in result["findings"]} == {"ML-KEM"}
        [ike] = _ike(result)
        assert ike["product"] == "FortiOS"
        assert ike["fragmentation"] == "not_found"
        assert ike["fragmentation_default"].startswith("enable (FortiOS 7.6.6")


def test_iked_defaults_off(tmp_path):
    text = 'ikev2 "pq" active esp from 10.0.0.0/24 to 10.1.0.0/24 \\\n  ikesa group sntrup761x25519\n'
    [ike] = _ike(_tool(scan_repo)(str(_tree(tmp_path, {"iked.conf": text}))))
    assert ike["product"] == "OpenBSD iked"
    assert ike["fragmentation_default"].startswith("nofragmentation")
    assert ike["post_quantum"] == ["NTRU"]


def test_a_classical_ike_config_says_nothing(tmp_path):
    text = "connections {\n  c {\n    proposals = aes256-sha256-x25519\n  }\n}\n"
    assert _ike(_tool(scan_repo)(str(_tree(tmp_path, {"swanctl.conf": text})))) == []


def test_ml_kem_outside_an_ike_config_says_nothing(tmp_path):
    result = _tool(scan_repo)(str(_tree(tmp_path, {
        "nginx.conf": "ssl_ecdh_curve X25519MLKEM768;\n"})))
    assert _ike(result) == []


def test_the_cbom_carries_the_fragmentation_state(tmp_path):
    doc = _tool(export_cbom)(str(_tree(tmp_path, {"swanctl.conf": SWANCTL % ""})))
    comp = next(c for c in doc["components"]
                if c["cryptoProperties"].get("protocolProperties", {}).get("type") == "ike")
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["qrp:fragmentation"] == "not_found"
    assert props["qrp:fragmentation_default"] == "yes (strongSwan, default since 5.5.1)"
    assert props["qrp:product"] == "strongSwan"
