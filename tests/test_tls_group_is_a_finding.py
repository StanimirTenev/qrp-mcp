"""A classical group offered in a TLS group setting is a finding of its family (ZA-OPRAVYANE
row 83, swarm C of 22.10.2026, `roy-2026-10-22/c-korpus` test_c5: oqs-demos postgresql).

`Groups = x448:mlkem768` put X448 in evidence.tls_groups and nowhere else: the summary said
pqc_ready with quantum_vulnerable_count 0. The X448 rule itself stays case-sensitive (row 83:
lowercase would take Bitcoin's `0X448` service flag).
"""

from qrp_mcp.scan import scan_directory


def _cnf(tmp_path, groups):
    (tmp_path / "openssl.cnf").write_text(
        f"[system_default_sect]\nGroups = {groups}\n", encoding="utf-8")
    return scan_directory(tmp_path)


def test_lowercase_x448_group(tmp_path):
    result = _cnf(tmp_path, "x448:mlkem768")
    assert "X448" in result["detected_algorithms"]
    assert result["summary"]["quantum_vulnerable_count"] >= 1
    assert result["summary"]["pqc_readiness"] != "pqc_ready"


def test_ffdhe_group(tmp_path):
    assert "DH" in _cnf(tmp_path, "X25519MLKEM768:ffdhe2048")["detected_algorithms"]


def test_removed_group_is_not_offered(tmp_path):
    assert "X448" not in _cnf(tmp_path, "DEFAULT:-x448")["detected_algorithms"]


def test_prime256v1_stays_one_family(tmp_path):
    found = _cnf(tmp_path, "X25519MLKEM768:prime256v1")["detected_algorithms"]
    assert "EC" in found and "ECDH" not in found, found


def test_hex_service_flags_are_not_x448(tmp_path):
    (tmp_path / "flags.py").write_text("SERVICES = [x1, x5, x9, x408, x448, xc08]\n",
                                       encoding="utf-8")
    assert "X448" not in scan_directory(tmp_path)["detected_algorithms"]
