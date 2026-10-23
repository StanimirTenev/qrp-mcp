"""The classical half of oqs-provider's hybrids (ZA-OPRAVYANE row 82, swarm C of 22.10.2026,
`roy-2026-10-22/c-korpus` test_c4: oqs-demos openvpn/openvpn-openssl.cnf `Groups =
mlkem768:p384_mlkem768`). Names from oqs-provider ALGORITHMS.md (read 23.10.2026)."""

import pytest

from qrp_mcp.scan import scan_directory


def test_p384_mlkem768_is_not_pqc_ready(tmp_path):
    (tmp_path / "openssl.cnf").write_text(
        "[system_default_sect]\nGroups = p384_mlkem768\n", encoding="utf-8")
    result = scan_directory(tmp_path)
    assert {"ECDH", "ML-KEM"} <= set(result["detected_algorithms"])
    assert result["summary"]["pqc_readiness"] != "pqc_ready"


@pytest.mark.parametrize("family, name", [
    ("ECDH", "bp256_mlkem512"), ("ECDH", "p521_frodo1344aes"), ("ECDH", "p256_bikel1"),
    ("ECDSA", "p256_mldsa44"), ("ECDSA", "p521_falcon1024"), ("RSA", "rsa3072_mldsa44"),
])
def test_classical_half(tmp_path, family, name):
    (tmp_path / "a.c").write_text(f'const char *alg = "{name}";\n', encoding="utf-8")
    assert family in scan_directory(tmp_path)["detected_algorithms"]


def test_a_palette_is_not_a_curve(tmp_path):
    (tmp_path / "a.py").write_text("p256_colors = load()\n", encoding="utf-8")
    assert "ECDH" not in scan_directory(tmp_path)["detected_algorithms"]
