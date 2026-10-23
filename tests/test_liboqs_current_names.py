"""liboqs's current HQC and UOV names (ZA-OPRAVYANE row 81, swarm C of 22.10.2026,
`roy-2026-10-22/c-korpus` test_c3). From liboqs src/kem/kem.h, src/sig/sig.h and
oqs-provider ALGORITHMS.md (read 23.10.2026)."""

import pytest

from qrp_mcp.scan import scan_directory


@pytest.mark.parametrize("family, line", [
    ("HQC", "OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_hqc_1);"),
    ("HQC", 'const char *name = "hqc5";'),
    ("UOV", "OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_uov_ov_Is);"),
    ("UOV", 'const char *name = "OV_Ip_pkc";'),
])
def test_liboqs_name(tmp_path, family, line):
    (tmp_path / "kem_sig.c").write_text(line + "\n", encoding="utf-8")
    assert family in scan_directory(tmp_path)["detected_algorithms"]


@pytest.mark.parametrize("line", ["int hqc12 = 0;", "ov_iter = 3;", "MOV_V(x);"])
def test_lookalikes(tmp_path, line):
    (tmp_path / "a.c").write_text(line + "\n", encoding="utf-8")
    assert not set(scan_directory(tmp_path)["detected_algorithms"]) & {"HQC", "UOV"}
