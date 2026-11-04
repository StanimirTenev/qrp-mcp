"""Rows 415 and 416 (04.11.2026): round-3 Dilithium and SPHINCS+ reported as the standards.

Bouncy Castle's `org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyPairGenerator` was
ML-DSA, and liboqs's `OQS_SIG_alg_sphincs_sha2_128f_simple` was SLH-DSA, both `pqc_ready`.
- Bouncy Castle's release notes call them "the pre-standardisation round-3 algorithms
  Dilithium, SPHINCS+ and Kyber" and name ML-DSA, SLH-DSA and ML-KEM the standardised forms
  (https://github.com/bcgit/bc-java/blob/main/docs/releasenotes.md).
- FIPS 204 Appendix D documents the differences between ML-DSA and CRYSTALS-Dilithium 3.1
  (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf).
- liboqs's SPHINCS+ is "NIST Round 3 submission, v3.1"
  (https://github.com/open-quantum-safe/liboqs/blob/0.12.0/docs/algorithms/sig/sphincs.md), and
  "SPHINCS+ was removed in 0.16.0" (https://github.com/open-quantum-safe/liboqs/blob/main/RELEASE.md);
  FIPS 205 "contains several minor modifications" to it
  (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf).
Both are now their own family, `superseded`, never `pqc_ready`."""

from __future__ import annotations


def _families(result):
    return {f["algorithm_family"]: f for f in result["findings"]}


def test_bouncy_castle_round3_dilithium(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "B.java").write_text(
        "import org.bouncycastle.pqc.crypto.crystals.dilithium.*;\nclass B { void b() {\n"
        "  DilithiumKeyPairGenerator g = new DilithiumKeyPairGenerator();\n} }\n")
    f = _families(scan_directory(tmp_path))
    assert "ML-DSA" not in f
    assert f["Dilithium round 3"]["classification"] == "pqc_pre_standard"
    assert f["Dilithium round 3"]["pqc_status"] == "superseded"


def test_liboqs_round3_sphincs(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "s.c").write_text(
        "#include <oqs/oqs.h>\nvoid f(void) {\n"
        "    OQS_SIG *s = OQS_SIG_new(OQS_SIG_alg_sphincs_sha2_128f_simple);\n}\n")
    result = scan_directory(tmp_path)
    f = _families(result)
    assert "SLH-DSA" not in f
    assert f["SPHINCS+ round 3"]["classification"] == "pqc_pre_standard"
    assert result["summary"]["pqc_readiness"] != "pqc_ready"


def test_the_standards_stay_standard(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "s.c").write_text(
        "#include <oqs/oqs.h>\nvoid f(void) {\n"
        "    OQS_SIG *a = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);\n"
        "    OQS_SIG *b = OQS_SIG_new(OQS_SIG_alg_slh_dsa_pure_sha2_128f);\n}\n")
    f = _families(scan_directory(tmp_path))
    assert f["ML-DSA"]["classification"] == "pqc_ready"
    assert f["SLH-DSA"]["classification"] == "pqc_ready"


def test_cbom_carries_the_round3_family(tmp_path):
    from qrp_mcp.cyclonedx import build
    from qrp_mcp.scan import scan_directory
    (tmp_path / "s.c").write_text(
        "void f(void) { OQS_SIG *s = OQS_SIG_new(OQS_SIG_alg_sphincs_sha2_128f_simple); }\n")
    import json
    assert "SPHINCS+ round 3" in json.dumps(build(scan_directory(tmp_path)))
