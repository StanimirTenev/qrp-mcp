"""The de-bsi profile, re-read against the 2026 documents (ZA-OPRAVYANE row 101; Ivezic #21/#22,
Neukart #25 on LinkedIn, 23.10.2026). Sources in qrp-kachestvo/linkedin-2026-10-23/izvori:
TR-02102-1 2026-01 (tr-02102-1.pdf: FrodoKEM and Classic McEliece recommended in hybrid,
sections 2.4.1-2.4.2) and the BMDS/BMI/BSI Leitlinie zur Umstellung auf PQC of 11 September
2026 (bsi-leitlinie-pqc.pdf: initial inventory by the end of 2026, section 4.3; high-risk by
2030, section 3)."""

from qrp_mcp import remediation
from qrp_mcp.scan import scan_directory

RSA = {"classification": "classical_vulnerable", "algorithm_family": "RSA"}


def test_key_establishment_names_frodokem_and_mceliece():
    out = remediation.suggest(RSA, None, "de-bsi")
    kem = next(o["use"] for o in out["options"] if o["for"].startswith("key establishment"))
    assert "FrodoKEM-976" in kem and "mceliece460896" in kem and "ML-KEM-768" in kem


def test_dates_carry_the_leitlinie():
    dates = remediation.suggest(RSA, None, "de-bsi")["profile"]["dates"]
    assert "end of 2026" in dates and "4.3" in dates and "2030" in dates


def test_mceliece_says_bsi_recommends_it(tmp_path):
    (tmp_path / "kem.py").write_text(
        "from pqcrypto.kem.mceliece460896 import generate_keypair\n")
    finding = next(f for f in scan_directory(tmp_path, profile="de-bsi")["findings"]
                   if f["algorithm_family"] == "Classic McEliece")
    assert finding["pqc_status"] == "candidate"          # NIST's standing, unchanged
    assert "2.4.2" in finding["profile_standing"]["standing"]


def test_nist_profile_adds_no_standing(tmp_path):
    (tmp_path / "kem.py").write_text(
        "from pqcrypto.kem.mceliece460896 import generate_keypair\n")
    finding = next(f for f in scan_directory(tmp_path)["findings"]
                   if f["algorithm_family"] == "Classic McEliece")
    assert "profile_standing" not in finding
