"""PQC is not one bucket: a scheme has a family, and a standing in the world.

Before this dimension existed, SIKE and HAWK were unrecognised, which reads as
"nothing found" rather than "found and broken" — the failure mode this scanner
exists to avoid.
"""

import pytest

from qrp_mcp.classifier import _PQC_SCHEMES, _PUBLIC_KEY_FAMILIES, classify_algorithm


def classify(value):
    return classify_algorithm(value, "signature", source="test", location="test")


def test_every_pqc_token_has_a_family():
    for _token, family, classification, _kind in _PUBLIC_KEY_FAMILIES:
        if classification == "pqc_ready":
            assert family in _PQC_SCHEMES, f"{family} has no family/status entry"


@pytest.mark.parametrize(
    "value,family,pqc_family,pqc_status",
    [
        ("ML-KEM-768", "ML-KEM", "structured lattice", "standardised"),
        ("SPHINCS+-SHA2-128s", "SLH-DSA", "hash-based", "standardised"),
        ("Classic-McEliece-6688128", "Classic McEliece", "code-based", "candidate"),
        ("BIKE-L3", "BIKE", "code-based", "candidate"),
        ("HQC-192", "HQC", "code-based", "selected"),
        ("FrodoKEM-976", "FrodoKEM", "unstructured lattice", "candidate"),
        ("sntrup761x25519", "NTRU", "structured lattice", "candidate"),
        ("XMSS-SHA2_10_256", "XMSS", "hash-based", "standardised"),
    ],
)
def test_standing_schemes_carry_their_family(value, family, pqc_family, pqc_status):
    f = classify(value)
    assert f.algorithm_family == family
    assert f.classification == "pqc_ready"
    assert (f.pqc_family, f.pqc_status) == (pqc_family, pqc_status)


def test_hash_based_and_lattice_are_not_the_same_bucket():
    assert classify("ML-DSA-65").pqc_family != classify("SLH-DSA-128f").pqc_family


@pytest.mark.parametrize(
    "value,family,pqc_status",
    [("SIKEp434", "SIKE", "broken"), ("HAWK-512", "HAWK", "withdrawn")],
)
def test_broken_and_withdrawn_are_not_reported_as_ready(value, family, pqc_status):
    f = classify(value)
    assert f.algorithm_family == family
    assert f.pqc_status == pqc_status
    assert f.classification == "deprecated_weak"
    assert f.severity == "high"
    assert "must not be counted as quantum-resistant" in f.reason


# --- detector layer -------------------------------------------------------
# The classifier knowing a scheme is not enough: without a detector pattern a
# codebase that has adopted ML-KEM scans as having no post-quantum cryptography.
def _scan(tmp_path, text):
    (tmp_path / "crypto.py").write_text(text)
    from qrp_mcp.scan import scan_directory

    return {f["algorithm_family"] for f in scan_directory(str(tmp_path))["findings"]}


@pytest.mark.parametrize(
    "text,expected",
    [
        ("from pqcrystals_kyber import ML_KEM_768", "ML-KEM"),
        ('sig = "Dilithium3"', "ML-DSA"),
        ('sig = "SPHINCS+-SHA2-128s"', "SLH-DSA"),
        ('kem = "Classic-McEliece-6688128"', "Classic McEliece"),
        ('kem = "ntruhps2048509"', "NTRU"),
        ('kem = "BIKE-L3"', "BIKE"),
        ('kem = "HQC-192"', "HQC"),
        ('kem = "FrodoKEM-976"', "FrodoKEM"),
        ('sig = "XMSSMT-SHA2_20/2_256"', "XMSS"),
        ('sig = "Falcon-512"', "Falcon"),
        ('old = "SIKEp434"', "SIKE"),
        ('pulled = "HAWK-512"', "HAWK"),
    ],
)
def test_source_scan_detects_pqc_schemes(tmp_path, text, expected):
    assert expected in _scan(tmp_path, text)


def test_ordinary_words_are_not_mistaken_for_schemes(tmp_path):
    prose = "I ride my bike to work past the falcon and the tomahawk and frodo."
    assert _scan(tmp_path, prose) == set()


# The way a scheme is written in a library is not the way it is written in a
# standard. A trailing word boundary after the scheme name refuses every
# parameter-set suffix, so a codebase that had migrated scanned as one that had
# not. Found by running the scanner against a file that imported SLH-DSA.
@pytest.mark.parametrize(
    "text,expected",
    [
        ("from pqcrypto.sign import slh_dsa_sha2_128s", "SLH-DSA"),
        ("sig = slh_dsa_sign(msg)", "SLH-DSA"),
        ("from pqcrypto.kem import ml_kem_768", "ML-KEM"),
        ("ml_kem_768_keygen()", "ML-KEM"),
        ("ml_dsa_65_verify(sig)", "ML-DSA"),
        ('kem = "mceliece348864"', "Classic McEliece"),
        ("xmss_sha256_h10_sign(msg)", "XMSS"),
        ("frodokem640shake_keypair()", "FrodoKEM"),
        ("bike_l1_keygen()", "BIKE"),
        ("sike_p434_keygen()", "SIKE"),
    ],
)
def test_parameter_set_suffixes_are_detected(tmp_path, text, expected):
    assert expected in _scan(tmp_path, text)


# The leading boundary is what keeps the widened patterns honest. FXMSS is a
# separate construction with no security proof; reporting it as standardised
# XMSS is the same defect as reporting Classic McEliece as an elliptic curve.
def test_leading_boundary_still_separates_distinct_schemes(tmp_path):
    assert _scan(tmp_path, "root = fxmss_tree(seed)") == set()
