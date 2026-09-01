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


# RFC 10024 names the TLS 1.3 hybrids by concatenation, so the scheme is preceded
# by a digit rather than a separator. A word boundary refuses that, and a config
# that had adopted the standard scanned as having no cryptography at all.
@pytest.mark.parametrize(
    "text,expected",
    [
        ('groups = "X25519MLKEM768"', {"ML-KEM", "X25519"}),
        ('groups = "SecP256r1MLKEM768"', {"ML-KEM"}),
        ('groups = "SecP384r1MLKEM1024"', {"ML-KEM"}),
        ('groups = "X25519Kyber768Draft00"', {"ML-KEM", "X25519"}),
        ("kex = sntrup761x25519-sha512@openssh.com", {"NTRU", "X25519"}),
    ],
)
def test_tls_hybrids_report_both_halves(tmp_path, text, expected):
    assert expected <= _scan(tmp_path, text)


# The classical half is the point: it is the component Shor actually breaks, and
# reporting only the post-quantum name would drop it from the inventory.
def test_the_classical_half_of_a_hybrid_is_not_dropped(tmp_path):
    findings = _scan(tmp_path, 'ssl_conf_curves = "X25519MLKEM768"')
    assert "X25519" in findings


# --- classifier layer -----------------------------------------------------
# The source-code path was fixed first; this is the other one, which takes
# algorithm names from certificates and from someone else's CBOM. Squashing
# strips separators, and once they are gone a longer name and a shorter one are
# the same string: "XMSS" sits inside "FXMSS", and FXMSS is a different
# construction whose own specification says its security proof is TODO.
@pytest.mark.parametrize(
    "value",
    ["FXMSS", "fxmss_tree", "FXMSS-SHA2-256", "specification", "records", "technical"],
)
def test_a_longer_word_is_not_the_scheme_inside_it(value):
    assert classify(value).classification == "unknown"


# ...while every name that really does carry the scheme still resolves, including
# the parameter-set suffixes and the camelCase spellings certificates use.
@pytest.mark.parametrize(
    "value,family",
    [
        ("XMSS", "XMSS"),
        ("XMSSMT-SHA2_20/2_256", "XMSS"),
        ("xmss_sha256_h10", "XMSS"),
        ("md5WithRSAEncryption", "RSA"),
        ("rsaEncryption", "RSA"),
        ("id-ecPublicKey", "EC"),
        ("secp256k1", "EC"),
        ("sntrup761x25519", "NTRU"),
        ("Classic-McEliece-6688128", "Classic McEliece"),
    ],
)
def test_real_names_still_resolve(value, family):
    assert classify(value).algorithm_family == family


# Four scheme names are also ordinary English words. A value that is nothing but
# the name is an algorithm field and is taken at face value; the same word inside
# a phrase has to carry a parameter set, or a bicycle becomes post-quantum ready.
@pytest.mark.parametrize(
    "phrase", ["my bike", "the falcon", "frodo baggins", "Hawk Ridge", "a falcon in flight"]
)
def test_wordlike_names_need_more_than_the_word(phrase):
    assert classify(phrase).classification == "unknown"


@pytest.mark.parametrize(
    "value,family",
    [
        ("BIKE", "BIKE"),
        ("Falcon", "Falcon"),
        ("HAWK", "HAWK"),
        ("BIKE-L3", "BIKE"),
        ("bike_l1_keygen", "BIKE"),
        ("Falcon-1024", "Falcon"),
        ("FrodoKEM", "FrodoKEM"),
        ("frodo-976", "FrodoKEM"),
        ("HAWK-512", "HAWK"),
    ],
)
def test_wordlike_names_still_resolve_when_they_are_the_name(value, family):
    assert classify(value).algorithm_family == family
