"""The scanner checked against the names the standards actually use.

Every row here was taken from a specification, a registry or a shipping
implementation, not invented: NIST's third additional-signatures round (May
2026), SP 800-208, RFC 10024, OpenSSH 10, and draft-ietf-lamps-pq-composite-sigs.

The corpus exists because four defects in one day were all the same shape -- a
name spelled the way a standard spells it, and a matcher that had only ever been
shown the way a paper spells it. Keeping the corpus as a test means the next
scheme is added against real spellings rather than a guess.
"""

from __future__ import annotations

import pytest

from qrp_mcp.classifier import classify_algorithm
from qrp_mcp.scan import scan_directory


def classify(value):
    return classify_algorithm(value, "signature", source="test", location="test")


def scan(tmp_path, text):
    (tmp_path / "crypto.py").write_text(f'alg = "{text}"\n')
    return {f["algorithm_family"] for f in scan_directory(str(tmp_path))["findings"]}


# NIST advanced nine schemes to the third additional-signatures round on
# 14 May 2026. Unrecognised reads as "nothing found", not as "not standardised".
ROUND_THREE = [
    ("FAEST-128f", "FAEST", "symmetric-based"),
    ("SQIsign-I", "SQIsign", "isogeny-based"),
    ("SNOVA-24-5-16", "SNOVA", "multivariate"),
    ("SDitH", "SDitH", "code-based"),
    ("MQOM-L1", "MQOM", "multivariate"),
    ("QR-UOV", "QR-UOV", "multivariate"),
    ("UOV-Is", "UOV", "multivariate"),
    ("MAYO-2", "MAYO", "multivariate"),
]


@pytest.mark.parametrize("value,family,math", ROUND_THREE)
def test_round_three_candidates_are_named_and_placed(value, family, math):
    finding = classify(value)
    assert finding.algorithm_family == family
    assert finding.pqc_family == math
    assert finding.pqc_status == "candidate"


@pytest.mark.parametrize("value,family,_math", ROUND_THREE)
def test_round_three_candidates_are_detected_in_source(tmp_path, value, family, _math):
    assert family in scan(tmp_path, value)


# Dropped by NIST at the end of round two. Naming it is the point: a scheme that
# lost its process is not the same as a scheme nobody recognised.
def test_a_dropped_candidate_is_not_counted_as_ready():
    finding = classify("CROSS-R-SDP")
    assert finding.algorithm_family == "CROSS"
    assert finding.pqc_status == "eliminated"
    assert finding.classification == "deprecated_weak"


# SP 800-208, and CNSA 2.0 requires LMS or XMSS for firmware and code signing.
@pytest.mark.parametrize(
    "value", ["LMS", "HSS/LMS", "LMS_SHA256_M32_H10", "lms_sha256_m32_h10"]
)
def test_stateful_hash_based_signatures_are_recognised(value):
    finding = classify(value)
    assert finding.algorithm_family == "HSS/LMS"
    assert finding.pqc_family == "hash-based"
    assert finding.pqc_status == "standardised"


# FIPS 206 renames Falcon to FN-DSA, and "DSA" sits inside "FN-DSA".
def test_fips_206_name_is_not_read_as_classical_dsa():
    finding = classify("FN-DSA-512")
    assert finding.algorithm_family == "Falcon"
    assert finding.classification == "pqc_ready"


# RFC 10024 (TLS 1.3), OpenSSH 10, and draft-ietf-lamps-pq-composite-sigs. A
# hybrid holds if either half holds, so the post-quantum name leads -- and the
# classical half is recorded rather than dropped, because it is the half Shor
# breaks.
@pytest.mark.parametrize(
    "value,primary,alongside",
    [
        ("X25519MLKEM768", "ML-KEM", "X25519"),
        ("SecP256r1MLKEM768", "ML-KEM", "EC"),
        ("SecP384r1MLKEM1024", "ML-KEM", "EC"),
        ("mlkem768x25519-sha256", "ML-KEM", "X25519"),
        ("sntrup761x25519-sha512@openssh.com", "NTRU", "X25519"),
        ("id-MLDSA44-RSA2048-PSS-SHA256", "ML-DSA", "RSA"),
        ("id-MLDSA65-ECDSA-P384-SHA512", "ML-DSA", "ECDSA"),
    ],
)
def test_hybrids_and_composites_keep_both_halves(value, primary, alongside):
    finding = classify(value)
    assert finding.algorithm_family == primary
    assert alongside in finding.also_present
    assert alongside in finding.reason


# A single-algorithm name has no components, and the generic token inside a
# specific one is the same name seen through a shorter lens.
@pytest.mark.parametrize("value", ["ECDSA", "RSASSA-PSS", "ECDH", "Ed25519", "ML-KEM-768"])
def test_a_single_algorithm_has_no_components(value):
    assert classify(value).also_present == []


# Classical key agreement, reported as a hash primitive before Curve25519 had a
# name here -- an answer that reads as "fine".
def test_curve25519_is_key_agreement_not_a_hash():
    finding = classify("curve25519-sha256")
    assert finding.algorithm_family == "X25519"
    assert finding.classification == "classical_vulnerable"


@pytest.mark.parametrize("value", ["brainpoolP256r1", "prime256v1", "secp384r1"])
def test_named_curves_resolve(value):
    assert classify(value).algorithm_family == "EC"


# Every scheme named after an ordinary word, in a sentence where it is the word.
@pytest.mark.parametrize(
    "phrase",
    [
        "the mayo clinic", "crossroads", "cross-site scripting", "my bike",
        "the falcon", "frodo baggins", "Hawk Ridge", "films", "alarms", "realms",
    ],
)
def test_ordinary_language_is_not_an_inventory(tmp_path, phrase):
    assert classify(phrase).classification == "unknown"
    assert scan(tmp_path, phrase) == set()


# Object identifiers, as certificates and third-party CBOMs carry them. An OID
# has no letters, so token matching can never reach it -- every one of these
# classified as "unknown" until the number itself was looked up.
@pytest.mark.parametrize(
    "oid,family",
    [
        ("2.16.840.1.101.3.4.3.17", "ML-DSA"),   # ML-DSA-44
        ("2.16.840.1.101.3.4.3.19", "ML-DSA"),   # ML-DSA-87
        ("2.16.840.1.101.3.4.3.20", "SLH-DSA"),  # first of the twelve
        ("2.16.840.1.101.3.4.3.46", "SLH-DSA"),  # last of the pre-hash twelve
        ("2.16.840.1.101.3.4.4.2", "ML-KEM"),    # ML-KEM-768
        ("1.2.840.113549.1.1.1", "RSA"),         # rsaEncryption
        ("1.2.840.113549.1.1.11", "RSA"),        # sha256WithRSAEncryption
        ("1.2.840.10045.2.1", "EC"),             # id-ecPublicKey
        ("1.2.840.10045.4.3.2", "ECDSA"),        # ecdsa-with-SHA256
        ("1.2.840.10045.3.1.7", "EC"),           # prime256v1
        ("1.2.840.10040.4.3", "DSA"),            # dsa-with-SHA1
        ("1.3.101.112", "Ed25519"),
        ("1.3.101.110", "X25519"),
        ("1.3.132.0.34", "EC"),                  # secp384r1
        ("1.3.132.0.10", "EC"),                  # secp256k1
        ("1.3.36.3.3.2.8.1.1.7", "EC"),          # brainpoolP256r1
    ],
)
def test_object_identifiers_resolve(oid, family):
    finding = classify(oid)
    assert finding.algorithm_family == family
    assert finding.classification != "unknown"


# The post-quantum OIDs carry the family and standing too, not just a name.
def test_a_post_quantum_oid_carries_its_family_and_standing():
    finding = classify("2.16.840.1.101.3.4.4.3")
    assert finding.algorithm_family == "ML-KEM"
    assert finding.pqc_family == "structured lattice"
    assert finding.pqc_status == "standardised"


# An unregistered arc is unknown, not a guess. Dotted digits are not evidence.
@pytest.mark.parametrize("value", ["1.2.3.4.5", "0.0", "9.9.9.9.9.9", "not.an.oid", "1.2.840"])
def test_an_unrecognised_oid_stays_unknown(value):
    assert classify(value).classification == "unknown"
