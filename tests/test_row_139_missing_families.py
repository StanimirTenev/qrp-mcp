"""Families the vocabulary did not have (ZA-OPRAVYANE row 139).

Measured 23.10.2026 (`qrp-kachestvo/imena-2026-10-23`, A-C section 4 and B classes C16,
C19, C26): GOST R 34.10 (331 library names), RC2 (264), MD2 (112), MD4 (76), SM2 (47) and
ElGamal had no family at all, and SM2 came out as plain EC. The KpqC schemes (HAETAE,
SMAUG-T, AIMer, NTRU+), BIKE by Bouncy Castle's names, NTRU LPRime and Streamlined NTRU
Prime by class name, XMSS^MT after `WITH`, the LMS/HSS lightweight classes, and the bare
"RC2", TDEA and ARCFOUR were all silent. None of the post-quantum ones is a published
standard, so none may read pqc_ready (rows 8-9: not standardised is not ready).
"""

from pathlib import Path

import pytest

from qrp_mcp import detectors
from qrp_mcp.classifier import classify_algorithm


def _families(line: str, name: str = "A.java") -> set[str]:
    found = detectors.scan_source_file(Path(name), name, lines=[line])
    return {f["algorithm"] for f in found if f["evidence_kind"] not in ("ban", "comment")}


def _classify(name: str):
    return classify_algorithm(name, "explicit", source="t", location="t")


@pytest.mark.parametrize("family", ["GOST R 34.10", "SM2", "ElGamal"])
def test_discrete_log_families_are_quantum_vulnerable(family):
    finding = _classify(family)
    assert finding.algorithm_family == family
    assert finding.classification == "classical_vulnerable" and finding.quantum_vulnerable


@pytest.mark.parametrize("family", ["MD2", "MD4", "RC2"])
def test_old_hashes_and_ciphers_are_weak(family):
    assert _classify(family).classification == "deprecated_weak"


@pytest.mark.parametrize("family", ["HAETAE", "SMAUG-T", "AIMer", "BIKE"])
def test_unstandardised_post_quantum_is_not_ready(family):
    finding = _classify(family)
    assert finding.algorithm_family == family
    assert finding.classification == "pqc_pre_standard"
    assert finding.pqc_status == "candidate"


@pytest.mark.parametrize("line,family", [
    ("use(new SM2Engine());", "SM2"),
    ('use(Signature.getInstance("SHA256WITHSM2", "BC"));', "SM2"),
    ('use(Cipher.getInstance("SM2WITHSM3", "BC"));', "SM2"),
    ('use(KeyAgreement.getInstance("SM2", "BC"));', "SM2"),
    ("use(new ECGOST3410Signer());", "GOST R 34.10"),
    ('use(KeyFactory.getInstance("GOST-3410-2012", "BC"));', "GOST R 34.10"),
    ('use(Signature.getInstance("GOST3411WITHECGOST3410", "BC"));', "GOST R 34.10"),
    ("use(new ECVKOAgreement());", "GOST R 34.10"),
    ("use(new ElGamalEngine());", "ElGamal"),
    ('use(Cipher.getInstance("ElGamal/None/NoPadding"));', "ElGamal"),
    ("use(new RC2Engine());", "RC2"),
    ('use(Cipher.getInstance("RC2/CBC/PKCS5Padding"));', "RC2"),
    ("use(new MD2Digest());", "MD2"),
    ('use(MessageDigest.getInstance("MD4", "BC"));', "MD4"),
    ('use(Cipher.getInstance("TDEA", "BC"));', "3DES"),
    ('if ("ARCFOUR".equals(key.getAlgorithm())) { return; }', "RC4"),
    ("use(new HAETAESigner());", "HAETAE"),
    ('use(Signature.getInstance("HAETAE-3", "BC"));', "HAETAE"),
    ('use(KeyFactory.getInstance("Haetae", "BC"));', "HAETAE"),
    ("use(new SmaugTKeyPairGenerator());", "SMAUG-T"),
    ('use(KEM.getInstance("SMAUGT_MODE1", "BC"));', "SMAUG-T"),
    ('use(Signature.getInstance("AIMer-128f", "BC"));', "AIMer"),
    ("use(new AIMerSigner());", "AIMer"),
    ('use(Cipher.getInstance("BIKE128", "BC"));', "BIKE"),
    ('use(KeyFactory.getInstance("BIKE", "BC"));', "BIKE"),
    ('use(KeyFactory.getInstance("NTRULPRIME", "BC"));', "NTRU"),
    ("use(new SNTRUPrimeKeyPairGenerator());", "NTRU"),
    ("use(new NTRUPlusKEMGenerator());", "NTRU"),
    ("use(new HQCKeyPairGenerator());", "HQC"),
    ("use(new CMCEKEMGenerator());", "Classic McEliece"),
    ('use(Signature.getInstance("SHA256WITHXMSSMT-SHA256", "BC"));', "XMSS"),
    ("use(new LMSKeyPairGenerator());", "HSS/LMS"),
    ("use(new HSSPrivateKeyParameters(l, k));", "HSS/LMS"),
    ('use(KeyFactory.getInstance("LMS", "BC"));', "HSS/LMS"),
])
def test_java_and_bouncy_castle_names(line, family):
    assert family in _families(line)


@pytest.mark.parametrize("line,name,family", [
    ("algorithms.RC2(key)", "a.py", "RC2"),
    ("x = ARC2.new(key, ARC2.MODE_CBC)", "a.py", "RC2"),
    ("from Crypto.PublicKey import ElGamal", "a.py", "ElGamal"),
    ("let _ = rc2::Rc2;", "a.rs", "RC2"),
    ("let _ = md4::Md4;", "a.rs", "MD4"),
    ("forge.rc2.createEncryptionCipher();", "a.js", "RC2"),
    ("EVP_rc2_cbc();", "a.c", "RC2"),
    ("EVP_md4();", "a.c", "MD4"),
    ("MD4_Init(&c);", "a.c", "MD4"),
    ('EVP_PKEY_CTX_new_from_name(libctx, "SM2", NULL);', "a.c", "SM2"),
])
def test_other_languages(line, name, family):
    assert family in _families(line, name)


def test_sm2_is_no_longer_plain_ec():
    assert _families('EVP_PKEY_CTX_new_from_name(libctx, "SM2", NULL);', "a.c") == {"SM2"}


@pytest.mark.parametrize("line,name", [
    ("int BIKE = 3;", "a.c"), ("bike_count += 1", "a.py"), ('name = "Smaug the dragon"', "a.py"),
    ("DISCLAIMER = 'none'", "a.py"), ('version = "1.0.0-rc2"', "a.py"), ('tag = "RC2"', "a.py"),
    ("int SM2_LEN = 4;", "a.c"), ("x = md2_count", "a.py"), ("MayoClinic.load()", "a.py"),
    ("DESCRIPTION = 'x'", "a.py"), ("DHCP_OPTION_ROUTER = 3", "a.py"), ("rsa_logo_draw()", "a.c"),
    ("ECHO = True", "a.py"), ("int lms_course_id = 2;", "a.c"), ("LMSParameters p;", "A.java"),
    ("gostinyi_dvor = 1", "a.py"),
])
def test_lookalikes_stay_silent(line, name):
    assert _families(line, name) == set(), line
