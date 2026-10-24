"""JCA and Bouncy Castle algorithm names that were not read (ZA-OPRAVYANE row 138).

Measured 23.10.2026 (`qrp-kachestvo/imena-2026-10-23`, B classes C08, C10, C17, C18, C28,
C29, C30): `SHA256WithRSAEncryption` 0 of 60, `SHA256/RSA` 0 of 20, every
`...inP1363Format`, RSASSA-PSS and OAEP spellings (pyca `padding.PSS`, Go
`x509.SHA256WithRSAPSS`), `DSAwithSHA1`, `RAWDSA`, the PBE names (`PBEWITHMD5ANDDES`,
`PBEWITHSHAAND40BITRC2-CBC`), ECIES, ECNR, ECMQV and deterministic ECDSA, the DH KDF
agreements (`DHWITHSHA256KDF`) and ElGamal's Go and OpenPGP names.
"""

from pathlib import Path

import pytest

from qrp_mcp import detectors


def _families(line: str, name: str = "A.java") -> set[str]:
    found = detectors.scan_source_file(Path(name), name, lines=[line])
    return {f["algorithm"] for f in found if f["evidence_kind"] not in ("ban", "comment")}


def _sig(name: str) -> str:
    return f'use(Signature.getInstance("{name}", "BC"));'


@pytest.mark.parametrize("line,expected", [
    (_sig("SHA256WithRSAEncryption"), {"RSA"}), (_sig("SHA256WITHRSAENCRYPTION"), {"RSA"}),
    (_sig("SHA256/RSA"), {"RSA"}), (_sig("SHA512(224)/RSA"), {"RSA"}),
    (_sig("RIPEMD160withRSASSA-PSS"), {"RSA"}), (_sig("RAWRSA"), {"RSA"}),
    (_sig("RAWRSASSA-PSS"), {"RSA"}), ('use(AlgorithmParameters.getInstance("PSS", "BC"));', {"RSA"}),
    ('use(AlgorithmParameters.getInstance("OAEP", "BC"));', {"RSA"}),
    ('use(Cipher.getInstance("RSA-KTS-KEM-KWS", "BC"));', {"RSA"}),
    (_sig("SHA256withECDSAinP1363Format"), {"ECDSA"}),
    (_sig("NONEwithDSAinP1363Format"), {"DSA"}), (_sig("SHA256withDSAinP1363Format"), {"DSA"}),
    (_sig("DSAwithSHA1"), {"DSA", "SHA1"}),     # SHA1: row 143 (_sig("SHA256/DSA"), {"DSA"}), (_sig("RAWDSA"), {"DSA"}),
    (_sig("DETDSA"), {"DSA"}), (_sig("SHA256WITHDETDSA"), {"DSA"}), (_sig("DDSA"), {"DSA"}),
    (_sig("SHA256WITHDETECDSA"), {"ECDSA"}), (_sig("SHA256WITHECDDSA"), {"ECDSA"}),
    (_sig("SHA256WITHECNR"), {"EC"}), ("use(new ECNRSigner());", {"EC"}),
    ("use(new ECCSISigner());", {"EC"}),
    ('use(Cipher.getInstance("ECIESwithSHA256andAES-CBC", "BC"));', {"ECDH"}),
    ('use(Cipher.getInstance("ECIESwithDESEDE-CBC", "BC"));', {"ECDH", "3DES"}),
    ("use(new ECIESKEMGenerator());", {"ECDH"}),
    ('use(KeyAgreement.getInstance("ECCDHWITHSHA256KDF", "BC"));', {"ECDH"}),
    ('use(KeyAgreement.getInstance("ECDHWITHSHA256KDF", "BC"));', {"ECDH"}),
    ('use(KeyAgreement.getInstance("ECDHC", "BC"));', {"ECDH"}),
    ("use(new ECDHCBasicAgreement());", {"ECDH"}),
    ('use(KeyAgreement.getInstance("ECMQVWITHSHA256CKDF", "BC"));', {"ECDH"}),
    ("use(new ECMQVBasicAgreement());", {"ECDH"}),
    ('use(KeyAgreement.getInstance("MQVWITHSHA256KDF", "BC"));', {"ECDH"}),
    ("use(new MQVBasicAgreement());", {"DH"}),
    ('use(KeyAgreement.getInstance("DHWITHSHA256KDF", "BC"));', {"DH"}),
    ('use(KeyAgreement.getInstance("DHUWITHSHA256KDF", "BC"));', {"DH"}),
    ('use(Cipher.getInstance("DHIESwithAES-CBC", "BC"));', {"DH"}),
    ("use(new DHUnifiedAgreement());", {"DH"}), ("use(new DHStandardGroups());", {"DH"}),
    ("use(new XDHBasicAgreement());", {"X25519"}),
    ('use(KeyAgreement.getInstance("XDHwithSHA256HKDF", "BC"));', {"X25519"}),
    ('use(KEM.getInstance("DHKEM"));', {"ECDH"}),
    (_sig("MD5WithRSAEncryption"), {"RSA", "MD5"}), (_sig("MD2withRSAEncryption"), {"RSA", "MD2"}),
    (_sig("MD4/RSA"), {"RSA", "MD4"}),
    ('use(Cipher.getInstance("PBEWITHMD5ANDDES", "BC"));', {"MD5", "DES"}),
    ('use(SecretKeyFactory.getInstance("PBEWITHSHAAND40BITRC2-CBC", "BC"));', {"SHA1", "RC2"}),
    ('use(SecretKeyFactory.getInstance("PBEWITHMD2ANDRC2-CBC", "BC"));', {"MD2", "RC2"}),
    ('use(SecretKeyFactory.getInstance("PBEWITHSHAAND128BITRC4", "BC"));', {"SHA1", "RC4"}),
    ('use(AlgorithmParameters.getInstance("PBEWITHSHAANDDES3KEY-CBC", "BC"));', {"SHA1", "3DES"}),
    ('use(AlgorithmParameters.getInstance("PBEWITHSHAANDDES2KEY-CBC", "BC"));', {"SHA1", "3DES"}),
    ('use(Cipher.getInstance("PBEWITHSHA1AND256BITAES-CBC-BC", "BC"));', {"SHA1"}),
    ('use(Cipher.getInstance("PBEWITHMD5AND256BITAES-CBC-OPENSSL", "BC"));', {"MD5"}),
])
def test_java_names(line, expected):
    assert _families(line) == expected


@pytest.mark.parametrize("line,name,family", [
    ("padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)", "a.py", "RSA"),
    ("padding.OAEP(mgf=m, algorithm=a, label=None)", "a.py", "RSA"),
    ("key.sign(data, PKCS1v15(), hashes.SHA256())", "a.py", "RSA"),
    ("_ = x509.SHA256WithRSAPSS", "a.go", "RSA"),
    ("_ = elgamal.Encrypt(rand, pub, msg)", "a.go", "ElGamal"),
    ("var _ *elgamal.PublicKey", "a.go", "ElGamal"),
    ("_ = packet.PubKeyAlgoElGamal", "a.go", "ElGamal"),
    ("hpke.DHKEM(ecdh.X25519())", "a.go", "ECDH"),
])
def test_other_languages(line, name, family):
    assert family in _families(line, name)


@pytest.mark.parametrize("line,name", [
    ("padding.left = 3", "a.py"), ("PSSManager m;", "A.java"), ("x = oaep_label", "a.py"),
    ("DESCRIPTION_WITH_DHCP = 1", "a.py"), ("int ECHO_ECNRX = 0;", "a.c"),
    ("pbe_with_salt = 1", "a.py"), ("dhkem_count = 0", "a.py"), ("rawdsa_flag = 0", "a.py"),
])
def test_lookalikes_stay_silent(line, name):
    assert _families(line, name) == set(), line
