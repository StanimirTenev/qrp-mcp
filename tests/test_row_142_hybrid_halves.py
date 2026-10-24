"""Hybrids and composites with a half missing (ZA-OPRAVYANE row 142).

Measured 23.10.2026 (`qrp-kachestvo/imena-2026-10-23`, B classes C03 and C31): .NET's
`CompositeMLDsaAlgorithm.MLDsa65WithECDsaP256` gave ML-DSA and not ECDSA, Go's
`hpke.MLKEM768P256` and `ssh-mldsa87-p384` not the curve, `curveSM2MLKEM768` not SM2, Go's
`ssh.KeyExchangeMLKEM768X25519` not ML-KEM; Bouncy Castle's hash-then-sign names
(`SHA512WITHMLDSA65`, `HASHWITHSLHDSA`) and X-Wing classes gave nothing. A composite whose
classical half is not reported reads as post-quantum only -- the half Shor breaks is gone.
"""

from pathlib import Path

import pytest

from qrp_mcp import detectors


def _families(line: str, name: str) -> set[str]:
    found = detectors.scan_source_file(Path(name), name, lines=[line])
    return {f["algorithm"] for f in found if f["evidence_kind"] not in ("ban", "comment")}


@pytest.mark.parametrize("line,name,expected", [
    ("var a = CompositeMLDsaAlgorithm.MLDsa65WithECDsaP256;", "a.cs", {"ML-DSA", "ECDSA"}),
    ("var a = CompositeMLDsaAlgorithm.MLDsa44WithEd25519;", "a.cs", {"ML-DSA", "Ed25519"}),
    ("var a = CompositeMLDsaAlgorithm.MLDsa87WithEd448;", "a.cs", {"ML-DSA", "Ed448"}),
    ("var a = CompositeMLDsaAlgorithm.MLDsa65WithRSA3072Pss;", "a.cs", {"ML-DSA", "RSA"}),
    ("var a = (CompositeMLDsaCng)null;", "a.cs", {"ML-DSA"}),
    ("hpke.MLKEM768P256()", "a.go", {"ML-KEM", "ECDH"}),
    ("x = hpke.MLKEM1024P384PrivateKey", "a.py", {"ML-KEM", "ECDH"}),
    ("await crypto.subtle.generateKey({ name: 'MLKEM768-P256' }, true, usages);", "a.js",
     {"ML-KEM", "ECDH"}),
    ("_ = ssh.KeyExchangeMLKEM768X25519", "a.go", {"ML-KEM", "X25519"}),
    ("HostKeyAlgorithms ssh-mldsa87-p384", "sshd_config", {"ML-DSA", "ECDSA"}),
    ("Groups = curveSM2MLKEM768", "openssl.cnf", {"ML-KEM", "SM2"}),
    ('use(Signature.getInstance("SHA512WITHMLDSA65", "BC"));', "A.java", {"ML-DSA"}),
    ('use(KeyFactory.getInstance("SHA512WITHMLDSA", "BC"));', "A.java", {"ML-DSA"}),
    ('use(Signature.getInstance("HASHWITHSLHDSA", "BC"));', "A.java", {"SLH-DSA"}),
    ('use(Signature.getInstance("SHA512WITHSPHINCS256", "BC"));', "A.java", {"SLH-DSA"}),
    ("use(new HashMLDSASigner());", "A.java", {"ML-DSA"}),
    ("use(new HashSLHDSASigner());", "A.java", {"SLH-DSA"}),
    ("use(new XWingKeyPairGenerator());", "A.java", {"ML-KEM", "X25519"}),
])
def test_both_halves(line, name, expected):
    assert _families(line, name) == expected


@pytest.mark.parametrize("line,name", [
    ("x = withmldsa_flag", "a.py"), ("forthwith = 1", "a.py"), ("x = WithSphinx()", "a.py"),
])
def test_lookalikes_stay_silent(line, name):
    assert _families(line, name) == set(), line
