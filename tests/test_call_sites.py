"""Algorithms named where they are called, not only where they are imported.

Measured against Cryben (Näther & Hirsch, arXiv 2608.04857), an independent
corpus with its own reference CBOM: RSA scored 0 of 11 on the exact line. The
scanner saw `import "crypto/rsa"` on line 2 and nothing on the call. A report
that points at the import and not at the call points at the wrong line, and on a
file that imports a package it never uses it is simply wrong.
"""
from __future__ import annotations

import pytest

from qrp_mcp.scan import scan_directory


def families_on(tmp_path, name: str, body: str) -> set[str]:
    (tmp_path / name).write_text(body)
    result = scan_directory(tmp_path)
    return set(result["detected_algorithms"])


@pytest.mark.parametrize(
    "name,line,family",
    [
        # Go: the standard library, with no import line in the file at all.
        ("a.go", "_, _ = rsa.GenerateKey(rand.Reader, 2048)", "RSA"),
        ("a.go", "ct, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, msg, nil)", "RSA"),
        ("a.go", "pt, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, ct, nil)", "RSA"),
        ("a.go", "sig, _ := rsa.SignPSS(rand.Reader, key, crypto.SHA256, h, nil)", "RSA"),
        ("a.go", "err := rsa.VerifyPSS(pub, crypto.SHA256, h, sig, nil)", "RSA"),
        ("a.go", "sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h)", "RSA"),
        ("a.go", "k, _ := x509.ParsePKCS1PrivateKey(der)", "RSA"),
        ("a.go", "k, _ := dsa.GenerateKey(params, rand.Reader)", "DSA"),
        # Ruby.
        ("a.rb", "  OpenSSL::PKey::RSA.generate(2048)", "RSA"),
        ("a.rb", "  OpenSSL::PKey::DSA.generate(2048)", "DSA"),
        ("a.rb", "  OpenSSL::PKey::EC.generate('prime256v1')", "EC"),
        # Java: the algorithm is inside the signature name.
        ("A.java", 'Signature.getInstance("SHA256withRSA");', "RSA"),
        ("A.java", 'Signature.getInstance("SHA1withDSA");', "DSA"),
        ("A.java", 'Signature.getInstance("SHA256withECDSA");', "ECDSA"),
        # Node.
        ("a.js", "crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })", "RSA"),
        ("a.js", "crypto.generateKeyPair('ec', { namedCurve: 'P-256' }, cb)", "EC"),
        # Rust.
        ("a.rs", "let key = RsaPrivateKey::new(&mut rng, 2048)?;", "RSA"),
        # PKCS#11 mechanisms, which a HSM integration is written in.
        ("a.c", "mech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;", "RSA"),
    ],
)
def test_call_site_is_read(tmp_path, name, line, family):
    assert family in families_on(tmp_path, name, line + "\n")


@pytest.mark.parametrize(
    "name,line,family",
    [
        # JOSE/JWT names the algorithm and nothing else does. Vault carries 35
        # such lines, certbot one.
        ("a.go", 'token.SignedString(jwt.SigningMethodRS256, key)', "RSA"),
        ("a.py", 'jwt.encode(payload, key, algorithm="PS384")', "RSA"),
        ("a.py", 'jwt.encode(payload, key, algorithm="ES256")', "ECDSA"),
        ("a.js", "const alg = 'RSA-OAEP-256';", "RSA"),
        ("a.py", 'ALG = "RSA1_5"', "RSA"),
    ],
)
def test_jose_algorithm_names(tmp_path, name, line, family):
    assert family in families_on(tmp_path, name, line + "\n")


def test_a_word_in_prose_is_still_not_a_finding(tmp_path):
    """The call-site rules must not turn every mention into a use.

    A .py file, because a .md is not scanned at all and would make this pass
    whatever the rules said.
    """
    fam = families_on(tmp_path, "a.py", "# we should migrate away from RSA soon\n")
    assert fam == set()


@pytest.mark.parametrize("line", [
    "     * See FIPS 204 Section 5.2 Algorithm 2 ML-DSA.Sign()",
    "  ML-DSA.Verify(pk, M, sigma)",
    "  SLH-DSA.Sign(SK, M)",
])
def test_post_quantum_signature_is_not_classical_dsa(tmp_path, line):
    """Found in OpenSSL's crypto/ml_dsa/ by the corpus sweep, not by a unit test.

    The Go call-site rule dsa.Sign is case-insensitive and reached ML-DSA.Sign:
    a post-quantum algorithm reported as the classical one it replaces, which is
    the worst direction for this scanner to be wrong in.
    """
    (tmp_path / "a.c").write_text(line + "\n")
    assert "DSA" not in scan_directory(tmp_path)["detected_algorithms"]
