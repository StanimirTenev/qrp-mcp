"""The algorithm named only by a package, enum or constant (ZA-OPRAVYANE row 140).

Measured 23.10.2026 (`qrp-kachestvo/imena-2026-10-23`, B classes C20-C24, C32, C33, C35):
Go `dsa.PublicKey`, `elliptic.Marshal`, `crypto.SHA1`, `x509.DSA`, `ssh.KeyAlgoRSA`,
`ssh.InsecureCipherRC4`; Rust `k256::`, `dsa::`, rustls `SignatureAlgorithm::RSA`, ring's
`SHA1_FOR_LEGACY_USE_ONLY`; .NET `CngAlgorithmGroup.Rsa`, `RSASignaturePaddingMode.Pss`,
the CryptoConfig names; pycryptodome `RSA.generate(2048)` and python-rsa `rsa.sign`. The
family is the package or the enum member; the line has nothing else.
"""

from pathlib import Path

import pytest

from qrp_mcp import detectors


def _families(line: str, name: str) -> set[str]:
    found = detectors.scan_source_file(Path(name), name, lines=[line])
    return {f["algorithm"] for f in found if f["evidence_kind"] not in ("ban", "comment")}


@pytest.mark.parametrize("line,family", [
    ("var _ *dsa.PublicKey", "DSA"), ("_ = dsa.L2048N256", "DSA"),
    ("elliptic.Marshal(c, x, y)", "EC"), ("var _ *elliptic.CurveParams", "EC"),
    ("_ = crypto.SHA1", "SHA1"), ("_ = crypto.MD5", "MD5"), ("_ = crypto.MD4", "MD4"),
    ("_ = x509.DSA", "DSA"), ("_ = x509.RSA", "RSA"),
    ("_ = ssh.KeyAlgoRSA", "RSA"), ("_ = ssh.KeyAlgoDSA", "DSA"), ("_ = ssh.CertAlgoRSAv01", "RSA"),
    ("_ = ssh.KeyAlgoECDSA256", "ECDSA"), ("_ = ssh.KeyAlgoED25519", "Ed25519"),
    ("_ = ssh.KeyAlgoMLDSA65", "ML-DSA"), ("_ = ssh.InsecureCipherRC4", "RC4"),
    ("_ = ssh.KeyExchangeCurve25519", "X25519"), ("_ = ssh.KeyExchangeECDHP256", "ECDH"),
    ("_ = ssh.KeyExchangeDHGEXSHA256", "DH"), ("ssh.FingerprintLegacyMD5(k)", "MD5"),
    ("_ = agent.SignatureFlagRsaSha256", "RSA"), ("_ = packet.PubKeyAlgoRSA", "RSA"),
    ("packet.NewDSAPrivateKey(t, k)", "DSA"), ("_ = packet.PubKeyAlgoECDH", "ECDH"),
    ("rsa.EncryptOAEPWithOptions(r, k, m, o)", "RSA"), ("var _ *rsa.PSSOptions", "RSA"),
    ("_ = des.BlockSize", "DES"), ("_ = md5.Size", "MD5"), ("_ = sha1.BlockSize", "SHA1"),
    ("md4.New()", "MD4"),
])
def test_go(line, family):
    assert family in _families(line, "a.go")


@pytest.mark.parametrize("line,family", [
    ("let _ = k256::PublicKey;", "EC"), ("let _ = dsa::SigningKey;", "DSA"),
    ("let _ = elliptic_curve::SecretKey;", "EC"), ("let _ = rsa::BigUint;", "RSA"),
    ("let _ = des::WeakKeyError;", "DES"),
    ("let _ = rustls::SignatureAlgorithm::RSA;", "RSA"),
    ("let _ = rustls::SignatureAlgorithm::DSA;", "DSA"),
    ("let _ = rustls::HashAlgorithm::MD5;", "MD5"), ("let _ = rustls::HashAlgorithm::SHA1;", "SHA1"),
    ("let _ = rustls::NamedGroup::FFDHE2048;", "DH"),
    ("let _ = &ring::digest::SHA1_FOR_LEGACY_USE_ONLY;", "SHA1"),
    ("let _ = &aws_lc_rs::cipher::DES_FOR_LEGACY_USE_ONLY;", "DES"),
    ("let _ = &aws_lc_rs::cmac::TDES_FOR_LEGACY_USE_ONLY;", "3DES"),
    ("let _ = &aws_lc_rs::rsa::OAEP_SHA256_MGF1SHA256;", "RSA"),
])
def test_rust(line, family):
    assert family in _families(line, "a.rs")


@pytest.mark.parametrize("line,family", [
    ("var a = CngAlgorithmGroup.Rsa;", "RSA"), ("var a = CngAlgorithmGroup.Dsa;", "DSA"),
    ("var a = CngAlgorithm.Sha1;", "SHA1"), ("var a = CngAlgorithm.MD5;", "MD5"),
    ("var a = CngAlgorithm.ECDiffieHellmanP256;", "ECDH"),
    ("var a = RSASignaturePaddingMode.Pss;", "RSA"), ("var a = RSAEncryptionPaddingMode.Oaep;", "RSA"),
    ("var a = (RSASignaturePadding)null;", "RSA"), ("var a = CngKeyBlobFormat.EccPublicBlob;", "EC"),
    ("var a = new DSAOpenSsl();", "DSA"), ("var a = (DSAParameters)null;", "DSA"),
    ("var a = new RSAPKCS1SignatureFormatter();", "RSA"), ("var a = (RSAParameters)null;", "RSA"),
    ("var a = (ECDiffieHellmanPublicKey)null;", "ECDH"), ("var a = (ECCurve)null;", "EC"),
    ("var a = ExchangeAlgorithmType.RsaKeyX;", "RSA"), ("var a = HashAlgorithmType.Md5;", "MD5"),
    ("var a = HashAlgorithmType.Sha1;", "SHA1"), ("var a = CipherAlgorithmType.Des;", "DES"),
    ("var a = CipherAlgorithmType.Rc2;", "RC2"),
    ("var a = X509SubjectKeyIdentifierHashAlgorithm.CapiSha1;", "SHA1"),
    ('var a = CryptoConfig.CreateFromName("SHA1");', "SHA1"),
    ('var a = CryptoConfig.CreateFromName("System.Security.Cryptography.SHA1Cng");', "SHA1"),
    ('var a = CryptoConfig.CreateFromName("System.Security.Cryptography.MD5Managed");', "MD5"),
    ('var a = CryptoConfig.CreateFromName("RSA");', "RSA"),
    ('var a = CryptoConfig.CreateFromName("DSA");', "DSA"),
    ('var a = CryptoConfig.CreateFromName("DES");', "DES"),
    ('var a = CryptoConfig.CreateFromName("Triple DES");', "3DES"),
    ('var a = CryptoConfig.CreateFromName("RC2");', "RC2"),
    ('var a = CryptoConfig.CreateFromName("http://www.w3.org/2000/09/xmldsig#sha1");', "SHA1"),
    ('var a = CryptoConfig.CreateFromName("http://www.w3.org/2001/04/xmlenc#des-cbc");', "DES"),
    ('var a = CryptoConfig.CreateFromName("http://www.w3.org/2001/04/xmldsig-more#md5");', "MD5"),
])
def test_dotnet(line, family):
    assert family in _families(line, "a.cs")


@pytest.mark.parametrize("line,family", [
    ("x = RSA.generate(2048)", "RSA"), ("x = rsa.sign(msg, priv, 'SHA-256')", "RSA"),
    ("x = rsa.verify", "RSA"), ("x = rsa.encrypt", "RSA"), ("x = SHA.new()", "SHA1"),
    ("x = DH.key_agreement(static_priv=a, static_pub=b, kdf=k)", "ECDH"),
    ('key = ECC.generate(curve="curve448")', "X448"),
])
def test_python(line, family):
    assert family in _families(line, "a.py")


@pytest.mark.parametrize("line,name", [
    ("des.text = 'description'", "a.py"), ("x = des.value", "a.js"), ("_ = crypto.Hash", "a.go"),
    ("_ = ssh.KeyAlgoUnknown", "a.go"), ("var a = CngAlgorithm.Sha256;", "a.cs"),
    ('var a = CryptoConfig.CreateFromName("SHA256");', "a.cs"), ("let _ = p256k::Thing;", "a.rs"),
    ("x = mrsa.sign", "a.py"), ("x = coarse.sign", "a.py"), ("_ = sha1sum.Size", "a.go"),
    # `namespace dsa` / `des` in C++: data structures and algorithms, a design system.
    ("dsa::LinkedList<int> list;", "a.cpp"), ("auto b = des::Button();", "a.cpp"),
])
def test_lookalikes_stay_silent(line, name):
    assert _families(line, name) == set(), line
