"""Protocol settings that name an algorithm (ZA-OPRAVYANE row 141).

Measured 23.10.2026 (`qrp-kachestvo/imena-2026-10-23`, B classes C04, C05, C11-C15): the
TLS SignatureScheme names for RSA (`rsa_pss_rsae_sha256`, `rsa_pkcs1_sha256`) and Go's
`tls.PSSWithSHA256`; sshd's `des-cbc`, `hmac-md5`, `curve448-sha512`, the GSS and RSA key
exchanges and the SPKI/PGP host key types; strongSwan's `des`, `sha1`, `md5`, `modp768`,
`ecp512bp`, `curve448`; uncommon curves in an openssl.cnf `Groups =`; BIND's `algorithm dsa;`
and `ecc-gost`; JOSE/COSE `RS1`, `HS1`, `HPKE-*`, `ESB*`, `ESP*`, the numeric ECDH-ES and
RSAES-OAEP identifiers; and a JWK's `"crv": "P-256"` or `"kty": "EC"`. Short names only
under the setting that gives them their meaning: `des` and `sha1` alone are not findings.
"""

from pathlib import Path

import pytest

from qrp_mcp import detectors


def _families(line: str, name: str) -> set[str]:
    found = detectors.scan_source_file(Path(name), name, lines=[line], cipher_exclusions=True)
    return {f["algorithm"] for f in found if f["evidence_kind"] not in ("ban", "comment")}


@pytest.mark.parametrize("line,name,family", [
    ("SignatureAlgorithms = rsa_pss_rsae_sha256", "openssl.cnf", "RSA"),
    ("SignatureAlgorithms = rsa_pss_pss_sha512", "openssl.cnf", "RSA"),
    ("SignatureAlgorithms = rsa_pkcs1_sha256_legacy", "openssl.cnf", "RSA"),
    ("SignatureAlgorithms = sm2sig_sm3", "openssl.cnf", "SM2"),
    ("SignatureAlgorithms = gostr34102012_256a", "openssl.cnf", "GOST R 34.10"),
    ("_ = tls.PSSWithSHA256", "a.go", "RSA"), ("_ = tls.PKCS1WithSHA384", "a.go", "RSA"),
    ("Ciphers des-cbc", "sshd_config", "DES"), ("Ciphers arcfour256", "sshd_config", "RC4"),
    ("MACs hmac-md5", "sshd_config", "MD5"), ("MACs hmac-md5-96-etm@openssh.com", "sshd_config", "MD5"),
    ("KexAlgorithms curve448-sha512", "sshd_config", "X448"),
    ("KexAlgorithms rsa2048-sha256", "sshd_config", "RSA"),
    ("KexAlgorithms ecmqv-sha2", "sshd_config", "ECDH"),
    ("GSSAPIKexAlgorithms gss-group14-sha256-", "sshd_config", "DH"),
    ("GSSAPIKexAlgorithms gss-gex-sha1-", "sshd_config", "DH"),
    ("HostKeyAlgorithms spki-sign-rsa", "sshd_config", "RSA"),
    ("HostKeyAlgorithms pgp-sign-dss", "sshd_config", "DSA"),
    ("HostKeyAlgorithms x509v3-rsa2048-sha256", "sshd_config", "RSA"),
    ("proposals = des-sha256", "swanctl.conf", "DES"),
    ("proposals = aes128-sha1", "swanctl.conf", "SHA1"),
    ("proposals = aes128-sha", "swanctl.conf", "SHA1"),
    ("esp = aes128-md5_128", "swanctl.conf", "MD5"),
    ("ike=aes128-sha1_160-modp2048!", "ipsec.conf", "SHA1"),
    ("proposals = aes128gcm16-prfsha256-modp768", "swanctl.conf", "DH"),
    ("proposals = aes128gcm16-prfsha256-ecp512bp", "swanctl.conf", "EC"),
    ("proposals = aes128gcm16-prfsha256-curve448", "swanctl.conf", "X448"),
    ("Groups = sect163k1", "openssl.cnf", "ECDH"), ("Groups = secp160r1", "openssl.cnf", "ECDH"),
    ("Groups = secp256k1", "openssl.cnf", "ECDH"), ("Groups = GC256A", "openssl.cnf", "GOST R 34.10"),
    ("Groups = curveSM2", "openssl.cnf", "SM2"),
    ("csk lifetime unlimited algorithm dsa;", "named.conf", "DSA"),
    ("csk lifetime unlimited algorithm dh;", "named.conf", "DH"),
    ("csk lifetime unlimited algorithm ecc-gost;", "named.conf", "GOST R 34.10"),
    ("csk lifetime unlimited algorithm ecc-gost12;", "named.conf", "GOST R 34.10"),
    ("csk lifetime unlimited algorithm sm2sm3;", "named.conf", "SM2"),
    ("@ IN DNSKEY 257 3 12 AwEAAQ==", "example.zone", "GOST R 34.10"),
    ("@ IN DNSKEY 257 3 23 AwEAAQ==", "example.zone", "GOST R 34.10"),
    ("@ IN DNSKEY 257 3 17 AwEAAQ==", "example.zone", "SM2"),
    ('{"kid": "k1", "alg": "RS1"},', "jwks.json", "RSA"),
    ('{"kid": "k1", "alg": "RS1"},', "jwks.json", "SHA1"),
    ('{"kid": "k88", "alg": "HS1"},', "jwks.json", "SHA1"),
    ('{"kid": "k268", "alg": "ESB512"},', "cose.json", "ECDSA"),
    ('{"kid": "k51", "alg": "ESP384"},', "cose.json", "ECDSA"),
    ('{"kid": "k102", "alg": "HPKE-0"},', "jwks.json", "ECDH"),
    ('{"kid": "k124", "alg": "HPKE-3-KE"},', "jwks.json", "X25519"),
    ('{"kid": "k112", "alg": "HPKE-5"},', "jwks.json", "X448"),
    ('{"kid": "k42", "alg": "RSAES-OAEP w/ SHA-512"},', "cose.json", "RSA"),
    ('const pm = { type: "public-key", alg: -65535 };', "a.js", "RSA"),
    ('const pm = { type: "public-key", alg: -267 };', "a.js", "ECDSA"),
    ('const pm = { type: "public-key", alg: -46 };', "a.js", "HSS/LMS"),
    ('const pm = { type: "public-key", alg: -41 };', "a.js", "RSA"),
    ('const pm = { type: "public-key", alg: -25 };', "a.js", "ECDH"),
    ('const pm = { type: "public-key", alg: -14 };', "a.js", "SHA1"),
    ('{"kty": "EC2", "crv": "P-256"},', "cose.json", "EC"),
    ('{"kty": "EC2", "crv": "brainpoolP320r1"},', "cose.json", "EC"),
    ('{"kty": "EC", "use": "sig"},', "jwks.json", "EC"),
    ("crypto.generateKeyPairSync('x448', options);", "a.js", "X448"),
])
def test_settings(line, name, family):
    assert family in _families(line, name)


@pytest.mark.parametrize("line,name", [
    ("des = 'description'", "a.py"), ("sha1 = digest_of(x)", "a.py"),
    ("connections { des { local_addrs = 1.2.3.4 } }", "swanctl.conf"),
    ("proposals = aes256gcm16-prfsha384-ecp384", "swanctl.conf"),  # P-384 only: EC, not DES/SHA1
    ('{"alg": "RS256"}', "jwks.json"), ('{"name": "RS1 bike"}', "a.json"),
    ('{"crv": "Ed25519", "kty": "OKP"}', "jwks.json"), ('{"kty": "ECHO"}', "a.json"),
    ("int alg = -14;", "a.c"), ("x = 'HPKE-9'", "a.py"), ("algorithm dsalist;", "named.conf"),
    ("x = rsa_pss_flag", "a.py"), ("hmac_md5_count = 0", "a.py"),
])
def test_lookalikes_stay_silent(line, name):
    assert _families(line, name) - {"EC", "RSA", "Ed25519"} == set(), line


def test_short_names_do_not_leak_into_other_families():
    assert _families("proposals = aes256gcm16-prfsha384-ecp384", "swanctl.conf") == {"EC"}
    assert _families('{"alg": "RS256"}', "jwks.json") == {"RSA"}
