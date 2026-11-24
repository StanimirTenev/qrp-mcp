"""Post-quantum keys, certificates and requests for the closure catalogue (pqc/PKI, 24.11.2026).

Made when the tests run, never committed, as test_operation_closure._make_material makes the
classical ones. ML-DSA (44, 65, 87) and ML-KEM (768, 1024) come from cryptography; what it does not
make -- ML-KEM-512, SLH-DSA, the composite ML-DSA keys of RFC 10073, the expandedKey and `both`
private-key forms -- is DER built here with the OIDs and sizes of the RFCs (9881, 9909, 9935,
10073): random key bytes, a random signature. The scanner reads the structure; nothing here is
verified, and none of it is a usable key except what cryptography generated.
"""

from __future__ import annotations

import base64
import datetime
import os

NIST_SIG = "2.16.840.1.101.3.4.3."
NIST_KEM = "2.16.840.1.101.3.4.4."
# RFC 9909 section 3: pure SLH-DSA sigAlgs 20-31, HashSLH-DSA 35-46, in the same order of sets.
SLH_SETS = ("sha2-128s", "sha2-128f", "sha2-192s", "sha2-192f", "sha2-256s", "sha2-256f",
            "shake-128s", "shake-128f", "shake-192s", "shake-192f", "shake-256s", "shake-256f")
SLH_PUBLIC = {"128": 16, "192": 24, "256": 32}  # n bytes; a public key is 2n
MLDSA_PUBLIC = {"44": 1312, "65": 1952, "87": 2592}
MLDSA_EXPANDED = {"44": 2560, "65": 4032, "87": 4896}
MLDSA_SIGNATURE = {"44": 2420, "65": 3309, "87": 4627}
MLKEM_PUBLIC = {"512": 800, "768": 1184, "1024": 1568}
MLKEM_EXPANDED = {"512": 1632, "768": 2400, "1024": 3168}


def _der(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        return bytes([tag, n]) + body
    size = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(size)]) + size + body


def _oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    out = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(reversed(chunk))
    return _der(0x06, out)


def _alg(dotted: str) -> bytes:
    return _der(0x30, _oid(dotted))  # parameters absent (RFC 9881, 9909, 9935, 10073)


def _spki(dotted: str, key: bytes) -> bytes:
    return _der(0x30, _alg(dotted) + _der(0x03, b"\x00" + key))


def _pkcs8(dotted: str, private_key: bytes) -> bytes:
    return _der(0x30, _der(0x02, b"\x00") + _alg(dotted) + _der(0x04, private_key))


def _name(cn: str) -> bytes:
    attr = _der(0x30, _oid("2.5.4.3") + _der(0x0C, cn.encode()))
    return _der(0x30, _der(0x31, attr))


def _certificate(subject_oid: str, subject_key: bytes, signature_oid: str,
                 signature_length: int) -> bytes:
    validity = _der(0x30, _der(0x17, b"260101000000Z") + _der(0x17, b"360101000000Z"))
    tbs = _der(0x30, _der(0xA0, _der(0x02, b"\x02")) + _der(0x02, b"\x01\x23")
               + _alg(signature_oid) + _name("closure.example") + validity
               + _name("closure.example") + _spki(subject_oid, subject_key))
    return _der(0x30, tbs + _alg(signature_oid)
                + _der(0x03, b"\x00" + os.urandom(signature_length)))


def _pem(label: str, der: bytes) -> bytes:
    body = base64.b64encode(der).decode()
    return (f"-----BEGIN {label}-----\n"
            + "".join(body[i:i + 64] + "\n" for i in range(0, len(body), 64))
            + f"-----END {label}-----\n").encode()


def make() -> dict[str, bytes]:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem
    from cryptography.x509.oid import NameOID

    E, P, F = (serialization.Encoding, serialization.PrivateFormat,
               serialization.PublicFormat.SubjectPublicKeyInfo)
    none = serialization.NoEncryption()
    out: dict[str, bytes] = {}
    dsa = {"44": mldsa.MLDSA44PrivateKey.generate(), "65": mldsa.MLDSA65PrivateKey.generate(),
           "87": mldsa.MLDSA87PrivateKey.generate()}
    for level, key in dsa.items():
        out[f"MLDSA{level}_SPKI_PEM"] = key.public_key().public_bytes(E.PEM, F)
        out[f"MLDSA{level}_PKCS8_SEED_PEM"] = key.private_bytes(E.PEM, P.PKCS8, none)
    out["MLDSA65_SPKI_DER"] = dsa["65"].public_key().public_bytes(E.DER, F)
    out["MLDSA65_PKCS8_SEED_DER"] = dsa["65"].private_bytes(E.DER, P.PKCS8, none)
    # RFC 9881 section 6: ML-DSA-PrivateKey ::= CHOICE { seed [0], expandedKey, both }.
    for level in ("44", "65", "87"):
        expanded = _der(0x04, os.urandom(MLDSA_EXPANDED[level]))
        both = _der(0x30, _der(0x04, os.urandom(32)) + expanded)
        out[f"MLDSA{level}_PKCS8_EXPANDED_PEM"] = _pem(
            "PRIVATE KEY", _pkcs8(NIST_SIG + {"44": "17", "65": "18", "87": "19"}[level], expanded))
        out[f"MLDSA{level}_PKCS8_BOTH_PEM"] = _pem(
            "PRIVATE KEY", _pkcs8(NIST_SIG + {"44": "17", "65": "18", "87": "19"}[level], both))

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "closure.example")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)

    def build(public_key, signer, serial):
        return (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(public_key).serial_number(serial).not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=3650)).sign(signer, None))

    cert65 = build(dsa["65"].public_key(), dsa["65"], 10)
    out["CERT_MLDSA65_PEM"] = cert65.public_bytes(E.PEM)
    out["CERT_MLDSA65_DER"] = cert65.public_bytes(E.DER)
    out["CERT_MLDSA44_PEM"] = build(dsa["44"].public_key(), dsa["44"], 11).public_bytes(E.PEM)
    # Row 450: an ML-DSA-65 key certified by an ML-DSA-87 issuer.
    out["CERT_MLDSA65_BY_MLDSA87_PEM"] = build(dsa["65"].public_key(), dsa["87"], 12).public_bytes(E.PEM)
    out["CSR_MLDSA65_PEM"] = (x509.CertificateSigningRequestBuilder().subject_name(name)
                              .sign(dsa["65"], None).public_bytes(E.PEM))

    kem = {"768": mlkem.MLKEM768PrivateKey.generate(), "1024": mlkem.MLKEM1024PrivateKey.generate()}
    for level, key in kem.items():
        out[f"MLKEM{level}_SPKI_PEM"] = key.public_key().public_bytes(E.PEM, F)
        out[f"MLKEM{level}_PKCS8_SEED_PEM"] = key.private_bytes(E.PEM, P.PKCS8, none)
    out["MLKEM512_SPKI_PEM"] = _pem("PUBLIC KEY", _spki(NIST_KEM + "1", os.urandom(MLKEM_PUBLIC["512"])))
    out["MLKEM512_PKCS8_SEED_PEM"] = _pem("PRIVATE KEY", _pkcs8(NIST_KEM + "1",
                                                                _der(0x80, os.urandom(64))))
    # RFC 9935 section 6: ML-KEM-PrivateKey ::= CHOICE { seed [0], expandedKey, both }.
    for level, arc in (("512", "1"), ("768", "2"), ("1024", "3")):
        expanded = _der(0x04, os.urandom(MLKEM_EXPANDED[level]))
        out[f"MLKEM{level}_PKCS8_EXPANDED_PEM"] = _pem("PRIVATE KEY", _pkcs8(NIST_KEM + arc, expanded))
        out[f"MLKEM{level}_PKCS8_BOTH_PEM"] = _pem(
            "PRIVATE KEY", _pkcs8(NIST_KEM + arc, _der(0x30, _der(0x04, os.urandom(64)) + expanded)))
    out["CERT_MLKEM768_BY_MLDSA65_PEM"] = build(kem["768"].public_key(), dsa["65"], 13).public_bytes(E.PEM)

    for n, label in enumerate(SLH_SETS):
        size = SLH_PUBLIC[label.split("-")[1][:3]]
        key = label.upper().replace("-", "_")
        out[f"SLHDSA_{key}_SPKI_PEM"] = _pem("PUBLIC KEY", _spki(NIST_SIG + str(20 + n), os.urandom(2 * size)))
        out[f"HASHSLHDSA_{key}_SPKI_PEM"] = _pem("PUBLIC KEY", _spki(NIST_SIG + str(35 + n),
                                                                     os.urandom(2 * size)))
    out["CERT_SLHDSA_SHA2_128S_PEM"] = _pem("CERTIFICATE", _certificate(
        NIST_SIG + "20", os.urandom(32), NIST_SIG + "20", 7856))

    # RFC 10073: composite ML-DSA keys; the public key is the two keys' bytes, the size is not
    # checked here.
    for arc in range(37, 55):
        oid = f"1.3.6.1.5.5.7.6.{arc}"
        out[f"COMPOSITE_{arc}_SPKI_PEM"] = _pem("PUBLIC KEY", _spki(oid, os.urandom(1312 + 65)))
    out["CERT_COMPOSITE_45_PEM"] = _pem("CERTIFICATE", _certificate(
        "1.3.6.1.5.5.7.6.45", os.urandom(1952 + 65), "1.3.6.1.5.5.7.6.45", 3309 + 72))
    out["CERT_MLDSA65_BY_COMPOSITE_49_PEM"] = _pem("CERTIFICATE", _certificate(
        NIST_SIG + "18", os.urandom(1952), "1.3.6.1.5.5.7.6.49", 4627 + 104))
    return out
