"""Row 520 (17.11.2026, Bryant Nielson; probe `linkedin-postove/2026-11-17/stai-qrp/proba-nielson/`,
openssh 7fe3b24).

`regress/rsa_ssh2.prv` -- an RSA private key in ssh.com's SSH2 format (`---- BEGIN SSH2 ENCRYPTED
PRIVATE KEY ----`, four dashes, RFC 4716-style armour around ssh.com's own key blob) -- was in
`not_examined` as `type_not_claimed`, while the other five `.prv` files of the tree were read: the
peek for key material knew only the five-dash PEM header. The file is now read: the family from
the blob's key type (`if-modn{...}` is RSA, `dl-modp{...}` is DSA), and for an unencrypted RSA
key the size, from the bit count of its modulus.

Not claimed: an encrypted key's size (`key_unread: password_protected`), or a DSA key's size.
"""

import base64
import struct
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from qrp_mcp.scan import scan_directory

OPENSSH = Path.home() / "qrp-evidence/corpus/openssh/regress/rsa_ssh2.prv"


def _string(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def _mpint(n: int) -> bytes:
    bits = n.bit_length()
    return struct.pack(">I", bits) + n.to_bytes((bits + 7) // 8, "big")


def _sshcom(key_type: str, cipher: str, data: bytes) -> str:
    inner = _string(key_type.encode()) + _string(cipher.encode()) + _string(
        struct.pack(">I", len(data)) + data)
    blob = struct.pack(">II", 0x3F6FF9EB, 8 + len(inner)) + inner
    body = base64.b64encode(blob).decode()
    lines = [body[i:i + 70] for i in range(0, len(body), 70)]
    return ("---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\nSubject: test\n"
            "Comment: \"a key\"\n" + "\n".join(lines) +
            "\n---- END SSH2 ENCRYPTED PRIVATE KEY ----\n")


def _rsa(bits: int, cipher: str = "none") -> str:
    k = rsa.generate_private_key(public_exponent=65537, key_size=bits).private_numbers()
    data = b"".join(_mpint(x) for x in (k.public_numbers.e, k.d, k.public_numbers.n,
                                        k.iqmp, k.p, k.q))
    return _sshcom("if-modn{sign{rsa-pkcs1-sha1},encrypt{rsa-pkcs1v2-oaep}}", cipher, data)


def _scan(tmp_path, files):
    for name, text in files.items():
        (tmp_path / name).write_text(text)
    return scan_directory(tmp_path)


def _not_examined(result):
    return {p for r in result["coverage"]["not_examined"] for p in r.get("paths") or []}


def test_an_sshcom_rsa_key_is_read_with_its_size(tmp_path):
    result = _scan(tmp_path, {"rsa_ssh2.prv": _rsa(2048)})
    assert "rsa_ssh2.prv" not in _not_examined(result)
    [key] = result["evidence"]["embedded_keys"]
    assert (key["line"], key["key_algorithm"], key["key_size"]) == (1, "RSA", 2048)
    [row] = [r for r in result["evidence"]["source_code"] if r["path"] == "rsa_ssh2.prv"]
    assert (row["algorithm"], row["key_size"]) == ("RSA", 2048)


def test_an_encrypted_one_gives_its_family_and_says_why_not_its_size(tmp_path):
    result = _scan(tmp_path, {"enc.prv": _rsa(1024, cipher="3des-cbc"),
                              "dsa.prv": _sshcom("dl-modp{sign{dsa-nist-sha1},dh{plain}}",
                                                 "none", b"\0" * 40)})
    keys = {k["path"]: k for k in result["evidence"]["embedded_keys"]}
    assert keys["enc.prv"]["key_algorithm"] == "RSA"
    assert keys["enc.prv"]["key_unread"] == "password_protected"
    assert "key_size" not in keys["enc.prv"]
    assert keys["dsa.prv"]["key_algorithm"] == "DSA"


@pytest.mark.skipif(not OPENSSH.exists(), reason="the openssh corpus is not on this machine")
def test_openssh_regress_rsa_ssh2(tmp_path):
    result = _scan(tmp_path, {"rsa_ssh2.prv": OPENSSH.read_text()})
    [key] = result["evidence"]["embedded_keys"]
    assert (key["key_algorithm"], key["key_size"]) == ("RSA", 1024)
