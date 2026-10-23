"""Python beyond pyca/cryptography (ZA-OPRAVYANE row 71, swarm A of 22.10.2026,
`roy-2026-10-22/a-pravopisi/test_r10`).

pycryptodome module paths checked against Legrandin/pycryptodome lib/Crypto (read
23.10.2026); python-rsa's newkeys (rsa/key.py) and paramiko's DSSKey (dsskey.py) as the
swarm fetched them. Two deliberate differences from the swarm's expectation:
Crypto.Protocol.DH takes only ECC keys (its DH.py imports EccKey and handles Curve25519 and
Curve448), so it is ECDH, not DH; and Crypto.Signature.DSS signs with a DSA *or* an ECC key
(DSS.new), so the import alone names neither -- the key's own line does.
"""

import pytest

from qrp_mcp.scan import scan_directory


@pytest.mark.parametrize("family, line", [
    ("EC", "from Crypto.PublicKey import ECC"),
    ("RSA", "from Crypto.Signature import pkcs1_15"),
    ("RSA", "from Crypto.Cipher import PKCS1_OAEP"),
    ("ECDH", "from Crypto.Protocol.DH import key_agreement"),
    ("DES", "from Crypto.Cipher import DES"),
    ("3DES", "from Crypto.Cipher import DES3"),
    ("MD5", "from Crypto.Hash import MD5"),
    ("SHA1", "from Crypto.Hash import SHA1"),
    ("SHA1", "from Cryptodome.Hash import SHA256, SHA1"),
    ("RSA", "(pub, priv) = rsa.newkeys(2048)"),
    ("DSA", "key = paramiko.DSSKey.generate(1024)"),
])
def test_python_name(tmp_path, family, line):
    (tmp_path / "a.py").write_text(line + "\n", encoding="utf-8")
    assert family in scan_directory(tmp_path)["detected_algorithms"]


def test_dss_alone_names_no_family(tmp_path):
    (tmp_path / "a.py").write_text("from Crypto.Signature import DSS\n", encoding="utf-8")
    found = set(scan_directory(tmp_path)["detected_algorithms"])
    assert not found & {"DSA", "ECDSA"}, found


def test_des3_import_is_not_single_des(tmp_path):
    (tmp_path / "a.py").write_text("from Crypto.Cipher import DES3, AES\n", encoding="utf-8")
    found = set(scan_directory(tmp_path)["detected_algorithms"])
    assert "3DES" in found and "DES" not in found, found
