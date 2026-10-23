"""SHA-224, SHA3-224 and AES-ECB are seen (ZA-OPRAVYANE row 104; Wamala #42 on SP 800-131A
r3; probe qrp-kachestvo/linkedin-2026-10-23/sp800-131a, where all four lines gave 0 rows).

What r3 says is quoted from its initial public draft (October 2024; NIST.SP.800-131Ar3.ipd,
read 23.10.2026) and said as a draft: CSRC had no final revision that day.
"""

import pytest

from qrp_mcp.scan import scan_directory

PY = """from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
def h(data):
    d = hashes.Hash(hashes.SHA224()); d.update(data); return d.finalize()
def enc(key, data):
    return Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(data)
def tdes(key):
    return Cipher(algorithms.TripleDES(key), modes.ECB()).encryptor()
"""

JAVA = """class Legacy {
  byte[] a(byte[] d) throws Exception { Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding"); return c.doFinal(d); }
  byte[] b(byte[] d) throws Exception { return MessageDigest.getInstance("SHA-224").digest(d); }
  byte[] c(byte[] d) throws Exception { return MessageDigest.getInstance("SHA3-224").digest(d); }
}
"""


@pytest.mark.parametrize("name, text, families", [
    ("legacy.py", PY, {"SHA224", "AES-ECB", "3DES"}),
    ("Legacy.java", JAVA, {"SHA224", "SHA3-224", "AES-ECB"}),
])
def test_seen(tmp_path, name, text, families):
    (tmp_path / name).write_text(text)
    assert families <= set(scan_directory(tmp_path)["detected_algorithms"])


def test_said_as_a_draft(tmp_path):
    (tmp_path / "Legacy.java").write_text(JAVA)
    findings = {f["algorithm_family"]: f for f in scan_directory(tmp_path)["findings"]}
    assert findings["SHA-224"]["classification"] == "hash"
    assert findings["SHA3-224"]["classification"] == "hash"
    assert findings["AES-ECB"]["classification"] == "symmetric_reduced"
    for family in ("SHA-224", "SHA3-224", "AES-ECB"):
        assert "initial public draft" in findings[family]["reason"]


def test_ecb_under_triple_des_is_not_aes(tmp_path):
    (tmp_path / "t.py").write_text(
        "c = Cipher(algorithms.TripleDES(key), modes.ECB()).encryptor()\n")
    assert "AES-ECB" not in scan_directory(tmp_path)["detected_algorithms"]
