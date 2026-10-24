"""MD5, SHA-1 and DES used as a MAC, PRF or KDF are reported, as the hash or cipher, with
the use named and that a quantum computer does not break it (ZA-OPRAVYANE row 131, decided
24.10.2026: an inventory that skips something silently is the defect we criticise in others).

The names are the measured ones (`qrp-kachestvo/imena-2026-10-23/b-registri-ezici`, class
C09: JDK standard names, Bouncy Castle, .NET, Go x/crypto/ssh, ring, the IANA SSH registry,
strongSwan) and PKCS#11's (`a-c-biblioteki`, class E).
"""

import pytest

from qrp_mcp.scan import scan_directory


def _items(tmp_path, name, text):
    (tmp_path / name).write_text(text + "\n", encoding="utf-8")
    return scan_directory(tmp_path)["evidence"]["source_code"]


@pytest.mark.parametrize("family, name, line", [
    ("SHA1", "M.java", 'use(Mac.getInstance("HmacSHA1"));'),
    ("SHA1", "M.java", 'use(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1"));'),
    ("SHA1", "M.java", 'use(SecretKeyFactory.getInstance("PBKDF2WITHHMACSHA1", "BC"));'),
    ("SHA1", "M.java", 'use(Mac.getInstance("HmacPBESHA1"));'),
    ("SHA1", "M.cs", "var v412 = new HMACSHA1();"),
    ("SHA1", "m.go", "_ = ssh.InsecureHMACSHA196"),
    ("SHA1", "m.rs", "let _ = &ring::pbkdf2::PBKDF2_HMAC_SHA1;"),
    ("SHA1", "m.rs", "let _ = &ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY;"),
    ("SHA1", "M.cs", 'var v = CryptoConfig.CreateFromName("http://www.w3.org/2000/09/xmldsig#hmac-sha1");'),
    ("SHA1", "sshd_config", "MACs hmac-sha1,hmac-sha1-96"),
    ("SHA1", "swanctl.conf", "proposals = aes128gcm16-prfsha1-x25519"),
    ("SHA1", "p.c", "mech.mechanism = CKM_SHA_1_HMAC_GENERAL;"),
    ("MD5", "M.java", 'use(Mac.getInstance("HmacMD5"));'),
    ("MD5", "sshd_config", "MACs hmac-md5-96"),
    ("MD5", "p.c", "mech.mechanism = CKM_MD5_HMAC;"),
    ("DES", "M.java", 'use(Mac.getInstance("DESMAC64WITHISO7816-4PADDING", "BC"));'),
    ("DES", "p.c", "mech.mechanism = CKM_DES_MAC;"),
])
def test_mac_or_kdf_is_reported_with_its_use(tmp_path, family, name, line):
    found = [f for f in _items(tmp_path, name, line) if f["algorithm"] == family]
    assert found and found[0]["evidence_kind"] != "comment"
    said = found[0]["description"]
    assert ("MAC" in said or "KDF" in said) and "quantum computer does not break it" in said


@pytest.mark.parametrize("name, line", [
    ("sshd_config", "MACs -hmac-sha1"),
    ("c.py", 'client.connect(host, disabled_algorithms={"macs": ["hmac-sha1"]})'),
])
def test_a_ban_stays_a_ban(tmp_path, name, line):
    found = [f for f in _items(tmp_path, name, line) if f["algorithm"] == "SHA1"]
    assert [f["evidence_kind"] for f in found] == ["ban"]


@pytest.mark.parametrize("name, line", [
    ("M.java", 'use(Mac.getInstance("HmacSHA256"));'),
    ("sshd_config", "MACs hmac-sha2-256-etm@openssh.com"),
    ("M.java", 'use(Mac.getInstance("DESEDEMAC", "BC"));'),      # triple DES, not DES
])
def test_not_a_weak_mac(tmp_path, name, line):
    families = {f["algorithm"] for f in _items(tmp_path, name, line)}
    assert not families & {"SHA1", "MD5", "DES"}


def test_the_cipher_inside_pbe_is_not_called_a_mac(tmp_path):
    found = [f for f in _items(tmp_path, "p.c", "mech.mechanism = CKM_PBE_MD5_DES_CBC;")]
    said = {f["algorithm"]: f["description"] for f in found}
    assert "KDF" in said["MD5"] and "KDF" not in said["DES"] and "MAC" not in said["DES"]
