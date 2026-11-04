"""Row 312 (04.11.2026): `Cipher.getInstance("RSA/ECB/PKCS1Padding")` had no role.

A JCA Cipher with an RSA transformation is "The RSA encryption algorithm as defined in PKCS #1"
(https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html): it wraps a
key, so key establishment; `by_role.key_establishment` said none_found."""

from __future__ import annotations


def test_rsa_cipher_is_key_establishment(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "S.kt").write_text(
        'val c = Cipher.getInstance("RSA/ECB/PKCS1Padding")\n'
        'val d = Cipher.getInstance("RSA")\n'
        'val s = Signature.getInstance("SHA256withRSA")\n')
    roles = {e["line"]: e.get("role") for e in scan_directory(tmp_path)["evidence"]["source_code"]
             if e["algorithm"] == "RSA"}
    assert roles[1] == "key_establishment" and roles[2] == "key_establishment"
    assert roles[3] == "signature"
