"""Row 350 (04.11.2026): an .ovpn contradicted itself.

Line 1 said "RSA object identifier ... observed in the file; the file was not decoded as a
certificate" while line 8 held the decoded certificate. The identifier came from the inline
`<key>` block, which did parse. It is now named at the key's own line, as from a parsed key,
with the key's size."""

from __future__ import annotations


def test_inline_key_identifier_is_at_the_key_line(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from qrp_mcp.scan import scan_directory
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    (tmp_path / "client.ovpn").write_text("client\ndev tun\n<key>\n" + key + "</key>\n")
    rows = [e for e in scan_directory(tmp_path)["evidence"]["source_code"]
            if e["algorithm"] == "RSA"]
    assert [(e["line"], e.get("key_size")) for e in rows] == [(4, 2048)]
    assert "not decoded" not in rows[0]["description"]
