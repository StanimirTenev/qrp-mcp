"""UTF-16 without a byte-order mark is read as UTF-16 (ZA-OPRAVYANE row 61, the summary
probe of 22.10.2026).

A PowerShell script saved as UTF-16-LE without a BOM was decoded as UTF-8 with errors
ignored: every other byte a NUL, no finding, counted as read, and the verdict said every
file was read. Windows tools write such files. Now the NUL pattern of ASCII text in
UTF-16 -- one NUL in every pair, on the same side -- selects the decoding.
"""

import pytest

from qrp_mcp.scan import scan_directory

PS1 = "$rsa = [System.Security.Cryptography.RSA]::Create(2048)\r\n"


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le", "utf-16-be", "utf-16"])
def test_rsa_in_powershell_is_found_in_any_of_the_encodings(tmp_path, encoding):
    (tmp_path / "sign.ps1").write_bytes(PS1.encode(encoding))
    assert "RSA" in scan_directory(tmp_path)["detected_algorithms"]


def test_a_nul_in_utf8_text_does_not_switch_the_decoding(tmp_path):
    (tmp_path / "sign.py").write_bytes(
        b"from cryptography.hazmat.primitives.asymmetric import rsa\x00\n"
        b"k = rsa.generate_private_key(65537, 2048)\n")
    assert "RSA" in scan_directory(tmp_path)["detected_algorithms"]
