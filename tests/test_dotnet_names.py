""".NET names outside the listed ones (ZA-OPRAVYANE row 70, swarm A of 22.10.2026,
`roy-2026-10-22/a-pravopisi/test_r8`).

Checked against dotnet/runtime System.Security.Cryptography: DSA.cs and DES.cs (static
Create), SHA1.cs and MD5.cs (static HashData), HashAlgorithmName.cs, CngAlgorithm.cs
(read 23.10.2026).
"""

import pytest

from qrp_mcp.scan import scan_directory


@pytest.mark.parametrize("family, line", [
    ("DSA", "using DSA dsa = DSA.Create(2048);"),
    ("DES", "using DES des = DES.Create();"),
    ("SHA1", "byte[] h = SHA1.HashData(data);"),
    ("MD5", "byte[] h = MD5.HashData(data);"),
    ("SHA1", "var sig = ecdsa.SignData(data, HashAlgorithmName.SHA1);"),
    ("RSA", "var alg = CngAlgorithm.Rsa;"),
])
def test_dotnet_name(tmp_path, family, line):
    (tmp_path / "a.cs").write_text(line + "\n", encoding="utf-8")
    assert family in scan_directory(tmp_path)["detected_algorithms"]


def test_triple_des_create_is_not_single_des(tmp_path):
    (tmp_path / "a.cs").write_text("using var t = TripleDES.Create();\n", encoding="utf-8")
    found = set(scan_directory(tmp_path)["detected_algorithms"])
    assert "3DES" in found and "DES" not in found, found
