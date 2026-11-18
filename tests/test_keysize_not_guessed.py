"""Two of stage 2's key-size readers take the size from another line than the key's. Neither may
give a size the file does not tie to that key: a rule that invents a size is the same defect as
one that hides it."""

from __future__ import annotations

from qrp_mcp.scan import scan_directory


def _rows(tmp_path, name, text):
    (tmp_path / name).write_text(text, encoding="utf-8")
    return scan_directory(tmp_path)["evidence"]["source_code"]


def test_bcrypt_generate_key_pair_with_two_providers_open_gives_no_size(tmp_path):
    rows = _rows(tmp_path, "keys.c", (
        "#include <bcrypt.h>\n"
        "BCryptOpenAlgorithmProvider(&hRsa, BCRYPT_RSA_ALGORITHM, NULL, 0);\n"
        "BCryptOpenAlgorithmProvider(&hDh, L\"DH\", NULL, 0);\n"
        "BCryptGenerateKeyPair(hDh, &hKey, 1024, 0);\n"))
    rsa = [r for r in rows if r["algorithm"] == "RSA"]
    assert rsa and all(r.get("key_size") != 1024 for r in rsa), rsa


def test_bcrypt_generate_key_pair_with_one_provider_open_gives_its_size(tmp_path):
    rows = _rows(tmp_path, "keys.c", (
        "#include <bcrypt.h>\n"
        "BCryptOpenAlgorithmProvider(&hRsa, BCRYPT_RSA_ALGORITHM, NULL, 0);\n"
        "BCryptGenerateKeyPair(hRsa, &hKey, 1024, 0);\n"))
    assert any(r["algorithm"] == "RSA" and r.get("key_size") == 1024 for r in rows), rows


def test_a_closed_hashtable_gives_no_size_to_a_row_after_it(tmp_path):
    rows = _rows(tmp_path, "cert.ps1", (
        "$params = @{\n"
        "  Subject = 'CN=www.example.com'\n"
        "  KeyLength = 1024\n"
        "}\n"
        "Write-Host 'next'\n"
        "New-SelfSignedCertificate -DnsName www.example.com -KeyAlgorithm RSA\n"
        "if ($x) {\n"
        "}\n"))
    rsa = [r for r in rows if r["algorithm"] == "RSA" and r["line"] == 6]
    assert rsa and all(r.get("key_size") != 1024 for r in rsa), rsa
