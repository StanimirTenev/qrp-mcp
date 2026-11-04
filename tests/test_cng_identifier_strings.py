"""CNG algorithm identifier strings in BCryptOpenAlgorithmProvider (fix list row 377).

Measured on 0.41.0 (W1 fixture 03-cng-capi, wincrypt.c:13):
`BCryptOpenAlgorithmProvider(&hAlg, L"MD5", NULL, 0);` gave nothing, while line 12's
`BCRYPT_3DES_ALGORITHM` was found. The constants are wide strings: "BCRYPT_MD5_ALGORITHM
L"MD5" | The MD5 hash algorithm." (https://learn.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers),
and the second argument is "the identifier of the requested cryptographic algorithm"
(https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider).
"""

from qrp_mcp.scan import scan_directory


def test_wide_and_plain_identifier_strings(tmp_path):
    (tmp_path / "wincrypt.c").write_text(
        "void f(void) {\n"
        '    BCryptOpenAlgorithmProvider(&hAlg, L"MD5", NULL, 0);\n'
        '    BCryptOpenAlgorithmProvider(&hAlg, TEXT("RSA"), NULL, 0);\n'
        '    BCryptOpenAlgorithmProvider(&hAlg, "ECDH_P256", NULL, 0);\n'
        '    BCryptOpenAlgorithmProvider(&hAlg, L"3DES_112", NULL, 0);\n'
        '    BCryptOpenAlgorithmProvider(&hAlg, L"AES", NULL, 0);\n'
        "}\n")
    r = scan_directory(tmp_path)
    rows = {(e["line"], e["algorithm"]) for e in r["evidence"]["source_code"]}
    assert {(2, "MD5"), (3, "RSA"), (4, "ECDH"), (5, "3DES")} <= rows
    assert not any(line == 6 for line, _ in rows)
