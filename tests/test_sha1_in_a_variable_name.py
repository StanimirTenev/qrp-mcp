"""SHA-1 read from the name of a variable is an identifier, not a call (fix list row 368).

Measured on 0.41.0 (W1 fixture 18-identifier-names-sha1):
`using var implicitSha1 = new Rfc2898DeriveBytes(pwd, salt, 600000, HashAlgorithmName.SHA256);`
gave `SHA1 | SHA-1 named in a compound name | kind=call`. The call on that line passes
SHA-256 (Rfc2898DeriveBytes(String, Byte[], Int32, HashAlgorithmName),
https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rfc2898derivebytes.-ctor);
`implicitSha1` is only the name the result is stored under. Kept as `identifier`, which no
gate or readiness figure counts as a use.
"""

from qrp_mcp.scan import scan_directory


def _kinds(tmp_path, text):
    (tmp_path / "Kdf.cs").write_text(text)
    r = scan_directory(tmp_path)
    return {e["algorithm"]: e["evidence_kind"] for e in r["evidence"]["source_code"]}


def test_a_variable_named_sha1_is_an_identifier(tmp_path):
    kinds = _kinds(tmp_path, "using var implicitSha1 = new Rfc2898DeriveBytes(pwd, salt, "
                             "600000, HashAlgorithmName.SHA256);\n")
    assert kinds.get("SHA1") == "identifier"


def test_a_function_named_with_sha1_is_still_a_call(tmp_path):
    kinds = _kinds(tmp_path, "var h = ComputeSha1(data);\n")
    assert kinds.get("SHA1") == "call"
