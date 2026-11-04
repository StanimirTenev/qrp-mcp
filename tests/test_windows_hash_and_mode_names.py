"""Windows hash, mode and signing-digest names that were read and gave nothing (fix list
rows 379-383, W1 probe on 0.41.0).

- 379 `New-SelfSignedCertificate ... -HashAlgorithm SHA1`: "Specifies the name of the hash
  algorithm to use to sign the new certificate."
  https://learn.microsoft.com/en-us/powershell/module/pki/new-selfsignedcertificate
- 380 `new Rfc2898DeriveBytes(pwd, salt, 1000)`: "These overloads default the hash algorithm
  or number of iterations ... (the default is HashAlgorithmName.SHA1)."
  https://learn.microsoft.com/en-us/dotnet/fundamentals/syslib-diagnostics/syslib0041
- 381 `aes.Mode = CipherMode.ECB`, `aes.EncryptEcb(...)`:
  https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.ciphermode,
  https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.symmetricalgorithm.encryptecb
  Read as AES-ECB only where the object is named for AES (minimum: the type is on another line).
- 382 `signtool sign /fd SHA1`: "/fd alg | Specifies the file digest algorithm to use for
  creating file signatures." https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool
- 383 a `.ps1` signs as a pipeline does: `certutil -hashfile InFile [HashAlgorithm]`
  (https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil),
  `makecert -a sha1` ("Hash algorithm. Must be set to either SHA-1 or MD5",
  https://learn.microsoft.com/en-us/windows/win32/seccrypto/makecert).
"""

from qrp_mcp.scan import scan_directory


def _scan(tmp_path, name, text):
    (tmp_path / name).write_text(text)
    return scan_directory(tmp_path)


def _rows(r):
    return {(e["line"], e["algorithm"]) for e in r["evidence"]["source_code"]}


def test_selfsigned_certificate_hash_algorithm(tmp_path):
    r = _scan(tmp_path, "tls.ps1",
              '$c = New-SelfSignedCertificate -DnsName "web01" -KeyAlgorithm RSA '
              "-KeyLength 1024 -HashAlgorithm SHA1\n"
              '$e = New-SelfSignedCertificate -DnsName "web02" -HashAlgorithm SHA256\n')
    assert (1, "SHA1") in _rows(r)
    assert not any(line == 2 and alg == "SHA1" for line, alg in _rows(r))


def test_rfc2898_without_a_hash_is_sha1_by_default(tmp_path):
    r = _scan(tmp_path, "More.cs",
              "class M {\n"
              "    void Go() {\n"
              "        using var derive = new Rfc2898DeriveBytes(pwd, salt, 1000);\n"
              "        using var ok = new Rfc2898DeriveBytes(pwd, salt, 600000, "
              "HashAlgorithmName.SHA256);\n"
              "    }\n}\n")
    rows = _rows(r)
    assert (3, "SHA1") in rows
    assert not any(line == 4 and alg == "SHA1" for line, alg in rows)
    row = next(e for e in r["evidence"]["source_code"] if e["line"] == 3)
    assert "default" in row["description"]


def test_dotnet_ecb_mode(tmp_path):
    r = _scan(tmp_path, "Ecb.cs",
              "class E {\n"
              "    void Go(Aes aes, TripleDES tdes) {\n"
              "        aes.Mode = CipherMode.ECB;\n"
              "        byte[] ecb = aes.EncryptEcb(data, PaddingMode.PKCS7);\n"
              "        tdes.Mode = CipherMode.ECB;\n"
              "    }\n}\n")
    rows = _rows(r)
    assert (3, "AES-ECB") in rows and (4, "AES-ECB") in rows
    assert not any(line == 5 and alg == "AES-ECB" for line, alg in rows)


def test_signtool_file_digest_is_read(tmp_path):
    (tmp_path / "azure-pipelines.yml").write_text(
        "steps:\n- script: signtool sign /f codesign.pfx /fd SHA1 /t http://ts.example setup.exe\n")
    r = scan_directory(tmp_path)
    assert (2, "SHA1") in _rows(r)
    step = next(s for s in r["evidence"]["ci_pipeline"] if s["command_type"] == "signtool_sign")
    assert step["digest_algorithm"] == "SHA1"


def test_signing_in_a_powershell_script(tmp_path):
    r = _scan(tmp_path, "sign.ps1",
              "signtool sign /f codesign.pfx /fd SHA1 /t http://ts.example setup.exe\n"
              "certutil -hashfile setup.exe MD5\n"
              '& makecert -r -pe -n "CN=Dev" -a sha1 -len 1024 -sky signature -ss My dev.cer\n')
    rows = _rows(r)
    assert {(1, "SHA1"), (2, "MD5"), (3, "SHA1")} <= rows
    assert [s["command_type"] for s in r["evidence"]["ci_pipeline"]] == ["signtool_sign"]
