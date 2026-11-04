"""Key sizes in .NET constructors and in New-SelfSignedCertificate (fix list rows 369, 370, 374).

Measured on 0.41.0 (Windows probe W1, fixtures 01-dotnet-cs and 07-powershell): each line was
an RSA row with `key_size: undetermined` and no weak-key finding, while the size stood on it.

- `RSA.Create(1024)`: "Creates a new ephemeral RSA key with the specified key size."
  https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsa.create
- `new RSACryptoServiceProvider(512)`: "...with a random key pair of the specified key size."
  https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsacryptoserviceprovider.-ctor
  `RSACng(Int32)`: https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsacng.-ctor
  `DSA.Create(Int32)`: https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.dsa.create
- `New-SelfSignedCertificate -KeyAlgorithm RSA -KeyLength 1024`: "Specifies the length, in
  bits, of the key that is associated with the new certificate."
  https://learn.microsoft.com/en-us/powershell/module/pki/new-selfsignedcertificate
"""

from qrp_mcp.scan import scan_directory

CS = ("using System.Security.Cryptography;\n"
      "class K {\n"
      "    void Keys() {\n"
      "        using RSA small = RSA.Create(1024);\n"
      "        using var legacy = new RSACryptoServiceProvider(512);\n"
      "        using var cng = new RSACng(3072);\n"
      "        using DSA d = DSA.Create(1024);\n"
      "        using RSA plain = RSA.Create();\n"
      "    }\n"
      "}\n")
PS = ('$cert = New-SelfSignedCertificate -DnsName "web01" -CertStoreLocation '
      'Cert:\\LocalMachine\\My -KeyAlgorithm RSA -KeyLength 1024 -HashAlgorithm SHA256\n')


def _sizes(tmp_path, name, text):
    (tmp_path / name).write_text(text)
    r = scan_directory(tmp_path)
    return r, {(e["line"], e["algorithm"]): e.get("key_size")
               for e in r["evidence"]["source_code"]}


def test_dotnet_constructors_give_the_size(tmp_path):
    r, sizes = _sizes(tmp_path, "WinCrypto.cs", CS)
    assert sizes[(4, "RSA")] == 1024
    assert sizes[(5, "RSA")] == 512
    assert sizes[(6, "RSA")] == 3072
    assert sizes[(7, "DSA")] == 1024
    assert sizes[(8, "RSA")] == "undetermined"
    rsa = next(f for f in r["findings"] if f["algorithm_family"] == "RSA")
    assert rsa["weak_key"] is True


def test_new_selfsignedcertificate_keylength(tmp_path):
    r, sizes = _sizes(tmp_path, "tls.ps1", PS)
    assert sizes[(1, "RSA")] == 1024
