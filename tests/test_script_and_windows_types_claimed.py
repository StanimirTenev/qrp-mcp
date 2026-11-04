"""File types that were "type not claimed" on 0.41.0 though the rules for their lines exist
(ZA-OPRAVYANE rows 308, 386, 387, 388; fixtures from the 04.11.2026 rounds L1 and W1).

* 308: `.bash`/`.zsh`/`.ksh`, `.cmd`/`.bat` and `.mk` carry the same `openssl genrsa -out
  server.key 2048` as `.sh` and Makefile, which were read.
* 386: .NET's configuration by name. machineKey, https://learn.microsoft.com/en-us/previous-versions/dotnet/netframework-4.0/w8h3skw9(v=vs.100):
  "3DES Specifies that ASP.NET uses the TripleDES algorithm (3DES) to encrypt and decrypt
  data." `.reg` exports, decoded as every file is (UTF-16 with a BOM included).
* 387: Windows build and request files. certreq, https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certreq_1:
  KeyLength "Defines the length of the public and private key." SignTool,
  https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool: "/fd alg -- Specifies
  the file digest algorithm to use for creating file signatures."
* 388: Visual Basic and F# call System.Security.Cryptography as C# does (the RSA.Create
  page, https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsa.create,
  gives VB and F# syntax); `.psd1` is a PowerShell data file.
"""

import pytest

from qrp_mcp.scan import scan_directory

GENRSA = "openssl genrsa -out server.key 2048\n"


def _families(result, path):
    return {f["algorithm"] for f in result["evidence"]["source_code"] + result["evidence"]["iac"]
            if f["path"] == path}


@pytest.mark.parametrize("name", ["gen.bash", "gen.zsh", "gen.ksh", "gen.cmd", "gen.bat",
                                  "rules.mk"])
def test_shell_batch_and_make_files_are_read(tmp_path, name):
    (tmp_path / name).write_text(GENRSA)
    result = scan_directory(tmp_path)
    assert result["files_read"] == [name]
    assert result["files_skipped_by_type"] == {}
    rsa = [f for f in result["evidence"]["source_code"] if f["algorithm"] == "RSA"]
    assert [f["key_size"] for f in rsa] == [2048]


def test_batch_rem_line_is_a_comment(tmp_path):
    (tmp_path / "gen.bat").write_text("REM openssl genrsa -out old.key 1024\n")
    result = scan_directory(tmp_path)
    assert [f.get("evidence_kind") for f in result["evidence"]["source_code"]] in ([], ["comment"])


WEB_CONFIG = """<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.web>
    <machineKey validation="SHA1" decryption="3DES" />
  </system.web>
</configuration>
"""


@pytest.mark.parametrize("name", ["web.config", "Web.Release.config", "app.config",
                                  "machine.config", "applicationHost.config"])
def test_dotnet_configuration_is_read_by_name(tmp_path, name):
    (tmp_path / name).write_text(WEB_CONFIG)
    result = scan_directory(tmp_path)
    assert result["files_read"] == [name]
    assert {"3DES", "SHA1"} <= _families(result, name)


def test_other_config_files_stay_unclaimed(tmp_path):
    (tmp_path / "settings.config").write_text(WEB_CONFIG)
    result = scan_directory(tmp_path)
    assert result["files_skipped_by_type"] == {".config": 1}


GPO = ('Windows Registry Editor Version 5.00\r\n\r\n'
       '[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL'
       '\\00010002]\r\n'
       '"Functions"="TLS_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_RC4_128_SHA"\r\n')


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
def test_registry_export_is_read(tmp_path, encoding):
    # Python's utf-16 codec writes the BOM, as regedit does.
    (tmp_path / "cipherorder.reg").write_bytes(GPO.encode(encoding))
    result = scan_directory(tmp_path)
    assert result["files_read"] == ["cipherorder.reg"]
    assert {"3DES", "RC4", "RSA"} <= _families(result, "cipherorder.reg")


def test_certreq_inf_key_length(tmp_path):
    (tmp_path / "policy.inf").write_text('[NewRequest]\nSubject = "CN=web01"\nKeyAlgorithm = RSA\n'
                                         "KeyLength = 1024\nHashAlgorithm = SHA1\n")
    result = scan_directory(tmp_path)
    sizes = {f["key_size"] for f in result["evidence"]["source_code"] + result["evidence"]["iac"]
             if f["algorithm"] == "RSA"}
    assert 1024 in sizes


@pytest.mark.parametrize("name", ["App.vcxproj", "Directory.Build.targets", "App.csproj",
                                  "sign.bat", "release.cmd", "sign.bash"])
def test_signing_steps_in_build_files_and_scripts(tmp_path, name):
    (tmp_path / name).write_text(
        '<Project>\n  <Target Name="Sign" AfterTargets="Build">\n'
        '    <Exec Command="signtool sign /fd SHA1 /a $(TargetPath)" />\n'
        '  </Target>\n</Project>\n' if name.endswith(("proj", "targets")) else
        "signtool sign /a /fd SHA1 setup.exe\n")
    result = scan_directory(tmp_path)
    assert result["files_read"] == [name]
    steps = [c for c in result["evidence"]["ci_pipeline"] if c["path"] == name]
    assert "signtool_sign" in {c["command_type"] for c in steps}


def test_wix_and_props_are_read(tmp_path):
    (tmp_path / "Product.wxs").write_text('<Wix><Package Name="App"><DigitalSignature /></Package></Wix>\n')
    (tmp_path / "Directory.Build.props").write_text("<Project><PropertyGroup /></Project>\n")
    result = scan_directory(tmp_path)
    assert result["files_read"] == ["Directory.Build.props", "Product.wxs"]


@pytest.mark.parametrize("name,text,expected", [
    ("Crypto.vb", "Imports System.Security.Cryptography\nModule Crypto\n  Sub Main()\n"
                  "    Dim md5 As MD5 = MD5.Create()\n    Dim tdes As TripleDES = TripleDES.Create()\n"
                  "    Dim rsa As RSA = RSA.Create()\n  End Sub\nEnd Module\n",
     {"MD5", "3DES", "RSA"}),
    ("Crypto.fs", "open System.Security.Cryptography\nlet sha1 = SHA1.Create()\n"
                  "// let md5 = MD5.Create()\n", {"SHA1"}),
    ("Script.fsx", "let rsa = System.Security.Cryptography.RSA.Create()\n", {"RSA"}),
    ("Module.psd1", "@{\n  PrivateData = @{ CipherSuites = @('TLS_RSA_WITH_RC4_128_MD5') }\n}\n",
     {"RC4", "MD5", "RSA"}),
])
def test_dotnet_languages_and_psd1_are_read(tmp_path, name, text, expected):
    (tmp_path / name).write_text(text)
    result = scan_directory(tmp_path)
    assert result["files_read"] == [name]
    used = {f["algorithm"] for f in result["evidence"]["source_code"]
            if f.get("evidence_kind") != "comment"}
    assert expected <= used
    if name == "Crypto.fs":
        assert "MD5" not in used
