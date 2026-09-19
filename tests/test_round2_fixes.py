"""What a second measured comparison found, fixed.

Round 2 of the landscape work (19.09.2026) measured this scanner against
QuantaKrypto's qscan and against CBOMkit-hyperion on two corpora neither of us
wrote. The headline was that detection is level -- 149/176 each, McNemar p=1.000
-- and that of the 19 labels the rival finds and this tool does not, only four
are detection at all. Six are files never opened, and nine are an asset-model
decision.

These tests cover the four cheap categories: extensions not claimed, library
vocabulary never added, a quoted SSH key, and the three spellings a rival reads.
"""
from __future__ import annotations

import pytest

from qrp_mcp.scan import scan_directory


def families(tmp_path, name: str, body: str) -> set[str]:
    (tmp_path / name).write_text(body)
    return set(scan_directory(tmp_path)["detected_algorithms"])


# --- reading: 8 of the corpus's labels sit in files never opened --------------

@pytest.mark.parametrize("name,line,family", [
    ("Crypto.kt", 'val kp = KeyPairGenerator.getInstance("RSA")', "RSA"),
    ("Crypto.kts", 'Signature.getInstance("SHA256withECDSA")', "ECDSA"),
    ("Crypto.scala", 'val g = KeyPairGenerator.getInstance("DSA")', "DSA"),
    ("crypto.mjs", "const k = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })", "RSA"),
    ("crypto.cjs", "const s = crypto.createSign('RSA-SHA256')", "RSA"),
])
def test_an_extension_a_rival_reads_is_read_here_too(tmp_path, name, line, family):
    assert family in families(tmp_path, name, line + "\n")


def test_a_nuget_project_file_is_a_manifest(tmp_path):
    (tmp_path / "Acme.Signing.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        '  <ItemGroup>\n'
        '    <PackageReference Include="BouncyCastle.Cryptography" Version="2.4.0" />\n'
        '    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />\n'
        '  </ItemGroup>\n'
        '</Project>\n')
    found = scan_directory(tmp_path)["evidence"]["dependencies"]
    assert [d["package"] for d in found] == ["BouncyCastle.Cryptography"]
    assert found[0]["basis"] == "declared_dependency"


def test_a_lockfile_is_read_as_well_as_a_manifest(tmp_path):
    """A manifest says what was asked for; a lockfile says what shipped.

    For a register of what is actually installed, the lockfile is the honest one.
    """
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {'
        '"node_modules/node-forge": {"version": "1.3.1"},'
        '"node_modules/express": {"version": "4.19.2"}}}')
    found = scan_directory(tmp_path)["evidence"]["dependencies"]
    assert [d["package"] for d in found] == ["node-forge"]


# --- vocabulary: fix #9, written 18.09 and never applied ---------------------

@pytest.mark.parametrize("name,line,family", [
    ("a.rb", "  key = dh.compute_key(other_public)", "DH"),
    ("a.rs", "  let params = Dh::generate_params(2048)?;", "DH"),
    ("a.rs", "  use x448::{PublicKey, Secret};", "X448"),
    ("A.java", "  var a = new X448Agreement();", "X448"),
    ("A.java", "  var g = new Ed448KeyPairGenerator();", "Ed448"),
    ("a.c", '  #define SSH_HOSTKEY_ALGS "ssh-ed25519,rsa-sha2-512"', "Ed25519"),
])
def test_library_vocabulary_a_rival_reads(tmp_path, name, line, family):
    assert family in families(tmp_path, name, line + "\n")


# --- a quoted SSH key: a defect introduced in 0.10.0 -------------------------

def test_an_ssh_key_inside_a_string_literal(tmp_path):
    """0.10.0 anchored the rule at the start of the line.

    In openssh and Vault the same key appears quoted inside source. One case
    matched only because the optional host field absorbed the opening quote.
    """
    (tmp_path / "creds.cs").write_text(
        '    private const string Key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ deploy@ci";\n')
    result = scan_directory(tmp_path)
    assert "RSA" in result["detected_algorithms"]
    assert any(a["protocol"] == "ssh" for a in result["evidence"]["protocols"])
