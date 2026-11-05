"""`qrp-mcp build-gap SCAN.json BUILD_DIR` (direction 2 of 04.11.2026, W1).

A source scan set beside what the build carries: of K public-key-bearing packages or modules in
the build, the scan named J; the K-J list; the families on one side only; a Go binary's
DefaultGODEBUG crypto settings as recorded.

What was tested on what (said in the release notes too):
  Go      a real binary, built here at test time with the local toolchain (`go build`), read
          with `go version -m` and `go tool nm` -- skipped when `go` is not on PATH.
  .NET    the metadata reader on a minimal managed PE written by this test (ECMA-335 tables
          Module, TypeRef, TypeDef, Assembly, AssemblyRef), and on real compiler output where
          it exists on this machine (W1's DotnetCryptoRefs.dll, skipped elsewhere). No real
          crypto-bearing .NET publish was available here: no .NET SDK on this machine.

The patent constraint (qrp-kachestvo/nov-podhod-2026-11-04/patenti/PATENTI.md, section 4): only
tables the toolchain wrote; never IL or machine code, never parameters from the build. The
last tests fail if the module imports a disassembler or an IL reader, or reads a method body.
"""

import ast
import json
import os
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from qrp_mcp import buildgap
from qrp_mcp.buildgap import (build_gap, dotnet_families, go_families, go_package_of,
                              parse_go_version_m, read_metadata_names)
from qrp_mcp.server import main

GO = shutil.which("go")
W1_DLL = Path.home() / ("zadachi/qrp-kachestvo/nov-podhod-2026-11-04/W1/tools/DotnetCryptoRefs/"
                        "bin/Release/net8.0/DotnetCryptoRefs.dll")


# -- a minimal managed PE, written here --------------------------------------------------

def _managed_pe(assembly: str, refs: list[str], typerefs: list[tuple[str, str]],
                typedefs: list[tuple[str, str]]) -> bytes:
    """A PE32 file with one section holding a CLI header and metadata with five tables.
    Every index is 2 bytes wide (small heaps, few rows), as ECMA-335 II.24.2.6 sets them."""
    strings = bytearray(b"\0")
    at: dict[str, int] = {}

    def s(text: str) -> int:
        if text not in at:
            at[text] = len(strings)
            strings.extend(text.encode() + b"\0")
        return at[text]

    module = struct.pack("<HHHHH", 0, s(assembly + ".dll"), 0, 0, 0)
    tr = b"".join(struct.pack("<HHH", (1 << 2) | 2, s(n), s(ns)) for ns, n in typerefs)
    td = b"".join(struct.pack("<IHHHHH", 0, s(n), s(ns), 0, 1, 1)
                  for ns, n in [("", "<Module>"), *typedefs])
    asm = struct.pack("<IHHHHIHHH", 0x8004, 1, 0, 0, 0, 0, 0, s(assembly), 0)
    aref = b"".join(struct.pack("<HHHHIHHHH", 8, 0, 0, 0, 0, 0, s(r), 0, 0) for r in refs)
    counts = {0x00: 1, 0x01: len(typerefs), 0x02: len(typedefs) + 1, 0x20: 1, 0x23: len(refs)}
    valid = sum(1 << t for t in counts)
    tables = (struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, valid, 0)
              + b"".join(struct.pack("<I", counts[t]) for t in sorted(counts))
              + module + tr + td + asm + aref)
    tables += b"\0" * (-len(tables) % 4)
    strings += b"\0" * (-len(strings) % 4)
    version = b"v4.0.30319\0\0"
    header_len = 16 + len(version) + 4 + (8 + 4) + (8 + 12)
    root = (struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(version)) + version
            + struct.pack("<HH", 0, 2)
            + struct.pack("<II", header_len, len(tables)) + b"#~\0\0"
            + struct.pack("<II", header_len + len(tables), len(strings)) + b"#Strings\0\0\0\0"
            + tables + bytes(strings))
    va, raw_at = 0x2000, 0x200
    cli = struct.pack("<IHHII", 72, 2, 5, va + 72, len(root)) + b"\0" * 56
    body = cli + root
    body += b"\0" * (-len(body) % 0x200)
    pe = 0x80
    dos = b"MZ" + b"\0" * 0x3A + struct.pack("<I", pe) + b"\0" * (pe - 0x40)
    coff = b"PE\0\0" + struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 224, 0x2102)
    opt = bytearray(224)
    struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<I", opt, 92, 16)
    struct.pack_into("<II", opt, 96 + 14 * 8, va, 72)
    section = (b".text\0\0\0" + struct.pack("<IIII", len(body), va, len(body), raw_at)
               + b"\0" * 16)
    head = dos + coff + bytes(opt) + section
    return head + b"\0" * (raw_at - len(head)) + body


def _deps_json(packages: dict[str, tuple[str, list[str]]]) -> str:
    target = {"App/1.0.0": {"runtime": {"App.dll": {}}}}
    libraries = {"App/1.0.0": {"type": "project"}}
    for name, (version, dlls) in packages.items():
        target[f"{name}/{version}"] = {"runtime": {f"lib/net8.0/{d}.dll": {} for d in dlls}}
        libraries[f"{name}/{version}"] = {"type": "package", "serviceable": True}
    return json.dumps({"targets": {".NETCoreApp,Version=v8.0": target}, "libraries": libraries})


def _scan(findings: list[str], deps: list[tuple[str, str]], path: str = "App.csproj") -> dict:
    return {"target": "src", "coverage": {"instrument": {"version": "test"}},
            "findings": [{"algorithm_family": f} for f in findings],
            "evidence": {"dependencies": [{"ecosystem": e, "package": p, "path": path}
                                          for e, p in deps]}}


@pytest.fixture
def publish(tmp_path):
    out = tmp_path / "publish"
    out.mkdir()
    (out / "App.deps.json").write_text(_deps_json({
        "BouncyCastle.Cryptography": ("2.4.0", ["BouncyCastle.Cryptography"]),
        "SSH.NET": ("2024.2.0", ["Renci.SshNet"]),
        "Newtonsoft.Json": ("13.0.3", ["Newtonsoft.Json"]),
    }))
    (out / "BouncyCastle.Cryptography.dll").write_bytes(_managed_pe(
        "BouncyCastle.Cryptography", ["System.Runtime"], [("System", "Object")],
        [("Org.BouncyCastle.Crypto.Signers", "Ed25519Signer"),
         ("Org.BouncyCastle.Crypto.Engines", "RsaEngine"),
         ("Org.BouncyCastle.Crypto.Digests", "MD5Digest")]))
    (out / "Renci.SshNet.dll").write_bytes(_managed_pe(
        "Renci.SshNet", ["System.Runtime", "System.Security.Cryptography"],
        [("System.Security.Cryptography", "ECDsa"), ("System.Security.Cryptography", "RSA")],
        [("Renci.SshNet.Security", "KeyExchangeECCurve25519")]))
    (out / "Newtonsoft.Json.dll").write_bytes(_managed_pe(
        "Newtonsoft.Json", ["System.Runtime"], [("System", "Object")],
        [("Newtonsoft.Json", "JsonConvert")]))
    (out / "App.dll").write_bytes(_managed_pe(
        "App", ["System.Runtime", "System.Security.Cryptography"],
        [("System.Security.Cryptography", "RSA"), ("System.Security.Cryptography", "Aes")],
        [("App", "Program")]))
    (out / "native.so").write_bytes(b"\x7fELF" + b"\0" * 60)
    return out


# -- .NET ---------------------------------------------------------------------------------

def test_the_reader_reads_the_tables_it_was_given():
    names = read_metadata_names(_managed_pe(
        "Lib", ["System.Runtime", "BouncyCastle.Cryptography"],
        [("System.Security.Cryptography", "RSA")], [("Lib", "Signer")]))
    assert names["assembly"] == "Lib"
    assert names["assembly_refs"] == ["System.Runtime", "BouncyCastle.Cryptography"]
    assert names["typerefs"] == [("System.Security.Cryptography", "RSA")]
    assert ("Lib", "Signer") in names["typedefs"]


@pytest.mark.skipif(not W1_DLL.is_file(), reason="W1's DotnetCryptoRefs.dll is on this machine only")
def test_the_reader_reads_real_compiler_output():
    # Program.cs of that tool: `using System.Reflection.Metadata; ... System.Text.Json;
    # ... Regex`. The names are the ones the C# compiler wrote.
    names = read_metadata_names(W1_DLL.read_bytes())
    assert names["assembly"] == "DotnetCryptoRefs"
    assert {"System.Runtime", "System.Reflection.Metadata", "System.Text.Json",
            "System.Text.RegularExpressions"} <= set(names["assembly_refs"])
    refs = {n for _, n in names["typerefs"]}
    assert {"PEReader", "MetadataReader", "Regex", "JsonSerializer"} <= refs
    assert ("", "Program") in names["typedefs"]


def test_a_native_pe_is_not_managed(tmp_path):
    pe = bytearray(_managed_pe("X", [], [], []))
    struct.pack_into("<II", pe, 0x80 + 24 + 96 + 14 * 8, 0, 0)
    with pytest.raises(buildgap.NotManaged, match="native"):
        read_metadata_names(bytes(pe))


def test_type_names_onto_families():
    # W1's section 3.1: type names from the publish folder's metadata.
    assert dotnet_families("RsaEngine") == {"RSA"}
    assert dotnet_families("ECDsa") == {"ECDSA"}
    assert dotnet_families("ECDiffieHellmanCng") == {"ECDH"}
    assert dotnet_families("Ed25519Signer") == {"EdDSA"}
    assert dotnet_families("X25519Agreement") == {"X25519"}
    assert dotnet_families("MLKemParameters") == {"ML-KEM"}
    assert dotnet_families("DsaSigner") == {"DSA"}
    assert dotnet_families("MD5Digest") == {"MD5"}
    # A component, never a substring: `Dsa` behind EC is ECDSA, `Address` is not DES.
    assert dotnet_families("ECDsaSigner") == {"ECDSA"}
    assert dotnet_families("IPAddress") == set()
    assert dotnet_families("Description") == set()


def test_k_j_and_the_list_from_a_publish_folder(publish):
    scan = _scan(["RSA", "MD5", "DSA"], [("nuget", "BouncyCastle.Cryptography"),
                                         ("nuget", "Portable.BouncyCastle")])
    r = build_gap(scan, publish, go="")
    assert r["K_public_key_bearing"] == 2 and r["J_named_by_source_scan"] == 1
    assert [p["package"] for p in r["not_named_by_source_scan"]] == ["SSH.NET"]
    ssh = r["not_named_by_source_scan"][0]
    assert ssh["public_key_families"] == ["ECDSA", "RSA"]
    newtonsoft = next(p for p in r["packages"] if p["package"] == "Newtonsoft.Json")
    assert newtonsoft["public_key_bearing"] is False
    assert r["named_by_source_scan_not_in_build"] == ["nuget:portable.bouncycastle"]
    fam = r["families"]
    # The app's own App.dll (a project) counts for the families, not for K.
    assert set(fam["build"]) == {"RSA", "ECDSA", "EdDSA", "MD5"}
    assert fam["build_only"] == ["ECDSA", "EdDSA"] and fam["source_only"] == ["DSA"]
    assert [n["path"] for n in r["not_read"]] == ["native.so"]
    assert "a Go binary would not be read" in r["not_read"][0]["reason"]


def test_a_scan_that_read_a_deps_json_is_said(publish):
    scan = _scan([], [("nuget", "BouncyCastle.Cryptography")], path="bin/App.deps.json")
    assert any("taken after the build" in n for n in build_gap(scan, publish, go="")["notes"])


def test_no_parameter_is_read_from_the_build(publish):
    r = build_gap(_scan(["RSA"], []), publish, go="")
    text = json.dumps(r)
    for key in ('"key_size"', '"curve"', '"mode"', '"parameter_set"'):
        assert key not in text


# -- Go -----------------------------------------------------------------------------------

def test_go_symbols_and_paths():
    assert go_package_of("crypto/ecdsa.SignASN1") == "crypto/ecdsa"
    assert go_package_of("crypto/tls.(*Conn).Handshake") == "crypto/tls"
    assert go_package_of("type:.eq.crypto/tls.Config") is None
    assert go_package_of("example.com/app/vendor/golang.org/x/crypto/ssh.Dial") == \
        "golang.org/x/crypto/ssh"
    assert go_families("golang.org/x/crypto/curve25519") == {"X25519"}
    assert go_families("crypto/internal/edwards25519/field") == {"EdDSA"}
    assert go_families("crypto/tls") == set()


def test_go_version_m_as_the_toolchain_prints_it():
    # Recorded from the binary built below (go1.22.2, linux/amd64).
    text = ("goprobe: go1.22.2\n\tpath\texample.com/goprobe\n\tmod\texample.com/goprobe\t(devel)\t\n"
            "\tdep\texample.com/signlib\tv0.1.0\n\t=>\t./signlib\t(devel)\t\n"
            "\tbuild\t-buildmode=exe\n\tbuild\tDefaultGODEBUG=httplaxcontentlength=1,"
            "httpmuxgo121=1,panicnil=1,tls10server=1,tlsrsakex=1,tlsunsafeekm=1\n")
    info = parse_go_version_m(text)
    assert info["go_version"] == "go1.22.2" and info["main"] == "example.com/goprobe"
    assert info["modules"] == [{"module": "example.com/signlib", "version": "v0.1.0",
                                "replaced_by": "./signlib (devel)"}]
    assert info["godebug"].endswith("tlsrsakex=1,tlsunsafeekm=1")


def _go_build(root: Path) -> Path:
    (root / "signlib" / "ecdsa").mkdir(parents=True)
    (root / "plainlib").mkdir()
    (root / "go.mod").write_text(
        "module example.com/probe\n\ngo 1.20\n\nrequire (\n\texample.com/signlib v0.1.0\n"
        "\texample.com/plainlib v0.2.0\n)\n\nreplace example.com/signlib => ./signlib\n\n"
        "replace example.com/plainlib => ./plainlib\n")
    (root / "signlib" / "go.mod").write_text("module example.com/signlib\n\ngo 1.20\n")
    (root / "signlib" / "ecdsa" / "s.go").write_text(
        "package ecdsa\n\nimport (\n\t\"crypto/ecdsa\"\n\t\"crypto/elliptic\"\n\t\"crypto/rand\"\n)\n\n"
        "func New() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }\n")
    (root / "plainlib" / "go.mod").write_text("module example.com/plainlib\n\ngo 1.20\n")
    (root / "plainlib" / "p.go").write_text("package plainlib\n\nfunc Add(a, b int) int { return a + b }\n")
    (root / "main.go").write_text(
        "package main\n\nimport (\n\t\"crypto/tls\"\n\t\"fmt\"\n\n\t\"example.com/plainlib\"\n"
        "\tsig \"example.com/signlib/ecdsa\"\n)\n\nfunc main() {\n\tk, _ := sig.New()\n"
        "\tc := &tls.Config{MinVersion: tls.VersionTLS12}\n\tfmt.Println(k != nil, c.MinVersion, plainlib.Add(1, 2))\n}\n")
    out = root / "bin"
    out.mkdir()
    env = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOFLAGS="-mod=mod",
               GOCACHE=str(root / ".cache"), CGO_ENABLED="0")
    subprocess.run([GO, "build", "-o", str(out / "probe"), "."], cwd=root, env=env, check=True,
                   capture_output=True, timeout=600)
    return out


@pytest.fixture(scope="module")
def go_bin(tmp_path_factory):
    if GO is None:
        pytest.skip("the go toolchain is not on PATH")
    return _go_build(tmp_path_factory.mktemp("goprobe"))


def test_a_real_go_binary(go_bin):
    out = go_bin
    scan = _scan(["ECDSA", "DSA"], [])
    r = build_gap(scan, out)
    mods = {p["package"]: p for p in r["packages"]}
    assert mods["example.com/signlib"]["public_key_bearing"] is True
    assert mods["example.com/signlib"]["public_key_families"] == ["ECDSA"]
    assert mods["example.com/plainlib"]["public_key_bearing"] is False
    assert r["K_public_key_bearing"] == 1 and r["J_named_by_source_scan"] == 0
    assert [p["package"] for p in r["not_named_by_source_scan"]] == ["example.com/signlib"]
    # crypto/tls pulls in RSA, SHA-1, MD5 from the standard library; no source line names them.
    assert {"RSA", "SHA1", "MD5"} <= set(r["families"]["build_only"])
    assert r["families"]["source_only"] == ["DSA"]
    (settings,) = r["go_build_settings"]
    assert settings["DefaultGODEBUG"]            # `go 1.20` on a newer toolchain records some
    assert all(kv.split("=")[0].startswith(("tls", "x509", "crypto", "rsa", "fips140",
                                            "mlkem", "kyber", "dsa"))
               for kv in settings["crypto_settings"])
    assert settings["crypto_settings"] and settings["symbols_read"]
    assert r["not_read"] == []


def test_the_cli_writes_it(tmp_path, go_bin):
    out = go_bin
    scan_file = tmp_path / "scan.json"
    scan_file.write_text(json.dumps(_scan(["ECDSA"], [("go", "example.com/signlib")])))
    report = tmp_path / "gap.json"
    with pytest.raises(SystemExit) as done:
        main(["build-gap", str(scan_file), str(out), "--out", str(report)])
    assert done.value.code == 0
    r = json.loads(report.read_text())
    assert r["K_public_key_bearing"] == 1 and r["J_named_by_source_scan"] == 1
    assert len(r["scan"]["sha256"]) == 64


def test_the_cli_refuses_what_is_not_a_scan(tmp_path):
    bad = tmp_path / "x.json"
    bad.write_text("[]")
    with pytest.raises(SystemExit) as done:
        main(["build-gap", str(bad), str(tmp_path)])
    assert done.value.code == 2


# -- the words and the constraint ---------------------------------------------------------

def test_it_says_robustness_and_never_claims_recall_or_coverage(publish):
    r = build_gap(_scan([], []), publish, go="")
    assert "robustness on known patterns" in r["meaning"]
    assert "Not recall, and not coverage of the build" in r["meaning"]
    rest = json.dumps({k: v for k, v in r.items() if k != "meaning"}).lower()
    assert "recall" not in rest and "coverage" not in rest


FORBIDDEN_IMPORTS = {"dis", "capstone", "pefile", "dnfile", "lief", "angr", "r2pipe", "iced_x86",
                     "pyghidra", "binaryninja", "elftools", "dncil", "clr", "pythonnet", "miasm",
                     "unicorn", "keystone", "networkx", "sklearn", "torch", "numpy"}


def test_the_module_imports_no_disassembler_and_no_il_reader():
    tree = ast.parse(Path(buildgap.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            imported.add(node.module.split(".")[0])
    assert not imported & FORBIDDEN_IMPORTS, imported & FORBIDDEN_IMPORTS
    assert imported <= {"__future__", "json", "re", "shutil", "struct", "subprocess",
                        "pathlib", "typing"}, imported


def test_no_method_body_is_read():
    # The MethodDef row's RVA (where a body would be) is stepped over, never followed; the
    # only toolchain commands run are `go version -m` and `go tool nm`.
    source = Path(buildgap.__file__).read_text(encoding="utf-8")
    assert "objdump" not in source and "disasm" not in source.lower()
    assert source.count('"version", "-m"') == 1 and source.count('"tool", "nm"') == 1
    assert "0x06:" in source and "values[0]" not in source.split("def _read_tables")[1]
