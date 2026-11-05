"""`qrp-mcp build-gap SCAN.json BUILD_DIR`: a source scan set beside what the build carries.

Direction 2 of 04.11.2026 (W1): of K public-key-bearing packages or modules in a build, the
source scan named J; the K-J list; the families on one side only; and the cryptographic
settings a Go binary records in its DefaultGODEBUG line, as recorded.

Read ONLY from tables the toolchain already wrote:
  *.deps.json                .NET: packages in the build and the assemblies each ships
  .NET metadata tables       AssemblyRef, TypeRef, TypeDef: names, read from the #~ and
                             #Strings streams (ECMA-335 Partition II, 24.2 and 22)
  `go version -m BIN`        Go: modules linked and the DefaultGODEBUG build setting
  `go tool nm BIN`           Go: symbol names, of which only the package path is kept

Never read: method bodies, IL, machine code, call sites, arguments or data flow. No call
graph, no control-flow graph, no similarity, embedding or learned identification. Key
sizes, modes and curves are never recovered from the build: a parameter appears only where
the source scan already had it. tests/test_build_gap.py fails if this module imports a
disassembler or an IL reader. Nothing found is executed.

The figure is robustness on known patterns -- what these tables name, by the fixed lists
below -- and never a measure of how much of the build's cryptography is found.
"""
from __future__ import annotations

import json
import re
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Any

from . import __version__

MEANING = (
    "a source scan set beside the tables a build's toolchain wrote: robustness on known "
    "patterns, by the fixed name lists in `method`. Not recall, and not coverage of the build: "
    "a package whose metadata names no listed type, a module whose package paths name no "
    "listed algorithm, and anything chosen at run time are not counted.")
METHOD = (
    "*.deps.json (packages, and the assemblies each ships); .NET metadata tables AssemblyRef, "
    "TypeRef and TypeDef (names only; no method body or IL read); `go version -m` (modules, "
    "DefaultGODEBUG); `go tool nm` (package paths of the symbols). No binary is executed; no "
    "key size, mode or curve is read from the build.")

# Families compared, as W1 fixed them (compare.py): public-key and weak. AES and the hashes
# that are not weak are not compared.
PUBLIC_KEY = ("RSA", "ECDSA", "ECDH", "DSA", "EdDSA", "X25519", "ML-KEM", "ML-DSA", "SLH-DSA")
WEAK = ("MD5", "SHA1", "DES", "3DES", "RC4", "RC2")
COMPARED = PUBLIC_KEY + WEAK
# The scanner's names onto the compared ones (EC is folded into ECDSA, Ed25519 into EdDSA).
_SCAN_NAME = {"EC": "ECDSA", "Ed25519": "EdDSA", "Ed448": "EdDSA", "SHA-1": "SHA1",
              "TripleDES": "3DES", "Kyber": "ML-KEM"}

# -- .NET ------------------------------------------------------------------------------------

DOTNET_NAMESPACES = (
    "System.Security.Cryptography", "System.Net.Security", "Org.BouncyCastle.Crypto",
    "Org.BouncyCastle.Security", "Org.BouncyCastle.Math.EC", "Org.BouncyCastle.Pqc",
    "Org.BouncyCastle.Tls", "Org.BouncyCastle.X509", "Org.BouncyCastle.OpenSsl",
    "Org.BouncyCastle.Pkcs", "Microsoft.IdentityModel.Tokens",
    "Microsoft.IdentityModel.JsonWebTokens", "System.IdentityModel.Tokens",
    "Renci.SshNet.Security")
# A type name, or one of its CamelCase components, onto a family (W1's DotnetCryptoRefs list).
_DOTNET_PART = {p.lower(): f for f, parts in {
    "RSA": ("RSA", "Rsa"), "ECDSA": ("ECDsa", "Ecdsa"), "ECDH": ("ECDiffieHellman", "Ecdh"),
    "DSA": ("DSA", "Dsa"), "EdDSA": ("Ed25519", "Ed448"), "X25519": ("X25519", "X448"),
    "ML-KEM": ("MLKem", "Kyber"), "ML-DSA": ("MLDsa", "Dilithium"), "SLH-DSA": ("SlhDsa",),
    "MD5": ("MD5",), "SHA1": ("SHA1", "Sha1"), "DES": ("DES", "Des"),
    "3DES": ("TripleDES", "DesEde"), "RC4": ("RC4",), "RC2": ("RC2",),
}.items() for p in parts}
_CAMEL = re.compile(r"[A-Z0-9]+(?=[A-Z][a-z])|[A-Z][a-z]+[0-9]*|[A-Z0-9]+|[a-z]+[0-9]*")
# A DSA, DH or KEM component behind these is that scheme, not DSA.
_BEHIND = {("EC", "DSA"): "ECDSA", ("ED", "DSA"): "EdDSA", ("ML", "DSA"): "ML-DSA",
           ("SLH", "DSA"): "SLH-DSA", ("EC", "DH"): "ECDH", ("EC", "DIFFIE"): "ECDH",
           ("ML", "KEM"): "ML-KEM"}


def dotnet_families(type_name: str) -> set[str]:
    """Families a .NET type's simple name names: whole, or by CamelCase component."""
    whole = _DOTNET_PART.get(type_name.lower())
    if whole:
        return {whole}
    out: set[str] = set()
    parts = _CAMEL.findall(type_name)
    for i, part in enumerate(parts):
        prev = parts[i - 1].upper() if i else ""
        joined = _BEHIND.get((prev, part.upper()))
        if joined:
            out.add(joined)
            continue
        if prev in ("EC", "ED", "ML", "SLH"):
            continue
        family = _DOTNET_PART.get(part.lower())
        if family and len(part) >= 3:
            out.add(family)
    return out


def _is_crypto_namespace(ns: str) -> bool:
    return any(ns == p or ns.startswith(p + ".") for p in DOTNET_NAMESPACES)


# ECMA-335 Partition II, 22: the column layout of tables 0x00-0x2C. A column is a fixed width
# (an int), a heap index ("s", "g", "b"), a table index ("t:N") or a coded index ("c:NAME").
# Only the widths are used, to step over rows; only AssemblyRef, TypeRef and TypeDef names
# are read.
_TABLES: dict[int, tuple] = {
    0x00: (2, "s", "g", "g", "g"), 0x01: ("c:ResolutionScope", "s", "s"),
    0x02: (4, "s", "s", "c:TypeDefOrRef", "t:4", "t:6"), 0x03: ("t:4",),
    0x04: (2, "s", "b"), 0x05: ("t:6",), 0x06: (4, 2, 2, "s", "b", "t:8"), 0x07: ("t:8",),
    0x08: (2, 2, "s"), 0x09: ("t:2", "c:TypeDefOrRef"), 0x0A: ("c:MemberRefParent", "s", "b"),
    0x0B: (2, "c:HasConstant", "b"), 0x0C: ("c:HasCustomAttribute", "c:CustomAttributeType", "b"),
    0x0D: ("c:HasFieldMarshal", "b"), 0x0E: (2, "c:HasDeclSecurity", "b"), 0x0F: (2, 4, "t:2"),
    0x10: (4, "t:4"), 0x11: ("b",), 0x12: ("t:2", "t:20"), 0x13: ("t:20",),
    0x14: (2, "s", "c:TypeDefOrRef"), 0x15: ("t:2", "t:23"), 0x16: ("t:23",), 0x17: (2, "s", "b"),
    0x18: (2, "t:6", "c:HasSemantics"), 0x19: ("t:2", "c:MethodDefOrRef", "c:MethodDefOrRef"),
    0x1A: ("s",), 0x1B: ("b",), 0x1C: (2, "c:MemberForwarded", "s", "t:26"), 0x1D: (4, "t:4"),
    0x1E: (4, 4), 0x1F: (4,), 0x20: (4, 2, 2, 2, 2, 4, "b", "s", "s"), 0x21: (4,), 0x22: (4, 4, 4),
    0x23: (2, 2, 2, 2, 4, "b", "s", "s", "b"), 0x24: (4, "t:35"), 0x25: (4, 4, 4, "t:35"),
    0x26: (4, "s", "b"), 0x27: (4, 4, "s", "s", "c:Implementation"), 0x28: (4, 4, "s", "c:Implementation"),
    0x29: ("t:2", "t:2"), 0x2A: (2, 2, "c:TypeOrMethodDef", "s"), 0x2B: ("c:MethodDefOrRef", "b"),
    0x2C: ("t:42", "c:TypeDefOrRef"),
}
_CODED = {
    "TypeDefOrRef": (2, (0x02, 0x01, 0x1B)), "HasConstant": (2, (0x04, 0x08, 0x17)),
    "HasCustomAttribute": (5, (0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14,
                               0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B)),
    "HasFieldMarshal": (1, (0x04, 0x08)), "HasDeclSecurity": (2, (0x02, 0x06, 0x20)),
    "MemberRefParent": (3, (0x02, 0x01, 0x1A, 0x06, 0x1B)), "HasSemantics": (1, (0x14, 0x17)),
    "MethodDefOrRef": (1, (0x06, 0x0A)), "MemberForwarded": (1, (0x04, 0x06)),
    "Implementation": (2, (0x26, 0x23, 0x27)), "CustomAttributeType": (3, (0x06, 0x0A)),
    "ResolutionScope": (2, (0x00, 0x1A, 0x23, 0x01)), "TypeOrMethodDef": (1, (0x02, 0x06)),
}


class NotManaged(Exception):
    pass


def read_metadata_names(raw: bytes) -> dict[str, Any]:
    """AssemblyRef, TypeRef and TypeDef names of a managed PE file. Raises NotManaged for a PE
    file without a CLI header, or anything that is not a PE file."""
    try:
        if raw[:2] != b"MZ":
            raise NotManaged("not a PE file")
        pe = struct.unpack_from("<I", raw, 0x3C)[0]
        if raw[pe:pe + 4] != b"PE\0\0":
            raise NotManaged("not a PE file")
        sections, opt_size = struct.unpack_from("<H", raw, pe + 6)[0], struct.unpack_from("<H", raw, pe + 20)[0]
        opt = pe + 24
        magic = struct.unpack_from("<H", raw, opt)[0]
        dirs = opt + (96 if magic == 0x10B else 112)
        cli_rva, cli_size = struct.unpack_from("<II", raw, dirs + 14 * 8)
        if not cli_rva or not cli_size:
            raise NotManaged("no CLI header (native code)")
        table = opt + opt_size
        spans = [struct.unpack_from("<IIII", raw, table + 40 * i + 8) for i in range(sections)]

        def offset(rva: int) -> int:
            for vsize, vaddr, rawsize, rawptr in spans:
                if vaddr <= rva < vaddr + max(vsize, rawsize):
                    return rva - vaddr + rawptr
            raise NotManaged("an RVA outside every section")

        md_rva = struct.unpack_from("<I", raw, offset(cli_rva) + 8)[0]
        root = offset(md_rva)
        if struct.unpack_from("<I", raw, root)[0] != 0x424A5342:
            raise NotManaged("no metadata signature")
        vlen = struct.unpack_from("<I", raw, root + 12)[0]
        pos = root + 16 + vlen + 2
        count = struct.unpack_from("<H", raw, pos)[0]
        pos += 2
        streams: dict[str, tuple[int, int]] = {}
        for _ in range(count):
            off, size = struct.unpack_from("<II", raw, pos)
            end = raw.index(b"\0", pos + 8)
            streams[raw[pos + 8:end].decode("ascii")] = (root + off, size)
            pos = pos + 8 + ((end - (pos + 8)) // 4 + 1) * 4
        tilde = streams.get("#~") or streams.get("#-")
        strings_at = streams["#Strings"][0]
        if tilde is None:
            raise NotManaged("no metadata table stream")
        return _read_tables(raw, tilde[0], strings_at)
    except (struct.error, IndexError, KeyError, ValueError, UnicodeDecodeError) as err:
        raise NotManaged(f"metadata not readable: {type(err).__name__}") from None


def _read_tables(raw: bytes, at: int, strings_at: int) -> dict[str, Any]:
    heap_sizes = raw[at + 6]
    valid = struct.unpack_from("<Q", raw, at + 8)[0]
    pos = at + 24
    rows: dict[int, int] = {}
    for t in range(64):
        if valid >> t & 1:
            rows[t] = struct.unpack_from("<I", raw, pos)[0]
            pos += 4
    if heap_sizes & 0x40:
        pos += 4
    widths = {"s": 4 if heap_sizes & 1 else 2, "g": 4 if heap_sizes & 2 else 2,
              "b": 4 if heap_sizes & 4 else 2}

    def width(col) -> int:
        if isinstance(col, int):
            return col
        if col in widths:
            return widths[col]
        kind, _, arg = col.partition(":")
        if kind == "t":
            return 2 if rows.get(int(arg), 0) < 1 << 16 else 4
        bits, tables = _CODED[arg]
        return 2 if max(rows.get(t, 0) for t in tables) < 1 << (16 - bits) else 4

    def string(index: int) -> str:
        end = raw.index(b"\0", strings_at + index)
        return raw[strings_at + index:end].decode("utf-8", "replace")

    out: dict[str, Any] = {"assembly": None, "assembly_refs": [], "typerefs": [], "typedefs": []}
    for t in sorted(rows):
        if t not in _TABLES:
            raise ValueError("a table this reader does not know")
        cols = _TABLES[t]
        sizes = [width(c) for c in cols]
        for _ in range(rows[t]):
            values, p = [], pos
            for size in sizes:
                values.append(struct.unpack_from("<H" if size == 2 else "<I", raw, p)[0])
                p += size
            if t == 0x01:
                out["typerefs"].append((string(values[2]), string(values[1])))
            elif t == 0x02:
                out["typedefs"].append((string(values[2]), string(values[1])))
            elif t == 0x20:
                out["assembly"] = string(values[7])
            elif t == 0x23:
                out["assembly_refs"].append(string(values[6]))
            pos = p
    return out


def dotnet_assembly(raw: bytes) -> dict[str, Any]:
    """The cryptographic types an assembly references or defines, and their families."""
    names = read_metadata_names(raw)
    families: dict[str, list[str]] = {}
    crypto_types: set[str] = set()
    for kind in ("typerefs", "typedefs"):
        for ns, name in names[kind]:
            if not ns or name.startswith("<"):
                continue
            found = dotnet_families(name)
            if _is_crypto_namespace(ns) or (kind == "typerefs" and found):
                crypto_types.add(f"{ns}.{name}")
                for family in found:
                    evidence = families.setdefault(family, [])
                    if len(evidence) < 4 and f"{ns}.{name}" not in evidence:
                        evidence.append(f"{ns}.{name}")
    return {"assembly": names["assembly"], "assembly_refs": sorted(set(names["assembly_refs"])),
            "crypto_types": len(crypto_types), "families": families}


def _deps_json(path: Path) -> dict[str, dict[str, Any]]:
    """package -> {version, assemblies} out of a deps.json (`libraries` of type package;
    `runtime` and `runtimeTargets` of each target entry name the DLLs it ships)."""
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    out: dict[str, dict[str, Any]] = {}
    for key, entry in (data.get("libraries") or {}).items():
        if isinstance(entry, dict) and "/" in key:
            name, _, version = key.rpartition("/")
            out[name] = {"version": version, "type": entry.get("type"), "assemblies": set()}
    for target in (data.get("targets") or {}).values():
        for key, entry in (target or {}).items():
            name = key.rpartition("/")[0]
            if name in out and isinstance(entry, dict):
                for dll in [*(entry.get("runtime") or {}), *(entry.get("runtimeTargets") or {})]:
                    if dll.lower().endswith(".dll"):
                        out[name]["assemblies"].add(Path(dll).stem)
    return out


# -- Go --------------------------------------------------------------------------------------

# A package path component onto a family: `crypto/rsa`, `golang.org/x/crypto/curve25519`,
# `github.com/x/y/ecdsa`. A component, never a substring.
_GO_PART = {"rsa": "RSA", "ecdsa": "ECDSA", "ecdh": "ECDH", "dsa": "DSA", "ed25519": "EdDSA",
            "ed448": "EdDSA", "edwards25519": "EdDSA", "curve25519": "X25519", "x25519": "X25519",
            "mlkem": "ML-KEM", "kyber": "ML-KEM", "mldsa": "ML-DSA", "dilithium": "ML-DSA",
            "slhdsa": "SLH-DSA", "md5": "MD5", "sha1": "SHA1", "des": "DES", "rc4": "RC4"}
# DefaultGODEBUG settings that concern cryptography, by prefix (go.dev/doc/godebug).
_GODEBUG_CRYPTO = ("tls", "x509", "crypto", "rsa", "fips140", "mlkem", "kyber", "dsa")


def go_package_of(symbol: str) -> str | None:
    """`crypto/ecdsa.SignASN1` -> crypto/ecdsa; `type:.eq.crypto/tls.Config` -> None. A
    module's vendored copy (`app/vendor/golang.org/x/crypto/ssh`) is the vendored path."""
    if symbol.startswith(("type:", "go:", "go.", "runtime.", "_")):
        return None
    head = re.split(r"[(\[]", symbol, maxsplit=1)[0]
    slash = head.rfind("/")
    dot = head.find(".", slash + 1)
    if dot <= 0:
        return None
    package = head[:dot]
    vendored = re.search(r"(?:^|/)vendor/(.+)$", package)
    return vendored.group(1) if vendored else package


def go_families(package: str) -> set[str]:
    return {_GO_PART[p] for p in package.split("/") if p in _GO_PART}


def parse_go_version_m(text: str) -> dict[str, Any]:
    """Modules and build settings out of `go version -m` output."""
    out: dict[str, Any] = {"go_version": None, "main": None, "modules": [], "godebug": None}
    for line in text.splitlines():
        if not line.startswith("\t"):
            out["go_version"] = line.rpartition(": ")[2].strip() or None
            continue
        parts = line.strip("\t").split("\t")
        if parts[0] == "mod" and len(parts) >= 2:
            out["main"] = parts[1]
        elif parts[0] == "dep" and len(parts) >= 3:
            out["modules"].append({"module": parts[1], "version": parts[2]})
        elif parts[0] == "=>" and out["modules"] and len(parts) >= 2:
            out["modules"][-1]["replaced_by"] = " ".join(p for p in parts[1:3] if p)
        elif parts[0] == "build" and len(parts) >= 2 and parts[1].startswith("DefaultGODEBUG="):
            out["godebug"] = parts[1][len("DefaultGODEBUG="):]
    return out


def parse_go_nm(text: str) -> set[str]:
    """Package paths of the symbols `go tool nm` lists."""
    packages = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 2:
            package = go_package_of(fields[-1])
            if package:
                packages.add(package)
    return packages


def go_binary(path: Path, go: str) -> dict[str, Any] | None:
    """What `go version -m` and `go tool nm` say of a file, or None when it is not a Go
    binary. The binary is read by the toolchain; it is never executed."""
    info = subprocess.run([go, "version", "-m", str(path)], capture_output=True, text=True,
                          errors="replace", timeout=60)
    if info.returncode != 0 or "\tpath\t" not in info.stdout and "\tmod\t" not in info.stdout:
        return None
    nm = subprocess.run([go, "tool", "nm", str(path)], capture_output=True, text=True,
                        errors="replace", timeout=300)
    record = parse_go_version_m(info.stdout)
    record["packages"] = parse_go_nm(nm.stdout) if nm.returncode == 0 else set()
    record["symbols_read"] = nm.returncode == 0
    return record


# -- the comparison --------------------------------------------------------------------------

def _scan_families(scan: dict[str, Any]) -> set[str]:
    """The scan's findings and the families its declared dependencies implement (W1)."""
    names = [f.get("algorithm_family") for f in scan.get("findings") or []]
    for dep in (scan.get("evidence") or {}).get("dependencies") or []:
        names.extend(dep.get("families") or [])
    return {n for n in (_SCAN_NAME.get(x, x) for x in names) if n in COMPARED}


def _executable(raw: bytes) -> bool:
    return raw[:2] == b"MZ" or raw[:4] in (b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                                          b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")


def build_gap(scan: dict[str, Any], build_dir: Path, go: str | None = None) -> dict[str, Any]:
    go = go if go is not None else shutil.which("go")
    named = {(d.get("ecosystem"), (d.get("package") or "").lower())
             for d in (scan.get("evidence") or {}).get("dependencies") or []}
    not_read: list[dict[str, str]] = []
    deps: dict[str, dict[str, Any]] = {}
    assemblies: dict[str, dict[str, Any]] = {}
    binaries: list[dict[str, Any]] = []
    for path in sorted(p for p in build_dir.rglob("*") if p.is_file() and not p.is_symlink()):
        rel = path.relative_to(build_dir).as_posix()
        if path.name.endswith(".deps.json"):
            try:
                deps.update(_deps_json(path))
            except (ValueError, OSError):
                not_read.append({"path": rel, "reason": "deps.json that does not parse"})
            continue
        try:
            with path.open("rb") as fh:
                head = fh.read(4)
        except OSError:
            continue
        if not _executable(head):
            continue
        raw = path.read_bytes()
        if raw[:2] == b"MZ":
            try:
                record = dotnet_assembly(raw)
            except NotManaged as why:
                record = None
                reason = str(why)
            else:
                assemblies.setdefault(record["assembly"] or path.stem, {
                    "path": rel, "families": {}, "crypto_types": 0})
                merged = assemblies[record["assembly"] or path.stem]
                for family, evidence in record["families"].items():
                    merged["families"].setdefault(family, evidence)
                merged["crypto_types"] += record["crypto_types"]
                continue
        else:
            reason = "native code"
        if go:
            found = go_binary(path, go)
            if found is not None:
                found["path"] = rel
                binaries.append(found)
                continue
        else:
            reason += "; the go toolchain is not on PATH, so a Go binary would not be read"
        not_read.append({"path": rel, "reason": f"{reason}: no table this command reads"})

    packages: list[dict[str, Any]] = []
    build_families: dict[str, list[str]] = {}

    def add_families(families: dict[str, list[str]], where: str) -> None:
        for family, evidence in families.items():
            build_families.setdefault(family, [])
            if len(build_families[family]) < 4:
                build_families[family].append(f"{where}: {evidence[0]}")

    # .NET: a package is public-key-bearing when an assembly it ships references or defines a
    # type that names a public-key family.
    owned: set[str] = set()
    for name, entry in sorted(deps.items()):
        families: dict[str, list[str]] = {}
        for asm in sorted(entry["assemblies"]):
            if asm in assemblies:
                owned.add(asm)
                for family, evidence in assemblies[asm]["families"].items():
                    families.setdefault(family, evidence)
        add_families(families, name)
        if entry["type"] != "package":
            continue
        public = sorted(f for f in families if f in PUBLIC_KEY)
        packages.append({
            "ecosystem": "nuget", "package": name, "version": entry["version"],
            "public_key_bearing": bool(public), "public_key_families": public,
            "evidence": {f: families[f] for f in public},
            "named_by_source_scan": ("nuget", name.lower()) in named})
    for asm, entry in sorted(assemblies.items()):
        if asm not in owned:
            add_families(entry["families"], asm)
    # Go: a module is public-key-bearing when a package path under it that the linker kept
    # names a public-key family. The standard library's packages count for the families only.
    godebug = []
    for binary in binaries:
        for package in sorted(binary["packages"]):
            fams = go_families(package)
            if not fams or any(package == m["module"] or package.startswith(m["module"] + "/")
                               for m in binary["modules"]):
                continue
            where = ("own code" if binary["main"] and (package == binary["main"] or
                                                       package.startswith(binary["main"] + "/"))
                     else "Go standard library" if "." not in package.split("/")[0]
                     else "a module go version -m does not list")
            add_families({f: [package] for f in fams}, where)
        for module in binary["modules"]:
            under = [p for p in sorted(binary["packages"])
                     if p == module["module"] or p.startswith(module["module"] + "/")]
            families = {}
            for package in under:
                for family in go_families(package):
                    families.setdefault(family, [package])
            add_families(families, module["module"])
            public = sorted(f for f in families if f in PUBLIC_KEY)
            packages.append({
                "ecosystem": "go", "package": module["module"], "version": module["version"],
                "in_binary": binary["path"], "public_key_bearing": bool(public),
                "public_key_families": public, "evidence": {f: families[f] for f in public},
                "named_by_source_scan": ("go", module["module"].lower()) in named})
        settings = [kv for kv in (binary["godebug"] or "").split(",") if kv]
        godebug.append({
            "binary": binary["path"], "go_version": binary["go_version"],
            "DefaultGODEBUG": binary["godebug"],
            "crypto_settings": [kv for kv in settings if kv.split("=")[0].startswith(_GODEBUG_CRYPTO)],
            "symbols_read": binary["symbols_read"],
            "meaning": ("as recorded by the toolchain: the settings that differ from this Go "
                        "version's defaults, set by the `go` line of go.mod or a //go:debug "
                        "directive; what each does is in https://go.dev/doc/godebug")})

    k = [p for p in packages if p["public_key_bearing"]]
    j = [p for p in k if p["named_by_source_scan"]]
    source = _scan_families(scan)
    build = {f for f in build_families if f in COMPARED}
    notes = []
    if any(str(d.get("path", "")).endswith(".deps.json")
           for d in (scan.get("evidence") or {}).get("dependencies") or []):
        notes.append("the source scan read a *.deps.json; if it is this build's, the scan was "
                     "taken after the build and J counts the build as the source")
    if not go:
        notes.append("the go toolchain is not on PATH: Go binaries were not read")
    return {
        "tool": "qrp-mcp build-gap", "version": __version__,
        "meaning": MEANING, "method": METHOD,
        "scan": {"target": scan.get("target"),
                 "instrument": ((scan.get("coverage") or {}).get("instrument") or {}).get("version")},
        "build_dir": str(build_dir),
        "K_public_key_bearing": len(k),
        "J_named_by_source_scan": len(j),
        "not_named_by_source_scan": [{"ecosystem": p["ecosystem"], "package": p["package"],
                                      "version": p["version"],
                                      "public_key_families": p["public_key_families"]}
                                     for p in k if not p["named_by_source_scan"]],
        "named_by_source_scan_not_in_build": sorted(
            f"{eco}:{name}" for eco, name in named
            if eco in ("nuget", "go") and not any(
                p["ecosystem"] == eco and p["package"].lower() == name for p in packages)),
        "families": {
            "compared": list(COMPARED),
            "build": sorted(build), "source_scan": sorted(source),
            "build_only": sorted(build - source), "source_only": sorted(source - build),
            "build_evidence": {f: build_families[f] for f in sorted(build)},
            "parameters": "none read from the build; key sizes and curves are the source scan's",
        },
        "go_build_settings": godebug,
        "packages": packages,
        "not_read": not_read,
        "notes": notes,
    }
