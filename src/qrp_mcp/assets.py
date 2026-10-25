"""Cryptographic assets that are present without an algorithm being written down.

Three kinds, and the reason they are here rather than in `detectors`:

* **Protocols.** `MinVersion: tls.VersionTLS12` or `Protocol 2` in sshd_config
  says a protocol is configured and pinned. It does not say which algorithms
  will be negotiated, and TLS 1.3 is quantum-vulnerable with X25519 and is not
  with X25519MLKEM768. So a version line is an asset, not a verdict.
* **Dependencies.** `node-forge` in a package.json means the RSA implementation
  is installed. It does not mean a line of code calls it. Declared is not
  observed, and the finding says which it is.
* Neither gets an algorithm family invented for it. A tool that reports
  "unknown" and counts it as a find is measuring its own output, which is the
  practice this scanner was built to argue against.

Every asset carries `basis`, which is what separates these from a call site:
`configured_protocol` or `declared_dependency`, never `observed_call`.

The library-to-algorithm table below is the factual content of the
`vulnerableDependencies` list in QuantaKrypto's qscan (@quantakrypto/core,
Apache-2.0, github.com/quantakrypto/pqc-tools) -- the same licence as this file.
Which library implements which algorithm is a fact about those libraries; the
wording here is ours, and the credit is theirs.
"""

from __future__ import annotations

import json
import posixpath
import re
from pathlib import Path
from typing import Any

# ecosystem -> package name -> the classical families it implements
DEPENDENCY_FAMILIES: dict[str, dict[str, tuple[str, ...]]] = {
    "npm": {
        "node-forge": ("RSA",),
        "elliptic": ("ECDSA", "ECDH", "EdDSA"),
        "jsrsasign": ("RSA", "ECDSA", "DSA"),
        "node-rsa": ("RSA",),
        "ursa": ("RSA",),
        "sshpk": ("RSA", "ECDSA", "EdDSA", "DSA"),
        "jsonwebtoken": ("RSA", "ECDSA"),
        "jose": ("RSA", "ECDH", "ECDSA", "EdDSA"),
        "jws": ("RSA", "ECDSA"),
        "eccrypto": ("ECIES", "ECDH", "ECDSA"),
        "secp256k1": ("ECDSA", "ECDH"),
        "tweetnacl": ("X25519", "EdDSA"),
        "ed25519": ("EdDSA",),
        "@noble/curves": ("ECDSA", "ECDH", "EdDSA", "X25519"),
        "@noble/secp256k1": ("ECDSA", "ECDH"),
        "@noble/ed25519": ("EdDSA", "X25519"),
        "paseto": ("EdDSA", "RSA"),
        "bcrypto": ("RSA", "ECDSA", "ECDH", "EdDSA", "DSA"),
        "ecpair": ("ECDSA",),
        "keypair": ("RSA",),
        "ethers": ("ECDSA",),
        "web3": ("ECDSA",),
        "bitcoinjs-lib": ("ECDSA",),
        "ethereumjs-util": ("ECDSA",),
        "openpgp": ("RSA", "ECDSA", "ECDH", "EdDSA"),
        "node-jose": ("RSA", "ECDSA", "ECDH"),
        "jwa": ("RSA", "ECDSA"),
        "jwk-to-pem": ("RSA", "ECDSA"),
        "fast-jwt": ("RSA", "ECDSA"),
        "ssh2": ("RSA", "ECDSA", "EdDSA"),
        "@peculiar/x509": ("RSA", "ECDSA"),
        "pkijs": ("RSA", "ECDSA", "ECDH"),
        "http-signature": ("RSA", "ECDSA"),
        "libsodium-wrappers": ("EdDSA", "X25519"),
        "ecdsa-sig-formatter": ("ECDSA",),
        # No public-key algorithm; its weak hashes and ciphers (ZA-OPRAVYANE row 149).
        "crypto-js": ("MD5", "SHA1", "DES", "3DES", "RC4"),
    },
    "pypi": {
        "pycryptodome": ("RSA", "ECDSA", "DSA"),
        "pycrypto": ("RSA", "DSA"),
        "jwcrypto": ("RSA", "ECDSA", "ECDH"),
        "authlib": ("RSA", "ECDSA"),
        "pycryptodomex": ("RSA", "ECDSA", "DSA"),
        "rsa": ("RSA",),
        "ecdsa": ("ECDSA", "ECDH"),
        "cryptography": ("RSA", "ECDH", "ECDSA", "DSA"),
        "pyjwt": ("RSA", "ECDSA"),
        "python-jose": ("RSA", "ECDSA"),
        "paramiko": ("RSA", "ECDSA", "EdDSA", "DSA"),
        "pyopenssl": ("RSA", "ECDSA"),
        "pynacl": ("X25519", "EdDSA"),
        "tink": ("RSA", "ECDSA", "EdDSA", "ECIES"),
    },
    "go": {
        "golang.org/x/crypto": ("RSA", "ECDSA", "EdDSA", "ECDH"),
        "github.com/golang-jwt/jwt/v5": ("RSA", "ECDSA"),
        "github.com/golang-jwt/jwt/v4": ("RSA", "ECDSA"),
        "github.com/go-jose/go-jose/v4": ("RSA", "ECDSA", "ECDH"),
        "github.com/cloudflare/circl": ("ECDH", "EdDSA"),
        "github.com/decred/dcrd/dcrec/secp256k1/v4": ("ECDSA", "ECDH"),
        "github.com/tink-crypto/tink-go/v2": ("RSA", "ECDSA", "EdDSA", "ECIES"),
        "github.com/google/tink/go": ("RSA", "ECDSA", "EdDSA", "ECIES"),
    },
    "cargo": {
        "rsa": ("RSA",),
        "ring": ("RSA", "ECDSA", "EdDSA", "ECDH"),
        "openssl": ("RSA", "ECDSA"),
        "p256": ("ECDSA", "ECDH"),
        "p384": ("ECDSA", "ECDH"),
        "k256": ("ECDSA", "ECDH"),
        "secp256k1": ("ECDSA", "ECDH"),
        "ed25519-dalek": ("EdDSA",),
        "x25519-dalek": ("X25519",),
    },
    "maven": {
        "bcprov-jdk18on": ("RSA", "ECDSA", "ECDH", "DSA"),
        "bcprov-jdk15on": ("RSA", "ECDSA", "ECDH", "DSA"),
        "bcpkix-jdk18on": ("RSA", "ECDSA"),
        "java-jwt": ("RSA", "ECDSA"),
        "nimbus-jose-jwt": ("RSA", "ECDSA", "ECDH"),
        "jjwt-api": ("RSA", "ECDSA"),
        "tink": ("RSA", "ECDSA", "EdDSA", "ECIES"),
    },
    "rubygems": {
        "jwt": ("RSA", "ECDSA"),
        "net-ssh": ("RSA", "ECDSA", "ECDH"),
        "rbnacl": ("X25519", "EdDSA"),
        "ed25519": ("EdDSA",),
    },
    "nuget": {
        "BouncyCastle.Cryptography": ("RSA", "ECDSA", "ECDH", "DSA"),
        "Portable.BouncyCastle": ("RSA", "ECDSA", "ECDH", "DSA"),
        "System.IdentityModel.Tokens.Jwt": ("RSA", "ECDSA"),
        "Microsoft.IdentityModel.Tokens": ("RSA", "ECDSA"),
    },
    "composer": {
        "phpseclib/phpseclib": ("RSA", "DSA", "ECDSA", "DH"),
        "paragonie/sodium_compat": ("X25519", "EdDSA"),
        "paragonie/halite": ("X25519", "EdDSA"),
        "paragonie/paseto": ("EdDSA", "RSA"),
        "firebase/php-jwt": ("RSA", "ECDSA"),
        "lcobucci/jwt": ("RSA", "ECDSA"),
        "web-token/jwt-framework": ("RSA", "ECDSA", "ECDH"),
        "mdanter/ecc": ("ECDSA", "ECDH"),
        "simplito/elliptic-php": ("ECDSA", "ECDH"),
    },
}


# --- manifests --------------------------------------------------------------

MANIFEST_FILENAMES: dict[str, str] = {
    "package.json": "npm",
    "requirements.txt": "pypi",
    "pyproject.toml": "pypi",
    "Pipfile": "pypi",
    "go.mod": "go",
    "Cargo.toml": "cargo",
    "pom.xml": "maven",
    "build.gradle": "maven",
    "build.gradle.kts": "maven",
    "Gemfile": "rubygems",
    "composer.json": "composer",
    # A manifest says what was asked for; a lockfile says what shipped. For a
    # register of what is installed, the lockfile is the honest one, and this
    # scanner read none of them.
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "Cargo.lock": "cargo",
    "Gemfile.lock": "rubygems",
    "composer.lock": "composer",
    "Pipfile.lock": "pypi",
    "poetry.lock": "pypi",
}

# NuGet has no fixed filename: the project file is named after the project.
_NUGET_SUFFIXES = (".csproj", ".vbproj", ".fsproj")
_NUGET_FILENAMES = {"packages.config", "Directory.Packages.props"}

# A dependency is read from the structure of the manifest, never from the text
# anywhere in it: qscan reports RSA for a comment line in a go.mod, which is the
# false positive not to copy.
_GO_REQUIRE = re.compile(r"^\s*(?:require\s+)?([a-z0-9][\w./-]*\.[a-z]{2,}/[\w./-]+)\s+v\d")
_PY_REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:[=<>!~]|$|;)")
_CARGO_DEP = re.compile(r'^\s*([A-Za-z0-9][\w-]*)\s*=\s*[{"\d]')
_MAVEN_ARTIFACT = re.compile(r"<artifactId>\s*([^<\s]+)\s*</artifactId>")
_GRADLE_DEP = re.compile(r"""['"][\w.-]+:([\w.-]+):""")
_GEM = re.compile(r"""^\s*gem\s+['"]([^'"]+)['"]""")
_NUGET_PACKAGE = re.compile(r"""<(?:PackageReference|PackageVersion|package)\s[^>]*?(?:Include|id)\s*=\s*["']([^"']+)["']""")
_LOCK_NPM_PATH = re.compile(r'^\s*"node_modules/((?:@[^/"]+/)?[^/"]+)"\s*:')
_LOCK_YARN = re.compile(r'^"?((?:@[^/@"]+/)?[^@"\s][^@"]*)@[^"\s]+"?\s*:\s*$')
_LOCK_TOML_NAME = re.compile(r'^\s*name\s*=\s*"([^"]+)"')
_LOCK_GEM = re.compile(r"^\s{4}([A-Za-z0-9._-]+)\s*\(")
# pnpm writes its package keys two ways across lockfile versions:
#   v9:  `  node-forge@1.3.1:`   ·  scoped `  @scope/pkg@1.2.3:`
#   v6:  `  /node-forge/1.3.1:`  ·  scoped `  /@scope/pkg/1.2.3:`
_LOCK_PNPM = re.compile(
    r"^\s+/?((?:@[^/@\s]+/)?[^/@\s]+)[@/]\d[^\s:]*:\s*$")

# Every lockfile this tool claims, routed by its exact name. Routing by the
# `.lock` suffix sent `pnpm-lock.yaml` to a JSON parser and `composer.lock` --
# which is JSON -- to a Ruby regex; both were counted as read while their
# dependencies were silently dropped. An external retest of 0.11.0 found both.
_LOCKFILES = {
    "package-lock.json", "Pipfile.lock", "yarn.lock", "pnpm-lock.yaml",
    "Cargo.lock", "poetry.lock", "Gemfile.lock", "composer.lock",
}


def _names_from_lockfile(name: str, lines: list[str]) -> list[tuple[str, int]]:
    """Package names out of a lockfile, read by its own shape."""
    out: list[tuple[str, int]] = []
    if name in {"package-lock.json", "Pipfile.lock"}:
        # JSON, so parsed rather than matched: a lockfile is often one long line.
        try:
            data = json.loads("\n".join(lines))
        except (ValueError, TypeError):
            data = None
        if isinstance(data, dict):
            for key in ("packages", "dependencies", "default", "develop"):
                block = data.get(key)
                if not isinstance(block, dict):
                    continue
                for raw in block:
                    package = raw.split("node_modules/")[-1] if raw else ""
                    if not package:
                        continue
                    line = next((n for n, text in enumerate(lines, 1) if raw in text), 1)
                    out.append((package, line))
        if out:
            return out
        for number, text in enumerate(lines, 1):
            match = _LOCK_NPM_PATH.match(text)
            if match:
                out.append((match.group(1), number))
    elif name == "pnpm-lock.yaml":
        for number, text in enumerate(lines, 1):
            match = _LOCK_PNPM.match(text)
            if match:
                out.append((match.group(1), number))
    elif name == "yarn.lock":
        for number, text in enumerate(lines, 1):
            match = _LOCK_YARN.match(text) or _LOCK_NPM_PATH.match(text)
            if match:
                out.append((match.group(1), number))
    elif name in {"Cargo.lock", "poetry.lock"}:
        for number, text in enumerate(lines, 1):
            match = _LOCK_TOML_NAME.match(text)
            if match:
                out.append((match.group(1), number))
    elif name == "composer.lock":
        # JSON, with the names under `packages[]` and `packages-dev[]`.
        try:
            data = json.loads("\n".join(lines))
        except (ValueError, TypeError):
            return out
        if isinstance(data, dict):
            for key in ("packages", "packages-dev"):
                for entry in data.get(key) or []:
                    package = entry.get("name") if isinstance(entry, dict) else None
                    if not package:
                        continue
                    line = next((n for n, text in enumerate(lines, 1) if package in text), 1)
                    out.append((package, line))
    elif name == "Gemfile.lock":
        for number, text in enumerate(lines, 1):
            match = _LOCK_GEM.match(text)
            if match:
                out.append((match.group(1), number))
    return out


def _names_from_manifest(ecosystem: str, name: str, lines: list[str]) -> list[tuple[str, int]]:
    """(package name, line number) pairs, read structurally."""
    out: list[tuple[str, int]] = []
    if name in _LOCKFILES:
        return _names_from_lockfile(name, lines)
    if ecosystem == "npm" or (ecosystem == "composer" and name == "composer.json"):
        try:
            data = json.loads("\n".join(lines))
        except (ValueError, TypeError):
            return []
        if not isinstance(data, dict):
            return []
        for section in ("dependencies", "devDependencies", "peerDependencies",
                        "optionalDependencies", "require", "require-dev"):
            block = data.get(section)
            if isinstance(block, dict):
                for package in block:
                    line = next((n for n, text in enumerate(lines, 1)
                                 if f'"{package}"' in text), 1)
                    out.append((package, line))
        return out

    if ecosystem == "nuget":
        return [(m.group(1), n) for n, text in enumerate(lines, 1)
                for m in _NUGET_PACKAGE.finditer(text)]
    inside_cargo_deps = False
    for number, text in enumerate(lines, 1):
        stripped = text.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if ecosystem == "go":
            match = _GO_REQUIRE.match(text)
            if match:
                out.append((match.group(1), number))
        elif ecosystem == "pypi" and name == "requirements.txt":
            if stripped.startswith("-"):
                continue
            match = _PY_REQUIREMENT.match(text)
            if match:
                out.append((match.group(1), number))
        elif ecosystem == "cargo":
            if stripped.startswith("["):
                inside_cargo_deps = "dependencies" in stripped
                continue
            if inside_cargo_deps:
                match = _CARGO_DEP.match(text)
                if match:
                    out.append((match.group(1), number))
        elif ecosystem == "maven":
            pattern = _MAVEN_ARTIFACT if name == "pom.xml" else _GRADLE_DEP
            for match in pattern.finditer(text):
                out.append((match.group(1), number))
        elif ecosystem == "rubygems":
            match = _GEM.match(text)
            if match:
                out.append((match.group(1), number))
    return out


# pyproject.toml and Pipfile (ZA-OPRAVYANE rows 125, 149): read by their tables, line by
# line, so that each package keeps its line (tomllib gives none, and is 3.11+). PEP 621
# `[project] dependencies`, `[project.optional-dependencies]`, PEP 735 `[dependency-groups]`
# (arrays of PEP 508 strings); Poetry's `[tool.poetry.dependencies]`, its dev and group
# tables, and Pipfile's `[packages]`/`[dev-packages]` (`name = "spec"` or an inline table
# with `version`). What a package asks for is kept as written: a range is a request.
_TOML_TABLE = re.compile(r"^\s*\[\[?\s*([^\]]+?)\s*\]\]?\s*(?:#.*)?$")
_TOML_ARRAY_KEY = re.compile(r"^\s*([A-Za-z0-9_.\"'-]+)\s*=\s*\[")
_TOML_KEY_VALUE = re.compile(r"""^\s*["']?([A-Za-z0-9][A-Za-z0-9._-]*)["']?\s*=\s*(.+?)\s*$""")
_TOML_STRING = re.compile(r'"((?:[^"\\]|\\.)*)"|\'([^\']*)\'')
_PEP508 = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*([^;]*)")
_INLINE_VERSION = re.compile(r"""\bversion\s*=\s*["']([^"']*)["']""")
_KEY_VALUE_TABLES = re.compile(
    r"^(?:tool\.poetry\.(?:dev-)?dependencies|tool\.poetry\.group\.[^.]+\.dependencies|"
    r"packages|dev-packages)$")


def _without_comment(text: str) -> str:
    strings = [m.span() for m in _TOML_STRING.finditer(text)]
    for i, char in enumerate(text):
        if char == "#" and not any(s <= i < e for s, e in strings):
            return text[:i]
    return text


def _requested(spec: str) -> str | None:
    spec = spec.strip()
    return None if spec in {"", "*"} else spec


def _pep_requests(name: str, lines: list[str]) -> list[tuple[str, int, str | None]]:
    """(package, line, what it asks for) from a pyproject.toml or a Pipfile."""
    out: list[tuple[str, int, str | None]] = []
    table, in_array = "", False
    for number, text in enumerate(lines, 1):
        stripped = text.strip()
        if not stripped or stripped.startswith("#"):
            continue
        header = _TOML_TABLE.match(text) if not in_array else None
        if header:
            table = header.group(1).strip()
            continue
        if not in_array and name == "pyproject.toml":
            key = _TOML_ARRAY_KEY.match(text)
            if key and ((table == "project" and key.group(1) == "dependencies")
                        or table in {"project.optional-dependencies", "dependency-groups"}):
                in_array = True
                text = text[key.end():]
        if in_array:
            code = _without_comment(text)
            for match in _TOML_STRING.finditer(code):
                requirement = _PEP508.match(match.group(1) or match.group(2) or "")
                if requirement:
                    out.append((requirement.group(1), number, _requested(requirement.group(2))))
            if "]" in _TOML_STRING.sub("", code):
                in_array = False
            continue
        if _KEY_VALUE_TABLES.match(table):
            pair = _TOML_KEY_VALUE.match(text)
            if not pair or pair.group(1) in {"python", "python_version", "python_full_version"}:
                continue
            value = pair.group(2)
            if value.startswith("{"):
                version = _INLINE_VERSION.search(value)
                out.append((pair.group(1), number, _requested(version.group(1)) if version else None))
            else:
                string = _TOML_STRING.match(value)
                out.append((pair.group(1), number,
                            _requested((string.group(1) or string.group(2) or "")) if string else None))
    return out


# A version pinned to one release, which is the only version a manifest states as a
# fact: `cryptography==44.0.0` in requirements.txt, `github.com/x/y v1.2.3` in go.mod.
# A range (`>=42`) is a request, not a version, and yields nothing. pyproject.toml,
# Pipfile and the lockfiles are not read for this.
_PY_PIN = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*"
    r"([A-Za-z0-9][A-Za-z0-9.+!_-]*)\s*(?:[;#]|$)")
_GO_PIN = re.compile(r"^\s*(?:require\s+)?([a-z0-9][\w./-]*\.[a-z]{2,}/[\w./-]+)\s+(v[\w.+-]+)")


def pinned_versions(path: Path, lines: list[str]) -> list[tuple[str, str, str, int]]:
    """(ecosystem, package, version, line) for each package pinned to one version."""
    if path.name == "requirements.txt":
        ecosystem, pattern = "pypi", _PY_PIN
    elif path.name == "go.mod":
        ecosystem, pattern = "go", _GO_PIN
    else:
        return []
    out = []
    for number, text in enumerate(lines, 1):
        if text.strip().startswith(("#", "//", "-")):
            continue
        match = pattern.match(text)
        if match:
            out.append((ecosystem, match.group(1), match.group(2), number))
    return out


def is_manifest(path: Path) -> bool:
    return (path.name in MANIFEST_FILENAMES
            or path.name in _NUGET_FILENAMES
            or path.suffix in _NUGET_SUFFIXES)


def _ecosystem_of(path: Path) -> str | None:
    if path.name in _NUGET_FILENAMES or path.suffix in _NUGET_SUFFIXES:
        return "nuget"
    return MANIFEST_FILENAMES.get(path.name)


def scan_manifest(path: Path, rel_path: str, lines: list[str]) -> list[dict[str, Any]]:
    """Dependencies that carry classical cryptography, as declared assets."""
    ecosystem = _ecosystem_of(path)
    if ecosystem is None:
        return []
    table = DEPENDENCY_FAMILIES.get(ecosystem, {})
    findings: list[dict[str, Any]] = []
    if path.name in {"pyproject.toml", "Pipfile"}:
        named = _pep_requests(path.name, lines)
    else:
        named = [(package, number, None) for package, number
                 in _names_from_manifest(ecosystem, path.name, lines)]
    for package, number, requested in named:
        families = table.get(package)
        if families is None and ecosystem == "pypi":
            families = table.get(package.lower())
        if not families:
            continue
        item = {
            "path": rel_path,
            "line": number,
            "package": package,
            "ecosystem": ecosystem,
            "families": list(families),
            # The distinction the whole bucket exists for.
            "basis": "declared_dependency",
            "description": (f"{package} is declared in {path.name}; it implements "
                            f"{', '.join(families)}. Declared, not observed: nothing "
                            f"here says a line of code calls it."),
        }
        # What the manifest asks for, as written: `>=47.0.0` is a request, not a version.
        if requested:
            item["requested"] = requested
        findings.append(item)
    return findings


# --- secrets encrypted at rest (ZA-OPRAVYANE row 146) -----------------------
#
# A sops/age/OpenPGP file in the tree is ciphertext whose key was agreed with a recipient's
# public key; whoever copies it today opens it once that key falls (harvest now, decrypt
# later). An age recipient (`age1` + 58 bech32 characters, age-encryption.org/v1) is an
# X25519 key. An OpenPGP recipient's family is not in a fingerprint, so none is named. The
# fingerprint lines are read only in a file that is sops's own (`.sops.yaml`, or one with
# its `sops:` metadata), where `pgp:` and `fp:` mean exactly that.
_AGE_RECIPIENT = re.compile(r"(?<![A-Za-z0-9])age1[02-9ac-hj-np-z]{58}(?![A-Za-z0-9])")
_AT_REST_ARMOUR = re.compile(r"-----BEGIN (AGE ENCRYPTED FILE|PGP MESSAGE)-----")
_SOPS_PGP = re.compile(r"^\s*-?\s*(?:fp|pgp)\s*:\s*[\"']?[0-9A-Fa-f]{40}(?![0-9A-Fa-f])")
_SOPS_METADATA = re.compile(r"^sops:\s*$")
_HNDL_NOTE = ("encrypted at rest: a copy taken today opens once the recipient's key is broken "
              "(harvest now, decrypt later)")


def scan_encrypted_at_rest(rel_path: str, lines: list[str]) -> tuple[list[dict[str, Any]],
                                                                      list[dict[str, Any]]]:
    """(X25519 findings for age recipients, protocol assets for what is encrypted at rest)."""
    findings: list[dict[str, Any]] = []
    assets: list[dict[str, Any]] = []
    sops = (posixpath.basename(rel_path) == ".sops.yaml"
            or any(_SOPS_METADATA.match(text) for text in lines))
    for number, text in enumerate(lines, 1):
        excerpt = text.strip()[:200]
        if "age1" in text and _AGE_RECIPIENT.search(text):
            findings.append({
                "path": rel_path, "line": number, "algorithm": "X25519",
                "description": f"X25519 named by an age recipient; {_HNDL_NOTE}",
                "excerpt": excerpt, "evidence_kind": "declaration", "hndl": True,
            })
            assets.append(_at_rest("age", rel_path, number, excerpt, "X25519"))
        armour = _AT_REST_ARMOUR.search(text) if "-----BEGIN" in text else None
        if armour:
            assets.append(_at_rest("age" if armour.group(1).startswith("AGE") else "openpgp",
                                   rel_path, number, excerpt, None))
        elif sops and _SOPS_PGP.match(text):
            assets.append(_at_rest("openpgp", rel_path, number, excerpt, None))
    return findings, assets


def _at_rest(protocol: str, path: str, line: int, excerpt: str,
             family: str | None) -> dict[str, Any]:
    asset = {
        "protocol": protocol, "banned": False, "basis": "encrypted_at_rest",
        "deprecated": False, "hndl": True, "path": path, "line": line, "excerpt": excerpt,
        "description": (f"A secret {_HNDL_NOTE}. " + (
            f"The recipient key is {family}." if family else
            "The recipient's key family is not in the tree: an OpenPGP fingerprint does "
            "not state it." if protocol == "openpgp" else
            "The armour does not state the recipient's key family.")),
    }
    if family:
        asset["recipient_family"] = family
    return asset


# --- protocols --------------------------------------------------------------

# The spellings a version pin actually takes, across the languages that pin one.
_TLS_VERSION = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"TLSv1(?:[._](\d))?|"                       # TLSv1.2, TLSv1_2, TLSv1
    r"SSLv(2|3)|"                                # SSLv3
    r"tls\.VersionTLS(1[0-3])|"                  # Go
    r"SslProtocols\.Tls(1[123])?|"               # .NET
    r"PROTOCOL_TLSv1(?:_(\d))?|"                 # Python ssl
    r"TLS1_(\d)_VERSION|"                        # OpenSSL
    r"TLS_?v?1\.(\d)"                            # rustls, prose in config
    r")(?![A-Za-z0-9])")

# Where a protocol is being configured rather than mentioned. Without one of
# these on the line, "TLSv1.2" in a sentence stays a sentence.
_TLS_CONTEXT = re.compile(
    r"min_?version|max_?version|MinVersion|MaxVersion|ssl_protocols|"
    r"enabled-protocols|SSLProtocol|set_ciphers|SslProtocols|protocol_version|"
    r"PROTOCOL_TLS|SSL_CTX_set_|supported_protocols|versions\s*[:=]|"
    r"ServerOptions|SSLContext|tls\.Config|rustls|sslVersion|"
    # HAProxy: `ssl-min-ver`/`ssl-max-ver` on a bind or server line, and the global
    # defaults that carry them (Configuration Manual 3.5; ZA-OPRAVYANE row 30).
    r"ssl-(?:min|max)-ver|ssl-default-(?:bind|server)-options",
    re.IGNORECASE)

# SSH transport, configured the same way.
_SSH_PROTOCOL = re.compile(
    r"^\s*Protocol\s+(1|2|1,2|2,1)\s*$|"
    # Directives whose names are specific enough to mean SSH wherever they appear.
    r"(?<![A-Za-z])(?:HostKeyAlgorithms|KexAlgorithms|PubkeyAcceptedAlgorithms|"
    r"PubkeyAcceptedKeyTypes|HostbasedAcceptedAlgorithms)(?![A-Za-z])|"
    # Ciphers and MACs are ordinary words. Only at the start of a line, the way
    # sshd_config writes a directive, are they SSH configuration -- otherwise
    # every cryptography library in the world configures SSH.
    r"^\s*(?:Ciphers|MACs)\s+\S")

# An SSH public key line names the algorithm and the transport both: `ssh-rsa`
# in an authorized_keys is RSA, and it is RSA reached over SSH.
_SSH_KEY_LINE = re.compile(
    # authorized_keys starts with the type; known_hosts starts with the host, so
    # the type may be the second field; and source code keeps the same line inside
    # a string literal, where the opening quote sits exactly where the type must
    # be. Anchoring at the start of the line missed 8 such lines in OpenSSH and
    # Vault, and matched one only because the host field absorbed the quote.
    r"(?:^|[\s\"'`(\[{,=:])(?:ssh-(?:rsa|dss|ed25519|mldsa\w*)|ecdsa-sha2-nistp\d+|sk-\S+)"
    r"(?:-cert-v01@openssh\.com)?(?:@openssh\.com)?\s+[A-Za-z0-9+/]{20,}")

# OpenSSL's version macros are unambiguous identifiers: nothing but a protocol
# version is spelled SSL3_VERSION, so they carry their own context. The oldest
# two have no minor digit, which is why a pattern requiring one read TLS 1.1
# through 1.3 in that tree and neither of the deprecated ones.
_VERSION_MACRO = re.compile(r"(?<![A-Za-z0-9_])(SSL[23]|TLS1(?:_[0-3])?)_VERSION(?![A-Za-z0-9_])")

_DEPRECATED_TLS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}

# `SSLProtocol all` or `+all`, but not `-all`, as Apache writes the directive.
_SSL_PROTOCOL_ALL = re.compile(r"^\s*SSLProtocol\s+(?:.*\s)?\+?all(?:\s|$)",
                               re.IGNORECASE)
_ALL_VERSIONS = ("SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")


# -- OpenSSL's FIPS provider, activated in openssl.cnf -----------------------------------
#
# ZA-OPRAVYANE row 35 (Paul J. Lilly, 22.10.2026): an openssl.cnf that activates the FIPS
# provider was read and said nothing, and the ML-KEM line read "OpenSSL 3" either way --
# the difference a certificate-number check turns on. The settings are OpenSSL's own
# (config(5), fips_module(7)): `.include .../fipsmodule.cnf`, `fips = <section>` in the
# section `providers =` names, with `activate` there yes/on/true/1 or the section in the
# included file, and `default_properties = fips=yes` (or the deprecated `fips_mode = yes`).
# Activated in configuration is all a file can say. Whether the process that runs the
# code loads this file, and whether that module is CMVP-validated, it cannot.
_CNF_SECTION = re.compile(r"^\s*\[\s*([^\]\s]+)\s*\]")
_CNF_SETTING = re.compile(r"^\s*([A-Za-z0-9_.]+)\s*=\s*\"?([^\"#]*?)\"?\s*(?:#.*)?$")
_CNF_INCLUDE_FIPS = re.compile(r"^\s*\.include\s*=?\s*\S*fipsmodule\.cnf\b")
_FIPS_YES = re.compile(r"(?:^|,)\s*fips\s*=\s*yes\b", re.IGNORECASE)
_ON = {"yes", "on", "true", "1"}


def scan_openssl_fips(rel_path: str, lines: list[str]) -> list[dict[str, Any]]:
    """Lines of an OpenSSL configuration that bring the FIPS provider in."""
    sections: dict[str, list[tuple[int, str, str]]] = {}
    current = ""
    for number, text in enumerate(lines, 1):
        head = _CNF_SECTION.match(text)
        if head:
            current = head.group(1)
            continue
        setting = _CNF_SETTING.match(text)
        if setting:
            sections.setdefault(current, []).append(
                (number, setting.group(1), setting.group(2).strip()))
    includes = [n for n, text in enumerate(lines, 1) if _CNF_INCLUDE_FIPS.match(text)]
    provider_sections = {value for entries in sections.values()
                         for _, name, value in entries if name == "providers"}
    out: list[dict[str, Any]] = []

    def add(number: int, activation: str, said: str) -> None:
        out.append({"path": rel_path, "line": number, "activation": activation,
                    "excerpt": lines[number - 1].strip()[:200],
                    "basis": "configured_provider",
                    "description": said + " Activated in configuration, not validated: "
                                          "whether the process that runs the code loads "
                                          "this file is not in the files, and CMVP status "
                                          "is checked against the CMVP list."})

    for number in includes:
        add(number, "includes_fips_module_config",
            f"FIPS module configuration included in {rel_path}:{number}.")
    for section in sorted(provider_sections):
        for number, name, value in sections.get(section, []):
            if name != "fips":
                continue
            activate = [v.lower() for _, n, v in sections.get(value, []) if n == "activate"]
            if activate and activate[-1] not in _ON:
                continue
            if not activate and not includes:
                continue
            add(number, "loads_fips_provider",
                f"FIPS provider activated in {rel_path}:{number} ({name} = {value}).")
    for entries in sections.values():
        for number, name, value in entries:
            if ((name == "default_properties" and _FIPS_YES.search(value))
                    or (name == "fips_mode" and value.lower() == "yes")):
                add(number, "fips_default_property",
                    f"FIPS provider activated in {rel_path}:{number} ({name} = {value}): "
                    f"algorithm fetches default to the FIPS provider.")
    return sorted(out, key=lambda item: item["line"])


# -- An HAProxy listener that terminates TLS, and peer verification switched off ----------
#
# `bind :8443 ssl crt edge.pem` terminates TLS and was not a TLS place: with no
# ssl-min-ver and no cipher list in the file, the scan said nothing, while on the wire
# that listener took TLS 1.2 with 13 suites, 6 of them static RSA (ZA-OPRAVYANE row 42,
# the network-vs-code probe of 22.10.2026). A setting that is absent is still a fact
# about the file: the defaults apply. What they are depends on the HAProxy and the TLS
# library that run, which the file does not say, so it is not said here either -- except
# what HAProxy's own manual documents (3.2: "ssl-min-ver ... The default value is
# TLSv1.2"), named as that.
#
# And `server app1 app:443 ssl verify none` turns off the check of the backend's
# certificate (HAProxy 3.2 manual, `verify`: "If set to 'none', server certificate is not
# verified"; `ssl-server-verify none` does it for every server). nginx's
# `proxy_ssl_verify off` does the same, and is also nginx's default (ngx_http_proxy_module:
# "Default: proxy_ssl_verify off"), which a file without the line does not show and this
# scan does not infer. The hop behind a proxy is the one thing the wire outside cannot
# see (ZA-OPRAVYANE row 44). `verify` on a `bind` line is the client-certificate check,
# not this, and is left alone.
_HAPROXY_BIND = re.compile(r"^\s*bind\s")
_HAPROXY_SERVER = re.compile(r"^\s*(?:server|default-server)\s")
_HAPROXY_VERSION_OPTION = re.compile(
    r"(?<!\S)(?:ssl-min-ver|ssl-max-ver|force-(?:sslv3|tlsv1\d?)|no-(?:sslv3|tlsv1\d?))(?!\S)",
    re.IGNORECASE)
_NGINX_VERIFY_OFF = re.compile(r"^\s*proxy_ssl_verify\s+off\s*;")
_HAPROXY_GLOBAL_VERIFY_NONE = re.compile(r"^\s*ssl-server-verify\s+none(?:\s|$)")


def _tokens(line: str) -> list[str]:
    return line.split("#", 1)[0].split()


def scan_tls_listeners(rel_path: str, lines: list[str]) -> list[dict[str, Any]]:
    """HAProxy listeners that terminate TLS, with the settings left to the defaults, and
    backend connections whose certificate is not verified (HAProxy, nginx)."""
    defaults = {"versions": False, "ciphers": False, "ciphersuites": False, "curves": False}
    for text in lines:
        words = _tokens(text)
        if not words:
            continue
        if words[0] == "ssl-default-bind-options" and _HAPROXY_VERSION_OPTION.search(text):
            defaults["versions"] = True
        for key in ("ciphers", "ciphersuites", "curves"):
            if words[0] == f"ssl-default-bind-{key}":
                defaults[key] = True
    out: list[dict[str, Any]] = []
    said = {"versions": "protocol versions", "ciphers": "TLS 1.2 cipher list",
            "ciphersuites": "TLS 1.3 cipher suites", "curves": "groups"}
    for number, text in enumerate(lines, 1):
        words = _tokens(text)
        if _HAPROXY_BIND.match(text) and "ssl" in words:
            here = {"versions": bool(_HAPROXY_VERSION_OPTION.search(" ".join(words))),
                    "ciphers": "ciphers" in words, "ciphersuites": "ciphersuites" in words,
                    "curves": "curves" in words}
            absent = [said[k] for k in said if not (here[k] or defaults[k])]
            description = "TLS is terminated here (HAProxy `bind ... ssl`)."
            if absent:
                description += (
                    f" Not set for this listener, on its line or in this file's "
                    f"ssl-default-bind-*: {', '.join(absent)}. There HAProxy's and the TLS "
                    f"library's defaults apply, and which they are depends on the versions "
                    f"that run, which the file does not say.")
                if "protocol versions" in absent:
                    description += (" HAProxy 3.2's manual gives TLSv1.2 as the "
                                    "ssl-min-ver default.")
            out.append({"path": rel_path, "line": number, "protocol": "tls", "version": None,
                        "basis": "configured_listener", "listener": "HAProxy bind",
                        "library_defaults": absent, "deprecated": False,
                        "excerpt": text.strip()[:200], "description": description})
        verify_off = None
        if _HAPROXY_SERVER.match(text) and "ssl" in words:
            at = [i for i, w in enumerate(words) if w == "verify"]
            if at and at[-1] + 1 < len(words) and words[at[-1] + 1] == "none":
                verify_off = ("verify none", f"HAProxy, on a {words[0]} line")
        elif _HAPROXY_GLOBAL_VERIFY_NONE.match(text):
            verify_off = ("ssl-server-verify none",
                          "HAProxy, for every server line that does not say verify required")
        elif _NGINX_VERIFY_OFF.match(text):
            verify_off = ("proxy_ssl_verify off", "nginx; off is also nginx's default")
        if verify_off:
            setting, where = verify_off
            out.append({
                "path": rel_path, "line": number, "protocol": "tls", "version": None,
                "basis": "configured_verification", "peer_verification": "off",
                "verification_setting": setting, "deprecated": False,
                "excerpt": text.strip()[:200],
                "description": (f"The backend's certificate is not verified ({setting}; "
                                f"{where}): this TLS hop is encrypted but not "
                                f"authenticated, so whoever sits on the path can stand in "
                                f"for the server. It is not visible from outside."),
            })
    return out


def _tls_version_name(match: re.Match) -> str:
    minor = next((g for g in match.groups() if g), None)
    text = match.group(0)
    if text.upper().startswith("SSLV"):
        return f"SSLv{minor}"
    if minor is None:
        return "TLSv1.0"
    if len(minor) == 2:            # VersionTLS12, TLS1_2_VERSION spelled 12/13
        return f"TLSv1.{minor[1]}"
    return f"TLSv1.{minor}"


# FreeRADIUS writes the version bare: `tls_min_version = "1.0"` in raddb/mods-available/eap
# ("Allowed values are "1.0", "1.1", "1.2", and "1.3"", v3.2.x, read 23.10.2026). The
# spellings above need `TLSv1`/`TLS1.x`, so the EAP-TLS minimum gave nothing
# (ZA-OPRAVYANE row 103).
_BARE_TLS_VERSION_SETTING = re.compile(
    r"^\s*tls_(?:min|max)_version\s*=\s*[\"']?1\.([0-3])[\"']?\s*(?:#.*)?$")


def names_none_of(line: str, words: tuple[str, ...]) -> bool:
    """True when the line holds none of the words in any case, so a rule every match of
    which contains one of them cannot match it. Asked before the rule's regex, which costs
    more (release D). A line that is not ASCII is never ruled out here: case-folding beyond
    ASCII is the regex's to decide."""
    if not line.isascii():
        return False
    low = line.lower()
    return not any(word in low for word in words)


# Every match of a rule in scan_protocols contains one of these: _BARE_TLS_VERSION_SETTING
# and _VERSION_MACRO `_version`; the _TLS_CONTEXT branch reports only through _TLS_VERSION
# (each alternative has `tls` or `sslv`) or _SSL_PROTOCOL_ALL (`protocol`); _SSH_KEY_LINE
# `ssh-`, `ecdsa-sha2-` or `sk-`; _SSH_PROTOCOL `protocol`, `algorithms`, `pubkeyaccepted`,
# `ciphers` or `macs`.
_PROTOCOL_WORDS = ("_version", "tls", "sslv", "protocol", "ssh-", "ecdsa-sha2-", "sk-",
                   "algorithms", "pubkeyaccepted", "ciphers", "macs")


def scan_protocols(line: str) -> list[dict[str, Any]]:
    """Protocol versions pinned on this line, as assets with no algorithm claim."""
    if names_none_of(line, _PROTOCOL_WORDS):
        return []
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, bool]] = set()
    bare = _BARE_TLS_VERSION_SETTING.match(line)
    if bare:
        name = f"TLSv1.{bare.group(1)}"
        seen.add((name, False))
        out.append({
            "protocol": "tls",
            "version": name,
            "banned": False,
            "basis": "configured_protocol",
            "deprecated": name in _DEPRECATED_TLS,
            "description": (f"{name} is configured here. Which algorithms it negotiates "
                            f"is not stated by the version."),
        })
    for macro in _VERSION_MACRO.finditer(line):
        raw = macro.group(1)
        name = (f"SSLv{raw[3]}" if raw.startswith("SSL")
                else f"TLSv1.{raw[5]}" if len(raw) > 4 else "TLSv1.0")
        seen.add((name, False))
        out.append({
            "protocol": "tls",
            "version": name,
            "banned": False,
            "basis": "configured_protocol",
            "deprecated": name in _DEPRECATED_TLS,
            "description": (f"{name} is named here. Which algorithms it negotiates "
                            f"is not stated by the version."),
        })
    if _TLS_CONTEXT.search(line):
        for match in _TLS_VERSION.finditer(line):
            name = _tls_version_name(match)
            # `SSLProtocol all -SSLv2 -SSLv3` forbids SSL 2 and SSL 3. A ban is
            # not a use -- the same rule this scanner applies to `!MD5` in a
            # cipher list, and certbot carries 27 lines that depend on it.
            banned = match.start() > 0 and line[match.start() - 1] in "-!"
            key = (name, banned)
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "protocol": "tls",
                "version": name,
                "banned": banned,
                "basis": "configured_protocol",
                # Deprecation is a fact about the version. Quantum vulnerability
                # is a fact about the key exchange, which a version does not fix:
                # TLS 1.3 over X25519MLKEM768 is not vulnerable and over X25519 is.
                "deprecated": name in _DEPRECATED_TLS,
                "description": (f"{name} is forbidden here." if banned else
                                f"{name} is configured here. Which algorithms it "
                                f"negotiates is not stated by the version."),
            })
        # Apache's `SSLProtocol all` names no version and enables them all: mod_ssl's
        # manual (2.4, read 22.10.2026) says `all` is "+SSLv3 +TLSv1 +TLSv1.1 +TLSv1.2
        # +TLSv1.3" with OpenSSL 1.0.1 and later, without SSLv3 where OpenSSL was built
        # with no-ssl3. So `SSLProtocol all -SSLv3` enables TLS 1.0 and 1.1, and was
        # reported only as "SSLv3 is forbidden here" (ZA-OPRAVYANE row 43).
        enabled = _SSL_PROTOCOL_ALL.match(line)
        if enabled:
            removed = {name for name, banned in seen if banned}
            for name in _ALL_VERSIONS:
                if name in removed or (name, False) in seen:
                    continue
                seen.add((name, False))
                out.append({
                    "protocol": "tls",
                    "version": name,
                    "banned": False,
                    "basis": "configured_protocol",
                    "included_by": "all",
                    "deprecated": name in _DEPRECATED_TLS,
                    "description": (
                        f"{name} is enabled by `all` on this line (mod_ssl: all is +SSLv3 "
                        f"+TLSv1 +TLSv1.1 +TLSv1.2 +TLSv1.3 with OpenSSL 1.0.1 and later; "
                        f"TLSv1.3 needs OpenSSL 1.1.1, and SSLv3 is absent from an OpenSSL "
                        f"built with no-ssl3). Whether the TLS library still allows it at "
                        f"run time is not stated by this line."),
                })
    if _SSH_KEY_LINE.search(line):
        out.append({
            "protocol": "ssh",
            "version": None,
            "basis": "configured_protocol",
            "deprecated": False,
            "description": ("an SSH public key entry: the algorithm is named on the "
                            "line, and SSH is how it is reached."),
        })
        return out
    match = _SSH_PROTOCOL.search(line)
    if match:
        version = match.group(1)
        out.append({
            "protocol": "ssh",
            "version": f"SSHv{version}" if version else None,
            "basis": "configured_protocol",
            "deprecated": version in {"1", "1,2", "2,1"},
            "description": ("SSH transport is configured here"
                            + (f" with protocol {version}" if version else "")
                            + "; the algorithms it offers are the lines it names."),
        })
    return out


# -- Where TLS terminates is not in the files ------------------------------------------
#
# A line that configures TLS is what this server asks for, not what a connection got.
# The group is settled where TLS terminates -- here, or at a proxy, load balancer or CDN
# in front -- together with the client. A CDN that upgrades origins on its own makes a
# domain show X25519MLKEM768 that nobody in the organisation configured; a classical
# terminator in front of a post-quantum origin does the reverse. This scanner reads
# files, so on the first case it reports the origin as classical: right about the file,
# silent about the wire. Raised in public on 2026-10-01 (G. Ivanov) and promised there.
#
# Said only where TLS configuration was read. Said everywhere, it is boilerplate.

# A setting that chooses TLS key-exchange groups. Matched only on a line where an
# algorithm was already found, so `groups = admin` in an .ini configures nothing.
_TLS_GROUP_SETTING = re.compile(
    r"ssl_ecdh_curve|set_ecdh_curve|ecdhCurve|ecdh_curves|"
    r"(?:ssl_conf_command|SSLOpenSSLConfCmd)\s+(?:groups|curves)|"
    r"^\s*(?:groups|curves)\s*=|CurvePreferences|namedGroups|"
    r"set1_(?:groups|curves)|supported_groups|"
    # HAProxy's global defaults (Configuration Manual 3.5; ZA-OPRAVYANE row 30). Its
    # `curves` keyword on a bind or server line is matched below, by the line's shape.
    r"ssl-default-(?:bind|server)-curves",
    re.IGNORECASE)

# `curves X25519:P-256` as a keyword of an HAProxy `bind` or `server` line. The word on
# its own is prose; only on such a line is it a setting. Not `ecdhe <curve>`: ECDHE is
# in nearly every cipher suite, and every cipher line would become a group setting.
_HAPROXY_LINE = re.compile(r"^\s*(?:bind|server|default-server)\s")
_HAPROXY_CURVES = re.compile(r"(?<=\s)curves(?=\s)")


def _group_setting(line: str) -> re.Match | None:
    """The group setting on this line, if it has one."""
    # Every alternative of the two regexes contains one of these words (release D).
    if names_none_of(line, ("ecdh_curve", "ecdhcurve", "groups", "curves", "curvepreferences")):
        return None
    setting = _TLS_GROUP_SETTING.search(line)
    if setting is None and _HAPROXY_LINE.match(line):
        setting = _HAPROXY_CURVES.search(line)
    return setting

_COMMENT_START = ("#", ";", "//", "--", "/*", "*")

# A setting that chooses TLS cipher suites. A suite is negotiated where TLS terminates,
# like a group, so the line is a TLS place (ZA-OPRAVYANE row 31, 22.10.2026: 0.31.0
# said "beside every TLS setting" and left these out). The setting, not the suite: an
# OpenSSL header defines every suite as a C constant, and those configure nothing.
# nginx (`*ssl_ciphers`), Apache (`SSL[Proxy]CipherSuite`), HAProxy (global defaults,
# and `ciphers`/`ciphersuites` on a bind or server line, below), OpenSSL's SSL_CONF
# (`CipherString`, `Ciphersuites`), the OpenSSL and Python calls, Envoy, Go and Java.
_TLS_CIPHER_SETTING = re.compile(
    r"ssl_ciphers\b|SSL(?:Proxy)?CipherSuite\b|ssl-default-(?:bind|server)-ciphers(?:uites)?\b|"
    r"(?:ssl_conf_command|SSLOpenSSLConfCmd)\s+(?:CipherString|Ciphersuites)\b|"
    r"^\s*(?:CipherString|Ciphersuites)\s*=|"
    r"\bset_cipher_list\b|\bset_ciphersuites\b|\bset_ciphers\b|"
    r"\bcipher_suites\s*[:=]|\bCipherSuites\s*[:=]|\bsetEnabledCipherSuites\b",
    re.IGNORECASE)
_HAPROXY_CIPHERS = re.compile(r"(?<=\s)ciphers(?:uites)?(?=\s)")


def _cipher_setting(line: str) -> bool:
    """Whether this line sets TLS cipher suites."""
    # Every alternative of both regexes contains `cipher` (release D).
    if names_none_of(line, ("cipher",)):
        return False
    return bool(_TLS_CIPHER_SETTING.search(line)
                or (_HAPROXY_LINE.match(line) and _HAPROXY_CIPHERS.search(line)))


# -- RSA key exchange in a cipher-suite setting ------------------------------------------
#
# OpenSSL names a suite with RSA key exchange by its cipher alone: AES256-SHA is
# TLS_RSA_WITH_AES_256_CBC_SHA, and no word in the name says RSA. So `SSLCipherSuite
# HIGH:!aNULL:AES256-SHA:DES-CBC3-SHA` gave 3DES and nothing else, and an nginx line with
# ECDHE-RSA-... gave RSA from the authentication half only (ZA-OPRAVYANE row 43, the
# network-vs-code probe of 22.10.2026). The session key of such a suite travels encrypted
# to the server's RSA key: no forward secrecy, and a recorded session opens to whoever
# later has that key -- a quantum computer that can factor it included.
#
# The names are every TLS_RSA_WITH_* suite in openssl-ciphers(1) (OpenSSL 3.5, section
# "CIPHER SUITE NAMES", read 22.10.2026), with OpenSSL's `kRSA` keyword ("cipher suites
# using RSA key exchange") and the IANA spelling. Case matters: OpenSSL writes them in
# capitals, and `aes128-sha256-modp2048` is a strongSwan proposal, not a TLS suite.
# Matched only on a cipher-suite setting: OpenSSL's headers define every name as a
# C constant, and those configure nothing. `RSA` and `aRSA` are left alone: they select
# by authentication too.
STATIC_RSA_SUITES = (
    "AES128-CCM", "AES128-CCM8", "AES128-GCM-SHA256", "AES128-SHA", "AES128-SHA256",
    "AES256-CCM", "AES256-CCM8", "AES256-GCM-SHA384", "AES256-SHA", "AES256-SHA256",
    "ARIA128-CBC-SHA256", "ARIA128-GCM-SHA256", "ARIA256-CBC-SHA384", "ARIA256-GCM-SHA384",
    "CAMELLIA128-GCM-SHA256", "CAMELLIA128-SHA", "CAMELLIA128-SHA256",
    "CAMELLIA256-GCM-SHA384", "CAMELLIA256-SHA", "CAMELLIA256-SHA256",
    "DES-CBC3-SHA", "IDEA-CBC-SHA", "NULL-MD5", "NULL-SHA", "NULL-SHA256",
    "RC4-MD5", "RC4-SHA", "SEED-SHA", "SM4-CCM-SM3", "SM4-GCM-SM3",
    # The single-DES and export suites, removed from openssl-ciphers(1) but still named in
    # include/openssl/{ssl3,tls1}.h (OpenSSL 3.6.5), ZA-OPRAVYANE row 136.
    "DES-CBC-SHA", "EXP-DES-CBC-SHA", "EXP-RC2-CBC-MD5", "EXP-RC4-MD5",
)
_STATIC_RSA = re.compile(
    r"(?<![A-Za-z0-9_-])("
    + "|".join(re.escape(s) for s in sorted(STATIC_RSA_SUITES, key=len, reverse=True))
    + r"|kRSA|TLS_RSA_WITH_[A-Z0-9_]+)(?![A-Za-z0-9_-])")


def _cipher_setting_name(line: str) -> str:
    setting = _TLS_CIPHER_SETTING.search(line) or _HAPROXY_CIPHERS.search(line)
    return " ".join(setting.group(0).replace("=", " ").split()) if setting else ""


def static_rsa_positions(line: str) -> list[tuple[str, int]]:
    """(suite, position) for each RSA-key-exchange suite this cipher-suite setting
    enables. A suite struck out with `!` or `-` is not enabled."""
    if line.lstrip().startswith(_COMMENT_START) or not _cipher_setting(line):
        return []
    return [(m.group(1), m.start()) for m in _STATIC_RSA.finditer(line)
            if not (m.start() > 0 and line[m.start() - 1] in "!-")]


def scan_static_rsa_kex(line: str) -> list[dict[str, Any]]:
    """RSA key exchange enabled by this cipher-suite setting, as one finding per line."""
    suites: list[str] = []
    for suite, _ in static_rsa_positions(line):
        if suite not in suites:
            suites.append(suite)
    if not suites:
        return []
    return [{
        "family": "RSA",
        "key_exchange": "RSA",
        "suites": suites,
        "setting": _cipher_setting_name(line),
        "basis": "configured_cipher_suite",
        "description": (f"{', '.join(suites)}: RSA key exchange (static RSA). The session "
                        f"key is sent encrypted to the server's RSA key, so there is no "
                        f"forward secrecy and a recorded session opens to whoever later "
                        f"recovers that key, by a quantum computer included. Which suite "
                        f"a connection uses is chosen with the client and is not stated "
                        f"by this line."),
    }]

# -- A classical group offered on its own ------------------------------------------------
#
# `ssl_ecdh_curve X25519MLKEM768:X25519` and `ssl_ecdh_curve X25519MLKEM768` scanned the
# same: the X25519 inside the hybrid's name is the same family as X25519 offered alone,
# so removing the classical fallback -- the step that ends a hybrid migration -- was
# invisible, and `closure` called it "3 closed, 3 new" on one line. Raised in public on
# 2026-10-03 (Addie LaMarr). So a classical group named as a group of its own in a group
# setting is a finding of its own, and it carries no excerpt: its identity is the file,
# the setting and the group, so editing the line around it neither closes nor reopens it.
#
# Said about the file only. Whether a connection ever uses the fallback is settled where
# TLS terminates; TLS_TERMINATION below still says so.

# Group names as configuration spells them, lower-cased with '-' and '_' removed, to the
# family the classifier already uses. A hybrid's name (X25519MLKEM768, SecP256r1MLKEM768)
# is one token and is not in this table, which is the whole point. A name not here
# (`auto`, `admin`) yields nothing.
CLASSICAL_GROUPS = {
    "x25519": "X25519", "x448": "X448",
    "p256": "ECDH", "p384": "ECDH", "p521": "ECDH",
    "curvep256": "ECDH", "curvep384": "ECDH", "curvep521": "ECDH",      # Go
    "secp256r1": "ECDH", "secp384r1": "ECDH", "secp521r1": "ECDH",
    "prime256v1": "ECDH",
    "brainpoolp256r1": "ECDH", "brainpoolp384r1": "ECDH", "brainpoolp512r1": "ECDH",
    "brainpoolp256r1tls13": "ECDH", "brainpoolp384r1tls13": "ECDH",
    "brainpoolp512r1tls13": "ECDH",
    "ffdhe2048": "DH", "ffdhe3072": "DH", "ffdhe4096": "DH", "ffdhe6144": "DH",
    "ffdhe8192": "DH",
}
# The rest of IANA's TLS Supported Groups an OpenSSL `Groups =` accepts: the deprecated
# binary and small prime curves, secp256k1, the GOST curves (RFC 9189) and SM2 (RFC 8998),
# ZA-OPRAVYANE row 141.
CLASSICAL_GROUPS.update({
    **{f"sect{n}": "ECDH" for n in ("163k1", "163r1", "163r2", "193r1", "193r2", "233k1",
                                     "233r1", "239k1", "283k1", "283r1", "409k1", "409r1",
                                     "571k1", "571r1")},
    **{f"secp{n}": "ECDH" for n in ("160k1", "160r1", "160r2", "192k1", "192r1", "224k1",
                                     "224r1", "256k1")},
    **{f"gc{n}": "GOST R 34.10" for n in ("256a", "256b", "256c", "256d", "512a", "512b", "512c")},
    "curvesm2": "SM2",
})

_GROUP_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9_-]*")


def scan_tls_groups(line: str) -> list[dict[str, Any]]:
    """Classical groups this line offers as groups of their own in a TLS group setting."""
    if line.lstrip().startswith(_COMMENT_START):
        return []
    setting = _group_setting(line)
    if not setting:
        return []
    name = " ".join(setting.group(0).replace("=", " ").split())
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for token in _GROUP_TOKEN.finditer(line, setting.end()):
        # OpenSSL 3.5 removes a group with a leading '-'; a removal is not an offer.
        if token.start() > 0 and line[token.start() - 1] in "-!":
            continue
        group = token.group(0)
        key = group.lower().replace("-", "").replace("_", "")
        family = CLASSICAL_GROUPS.get(key)
        if family is None or key in seen:
            continue
        seen.add(key)
        out.append({
            "group": group,
            "family": family,
            "setting": name,
            "offered": "alone",
            "basis": "configured_group",
            "description": (f"{group} is offered here as a group of its own, without a "
                            f"post-quantum half. What a connection negotiates is not "
                            f"stated by this line."),
        })
    return out


# -- A classical SSH key exchange offered on its own -------------------------------------
#
# The same defect as above, in OpenSSH (ZA-OPRAVYANE row 22, 2026-10-21): `KexAlgorithms
# mlkem768x25519-sha256,curve25519-sha256` and `KexAlgorithms mlkem768x25519-sha256`
# scanned the same, so removing the classical fallback from sshd closed nothing. Kept
# apart from the TLS groups: an sshd_config is not a TLS configuration, and the TLS
# statement below must not be said about it.
#
# The names and their families are OpenSSH's own: every algorithm sshd_config(5) lists
# under KexAlgorithms that kex-names.c marks KEX_NOT_PQ (OpenSSH at 7fe3b24, 2026-09-04).
# The hybrids (mlkem768x25519-sha256, mlkem768nistp256-sha256, sntrup761x25519-sha512)
# are not in this table, which is the whole point.
CLASSICAL_SSH_KEX = {
    "curve25519-sha256": "X25519", "curve25519-sha256@libssh.org": "X25519",
    "ecdh-sha2-nistp256": "ECDH", "ecdh-sha2-nistp384": "ECDH", "ecdh-sha2-nistp521": "ECDH",
    "diffie-hellman-group1-sha1": "DH", "diffie-hellman-group14-sha1": "DH",
    "diffie-hellman-group14-sha256": "DH", "diffie-hellman-group16-sha512": "DH",
    "diffie-hellman-group18-sha512": "DH", "diffie-hellman-group-exchange-sha1": "DH",
    "diffie-hellman-group-exchange-sha256": "DH",
}

# The keyword, then the value: `KexAlgorithms list`, `KexAlgorithms=list` (ssh_config and
# `ssh -o`). The keyword is case-insensitive in both config files.
_SSH_KEX_SETTING = re.compile(r"\bKexAlgorithms\b\s*(?:=\s*|\s+)([^\s\"']+)", re.IGNORECASE)


def scan_ssh_kex(line: str) -> list[dict[str, Any]]:
    """Classical key exchange algorithms this line offers in an SSH KexAlgorithms list."""
    if line.lstrip().startswith(_COMMENT_START) or names_none_of(line, ("kexalgorithms",)):
        return []
    setting = _SSH_KEX_SETTING.search(line)
    if not setting:
        return []
    value = setting.group(1)
    # sshd_config(5): a list beginning with '-' removes what it names from the default;
    # '+' appends to the default and '^' places it at the head -- both still offer it.
    # The prefix applies to the whole list, not to one name.
    if value.startswith("-"):
        return []
    relative = value[:1] in "+^"
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for name in value.lstrip("+^").split(","):
        key = name.strip().lower()
        family = CLASSICAL_SSH_KEX.get(key)
        if family is None or key in seen:
            continue
        seen.add(key)
        out.append({
            "group": name.strip(),
            "family": family,
            "setting": "KexAlgorithms",
            "offered": "alone",
            "basis": "configured_kex",
            "description": (f"{name.strip()} is offered here as a key exchange of its own, "
                            f"without a post-quantum half"
                            + (", added to the default set this line does not name"
                               if relative else "")
                            + ". Which one a connection uses is chosen with the client "
                              "and is not stated by this line."),
        })
    return out

TLS_TERMINATION = (
    "These files configure TLS. This scan reads files, not connections. The key "
    "exchange a connection negotiates is settled where TLS terminates -- this server, "
    "or a proxy, load balancer or CDN in front of it -- together with the client, and "
    "a terminator outside the files read can negotiate a different group from the one "
    "configured here, in either direction. A post-quantum group seen on the wire does "
    "not show that these files changed; a classical group configured here does not "
    "show that the wire is classical. The same holds for authentication: a Merkle Tree "
    "Certificate is issued by the CA and verified by the browser, often served from an "
    "edge, and an origin whose files name an ECDSA key can be served with one -- its own "
    "key is still ECDSA, and reported as such.")


# Beside every evidence item at a TLS place, so the caveat is next to each setting and
# not only once per scan (ZA-OPRAVYANE row 25, 21.10.2026). Short, and pointing at the
# statement, which is still printed once.
TLS_SETTING_NOTE = (
    "Configured, not negotiated: a terminator outside the files can negotiate otherwise. "
    "See tls_termination.statement.")


# -- A hybrid group and the library version that has to negotiate it ---------------------
#
# The probe of 22.10.2026 (ZA-OPRAVYANE row 41): the repository configures
# X25519MLKEM768, and ops keeps the service on nginx:1.24.0, whose OpenSSL is 1.1.1. That
# OpenSSL does not know the group, nginx refused the repository's configuration, and the
# host runs a classical hotfix. The pin was in a compose file the scanner reads; nothing
# joined it to the group.
#
# Said only from facts read at the source, and otherwise "not established":
# * the group names are the IANA TLS Supported Groups registry's (read 22.10.2026);
# * OpenSSL added X25519MLKEM768, SecP256r1MLKEM768 and SecP384r1MLKEM1024 in 3.5.0
#   (CHANGES.md, "Changes between 3.4 and 3.5.0"), so an OpenSSL older than 3.5 cannot
#   negotiate them;
# * which OpenSSL an image carries: only nginx:1.24.0, the Debian image of docker-nginx
#   1.24.0 (stable/debian/Dockerfile: FROM debian:bullseye-slim), whose OpenSSL is 1.1.1
#   (packages.debian.org, bullseye: openssl 1.1.1w). Every other tag, an -alpine one
#   included, is "not established".
# Pins are read from `image:` lines (compose, Kubernetes); a Dockerfile's `FROM` line is
# not read for this (the file is read since 0.35.0, for the algorithms it names), and a
# package pin is not read for this. A compose service is
# joined to the configuration file it mounts (short volume syntax, inside the tree);
# without such a mount the pin and the group are named side by side, not joined.
HYBRID_TLS_GROUPS = {
    name.lower(): name for name in (
        "X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024",
        "SecP256r1MLKEM512", "MLKEM512X25519", "curveSM2MLKEM768",
        "X25519Kyber768Draft00", "SecP256r1Kyber768Draft00")}
_OPENSSL_35_HYBRIDS = ("X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024")
# image name, tag -> (TLS library, whether it is older than OpenSSL 3.5, the source)
_IMAGE_TLS_LIBRARY = {
    ("nginx", "1.24.0"): ("OpenSSL 1.1.1 (Debian bullseye)", True,
                          "docker-nginx 1.24.0 stable/debian/Dockerfile is FROM "
                          "debian:bullseye-slim; bullseye's openssl is 1.1.1w"),
}
# Images whose job is to terminate TLS with the configuration they are given.
_TLS_SERVER_IMAGES = {"nginx", "haproxy", "httpd", "traefik", "caddy", "envoy", "openresty"}
_IMAGE_LINE = re.compile(
    r"^(\s*)(?:-\s+)?image:\s*[\"']?([A-Za-z0-9][\w./-]*?):([A-Za-z0-9_][\w.-]*)[\"']?\s*(?:#.*)?$")
_VOLUME_ITEM = re.compile(r"^\s*-\s+[\"']?([^\s\"':]+):(/[^\s\"':]*)(?::\w+)?[\"']?\s*$")


def scan_hybrid_groups(line: str) -> list[str]:
    """Hybrid groups named in this line's TLS group setting."""
    if line.lstrip().startswith(_COMMENT_START):
        return []
    setting = _group_setting(line)
    if not setting:
        return []
    out: list[str] = []
    for token in _GROUP_TOKEN.finditer(line, setting.end()):
        if token.start() > 0 and line[token.start() - 1] in "-!":
            continue
        name = HYBRID_TLS_GROUPS.get(token.group(0).lower())
        if name and name not in out:
            out.append(name)
    return out


def image_pins(rel_path: str, lines: list[str]) -> list[dict[str, Any]]:
    """`image: name:tag` lines naming a TLS-terminating server, with the configuration
    files the same compose service mounts from inside the tree (short volume syntax)."""
    def indent(text: str) -> int:
        return len(text) - len(text.lstrip())

    def meaningful(text: str) -> bool:
        return bool(text.strip()) and not text.lstrip().startswith("#")

    pins: list[dict[str, Any]] = []
    base = posixpath.dirname(rel_path)
    for number, text in enumerate(lines, 1):
        image = _IMAGE_LINE.match(text)
        if not image or image.group(2).rsplit("/", 1)[-1] not in _TLS_SERVER_IMAGES:
            continue
        name, tag = image.group(2), image.group(3)
        level = len(image.group(1))
        # The service block: back to the line that opens it, forward to the next line
        # at a lower indent. `image:` and `volumes:` are its keys, in either order.
        first = number - 1
        while first > 0 and not (meaningful(lines[first - 1]) and indent(lines[first - 1]) < level):
            first -= 1
        last = number
        while last < len(lines) and not (meaningful(lines[last]) and indent(lines[last]) < level):
            last += 1
        mounts: list[str] = []
        in_volumes = False
        for inner in lines[first:last]:
            if not meaningful(inner):
                continue
            if indent(inner) == level:
                in_volumes = inner.strip().startswith("volumes:")
                continue
            volume = _VOLUME_ITEM.match(inner) if in_volumes else None
            # A path inside the tree; a named volume and an absolute host path are not.
            if volume and not volume.group(1).startswith("/") and (
                    volume.group(1).startswith(".") or "/" in volume.group(1)):
                mounts.append(posixpath.normpath(posixpath.join(base, volume.group(1))))
        pins.append({"path": rel_path, "line": number, "image": f"{name}:{tag}",
                     "name": name.rsplit("/", 1)[-1], "tag": tag, "mounts": mounts})
    return pins


def library_support(pins: list[dict[str, Any]], hybrids: list[tuple[str, int, str]],
                    files_read: list[str]) -> list[dict[str, Any]]:
    """For each pinned TLS server image, whether it can negotiate the hybrid groups this
    tree configures: not, where that is established at the source, else not established.
    Nothing when the tree configures no hybrid group."""
    if not hybrids:
        return []
    groups = sorted({g for _, _, g in hybrids})
    read = set(files_read)
    out: list[dict[str, Any]] = []
    for pin in pins:
        library = _IMAGE_TLS_LIBRARY.get((pin["name"], pin["tag"]))
        served = sorted({m for m in pin["mounts"] if m in read}
                        | {f for f in read for m in pin["mounts"] if f.startswith(m + "/")})
        serving = [f"{p}:{n}" for p, n, _ in sorted(set(hybrids)) if p in served]
        item = {"path": pin["path"], "line": pin["line"], "image": pin["image"],
                "basis": "pinned_image", "groups": groups,
                "group_places": [f"{p}:{n}" for p, n, _ in sorted(set(hybrids))],
                "serves": served, "serves_group_places": serving}
        if library and library[1]:
            unknown = [g for g in groups if g in _OPENSSL_35_HYBRIDS]
            item.update(tls_library=library[0], support="not_supported",
                        not_negotiable=unknown, source=library[2])
            said = (f"{pin['image']} is pinned here, and its TLS library is {library[0]} "
                    f"({library[2]}). OpenSSL added {', '.join(_OPENSSL_35_HYBRIDS)} in "
                    f"3.5.0, so a server on this image cannot negotiate "
                    f"{', '.join(unknown) or 'them'}, which this tree configures; it may "
                    f"refuse the setting or run with a classical group instead.")
            rest = [g for g in groups if g not in _OPENSSL_35_HYBRIDS]
            if rest:
                said += (f" For {', '.join(rest)} support in that library is not "
                         f"established here.")
        else:
            item.update(tls_library=None, support="not_established")
            said = (f"{pin['image']} is pinned here. Which TLS library and version that "
                    f"image carries is not established by this scan, so whether it can "
                    f"negotiate {', '.join(groups)}, which this tree configures, is not "
                    f"established either.")
        if not pin["mounts"]:
            said += " Which configuration this image serves is not joined here."
        elif serving:
            said += " Its compose service mounts a configuration that names the group."
        elif served:
            said += (" Its compose service mounts configuration from this tree that names "
                     "no hybrid group.")
        else:
            said += " What its compose service mounts was not read in this scan."
        item["description"] = said
        out.append(item)
    return out


def tls_termination(scan_result: dict[str, Any]) -> dict[str, Any] | None:
    """Where this tree configures TLS, and what that does not establish. None when it
    configures none.

    Every evidence item at one of those places -- and every classical group offered
    alone, which sits on such a line -- gets `tls_termination: TLS_SETTING_NOTE`."""
    places: set[tuple[str, int, str]] = set()
    marked: list[dict[str, Any]] = []
    for asset in scan_result.get("protocol_findings") or []:
        # A backend whose certificate is not checked is TLS configuration, but of the
        # client side of a hop: not where a connection from outside terminates.
        if asset.get("basis") == "configured_verification":
            continue
        if (asset.get("protocol") == "tls"
                and not asset.get("excerpt", "").lstrip().startswith(_COMMENT_START)):
            places.add((asset["path"], asset["line"],
                        "configured_listener" if asset.get("basis") == "configured_listener"
                        else "configured_protocol"))
            marked.append(asset)
    for key in ("source_code_findings", "ci_pipeline_findings", "iac_findings"):
        for item in scan_result.get(key) or []:
            if item.get("evidence_kind") == "comment":
                continue
            excerpt = item.get("excerpt", "")
            if _group_setting(excerpt):
                places.add((item["path"], item["line"], "configured_group"))
                marked.append(item)
            elif _cipher_setting(excerpt):
                places.add((item["path"], item["line"], "configured_cipher_suite"))
                marked.append(item)
    for group in scan_result.get("tls_group_findings") or []:
        places.add((group["path"], group["line"], "configured_group"))
        marked.append(group)
    for item in scan_result.get("static_rsa_kex_findings") or []:
        places.add((item["path"], item["line"], "configured_cipher_suite"))
        marked.append(item)
    if not places:
        return None
    for item in marked:
        item["tls_termination"] = TLS_SETTING_NOTE
    return {
        "statement": TLS_TERMINATION,
        "configured_in": [{"path": p, "line": n, "basis": b} for p, n, b in sorted(places)],
    }
