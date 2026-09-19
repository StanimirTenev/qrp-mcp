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
    elif name in {"yarn.lock", "pnpm-lock.yaml"}:
        for number, text in enumerate(lines, 1):
            match = _LOCK_YARN.match(text) or _LOCK_NPM_PATH.match(text)
            if match:
                out.append((match.group(1), number))
    elif name in {"Cargo.lock", "poetry.lock"}:
        for number, text in enumerate(lines, 1):
            match = _LOCK_TOML_NAME.match(text)
            if match:
                out.append((match.group(1), number))
    elif name in {"Gemfile.lock", "composer.lock"}:
        for number, text in enumerate(lines, 1):
            match = _LOCK_GEM.match(text)
            if match:
                out.append((match.group(1), number))
    return out


def _names_from_manifest(ecosystem: str, name: str, lines: list[str]) -> list[tuple[str, int]]:
    """(package name, line number) pairs, read structurally."""
    out: list[tuple[str, int]] = []
    if name.endswith(".lock") or name == "package-lock.json":
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
    for package, number in _names_from_manifest(ecosystem, path.name, lines):
        families = table.get(package)
        if families is None and ecosystem == "pypi":
            families = table.get(package.lower())
        if not families:
            continue
        findings.append({
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
        })
    return findings


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
    r"ServerOptions|SSLContext|tls\.Config|rustls|sslVersion",
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


def scan_protocols(line: str) -> list[dict[str, Any]]:
    """Protocol versions pinned on this line, as assets with no algorithm claim."""
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, bool]] = set()
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
