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
    if line.lstrip().startswith(_COMMENT_START):
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


def tls_termination(scan_result: dict[str, Any]) -> dict[str, Any] | None:
    """Where this tree configures TLS, and what that does not establish. None when it
    configures none.

    Every evidence item at one of those places -- and every classical group offered
    alone, which sits on such a line -- gets `tls_termination: TLS_SETTING_NOTE`."""
    places: set[tuple[str, int, str]] = set()
    marked: list[dict[str, Any]] = []
    for asset in scan_result.get("protocol_findings") or []:
        if (asset.get("protocol") == "tls"
                and not asset.get("excerpt", "").lstrip().startswith(_COMMENT_START)):
            places.add((asset["path"], asset["line"], "configured_protocol"))
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
