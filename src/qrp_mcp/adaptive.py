"""Adaptive scanning by rules (stage 3): four context sections built on the finished result.

- `ecosystems`: the ecosystems the files read belong to, each with the rule that put it there, and
  whether the closure catalogue (data/operations) holds the operations of that ecosystem;
- `angles`: where the dependency manifests, the code and the key files contradict each other;
- `chosen_outside_files.leads`: the include directives of a configuration and the key or
  certificate files named by path or by environment variable, each followed to the files read or
  said not followed;
- `where_to_look`: the three above in one list, in the order a reviewer reads them.

Every rule is named and deterministic; nothing here learns, fetches or guesses. All four are built
after `findings_fingerprint` and outside findings and evidence: they read the result and never
change a row of it, so they move neither the findings, their fingerprint, a gate nor the exit
code (tests/test_adaptive.py scans one tree with them and without them).
"""

from __future__ import annotations

import fnmatch
import os
import posixpath
import re
from pathlib import Path, PurePosixPath
from typing import Any

from . import assets, confidence, detectors, operations

# --- 1. by ecosystem ----------------------------------------------------------------------------

# The detection operations in which a gap of each ecosystem has been recorded: the 438 rows of
# qrp-mcp's ZA-OPRAVYANE labelled by operation and ecosystem on 18.11.2026
# (qrp-kachestvo/obratna-proba/operacii/labels.tsv; the residual cells multi/none/other left out).
# An ecosystem is `closed` when the catalogue holds every one of them: a statement about the gaps
# known so far, not about every way the ecosystem can name an algorithm. `vrf` of Go and Rust:
# row 535 (19.11.2026). Go's apiname, pqc and sign and Rust's pqc: the crypto-asset probe of
# 25.11.2026 (rows 561, 576-579, 582, 586, 587); JS's sign: row 593. keysize of CI: row 557,
# tlsend of Java (Android): row 556 (25.11.2026).
KNOWN_OPERATIONS: dict[str, tuple[str, ...]] = {
    "C": ("apiname", "ciphers", "external", "keyfile", "keysize", "pqc", "protover", "sign",
          "tlsgroups", "usectx"),
    "CI": ("encrypt", "external", "keysize", "sign", "usectx"),
    "DNSSEC": ("apiname", "keyfile"),
    "Go": ("apiname", "external", "pqc", "sign", "vrf"),
    "IPsec": ("ike", "keysize", "symhash"),
    "IaC": ("ciphers", "encrypt", "external", "keyfile", "keysize", "pqc", "sign"),
    "JS": ("apiname", "encrypt", "keysize", "protover", "sign", "usectx"),
    "Java": ("apiname", "ciphers", "encrypt", "external", "keyfile", "keysize", "pqc", "protover",
             "symhash", "tlsend"),
    "NET": ("apiname", "ciphers", "external", "keyfile", "keysize", "protover", "sign", "symhash",
            "tlsgroups", "usectx"),
    "PHP": ("apiname", "encrypt", "keysize", "protover"),
    "PKI": ("keyfile", "keysize", "pqc"),
    "Py": ("apiname", "encrypt", "external", "keysize", "pqc", "protover", "sign", "symhash",
           "usectx"),
    "Rust": ("apiname", "keysize", "pqc", "protover", "vrf"),
    "SSH": ("keyfile", "keysize", "pqc", "ssh"),
    "embed": ("apiname", "keysize", "pqc", "sign", "usectx"),
    "netdev": ("ciphers", "external", "keyfile", "keysize", "protover", "tlsend"),
    "nginx": ("ciphers", "external", "keysize", "pqc", "tlsend", "tlsgroups", "usectx"),
    "Apache": (),
}

_CODE_SUFFIXES = {
    "C": (".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp"),
    "Java": (".java", ".kt", ".kts", ".scala", ".sc", ".groovy"),
    "NET": (".cs", ".vb", ".fs", ".fsx", ".ps1", ".psm1", ".psd1"),
    "Py": (".py",),
    "Go": (".go",),
    "Rust": (".rs",),
    "JS": (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts"),
    "PHP": (".php", ".rb"),
    "CI": (".sh", ".bash", ".zsh", ".ksh", ".bat", ".cmd"),
}
_SUFFIX_TO_CODE = {s: eco for eco, suffixes in _CODE_SUFFIXES.items() for s in suffixes}
# An operation most trees never perform counts toward an ecosystem's status -- known, closed or
# open -- only where the scan found it there: a row of its family in a file of that ecosystem. A
# VRF catalogue made every Go and Rust tree read `partially_closed` (independent review of 0.51.0,
# 19.11: Vault, Go rank 1 -> 40, with `external` still open and untested).
_FOUND_ONLY = {"vrf": "ECVRF"}
# `rng_source` (rows 531, 539) is catalogued but never counts toward an ecosystem's status: almost every
# tree calls a generator, so counting it could only raise a status and push an ecosystem with open,
# untested operations down `where_to_look` (Vault, Go rank 1 -> 39; the same effect as `vrf` in 0.51.0).
# The parts of an operation catalogued under a name of their own (25.11.2026, rows 555-557, 560): gpg's
# key generation is not all of keysize/CI, nor Spring placeholders all of external/Java, Android's
# configuration all of tlsend/Java, standalone ML-KEM in Go all of pqc/Go, an unverified JWT (row 594) all of sign. Their spellings are tested
# like any other; a part does not close or open its ecosystem.
_NOT_IN_STATUS = {"rng_source", "keysize_gpg", "external_placeholder", "tlsend_android",
                  "pqc_standalone", "sign_unverified"}
# A manifest's (or a dependency row's) package ecosystem, as the catalogue names ecosystems.
_PACKAGE_ECOSYSTEM = {"pypi": "Py", "npm": "JS", "go": "Go", "cargo": "Rust", "maven": "Java",
                      "nuget": "NET", "rubygems": "PHP", "composer": "PHP"}
_CONFIG_NAMES = {
    "nginx.conf": "nginx", "haproxy.cfg": "nginx", "Caddyfile": "nginx", "envoy.yaml": "nginx",
    "traefik.yml": "nginx", "traefik.yaml": "nginx", "traefik.toml": "nginx",
    "httpd.conf": "Apache", "apache2.conf": "Apache", ".htaccess": "Apache",
    "sshd_config": "SSH", "ssh_config": "SSH", "authorized_keys": "SSH", "known_hosts": "SSH",
    "swanctl.conf": "IPsec", "ipsec.conf": "IPsec", "strongswan.conf": "IPsec",
    "ipsec.secrets": "IPsec",
    "java.security": "Java", "java.policy": "Java",
    "Dockerfile": "CI", "Containerfile": "CI", "Jenkinsfile": "CI", ".gitlab-ci.yml": "CI",
    "azure-pipelines.yml": "CI",
    "Kconfig": "embed",
    "Chart.yaml": "IaC", "kustomization.yaml": "IaC", "kustomization.yml": "IaC",
}
_CONFIG_SUFFIXES = {".cnf": "C", ".ovpn": "IPsec", ".reg": "NET", ".tf": "IaC", ".tfvars": "IaC",
                    ".dts": "embed", ".dtsi": "embed", ".dtso": "embed", ".its": "embed"}
# A zone file is DNSSEC only when it carries a DNSSEC record: a zone of HTTPS records with an ECH
# config was filed under DNSSEC by its suffix (row 552, Dong's ECH bench, 24.11.2026).
_DNSSEC_RECORD = re.compile(r"\bIN\s+(?:DNSKEY|RRSIG|DS|NSEC3?|NSEC3PARAM|CDS|CDNSKEY)\b", re.I)
_CONFIG_DIRS = {"nginx": "nginx", "haproxy": "nginx", "caddy": "nginx", "apache2": "Apache",
                "httpd": "Apache", "sshd_config.d": "SSH", "ssh_config.d": "SSH",
                "swanctl": "IPsec", "strongswan": "IPsec", "ipsec.d": "IPsec",
                "wireguard": "IPsec", ".github/workflows": "CI", ".circleci": "CI"}
_CONFIG_PATTERNS = (
    (re.compile(r"^(?:Dockerfile|Containerfile)[-.][\w.-]+$"
                r"|^[\w.-]+\.(?:Dockerfile|Containerfile)$"), "CI"),
    (re.compile(r"^(?:sshd|ssh)_config[-_.][\w.-]+$"), "SSH"),
    (re.compile(r"^wg\d*\.conf$"), "IPsec"),
    (re.compile(r"^(?:web|app|machine|applicationhost)(?:\.[\w-]+)?\.config$"), "NET"),
    (re.compile(r"^sdkconfig(?:\.[\w.-]+)?$|^[\w.-]+_defconfig$"), "embed"),
    (re.compile(r"^dsset-[\w.-]+$|^K[\w.-]*\+\d{3}\+\d{5}\.(?:key|private)$"), "DNSSEC"),
)
# Read from the text of a .conf or extension-less configuration: an nginx `server {` or a
# `<VirtualHost`, which name no file of their own.
_CONTENT_RULES = ((re.compile(r"^\s*server\s*\{", re.M), "nginx"),
                  (re.compile(r"^\s*<VirtualHost\b", re.M | re.I), "Apache"))
KEY_SUFFIXES = (".pem", ".crt", ".cer", ".der", ".key", ".p12", ".pfx", ".csr", ".crl", ".jks",
                ".keystore", ".p7b", ".p7c", ".p8", ".jwk", ".jwks", ".pub")

ECOSYSTEMS_MEANING = (
    "the ecosystems the files read belong to, each with the rules that put it here (code_suffix, "
    "manifest, crypto_dependency, config_name, config_content, key_file) and how many files each "
    "matched; and whether this version's closure catalogue (operation_closure) holds its "
    "operations. The operations of an ecosystem are those in which a gap has been recorded "
    "(known_operations, from the labelled ZA-OPRAVYANE rows of 18.11.2026 and the later rows "
    "that name an operation, as `vrf` of Go and Rust, row 535): `closed` -- the "
    "catalogue holds every one; `partially_closed` -- some; `not_closed` -- none, or the "
    "ecosystem has no catalogue entry at all. A closed operation is one whose documented "
    "spellings are tested one by one; it is not a claim that nothing can be missed, and an "
    "operation with no recorded gap is not counted. An operation is closed against the libraries "
    "and names its catalogue entries list, given for each closed operation in `closed_scope`; "
    "another library of the same ecosystem is not covered by it. An operation most trees never perform (`vrf`) "
    "counts -- known, closed or open -- only where the scan found it in that ecosystem, outside test "
    "code. `rng_source` is in operation_closure but never counts toward a status here: its rows "
    "are in `randomness`. Context only: it does not affect the "
    "findings, their fingerprint, a gate or the exit code")


NOT_ATTRIBUTED_MEANING = (
    "here we may miss: files read that no rule puts in an ecosystem (by suffix, manifest, "
    "configuration name or content, or key file), so no operation of theirs is in the closure "
    "catalogue; what the scan reports in them comes from its rules, never tested spelling by "
    "spelling. Context only: it does not affect the findings, their fingerprint, a gate or the "
    "exit code")


def _config_ecosystem(rel: str) -> str | None:
    parts = rel.split("/")
    name = parts[-1]
    if name in _CONFIG_NAMES:
        return _CONFIG_NAMES[name]
    suffix = Path(name).suffix.lower()
    if suffix in _CONFIG_SUFFIXES:
        return _CONFIG_SUFFIXES[suffix]
    for pattern, eco in _CONFIG_PATTERNS:
        if pattern.match(name):
            return eco
    directory = "/".join(parts[:-1])
    for segment, eco in _CONFIG_DIRS.items():
        if ("/" + directory + "/").find("/" + segment + "/") >= 0 and confidence._is_config(rel):
            return eco
    return None


def _read(root: Path, rel: str, limit: int | None = None) -> str:
    try:
        with open(root / rel, encoding="utf-8", errors="replace") as handle:
            return handle.read(limit) if limit else handle.read()
    except OSError:
        return ""


def _ecosystems(result: dict[str, Any], root: Path) -> dict[str, Any]:
    files: dict[str, dict[str, set[str]]] = {}

    def add(eco: str, rule: str, rel: str) -> None:
        files.setdefault(eco, {}).setdefault(rule, set()).add(rel)

    files_read = result.get("files_read") or []
    key_files = {i["path"] for i in result["evidence"].get("embedded_keys") or []}
    for rel in files_read:
        name = rel.rsplit("/", 1)[-1]
        suffix = Path(name).suffix.lower()
        if suffix in _SUFFIX_TO_CODE:
            add(_SUFFIX_TO_CODE[suffix], "code_suffix", rel)
        package = assets._ecosystem_of(Path(rel)) if assets.is_manifest(Path(rel)) else None
        if package in _PACKAGE_ECOSYSTEM:
            add(_PACKAGE_ECOSYSTEM[package], "manifest", rel)
        eco = _config_ecosystem(rel)
        if eco:
            add(eco, "config_name", rel)
        elif suffix == ".zone":
            if _DNSSEC_RECORD.search(_read(root, rel)):
                add("DNSSEC", "config_content", rel)
        elif suffix in (".conf", "") and confidence._is_config(rel):
            text = _read(root, rel, 65536)
            for pattern, eco in _CONTENT_RULES:
                if pattern.search(text):
                    add(eco, "config_content", rel)
        if suffix in KEY_SUFFIXES or rel in key_files:
            add("PKI", "key_file", rel)
    for dep in result["evidence"].get("dependencies") or []:
        eco = _PACKAGE_ECOSYSTEM.get(dep.get("ecosystem"))
        if eco:
            add(eco, "crypto_dependency", dep["path"])
    catalogue: dict[str, set[str]] = {}
    scopes: dict[tuple[str, str], list[str]] = {}
    for doc in operations.catalogue():
        for entry in doc["ecosystems"]:
            catalogue.setdefault(entry["ecosystem"], set()).add(doc["operation"])
            if entry.get("scope"):
                scopes.setdefault((entry["ecosystem"], doc["operation"]), []).append(entry["scope"])
    found: dict[str, set[str]] = {}
    for rows in (result.get("evidence") or {}).values():
        for row in rows if isinstance(rows, list) else ():
            if (isinstance(row, dict) and row.get("evidence_kind") not in {"comment", "ban"}
                    and not row.get("in_test_code")
                    and row.get("algorithm") in _FOUND_ONLY.values()):
                eco = _SUFFIX_TO_CODE.get(PurePosixPath(str(row.get("path", ""))).suffix.lower())
                if eco:
                    found.setdefault(eco, set()).add(row["algorithm"])
    present = []
    for eco in sorted(files):
        every = set().union(*files[eco].values())
        absent = {op for op, family in _FOUND_ONLY.items() if family not in found.get(eco, set())}
        absent |= _NOT_IN_STATUS
        known = set(KNOWN_OPERATIONS.get(eco, ())) - absent
        closed = sorted(catalogue.get(eco, set()) - absent)
        still_open = sorted(known - set(closed))
        entry: dict[str, Any] = {
            "ecosystem": eco,
            "files": len(every),
            "basis": {rule: len(paths) for rule, paths in sorted(files[eco].items())},
            "example": sorted(every)[0],
            "only_in_test_code": all(detectors.in_test_code(p) for p in every),
            "known_operations": sorted(known),
            "closed_operations": closed,
            # 25.11.2026: what each closed operation is closed against -- its catalogue's scope.
            "closed_scope": {op: scopes.get((eco, op), []) for op in closed},
            "open_operations": still_open,
        }
        if not catalogue:
            entry["status"] = "catalogue_not_loaded"
        elif not closed:
            entry["status"] = "not_closed"
            entry["may_miss"] = (f"here we may miss: no operation of {eco} is in this version's "
                                 f"closure catalogue; what the scan reports here comes from its "
                                 f"rules, never tested spelling by spelling")
        elif still_open:
            entry["status"] = "partially_closed"
            entry["may_miss"] = (f"here we may miss: {', '.join(still_open)} of {eco} -- "
                                 f"operations with a recorded gap that the closure catalogue "
                                 f"does not hold")
        else:
            entry["status"] = "closed"
        present.append(entry)
    # A file read that no rule puts in an ecosystem has no closed operation either; without this
    # it got no "here we may miss" at all (keys/ech-keys.json in Dong's ECH bench, 24.11.2026).
    attributed = set().union(*(set().union(*rules.values()) for rules in files.values()))
    unattributed = sorted(set(files_read) - attributed)
    return {"meaning": ECOSYSTEMS_MEANING, "count": len(present), "present": present,
            "not_attributed": {
                "meaning": NOT_ATTRIBUTED_MEANING, "count": len(unattributed),
                "only_in_test_code": bool(unattributed) and all(
                    detectors.in_test_code(p) for p in unattributed),
                "paths": unattributed}}


# --- 2. angles ----------------------------------------------------------------------------------

# What a dependency's family is seen as in the code: the table says EdDSA, a line says Ed25519.
_SEEN_AS = {"EdDSA": {"EdDSA", "Ed25519", "Ed448"}, "ECDH": {"ECDH", "X25519", "X448", "EC"},
            "ECDSA": {"ECDSA", "EC"}, "ECIES": {"ECIES", "EC", "ECDH"}, "SHA1": {"SHA1"}}
# Kinds of a line that are not a call site: a comment, a ban list, a bare identifier, an import.
_NOT_A_CALL_SITE = ("comment", "ban", "identifier", "import")
_IMPORTS_READ = ("pypi", "npm")
ANGLE_RULES = {
    "declared_not_imported": (
        "declared, not seen: a crypto library a manifest asks for (not a lockfile) that no file "
        "read imports; imports are read for Python and JavaScript only"),
    "declared_no_family_in_code": (
        "declared, not seen: a crypto library declared, and no line of code in its language "
        "(comments, ban lists, identifiers and imports left out) names a family it implements"),
    "imported_not_declared": (
        "seen, not declared: a Python or JavaScript file imports a crypto library of the table "
        "that no manifest read declares, where the tree has a manifest of that ecosystem and no "
        "local module of that name"),
    "named_key_file_absent": (
        "declared, not seen: a configuration or a line of code names a key or certificate file "
        "by a relative path, and the tree has no such file (chosen_outside_files.leads, "
        "status not_found)"),
}
ANGLES_MEANING = (
    "contradictions between the angles a tree can be read from -- dependency manifests, code, "
    "configuration, key and certificate files -- each with the named rule that found it "
    "(rules). `declared, not seen` and `seen, not declared` say where two angles disagree, not "
    "which is right: a library used through another, or code generated at build time, gives "
    "the same. not_compared lists the package ecosystems whose imports this version does not "
    "read, where the two import rules did not run. Context only: it does not affect the "
    "findings, their fingerprint, a gate or the exit code")


def _families_in_code(result: dict[str, Any]) -> dict[str, set[str]]:
    seen: dict[str, set[str]] = {}
    for item in result["evidence"].get("source_code") or []:
        if item.get("evidence_kind") in _NOT_A_CALL_SITE or not item.get("algorithm"):
            continue
        eco = _SUFFIX_TO_CODE.get(Path(item["path"]).suffix.lower())
        if eco:
            seen.setdefault(eco, set()).add(item["algorithm"])
    return seen


def _import_names(root: Path, files_read: list[str], wanted: dict[str, dict[str, str]]
                  ) -> list[tuple[str, str, str, int]]:
    """(ecosystem, package, path, line) of each import of a table package by its import name."""
    out = []
    for rel in files_read:
        eco = ("pypi" if rel.endswith(".py") else
               "npm" if rel.endswith(assets._JS_SUFFIXES) else None)
        if eco is None:
            continue
        for number, line in enumerate(_read(root, rel).splitlines(), 1):
            if eco == "pypi":
                m = assets._PY_IMPORT.match(line)
                names = ([m.group(1)] if m and m.group(1) else
                         [n.strip().split(".")[0] for n in m.group(2).split(",")] if m else [])
            else:
                names = [m.group(1) for m in assets._JS_IMPORT.finditer(line)]
            for name in names:
                if name in wanted[eco]:
                    out.append((eco, wanted[eco][name], rel, number))
    return out


def _angles(result: dict[str, Any], root: Path, leads: list[dict[str, Any]]) -> dict[str, Any]:
    files_read = result.get("files_read") or []
    deps = [d for d in result["evidence"].get("dependencies") or []
            if d.get("ecosystem") in _PACKAGE_ECOSYSTEM
            and not assets.is_lockfile(Path(d["path"]))]
    in_code = _families_in_code(result)
    out: list[dict[str, Any]] = []
    for d in deps:
        base = {"package": d["package"], "ecosystem": d["ecosystem"], "path": d["path"],
                "line": d["line"], "in_test_code": detectors.in_test_code(d["path"])}
        if d["ecosystem"] in _IMPORTS_READ and not d.get("imported_in"):
            out.append({"rule": "declared_not_imported", "kind": "declared, not seen", **base,
                        "statement": f"{d['package']} is declared in {d['path']}:{d['line']} "
                                     f"and no file read imports it"})
            continue
        lang = _PACKAGE_ECOSYSTEM[d["ecosystem"]]
        seen_as = set().union(*(_SEEN_AS.get(f, {f}) for f in d.get("families") or []))
        if seen_as and not seen_as & in_code.get(lang, set()):
            named = ", ".join(d.get("families") or [])
            out.append({"rule": "declared_no_family_in_code", "kind": "declared, not seen", **base,
                        "families": list(d.get("families") or []),
                        "statement": f"{d['package']} is declared in {d['path']}:{d['line']}; no "
                                     f"{lang} code read names {named}"})
    # Seen, not declared.
    manifests = {_PACKAGE_ECOSYSTEM.get(assets._ecosystem_of(Path(r)) or "") for r in files_read
                 if assets.is_manifest(Path(r)) and not assets.is_lockfile(Path(r))}
    declared = {(d["ecosystem"], d["package"].lower())
                for d in result["evidence"].get("dependencies") or []}
    modules = {Path(r).stem for r in files_read if r.endswith(".py")} | {
        p for r in files_read if r.endswith("/__init__.py") for p in [r.split("/")[-2]]}
    wanted: dict[str, dict[str, str]] = {"pypi": {}, "npm": {}}
    if "Py" in manifests:
        wanted["pypi"] = {assets._py_module(p): p for p in assets.DEPENDENCY_FAMILIES["pypi"]
                          if ("pypi", p) not in declared and assets._py_module(p) not in modules}
    if "JS" in manifests:
        wanted["npm"] = {p: p for p in assets.DEPENDENCY_FAMILIES["npm"]
                         if ("npm", p.lower()) not in declared}
    first: dict[tuple[str, str], tuple[str, int]] = {}
    count: dict[tuple[str, str], int] = {}
    if wanted["pypi"] or wanted["npm"]:
        for eco, package, rel, number in _import_names(root, files_read, wanted):
            first.setdefault((eco, package), (rel, number))
            count[(eco, package)] = count.get((eco, package), 0) + 1
    for (eco, package), (rel, number) in sorted(first.items()):
        out.append({"rule": "imported_not_declared", "kind": "seen, not declared",
                    "package": package, "ecosystem": eco, "path": rel, "line": number,
                    "imported_count": count[(eco, package)],
                    "in_test_code": detectors.in_test_code(rel),
                    "statement": f"{package} is imported in {rel}:{number} and no {eco} manifest "
                                 f"read declares it"})
    for lead in leads:
        if lead["status"] == "not_found" and lead["rule"] in ("key_file_path",):
            out.append({"rule": "named_key_file_absent", "kind": "declared, not seen",
                        "path": lead["path"], "line": lead["line"], "file": lead["target"],
                        "in_test_code": lead["in_test_code"],
                        "statement": f"{lead['path']}:{lead['line']} names {lead['target']}, "
                                     f"which is not in the tree"})
    out.sort(key=lambda c: (c["path"], c["line"], c["rule"], c.get("package") or ""))
    not_compared = sorted({d["ecosystem"] for d in deps if d["ecosystem"] not in _IMPORTS_READ})
    return {"meaning": ANGLES_MEANING, "rules": ANGLE_RULES, "count": len(out),
            "contradictions": out,
            "not_compared": [{"ecosystem": e,
                              "rules": ["declared_not_imported", "imported_not_declared"],
                              "because": "this version does not read the imports of " + e}
                             for e in not_compared]}


# --- 3. leads -----------------------------------------------------------------------------------

# Include directives, by the formats that have one: nginx `include x;`, Apache
# `Include`/`IncludeOptional`, OpenSSH `Include` (several paths), OpenSSL `.include`, strongSwan
# `include`, Caddy `import` (a word without a dot or a slash there is a snippet, not a file).
_INCLUDE = re.compile(
    r"^\s*(include|Include|IncludeOptional|\.include|import)\b\s*=?\s*(.+?)\s*;?\s*$")
# The configurations an include is read in: not build files, whose `include` is another make
# rule, nor JSON, TOML or YAML, which have none.
_INCLUDE_SUFFIXES = (".conf", ".cnf", ".cfg", "")
_NOT_INCLUDING = {"Makefile", "GNUmakefile", "makefile", "Kconfig", "Dockerfile", "Containerfile",
                  "CMakeLists.txt", "Jenkinsfile"}
_KEY_SUFFIX = r"(?:" + "|".join(re.escape(s) for s in KEY_SUFFIXES) + r")"
# A setting whose value is a key or certificate file: `smtpd_tls_cert_file = /x.pem`,
# `cert: tls/server.crt`, OpenVPN `ca ca.crt`, OpenSSH `HostKey` (whose files have no suffix).
# Separated by a space only for the settings named here (OpenVPN, nginx, Apache): any word
# before a path is a command as often (`sha256sum ./key.pem` in a workflow, Vault 18.11).
_SPACE_KEY_SETTINGS = (r"ca|cert|key|dh|pkcs12|tls-auth|tls-crypt|tls-crypt-v2|crl-verify|"
                       r"ssl_dhparam|ssl_password_file|ssl_stapling_file|ssl_crl|"
                       r"SSL(?:CACertificate|CertificateChain|CARevocation|ProxyMachineCertificate"
                       r"|ProxyCACertificate|OpenSSLConfCmd)File")
_CONFIG_KEY_SETTING = re.compile(
    r"^\s*(?:-\s+)?(?:([A-Za-z_][\w.-]*)[\"']?\s*[=:]\s*|(" + _SPACE_KEY_SETTINGS + r")\s+)"
    r"[\"']?([^\s\"';,]+" + _KEY_SUFFIX + r")[\"']?\s*[;,]?\s*(?:#.*)?$", re.IGNORECASE)
_SSH_KEY_SETTING = re.compile(r"^\s*(HostKey|HostCertificate|TrustedUserCAKeys|IdentityFile|"
                              r"CertificateFile|RevokedKeys)\s+[\"']?([^\s\"']+)")
# A call that opens or loads a file, with a literal key or certificate path among its first
# arguments: Python open/load_cert_chain/load_pem_*, Go os.ReadFile/tls.LoadX509KeyPair, Node
# readFileSync, Java FileInputStream/Paths.get, .NET X509Certificate2/File.ReadAll*.
_CODE_LOAD = re.compile(
    r"\b(open|load_cert_chain|load_pem_\w+|from_file|ReadFile|LoadX509KeyPair|readFileSync|"
    r"readFile|FileInputStream|FileReader|Paths\.get|Path\.of|X509Certificate2|ReadAllBytes|"
    r"ReadAllText|CreateFromPemFile|load_key|load_certificate|use_certificate_file|"
    r"use_PrivateKey_file|SSL_CTX_use_certificate(?:_chain)?_file|SSL_CTX_use_PrivateKey_file|"
    r"SSL_CTX_load_verify_locations)\s*\(")
# A name joined to a directory known only at run time (Vault's tests:
# filepath.Join(tempDir, "ca_cert.pem"); certbot's join(config_dir, 'live', ..., 'cert.pem')).
_PATH_JOIN = re.compile(r"\b(?:[Jj]oin|Combine|resolve)\s*\(")
_LITERAL_KEY_PATH = re.compile(r"[\"']([^\"'\s]{1,200}?" + _KEY_SUFFIX + r")[\"']", re.IGNORECASE)
# A key or certificate file read from an environment variable: a name that says a certificate,
# key, CA or trust store and a file, path or directory, or one of the names libraries read.
# Each as a word between underscores: CERTBOT_PLUGIN_PATH says neither (certbot, 18.11).
_ENV_NAME = (r"((?:[A-Z0-9]+_)*(?:CERTS?|CRT|KEY|CA|CACERT|TLS|SSL|PEM|KEYSTORE|TRUSTSTORE)_"
             r"(?:[A-Z0-9]+_)*(?:FILE|PATH|DIR|BUNDLE|LOCATION)S?(?![A-Za-z0-9_])|"
             r"REQUESTS_CA_BUNDLE|CURL_CA_BUNDLE|NODE_EXTRA_CA_CERTS)")
_ENV_KEY_READ = re.compile(
    r"(?:os\.environ(?:\.get)?\s*[\[(]\s*|os\.getenv\s*\(\s*|os\.(?:Getenv|LookupEnv)\s*\(\s*|"
    r"System\.getenv\s*\(\s*|Environment\.GetEnvironmentVariable\s*\(\s*|\bgetenv\s*\(\s*)"
    r"[\"']" + _ENV_NAME + r"[\"']"
    r"|process\.env(?:\.|\[\s*[\"'])" + _ENV_NAME + r"\b")
_COMMENT = ("#", "//", "*", "/*", ";", "--")
LEAD_RULES = {
    "include": ("an include directive of a configuration (nginx, Apache, OpenSSH, OpenSSL, "
                "strongSwan, Caddy): its target followed to the files read"),
    "key_file_path": ("a key or certificate file named by path: a configuration setting whose "
                      "value is one (OpenSSH HostKey too), or a call that opens or loads a "
                      "literal path with a key or certificate suffix"),
    "key_file_from_environment": ("a key or certificate file whose path is read from an "
                                  "environment variable at run time: the file is not known "
                                  "from the files read"),
}
LEADS_MEANING = (
    "the leads the files read point to -- an include directive, a key or certificate file named "
    "by path or read from an environment variable -- each followed to the files this scan read: "
    "`followed` -- the target, from the file's directory or the root, is among them (files) "
    "and was scanned with the rest; `followed_from_parent` -- the same from a directory "
    "between (base), as nginx reads an include from its prefix; "
    "`in_the_tree_not_read` -- the target exists in the tree, a symlink too, but is not among "
    "the files read; "
    "`outside_the_tree` -- an absolute path (same_name_read lists files read with that name, "
    "a possible copy, not linked); `not_found` -- a relative path the tree does not have; "
    "`pattern_not_followed` -- a pattern no file read matches and that is not looked for in "
    "the tree (`**` inside a path component, or a pattern the file system refuses); "
    "`templated` -- a path built from a variable, a template or a format field, joined to a "
    "directory of the run (filepath.Join, os.path.join), or written as "
    "a placeholder (/path/to/, a first segment in capitals), not resolved; "
    "`read_at_run_time` -- an environment variable. Following never opens a new file: what "
    "the scan found in a followed file is in the findings already. Certificate lines of a TLS "
    "server are in tls_listeners and tls_termination.authentication_not_read, trust stores "
    "in trust_stores, and cryptographic settings read at run time in `places` above: they are "
    "not repeated here (reported_elsewhere). Context only: it does not affect the findings, "
    "their fingerprint, a gate or the exit code")


_FOLLOWED = ("followed", "followed_from_parent")
_FIXED_SPACE_SETTING = re.compile(r"(?:" + _SPACE_KEY_SETTINGS + r")", re.IGNORECASE)
_FIXED_SSH_SETTING = re.compile(r"HostKey|HostCertificate|TrustedUserCAKeys|IdentityFile|"
                                r"CertificateFile|RevokedKeys")
# _CODE_LOAD's names with `load_pem_\w+` closed to the ones cryptography gives: any key or call
# that begins with `load_pem_` (`load_pem_zzcodehost: keys/z.pem`) is source text (second
# review, 18.11).
_FIXED_CODE_LOAD = re.compile(_CODE_LOAD.pattern.replace(
    r"load_pem_\w+", r"load_pem_(?:private_key|public_key|parameters|x509_certificates?|x509_csr|"
                     r"x509_crl)"))


def fixed_setting(lead: dict[str, Any]) -> bool:
    """Whether a lead's `setting` is this module's own vocabulary -- a directive, an OpenSSH or
    OpenVPN/nginx/Apache setting, a call's name, `environment variable` -- rather than a key
    taken from the scanned file (`zzhost.corp.example: certs/c.pem`), which is source text and is
    masked below `full` (review B2, 18.11)."""
    setting, rule = str(lead.get("setting") or ""), lead.get("rule")
    if rule == "include" or rule == "key_file_from_environment":
        return True
    return bool(_FIXED_SPACE_SETTING.fullmatch(setting) or _FIXED_SSH_SETTING.fullmatch(setting)
                or _FIXED_CODE_LOAD.fullmatch(setting + "("))
# A path built at run time or written as a placeholder: a variable ($X, %h), a template or format
# field ({{ x }}, {0}), a home directory (~), a first segment in capitals that a program replaces
# (certbot's MAGICDIR/live/...), or documentation's /path/to/ (the control's sample, 18.11).
_TEMPLATED = re.compile(r"[$%{}]|^~|^[A-Z][A-Z0-9_]{3,}/|(?:^|/)path/to/")


def _resolve(target: str, rel: str, read: set[str], root: Path,
             limit: int | None = 20) -> dict[str, Any]:
    """`limit` bounds the files a lead reports; None (scan.py's include link) gives them all."""
    if _TEMPLATED.search(target):
        return {"status": "templated"}
    if target.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", target):
        name = target.rsplit("/", 1)[-1]
        same = sorted(f for f in read if fnmatch.fnmatchcase(f.rsplit("/", 1)[-1], name))[:10] \
            if name and name != "*" else []
        return {"status": "outside_the_tree", **({"same_name_read": same} if same else {})}
    # The file's directory, then the root, then the directories between, nearest first: nginx
    # reads a relative include from its prefix, the directory of nginx.conf, not of the file
    # that includes (certbot's sites-available/*.conf, 18.11).
    here = PurePosixPath(rel).parent
    bases = list(dict.fromkeys([here, PurePosixPath("."), *here.parents]))
    glob = any(c in target for c in "*?[")
    candidates = [(b, posixpath.normpath(str(b / target))) for b in bases]
    candidates = [(b, p) for b, p in candidates if not p.startswith("..")]
    for base, pattern in candidates:
        matched = sorted(f for f in read
                         if (fnmatch.fnmatchcase(f, pattern) if glob else f == pattern))
        if matched:
            if base in (here, PurePosixPath(".")):
                return {"status": "followed", "files": matched[:limit]}
            return {"status": "followed_from_parent", "base": str(base), "files": matched[:limit]}
    # A symlink is in the tree though the scan does not follow it (certbot's live/*.pem).
    for _base, pattern in candidates:
        # The pattern is source text: `**` inside a component (`sites/**.conf`) makes pathlib
        # raise on Python 3.10-3.12 and ended the whole scan (review B1, 18.11). Such a pattern
        # is not globbed on any version, and nothing else pathlib refuses (ValueError, OSError,
        # IndexError on a pattern that normalises to nothing) ends the scan.
        if glob and any("**" in part and part != "**" for part in pattern.split("/")):
            return {"status": "pattern_not_followed"}
        try:
            if any(root.glob(pattern)) if glob else os.path.lexists(root / pattern):
                return {"status": "in_the_tree_not_read"}
        except Exception:  # noqa: BLE001 -- whatever pathlib refuses, the lead is not followed
            return {"status": "pattern_not_followed"}
    return {"status": "not_found"}


def _elsewhere(result: dict[str, Any]) -> tuple[set[tuple[str, int]], set[tuple[str, str]],
                                                dict[str, int]]:
    trust = (result.get("trust_stores") or {}).get("places") or []
    auth = ((result.get("tls_termination") or {}).get("authentication_not_read") or {}).get(
        "places") or []
    places = (result.get("chosen_outside_files") or {}).get("places") or []
    lines = {(p["path"], p["line"]) for p in [*trust, *auth, *places]}
    files = {(p["path"], p.get("file")) for p in trust if p.get("file")}
    return lines, files, {"trust_stores": len(trust),
                          "tls_termination.authentication_not_read": len(auth),
                          "chosen_outside_files.places": len(places)}


def _leads(result: dict[str, Any], root: Path) -> dict[str, Any]:
    files_read = result.get("files_read") or []
    read = set(files_read)
    taken_lines, taken_files, elsewhere = _elsewhere(result)
    items: list[dict[str, Any]] = []

    def add(rule: str, rel: str, n: int, setting: str, target: str, resolved: dict) -> None:
        if (rel, n) in taken_lines or (rel, target) in taken_files:
            return
        items.append({"rule": rule, "path": rel, "line": n, "setting": setting, "target": target,
                      **resolved, "in_test_code": detectors.in_test_code(rel)})

    for rel in files_read:
        name = rel.rsplit("/", 1)[-1]
        suffix = Path(name).suffix.lower()
        code = suffix in _SUFFIX_TO_CODE
        config = confidence._is_config(rel) and not assets.is_manifest(Path(rel))
        if not code and not config:
            continue
        text = _read(root, rel)
        if not text:
            continue
        including = (config and suffix in _INCLUDE_SUFFIXES and name not in _NOT_INCLUDING
                     and not name.startswith("Dockerfile"))
        for n, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith(_COMMENT):
                continue
            if including:
                m = _INCLUDE.match(raw)
                if m and not (m.group(1) == "import" and name != "Caddyfile"):
                    words = m.group(2).split("#", 1)[0].strip().rstrip(";").split()
                    if m.group(1) == "Include":  # OpenSSH: several paths on one line
                        targets = words
                    else:
                        targets = [m.group(2).split(" #", 1)[0].strip().rstrip(";").strip()
                                   .strip("\"'")]
                    for target in targets:
                        if m.group(1) == "import" and "/" not in target and "." not in target:
                            continue
                        if target:
                            add("include", rel, n, m.group(1), target,
                                _resolve(target, rel, read, root))
                    continue
            if config:
                if detectors.CERTIFICATE_FILE_SETTING.match(raw):
                    continue
                m = _SSH_KEY_SETTING.match(raw)
                setting, target = (m.group(1), m.group(2)) if m else (None, None)
                m = None if m else _CONFIG_KEY_SETTING.match(raw)
                if m:
                    setting, target = m.group(1) or m.group(2), m.group(3)
                if target:
                    add("key_file_path", rel, n, setting, target,
                        _resolve(target, rel, read, root))
            if code and _CODE_LOAD.search(raw):
                joined = _PATH_JOIN.search(raw)
                for lit in _LITERAL_KEY_PATH.finditer(raw):
                    add("key_file_path", rel, n, _CODE_LOAD.search(raw).group(1), lit.group(1),
                        {"status": "templated"} if joined
                        else _resolve(lit.group(1), rel, read, root))
            if "env" in raw or "ENV" in raw or "getenv" in raw.lower():
                for m in _ENV_KEY_READ.finditer(raw):
                    variable = m.group(1) or m.group(2)
                    add("key_file_from_environment", rel, n, "environment variable", variable,
                        {"status": "read_at_run_time"})
    items.sort(key=lambda i: (i["path"], i["line"], i["rule"], i["target"]))
    followed = sum(1 for i in items if i["status"] in _FOLLOWED)
    return {"meaning": LEADS_MEANING, "rules": LEAD_RULES, "count": len(items),
            "followed": followed, "not_followed": len(items) - followed, "items": items,
            "reported_elsewhere": elsewhere}


# --- 4. where to look ---------------------------------------------------------------------------

# The order of the kinds: a whole ecosystem no test closes first, then what the files point to
# and the scan could not read, then the angles that disagree, then the open operations of an
# ecosystem the catalogue holds in part, then the import comparisons that did not run.
KIND_ORDER = ("ecosystem_not_closed", "lead_not_followed", "contradiction",
              "ecosystem_partially_closed", "files_not_attributed", "angle_not_compared")
WHERE_MEANING = (
    "one list of the places above where this scan may miss, for a reviewer to read from the "
    "top: an ecosystem the closure catalogue holds nothing of (ecosystems), a lead not followed "
    "(chosen_outside_files.leads, and the certificate and trust-store files named outside the "
    "files read in tls_termination and trust_stores), a contradiction between angles (angles), "
    "an ecosystem held in part, the files read that belong to no ecosystem "
    "(ecosystems.not_attributed), and the comparisons that did not run")
WHERE_ORDER = (
    "first what is in production code, then what is only in test code; within each, by kind in "
    "the order of `kinds`; an ecosystem by its number of files, most first; the rest by path "
    "and line")


def _where_to_look(ecosystems: dict[str, Any], angles: dict[str, Any], leads: dict[str, Any],
                   result: dict[str, Any]) -> dict[str, Any]:
    rows: list[tuple[tuple, dict[str, Any]]] = []

    def add(kind: str, in_test: bool, weight: int, path: str, line: int, entry: dict) -> None:
        rows.append(((in_test, KIND_ORDER.index(kind), -weight, path, line,
                      entry.get("rule") or ""), {"kind": kind, **entry, "in_test_code": in_test}))

    for e in ecosystems["present"]:
        if e["status"] in ("not_closed", "partially_closed"):
            kind = ("ecosystem_not_closed" if e["status"] == "not_closed"
                    else "ecosystem_partially_closed")
            add(kind, e["only_in_test_code"], e["files"], e["ecosystem"], 0,
                {"ecosystem": e["ecosystem"], "files": e["files"], "example": e["example"],
                 "open_operations": e["open_operations"], "statement": e["may_miss"]})
    na = ecosystems.get("not_attributed") or {}
    if na.get("count"):
        add("files_not_attributed", na["only_in_test_code"], na["count"], "", 0,
            {"files": na["count"], "example": na["paths"][0], "statement": na["meaning"]})
    absent = {(c["path"], c["line"]) for c in angles["contradictions"]
              if c["rule"] == "named_key_file_absent"}
    for lead in leads["items"]:
        if lead["status"] in _FOLLOWED or (lead["path"], lead["line"]) in absent:
            continue
        add("lead_not_followed", lead["in_test_code"], 0, lead["path"], lead["line"],
            {"rule": lead["rule"], "path": lead["path"], "line": lead["line"],
             "target": lead["target"], "status": lead["status"],
             "statement": f"{lead['setting']} {lead['target']}: {lead['status']}"})
    for p in ((result.get("trust_stores") or {}).get("places") or []):
        if p.get("file") and not p.get("file_read"):
            add("lead_not_followed", p.get("in_test_code", False), 0, p["path"], p["line"],
                {"rule": "trust_stores", "path": p["path"], "line": p["line"],
                 "target": p["file"], "status": ("outside_the_tree" if p.get("outside_the_tree")
                                                 else "not_read"),
                 "statement": f"{p['setting']} {p['file']}: trust store not among the files "
                              f"read (trust_stores)"})
    for p in (((result.get("tls_termination") or {}).get("authentication_not_read") or {})
              .get("places") or []):
        add("lead_not_followed", detectors.in_test_code(p["path"]), 0, p["path"], p["line"],
            {"rule": "authentication_not_read", "path": p["path"], "line": p["line"],
             "target": p["file"], "status": "not_read",
             "statement": f"{p['setting']} {p['file']}: certificate or key not among the files "
                          f"read (tls_termination.authentication_not_read)"})
    for c in angles["contradictions"]:
        add("contradiction", c["in_test_code"], 0, c["path"], c["line"],
            {"rule": c["rule"], "path": c["path"], "line": c["line"],
             **({"package": c["package"]} if c.get("package") else {}),
             "statement": f"{c['kind']}: {c['statement']}"})
    for n in angles["not_compared"]:
        add("angle_not_compared", False, 0, n["ecosystem"], 0,
            {"ecosystem": n["ecosystem"], "statement": n["because"]})
    rows.sort(key=lambda r: r[0])
    items = [{"rank": i, **entry} for i, (_, entry) in enumerate(rows, 1)]
    return {"meaning": WHERE_MEANING, "order": WHERE_ORDER, "kinds": list(KIND_ORDER),
            "count": len(items), "items": items}


def annotate(result: dict[str, Any], root: Path) -> None:
    """The four sections, set on the finished result. Reads it; changes no row of it.

    Context only, so it can never fail a scan (review B1, 18.11): all four are built before any
    is set, and a failure leaves none of them and names its exception class -- not its message,
    which may quote the scanned text."""
    try:
        leads = _leads(result, root)
        ecosystems = _ecosystems(result, root)
        angles = _angles(result, root, leads["items"])
        where = _where_to_look(ecosystems, angles, leads, result)
    except Exception as error:  # noqa: BLE001 -- a context section must not end the scan
        result["adaptive_not_built"] = {
            "error": type(error).__name__,
            "statement": ("ecosystems, angles, chosen_outside_files.leads and where_to_look were "
                          "not built for this tree; the findings, the evidence and the exit code "
                          "do not depend on them")}
        return
    result["ecosystems"] = ecosystems
    result["angles"] = angles
    if isinstance(result.get("chosen_outside_files"), dict):
        result["chosen_outside_files"]["leads"] = leads
    result["where_to_look"] = where
