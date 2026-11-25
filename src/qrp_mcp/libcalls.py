"""Calls into a cryptographic library, read only in a file that imports it (release 0.54.0).

The pattern table in detectors.py reads names that mean one thing wherever they stand:
`secp256k1`, `ecrecover`, `Groth16`. A wallet library's calls do not: `Wallet.createRandom()`,
`Account.sign_message(...)`, `crypto.Sign(h, key)`, `signer.sign_message_sync(...)` are ECDSA over
secp256k1 only because of what the file imports, and `crypto.Sign` is Go's standard library in a
file that does not import go-ethereum. So each library here is read as `_vrf_calls` reads a VRF
library (row 535): only in a file that imports it, under the name it is bound to there.

A library (`Lib`) gives:
  * `modules`: what the file imports -- a Python or JS module (a sub-path counts), a Go import
    path, a Rust crate path;
  * `classes`: names exported by it whose every constructor and member is the cryptography
    (`Wallet`, `Account`, `PrivateKeySigner`): `Wallet.createRandom()`, `new Wallet(k)`,
    `PrivateKeySigner::random()`;
  * `functions`: names exported by it that are the cryptography when called (`verifyMessage`,
    `GenerateKey`);
  * `methods`: names that are the cryptography when called on a value the file got from the
    library (`w.signMessage(...)` where `w = Wallet.createRandom()`). A method name alone, on a
    receiver the file did not bind from the library, is not read: `cert.Verify(...)` is not BLS.

The bound name is what the file binds: an alias (`import ckzg`, `const e = require("ethers")`, a Go
package name or its alias), a named import (`from eth_account import Account`, `import { Wallet }
from "ethers"`, `use alloy_signer_local::PrivateKeySigner`), and in Rust the crate's own name
(`solana_sdk::signature::Keypair::new()` needs no `use`). A receiver is a variable assigned from an
expression headed by a bound name or by another receiver (`hd = HDNodeWallet.fromPhrase(p)`,
`child = hd.derivePath(path)`).

Every library is listed with the page its names come from; a name not on that page is marked И
(inferred) beside it. The rows this module adds carry evidence_kind `call` (or `import` on the
import line), the library's family and, where the library has one curve only, that curve.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Lib:
    lang: str                      # "py", "js", "go", "rs"
    modules: tuple[str, ...]
    family: str
    curve: str | None
    what: str                      # the library, as the description names it
    classes: tuple[str, ...] = ()
    functions: tuple[str, ...] = ()
    methods: tuple[str, ...] = ()
    # Go: the package name a path is bound to when it is imported without an alias.
    go_names: dict[str, str] = field(default_factory=dict)


_EXT = {".py": "py", ".pyi": "py", ".js": "js", ".mjs": "js", ".cjs": "js", ".ts": "js",
        ".tsx": "js", ".jsx": "js", ".mts": "js", ".cts": "js", ".go": "go", ".rs": "rs"}

LIBRARIES: list[Lib] = []


def register(*libs: Lib) -> None:
    LIBRARIES.extend(libs)


# ---- imports ---------------------------------------------------------------------------------

def _module_re(modules: tuple[str, ...], sep: str) -> str:
    # The module itself or a sub-path of it.
    return "(?:" + "|".join(re.escape(m) for m in modules) + ")(?:" + re.escape(sep) + r"[\w.@/-]*)?"


def _split_names(text: str, as_word: str) -> list[str]:
    """`a, b as c` / `a, b: c` -> the names bound: a, c."""
    out = []
    for part in text.replace("\n", " ").split(","):
        part = part.strip().strip("{}()").strip()
        if not part or part == "*":
            continue
        if as_word == ":" and ":" in part:
            out.append(part.split(":", 1)[1].strip())
        elif re.search(rf"\s{as_word}\s", part):
            out.append(part.split(f" {as_word} ", 1)[1].strip())
        else:
            out.append(part.split()[-1] if part.split() else part)
    return [n for n in out if re.fullmatch(r"[A-Za-z_$][\w$]*", n)]


def _imports(lib: Lib, text: str) -> tuple[set[str], set[str], list[int]]:
    """(aliases, named, import line numbers) the file binds for `lib`."""
    aliases: set[str] = set()
    named: set[str] = set()
    lines: list[int] = []

    def at(m: re.Match) -> None:
        lines.append(text.count("\n", 0, m.start()) + 1)

    if lib.lang == "py":
        mod = _module_re(lib.modules, ".")
        for m in re.finditer(rf"(?m)^[ \t]*import[ \t]+({mod})(?:[ \t]+as[ \t]+(\w+))?[ \t]*$", text):
            aliases.add(m.group(2) or m.group(1).split(".")[0])
            if not m.group(2):
                aliases.add(m.group(1))
            at(m)
        for m in re.finditer(rf"(?m)^[ \t]*from[ \t]+({mod})[ \t]+import[ \t]+(\([^)]*\)|[^\n#]+)", text):
            named.update(_split_names(m.group(2), "as"))
            at(m)
    elif lib.lang == "js":
        mod = _module_re(lib.modules, "/")
        q = r"[\"']"
        for m in re.finditer(rf"\b(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?require\(\s*{q}{mod}{q}\s*\)", text):
            aliases.add(m.group(1))
            at(m)
        for m in re.finditer(rf"\b(?:const|let|var)\s*\{{([^}}]*)\}}\s*=\s*(?:await\s+)?require\(\s*{q}{mod}{q}\s*\)", text):
            named.update(_split_names(m.group(1), ":"))
            at(m)
        for m in re.finditer(rf"(?m)^[ \t]*import\s+([^;'\"]*?)\s+from\s+{q}{mod}{q}", text):
            clause = m.group(1)
            star = re.search(r"\*\s+as\s+(\w+)", clause)
            if star:
                aliases.add(star.group(1))
            braces = re.search(r"\{([^}]*)\}", clause)
            if braces:
                named.update(_split_names(braces.group(1), "as"))
            default = re.match(r"\s*(?:type\s+)?([A-Za-z_$][\w$]*)\s*(?:,|$)", clause)
            if default and default.group(1) != "type":
                aliases.add(default.group(1))
            at(m)
    elif lib.lang == "go":
        for path in lib.modules:
            for m in re.finditer(r"(?m)^[ \t]*(?:import[ \t]+)?(?:(\w+)[ \t]+)?\"" + re.escape(path)
                                 + r"\"", text):
                alias = m.group(1)
                if alias == "_":
                    continue
                aliases.add(alias or lib.go_names.get(path) or path.rstrip("/").split("/")[-1])
                at(m)
    elif lib.lang == "rs":
        crates = [m.split("::")[0] for m in lib.modules]
        aliases.update(crates)
        mod = "(?:" + "|".join(re.escape(m) for m in lib.modules) + r")(?:::\w+)*"
        for m in re.finditer(rf"(?m)^[ \t]*(?:pub[ \t]+)?use[ \t]+({mod})::\{{([^}}]*)\}}", text):
            named.update(_split_names(m.group(2), "as"))
            at(m)
        for m in re.finditer(rf"(?m)^[ \t]*(?:pub[ \t]+)?use[ \t]+({mod})::(\w+)(?:[ \t]+as[ \t]+(\w+))?[ \t]*;", text):
            named.add(m.group(3) or m.group(2))
            at(m)
        for m in re.finditer(rf"(?m)^[ \t]*(?:pub[ \t]+)?use[ \t]+({mod})(?:[ \t]+as[ \t]+(\w+))?[ \t]*;", text):
            if m.group(2):
                aliases.add(m.group(2))
            at(m)
        for m in re.finditer(rf"(?m)^[ \t]*(?:pub[ \t]+)?use[ \t]+({mod})::\*[ \t]*;", text):
            named.update(lib.classes + lib.functions)
            at(m)
    return aliases, named, sorted(set(lines))


# ---- calls -----------------------------------------------------------------------------------

_COMMENT_START = {"py": ("#",), "js": ("//", "/*", "*"), "go": ("//", "/*", "*"), "rs": ("//", "/*", "*")}
_STRING = re.compile(r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|`[^`]*`")


def _code(line: str, lang: str) -> str:
    text = _STRING.sub(lambda m: '""', line)
    marker = "#" if lang == "py" else "//"
    return text.split(marker, 1)[0]


def _alt(names) -> str:
    return "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))


def _call_patterns(lib: Lib, aliases: set[str], named: set[str], receivers: set[str]) -> list[re.Pattern]:
    sep = r"(?:\.|::)"
    pats: list[str] = []
    members = list(lib.classes) + list(lib.functions)
    if aliases and members:
        # alias.Class..., alias.function(...), with sub-modules between (`ethers.utils.SigningKey`).
        cls = _alt(lib.classes) if lib.classes else None
        fns = _alt(lib.functions) if lib.functions else None
        body = []
        if cls:
            body.append(rf"(?:{cls})\b")
        if fns:
            body.append(rf"(?:{fns})\s*(?:<[^>()]*>\s*)?\(")
        pats.append(rf"(?<![\w.$])(?:{_alt(aliases)})(?:{sep}\w+)*?{sep}(?:{'|'.join(body)})")
    named_classes = named & set(lib.classes)
    named_functions = named & set(lib.functions)
    if named_classes:
        pats.append(rf"(?<![\w.$])(?:new\s+)?(?:{_alt(named_classes)})(?:\s*{sep}\s*\w+|\s*(?:<[^>()]*>\s*)?\()")
        # Rust: `Groth16::<Bn254>::prove`
        pats.append(rf"(?<![\w.$])(?:{_alt(named_classes)})::<[^>]*>::\w+")
    if named_functions:
        pats.append(rf"(?<![\w.$])(?:{_alt(named_functions)})\s*(?:<[^>()]*>\s*)?\(")
    if receivers and lib.methods:
        pats.append(rf"(?<![\w.$])(?:{_alt(receivers)})(?:\s*\.\s*\w+(?:\(\s*\))?)*?\s*\.\s*(?:{_alt(lib.methods)})\s*(?:<[^>()]*>\s*)?\(")
    return [re.compile(p) for p in pats]


_ASSIGN = {
    "py": re.compile(r"^\s*(\w+)\s*(?::[^=]+)?=(?!=)\s*(?:await\s+)?(.+)$"),
    "js": re.compile(r"^\s*(?:(?:const|let|var)\s+)?(\w+)\s*(?::[^=]+)?=(?![=>])\s*(?:await\s+)?(?:new\s+)?(.+)$"),
    "go": re.compile(r"^\s*(?:var\s+)?(\w+)(?:\s*,\s*\w+)*\s*:?=(?!=)\s*(.+)$"),
    "rs": re.compile(r"^\s*let\s+(?:mut\s+)?\(?\s*(?:mut\s+)?(\w+)(?:\s*,[^)=]*)?\)?\s*(?::[^=]+)?=(?!=)\s*(.+)$"),
}


def _receivers(lib: Lib, lines: list[str], aliases: set[str], named: set[str]) -> set[str]:
    """Variables assigned from the library: from a bound name, then from those, to a fixed point."""
    if not lib.methods:
        return set()
    heads = set(aliases) | (named & (set(lib.classes) | set(lib.functions)))
    assigns = []
    for line in lines:
        m = _ASSIGN[lib.lang].match(_code(line, lib.lang))
        if m:
            head = re.match(r"\(?\s*(?:new\s+)?(\w+)", m.group(2))
            if head:
                assigns.append((m.group(1), head.group(1)))
    found: set[str] = set()
    while True:
        more = {var for var, head in assigns if (head in heads or head in found) and var not in found}
        if not more:
            return found - {"_"}
        found |= more


def calls(findings: list[dict[str, Any]], lines: list[str], rel_path: str, ext: str,
          in_test_code) -> list[dict[str, Any]]:
    lang = _EXT.get(ext)
    if lang is None or not lines:
        return findings
    text = "\n".join(lines)
    added: list[dict[str, Any]] = []
    for lib in LIBRARIES:
        if lib.lang != lang or not any(m.split("::")[0] in text for m in lib.modules):
            continue
        aliases, named, import_lines = _imports(lib, text)
        if lang == "rs":
            # The crate's own name counts only where it is used as a path (`solana_sdk::...`).
            aliases = {a for a in aliases if re.search(rf"(?<![\w:]){re.escape(a)}::", text)}
        if not (aliases or named):
            continue
        receivers = _receivers(lib, lines, aliases, named)
        patterns = _call_patterns(lib, aliases, named, receivers)
        if not patterns and not import_lines:
            continue
        here = {}
        for f in findings + added:
            if f["algorithm"] == lib.family:
                here.setdefault(f["line"], f)
        for n, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if not stripped or stripped.startswith(_COMMENT_START[lang]):
                continue
            if n in import_lines:
                kind = "import"
            elif any(p.search(_code(line, lang)) for p in patterns):
                kind = "call"
            else:
                continue
            held = here.get(n)
            if held is not None:
                if kind == "call" and held.get("evidence_kind") in ("import", "identifier",
                                                                   "declaration", "reference"):
                    held["evidence_kind"] = "call"
                if lib.curve and not held.get("curve"):
                    held["curve"] = lib.curve
                continue
            item = {"path": rel_path, "line": n, "algorithm": lib.family,
                    "description": (f"{lib.family} usage ({lib.what}, which this file imports)"
                                    if kind == "import" else
                                    f"{lib.family} usage (a call into {lib.what}, which this file "
                                    f"imports)"),
                    "excerpt": line.strip()[:200], "evidence_kind": kind,
                    "in_test_code": in_test_code(rel_path)}
            if lib.curve:
                item["curve"] = lib.curve
            added.append(item)
            here[n] = item
    return sorted(findings + added, key=lambda f: f["line"]) if added else findings


# ---- the libraries ---------------------------------------------------------------------------
# Rows 562, 563: pairing-based cryptography whose calls carry no curve or scheme word. Names that
# do (bn254, Groth16, KZG, snarkjs) are read by the pattern table wherever they stand.
register(
    # py_ecc: "Elliptic curve crypto in python including secp256k1, alt_bn128, and bls12_381"
    # (README). The modules are pairing curves; `pairing` is their pairing (И: the function is not
    # on the saved README page).
    Lib("py", ("py_ecc.optimized_bn128", "py_ecc.bn128"), "Pairing", "BN254",
        "py_ecc's alt_bn128 pairing", functions=("pairing", "final_exponentiate")),
    Lib("py", ("py_ecc.optimized_bls12_381", "py_ecc.bls12_381"), "Pairing", "BLS12-381",
        "py_ecc's BLS12-381 pairing", functions=("pairing", "final_exponentiate")),
    # gnark "currently supports: Groth16, PLONK" (README); the PLONK backend's package path and its
    # Setup/Prove/Verify are И (the README shows the Groth16 ones).
    Lib("go", ("github.com/consensys/gnark/backend/plonk",), "Pairing", None,
        "gnark's PLONK backend", functions=("Setup", "Prove", "Verify")),
)
