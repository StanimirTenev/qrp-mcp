"""Operation `rng_source`: the random number generators the code calls, as context (ZA-OPRAVYANE rows
531 and 539; design in rng-prouchvane/02-dizajn.md, 19.11.2026).

Each call is a row in one of three classes, from the generator's own documentation (the catalogue,
data/operations/rng_source.toml, cites the page and quotes it for every spelling):

- `weak`: a non-cryptographic PRNG (Python `random`, Go `math/rand`, `java.util.Random`, `Math.random`,
  C `rand`, `std::mt19937`, `System.Random`, PHP `rand`/`mt_rand`, ...);
- `csprng`: a named cryptographic generator (`secrets`, `os.urandom`, `crypto/rand`, `SecureRandom`,
  `getRandomValues`, `getrandom`, `arc4random`, `RAND_bytes`, `RandomNumberGenerator`, `random_int`);
- `check`: a call its documentation does not settle by itself (`std::random_device`, SHA1PRNG with
  `setSeed`, a literal seed into a CSPRNG API, Go's ChaCha8, a generator named in a variable).

The section is built on the finished result, after `findings_fingerprint`, and outside `evidence`:
a row is no finding, carries no classification of the code and moves neither the findings, their
fingerprint, a gate nor the exit code. Every field but `path` and `excerpt` holds a value from a
closed list (an API name of the catalogue, a class, a reason, a standard algorithm name); no
literal, variable name or other source text is copied into one.

The rules credit the prior art they were checked against, without taking code from any of it:
Bandit B311, gosec G404, CodeQL's insecure-randomness queries, Sonar S2245, Semgrep, FindSecBugs,
CA5394. The API names come from the documentation pages the catalogue cites.
"""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Any

from . import detectors

MEANING = (
    "the random number generators the code calls, each row in one class from the generator's own "
    "documentation: `weak` -- a non-cryptographic PRNG; `csprng` -- a named cryptographic "
    "generator; `check` -- a call its documentation does not settle by itself (`why` says which). "
    "The spellings read, with the page each comes from, are the rng_source catalogue "
    "(operation_closure). Context only: a row is no finding and no verdict on the code, and it does "
    "not affect the findings, their fingerprint, a gate or the exit code")

# Where each ecosystem is read. PHP's label also covers Ruby in `ecosystems`; only .php is read here.
_SUFFIXES = {
    "Py": (".py",),
    "Go": (".go",),
    "Java": (".java", ".kt"),
    "JS": (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts"),
    "C": (".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp"),
    "NET": (".cs", ".vb"),
    "PHP": (".php",),
}
_ECOSYSTEM = {s: eco for eco, suffixes in _SUFFIXES.items() for s in suffixes}
# A file is read line by line only if it holds one of these (or, for Go and Python, an alias the
# file imports a generator under).
_FILE_HINTS = {
    "Py": ("random", "secrets", "urandom", "getrandom"),
    "Go": ("math/rand", "crypto/rand"),
    "Java": ("Random", "Math.random"),
    "JS": ("Math.random", "getRandomValues", "crypto"),
    "C": ("rand", "mt19937", "random_device", "RAND_", "arc4random"),
    "NET": ("Random", "RNGCryptoServiceProvider"),
    "PHP": ("rand", "random_"),
}
_STRING = re.compile(r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'|`[^`\n]*`')
_BLOCK = re.compile(r"/\*.*?\*/")
_LITERAL_ARG = re.compile(r"\s*(?:-?\d|0x|[\"'`]|new\s+byte\s*\[\s*\]\s*\{|\{)")


def _blank(match: re.Match[str]) -> str:
    text = match.group(0)
    return text[0] + " " * (len(text) - 2) + text[-1]


def _code_lines(text: str, eco: str):
    """(line number, original line, the line with string contents blanked and comments removed),
    for every line that may hold a call. Positions in the two lines are the same."""
    hash_comment = eco in ("Py", "PHP")
    slash_comment = eco != "Py"
    in_block = False
    for number, line in enumerate(text.splitlines(), 1):
        code = _STRING.sub(_blank, line)
        if slash_comment:
            if in_block:
                end = code.find("*/")
                if end < 0:
                    continue
                code = " " * (end + 2) + code[end + 2:]
                in_block = False
            code = _BLOCK.sub(lambda m: " " * len(m.group(0)), code)
            start = code.find("/*")
            if start >= 0:
                code, in_block = code[:start], True
            cut = code.find("//")
            if cut >= 0:
                code = code[:cut]
        if hash_comment:
            cut = code.find("#")
            if cut >= 0:
                code = code[:cut]
        if code.strip():
            yield number, line, code


def _literal_after(code: str, end: int) -> bool:
    """Whether the first argument of the call whose `(` ends at `end` is written as a literal."""
    return bool(_LITERAL_ARG.match(code, end))


def _first_string(line: str, code: str, end: int) -> str | None:
    """The contents of a string literal that is the first argument after `end`, or None."""
    match = re.compile(r"\s*([\"'])").match(code, end)
    if not match:
        return None
    start = match.end()
    close = code.find(match.group(1), start)
    return line[start:close] if close > 0 else None


# --- Python -----------------------------------------------------------------------------------------

# The module-level functions and the class of `random` (docs.python.org/3/library/random.html).
_PY_RANDOM = frozenset((
    "seed", "getstate", "setstate", "randbytes", "randrange", "randint", "getrandbits", "choice",
    "choices", "shuffle", "sample", "binomialvariate", "random", "uniform", "triangular",
    "betavariate", "expovariate", "gammavariate", "gauss", "lognormvariate", "normalvariate",
    "vonmisesvariate", "paretovariate", "weibullvariate", "Random"))
# docs.python.org/3/library/secrets.html
_PY_SECRETS = frozenset(("token_bytes", "token_hex", "token_urlsafe", "randbelow", "randbits",
                         "choice", "SystemRandom"))
_PY_MODULES = ("random", "numpy", "numpy.random", "secrets", "os")
_PY_SEEDING = {"random.seed", "random.Random", "numpy.random"}
_PY_CALL = re.compile(r"(?<![\w.])([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*)\s*\(")
_PY_IMPORT = re.compile(r"^\s*import\s+([^#;]+)", re.M)
_PY_FROM = re.compile(r"^\s*from\s+([\w.]+)\s+import\s+\(?([^#;)]+)", re.M)


def _py_names(text: str) -> tuple[dict[str, str], dict[str, str]]:
    modules: dict[str, str] = {}
    names: dict[str, str] = {}
    for match in _PY_IMPORT.finditer(text):
        for part in match.group(1).split(","):
            bits = part.split()
            if not bits:
                continue
            module = bits[0]
            alias = bits[2] if len(bits) >= 3 and bits[1] == "as" else module.split(".")[0]
            if module in _PY_MODULES:
                modules[alias] = module if len(bits) >= 3 else module.split(".")[0]
    for match in _PY_FROM.finditer(text):
        module = match.group(1)
        for part in match.group(2).replace("\n", " ").split(","):
            bits = part.split()
            if not bits:
                continue
            alias = bits[2] if len(bits) >= 3 and bits[1] == "as" else bits[0]
            full = f"{module}.{bits[0]}"
            if full in _PY_MODULES:
                modules[alias] = full
            elif module in _PY_MODULES:
                names[alias] = full
    return modules, names


def _py_class(full: str) -> tuple[str, str] | None:
    if full.startswith("numpy.random."):
        return "numpy.random", "weak"
    module, _, attr = full.rpartition(".")
    if module == "random":
        if attr == "SystemRandom":
            return full, "csprng"
        if attr in _PY_RANDOM:
            return full, "weak"
    if module == "secrets" and attr in _PY_SECRETS:
        return full, "csprng"
    if full in ("os.urandom", "os.getrandom"):
        return full, "csprng"
    return None


def _python(text: str, rel: str):
    modules, names = _py_names(text)
    if not modules and not names:
        return
    aliases = tuple(modules) + tuple(names)
    for number, line, code in _code_lines(text, "Py"):
        if not any(a in code for a in aliases):
            continue
        for match in _PY_CALL.finditer(code):
            parts = [p.strip() for p in match.group(1).split(".")]
            if len(parts) == 1 and parts[0] in names:
                full = names[parts[0]]
            elif len(parts) > 1 and parts[0] in modules:
                full = ".".join([modules[parts[0]], *parts[1:]])
            else:
                continue
            said = _py_class(full)
            if said:
                api, cls = said
                extra = {}
                if api in _PY_SEEDING and _literal_after(code, match.end()):
                    extra["seed"] = "literal"
                yield number, line, match.start(), api, cls, extra


# --- Go ---------------------------------------------------------------------------------------------

# The exported functions of each package (pkg.go.dev/math/rand, /math/rand/v2, /crypto/rand); for
# crypto/rand the variable Reader too.
_GO_EXPORTS = {
    "math/rand": frozenset((
        "ExpFloat64", "Float32", "Float64", "Int", "Int31", "Int31n", "Int63", "Int63n", "Intn",
        "NormFloat64", "Perm", "Read", "Seed", "Shuffle", "Uint32", "Uint64", "New", "NewSource",
        "NewZipf")),
    "math/rand/v2": frozenset((
        "ExpFloat64", "Float32", "Float64", "Int", "Int32", "Int32N", "Int64", "Int64N", "IntN", "N",
        "NormFloat64", "Perm", "Shuffle", "Uint", "Uint32", "Uint32N", "Uint64", "Uint64N", "UintN",
        "New", "NewPCG", "NewChaCha8", "NewZipf")),
    "crypto/rand": frozenset(("Read", "Reader", "Int", "Prime", "Text")),
}
_GO_SEEDING = {"Seed", "NewSource", "NewPCG"}
_GO_IMPORT = re.compile(r'(?:^|[\s(;])(?:([A-Za-z_]\w*|\.)\s+)?"(math/rand(?:/v2)?|crypto/rand)"')


def _go(text: str, rel: str):
    aliases: dict[str, str] = {}
    for match in _GO_IMPORT.finditer(text):
        path, alias = match.group(2), match.group(1)
        # `import "math/rand"` puts the keyword where an alias would be.
        if alias in (None, "import"):
            alias = "rand"
        if alias not in (".", "_"):
            aliases[alias] = path
    if not aliases:
        return
    pattern = re.compile(r"(?<![\w.])(" + "|".join(map(re.escape, aliases)) + r")\.([A-Z]\w*)\b")
    for number, line, code in _code_lines(text, "Go"):
        for match in pattern.finditer(code):
            path, name = aliases[match.group(1)], match.group(2)
            if name not in _GO_EXPORTS[path]:
                continue
            after = code[match.end():].lstrip()
            if name != "Reader" and not after.startswith("("):
                continue
            extra: dict[str, Any] = {}
            if path == "crypto/rand":
                cls = "csprng"
            elif name == "NewChaCha8":
                cls, extra["why"] = "check", "strong_type_in_a_package_not_for_security"
            else:
                cls = "weak"
            if name in _GO_SEEDING and _literal_after(code, code.index("(", match.end()) + 1):
                extra["seed"] = "literal"
            yield number, line, match.start(), f"{path}.{name}", cls, extra


# --- Java and Kotlin --------------------------------------------------------------------------------

# docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html
_JAVA_SECURE_RANDOM_NAMES = frozenset((
    "NativePRNG", "NativePRNGBlocking", "NativePRNGNonBlocking", "PKCS11", "DRBG", "SHA1PRNG",
    "Windows-PRNG"))
_JAVA_UTIL_IMPORT = re.compile(r"(?:^|;)\s*import\s+java\.util\.(?:Random|\*)\s*(?:;|$)", re.M)
_JAVA_NEW_RANDOM = re.compile(r"(?:\bnew\s+(java\.util\.)?|(?<![\w.])(java\.util\.)?)Random\s*\(")
_JAVA_RULES = (
    (re.compile(r"(?<![\w.])ThreadLocalRandom\s*\.\s*current\s*\("),
     "java.util.concurrent.ThreadLocalRandom", "weak"),
    (re.compile(r"(?<![\w.])(?:java\.lang\.)?Math\s*\.\s*random\s*\("), "java.lang.Math.random",
     "weak"),
    (re.compile(r"(?<![\w.])(?:java\.security\.)?SecureRandom\s*\.\s*getInstanceStrong\s*\("),
     "java.security.SecureRandom.getInstanceStrong", "csprng"),
)
_JAVA_NEW_SECURE = re.compile(r"\bnew\s+(?:java\.security\.)?SecureRandom\s*\(")
_JAVA_GET_INSTANCE = re.compile(r"(?<![\w.])(?:java\.security\.)?SecureRandom\s*\.\s*getInstance\s*\(")
_JAVA_SET_SEED = re.compile(r"\.\s*setSeed\s*\(")


def _java(text: str, rel: str):
    util_random = bool(_JAVA_UTIL_IMPORT.search(text))
    kotlin = rel.endswith(".kt")
    secure_in_file = "SecureRandom" in text
    sets_seed = secure_in_file and bool(_JAVA_SET_SEED.search(text))
    for number, line, code in _code_lines(text, "Java"):
        for match in _JAVA_NEW_RANDOM.finditer(code):
            qualified = bool(match.group(1) or match.group(2))
            if not (qualified or util_random):
                continue
            if not kotlin and not match.group(0).startswith("new"):
                continue
            extra = {"seed": "literal"} if _literal_after(code, match.end()) else {}
            yield number, line, match.start(), "java.util.Random", "weak", extra
        for pattern, api, cls in _JAVA_RULES:
            for match in pattern.finditer(code):
                yield number, line, match.start(), api, cls, {}
        if not secure_in_file:
            continue
        for match in _JAVA_NEW_SECURE.finditer(code):
            rest = code[match.end():].lstrip()
            if rest.startswith(")"):
                yield number, line, match.start(), "java.security.SecureRandom", "csprng", {}
            elif _literal_after(code, match.end()):
                yield (number, line, match.start(), "java.security.SecureRandom", "check",
                       {"why": "fixed_seed", "seed": "literal"})
            else:
                yield (number, line, match.start(), "java.security.SecureRandom", "csprng",
                       {"seed": "supplied"})
        for match in _JAVA_GET_INSTANCE.finditer(code):
            api = "java.security.SecureRandom.getInstance"
            name = _first_string(line, code, match.end())
            if name is None:
                yield (number, line, match.start(), api, "check",
                       {"why": "algorithm_chosen_at_run_time"})
                continue
            known = name if name in _JAVA_SECURE_RANDOM_NAMES else "not_a_standard_name"
            if name == "SHA1PRNG" and sets_seed:
                yield (number, line, match.start(), api, "check",
                       {"algorithm": known, "why": "sha1prng_with_setseed"})
            else:
                yield number, line, match.start(), api, "csprng", {"algorithm": known}
        for match in _JAVA_SET_SEED.finditer(code):
            if _literal_after(code, match.end()):
                yield (number, line, match.start(), "java.security.SecureRandom.setSeed", "check",
                       {"why": "fixed_seed", "seed": "literal"})


# --- JavaScript and TypeScript ----------------------------------------------------------------------

_JS_RULES = (
    (re.compile(r"(?<![\w.$])Math\s*\.\s*random\s*\("), "Math.random", "weak", {}),
    (re.compile(r"\.\s*getRandomValues\s*\("), "crypto.getRandomValues", "csprng", {}),
    (re.compile(r"(?<![\w.$])crypto\s*\.\s*pseudoRandomBytes\s*\("), "crypto.pseudoRandomBytes",
     "check", {"why": "deprecated_alias"}),
)
_JS_NODE = re.compile(
    r"(?<![\w.$])crypto\s*\.\s*(randomBytes|randomFillSync|randomFill|randomInt|randomUUID)\s*\(")


def _js(text: str, rel: str):
    for number, line, code in _code_lines(text, "JS"):
        for pattern, api, cls, extra in _JS_RULES:
            for match in pattern.finditer(code):
                yield number, line, match.start(), api, cls, dict(extra)
        for match in _JS_NODE.finditer(code):
            yield number, line, match.start(), f"crypto.{match.group(1)}", "csprng", {}


# --- C and C++ --------------------------------------------------------------------------------------

_C_START = r"(?:^|(?<=[^\w.>:$]))"
_C_RULES = (
    (re.compile(_C_START + r"(?:std::|::)?rand\s*\(\s*\)"), "rand", "weak", {}),
    (re.compile(_C_START + r"(?:std::|::)?srand\s*\("), "srand", "weak", {}),
    (re.compile(_C_START + r"rand_r\s*\("), "rand_r", "weak", {}),
    (re.compile(r"(?<![\w.>])(?:std::)?mt19937_64\b"), "std::mt19937_64", "weak", {}),
    (re.compile(r"(?<![\w.>])(?:std::)?mt19937\b(?!_)"), "std::mt19937", "weak", {}),
    (re.compile(r"(?<![\w.>])(?:std::)?random_device\b"), "std::random_device", "check",
     {"why": "may_be_a_prng"}),
    (re.compile(_C_START + r"getrandom\s*\("), "getrandom", "csprng", {}),
    (re.compile(r"(?<![\w.>])arc4random_buf\s*\("), "arc4random_buf", "csprng", {}),
    (re.compile(r"(?<![\w.>])arc4random_uniform\s*\("), "arc4random_uniform", "csprng", {}),
    (re.compile(r"(?<![\w.>])arc4random\s*\("), "arc4random", "csprng", {}),
)
_C_OPENSSL = re.compile(r"(?<![\w.>])(RAND_bytes|RAND_priv_bytes)(_ex)?\s*\(")
_C_EVP_RAND = re.compile(r"(?<![\w.>])EVP_RAND_fetch\s*\(")
# docs/man7/EVP_RAND-{CTR,HASH,HMAC}-DRBG.pod; the right side is the CycloneDX registry's name.
_OPENSSL_DRBG = {"CTR-DRBG": "CTR_DRBG", "HASH-DRBG": "Hash_DRBG", "HMAC-DRBG": "HMAC_DRBG"}
_C_SECOND_STRING = re.compile(r"\(\s*[^,()]*,\s*\"([A-Z0-9-]+)\"")


def _c(text: str, rel: str):
    for number, line, code in _code_lines(text, "C"):
        for pattern, api, cls, extra in _C_RULES:
            for match in pattern.finditer(code):
                said = dict(extra)
                if api == "srand" and _literal_after(code, match.end()):
                    said["seed"] = "literal"
                if api == "getrandom" and "GRND_NONBLOCK" in code:
                    said["nonblocking"] = True
                yield number, line, match.start(), api, cls, said
        for match in _C_OPENSSL.finditer(code):
            yield number, line, match.start(), match.group(1) + (match.group(2) or ""), "csprng", {}
        for match in _C_EVP_RAND.finditer(code):
            named = _C_SECOND_STRING.match(line, match.end() - 1)
            if named and named.group(1) in _OPENSSL_DRBG:
                yield (number, line, match.start(), "EVP_RAND_fetch", "csprng",
                       {"drbg_family": _OPENSSL_DRBG[named.group(1)]})
            elif not named:
                yield (number, line, match.start(), "EVP_RAND_fetch", "check",
                       {"why": "algorithm_chosen_at_run_time"})


# --- .NET -------------------------------------------------------------------------------------------

_NET_RULES = (
    (re.compile(r"(?<![\w.])(?:System\.)?Random\s*\.\s*Shared\b"), "System.Random.Shared", "weak"),
    (re.compile(r"(?<![\w.])(?:System\.Security\.Cryptography\.)?RandomNumberGenerator\s*\.\s*"
                r"(?:Create|GetBytes|GetNonZeroBytes|Fill|GetInt32|GetHexString|GetString|"
                r"GetItems|Shuffle)\s*\("),
     "System.Security.Cryptography.RandomNumberGenerator", "csprng"),
    (re.compile(r"\bnew\s+(?:System\.Security\.Cryptography\.)?RNGCryptoServiceProvider\s*\(",
                re.I), "System.Security.Cryptography.RNGCryptoServiceProvider", "csprng"),
)
_NET_NEW_RANDOM = re.compile(r"\bnew\s+(?:System\.)?Random\s*\(", re.I)


def _dotnet(text: str, rel: str):
    for number, line, code in _code_lines(text, "NET"):
        for match in _NET_NEW_RANDOM.finditer(code):
            extra = {"seed": "literal"} if _literal_after(code, match.end()) else {}
            yield number, line, match.start(), "System.Random", "weak", extra
        for pattern, api, cls in _NET_RULES:
            for match in pattern.finditer(code):
                yield number, line, match.start(), api, cls, {}


# --- PHP --------------------------------------------------------------------------------------------

_PHP_CALL = re.compile(r"(?:^|(?<=[^\w$>:\\]))\\?(rand|mt_rand|srand|mt_srand|random_int|random_bytes)"
                       r"\s*\(")
_PHP_DECLARATION = re.compile(r"\bfunction\s*&?\s*$")


def _php(text: str, rel: str):
    for number, line, code in _code_lines(text, "PHP"):
        for match in _PHP_CALL.finditer(code):
            if _PHP_DECLARATION.search(code, 0, match.start()):
                continue
            name = match.group(1)
            cls = "csprng" if name.startswith("random_") else "weak"
            extra = ({"seed": "literal"} if name in ("srand", "mt_srand")
                     and _literal_after(code, match.end()) else {})
            yield number, line, match.start(), name, cls, extra


_READERS = {"Py": _python, "Go": _go, "Java": _java, "JS": _js, "C": _c, "NET": _dotnet,
            "PHP": _php}


def _read(root: Path, rel: str) -> str:
    try:
        with open(root / rel, encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def _rows(result: dict[str, Any], root: Path, texts: dict[str, tuple[str, str]],
          columns: list[tuple[int, str]]) -> list[dict[str, Any]]:
    """The rows; `texts` gets each file read that holds one, `columns` the column of each row and
    its line as matched, in the order of the rows returned."""
    rows: list[tuple[dict[str, Any], tuple[int, str]]] = []
    for rel in result.get("files_read") or []:
        eco = _ECOSYSTEM.get(PurePosixPath(rel).suffix.lower())
        if not eco:
            continue
        text = _read(root, rel)
        if not any(hint in text for hint in _FILE_HINTS[eco]):
            continue
        seen: set[tuple[int, int]] = set()
        code_of = {n: c for n, _, c in _code_lines(text, eco)}
        for number, line, column, api, cls, extra in _READERS[eco](text, rel):
            if (number, column) in seen:
                continue
            seen.add((number, column))
            texts[rel] = (text, eco)
            rows.append(({"path": rel, "line": number, "ecosystem": eco, "class": cls, "api": api,
                          **extra, "excerpt": line.strip()[:200],
                          "in_test_code": detectors.in_test_code(rel)},
                         (column, code_of.get(number, ""))))
    rows.sort(key=lambda r: (r[0]["path"], r[0]["line"], r[0]["api"]))
    columns.extend(c for _, c in rows)
    return [r for r, _ in rows]


# --- places to check ---------------------------------------------------------------------------------

PLACES_MEANING = (
    "a `weak` or `check` generator in the same line, function or file as an anchor: a public-key "
    "operation this scan reports (`public_key_operation` -- a key generation, a signature or a key "
    "exchange; the scan does not tell them apart), or its value assigned on that line to a name "
    "whose words include key, seed, nonce or iv (`assigned_to_name`). `link_scope` is the narrowest "
    "of same_line, same_function and same_file that holds; a function is a `def` block in Python and "
    "the innermost brace block opened after `)` or `=>` elsewhere, a heuristic. The link is "
    "co-location: no value is followed from the generator to the key, so a place is a place to "
    "check, not a finding and not a verdict. A `csprng` row is never a place")
# Our own list: the four kinds of value FIPS 203/204 and SP 800-90A name a generator for.
_KEY_WORDS = frozenset(("key", "keys", "seed", "seeds", "nonce", "nonces", "iv", "ivs"))
_WORD = {"keys": "key", "seeds": "seed", "nonces": "nonce", "ivs": "iv"}
_ANCHOR_CLASSES = frozenset(("classical_vulnerable", "pqc_ready", "pqc_pre_standard"))
_ASSIGNED = re.compile(r"([A-Za-z_$][\w$]*)\s*(?:\[[^\]]*\])?\s*(?::\s*[\w\[\]., ]+)?(?::=|=)\s*$")
_NAME_PARTS = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")
_SCOPES = ("same_line", "same_function", "same_file")
_NOT_HEADER = re.compile(r"^(?:if|for|foreach|while|switch|catch|using|lock|synchronized|with|"
                         r"else\s+if|elseif|return)\b")


def _name_word(code: str, column: int) -> str | None:
    """The word of _KEY_WORDS in the name the call at `column` is assigned to on its line."""
    match = _ASSIGNED.search(code, 0, column)
    if not match or match.end() != column and code[match.end():column].strip():
        return None
    for part in _NAME_PARTS.findall(match.group(1)):
        if part.lower() in _KEY_WORDS:
            return _WORD.get(part.lower(), part.lower())
    return None


def _python_functions(text: str) -> dict[int, list[tuple[int, int | None]]]:
    """For each line, [(0, the line of the enclosing def or None)]."""
    out: dict[int, list[tuple[int, int | None]]] = {}
    stack: list[tuple[int, int]] = []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            out[number] = [(0, stack[-1][1] if stack else None)]
            continue
        indent = len(line) - len(stripped)
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if re.match(r"(?:async\s+)?def\s", stripped):
            stack.append((indent, number))
        out[number] = [(0, stack[-1][1] if stack else None)]
    return out


def _brace_functions(text: str, eco: str) -> dict[int, list[tuple[int, int | None]]]:
    """For each line, the function open at each column where that changes: [(column, def line)].
    A function block is one opened after `)` or `=>` that does not start with a control word."""
    out: dict[int, list[tuple[int, int | None]]] = {}
    stack: list[int | None] = []
    previous = ""
    for number, _line, code in _code_lines(text, eco):
        current = next((s for s in reversed(stack) if s is not None), None)
        events: list[tuple[int, int | None]] = [(0, current)]
        for column, char in enumerate(code):
            if char == "{":
                header = code[:column].strip() or previous.strip()
                statement = re.split(r"[;{}]", header)[-1].strip()
                function = ((statement.endswith("=>") or re.search(r"\)[^()]*$", statement))
                            and not _NOT_HEADER.match(statement))
                stack.append(number if function else None)
            elif char == "}" and stack:
                stack.pop()
            else:
                continue
            events.append((column + 1, next((s for s in reversed(stack) if s is not None), None)))
        out[number] = events
        previous = code
    return out


def _function_at(functions: dict[int, list[tuple[int, int | None]]], line: int,
                 column: int | None) -> int | None:
    events = functions.get(line)
    if not events:
        return None
    if column is None:
        return events[0][1]
    current = None
    for start, function in events:
        if start > column:
            break
        current = function
    return current


def _anchor_rows(result: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """The public-key call rows of each file, with their family."""
    sizes = result.get("algorithm_key_sizes") or {}
    by_raw = {f.get("raw_value"): f for f in result.get("findings") or []}
    family: dict[str, str] = {}
    for alg in result.get("detected_algorithms") or []:
        finding = by_raw.get(f"{alg}-{sizes[alg]}" if alg in sizes else alg)
        if finding and finding.get("classification") in _ANCHOR_CLASSES:
            family[alg] = finding["algorithm_family"]
    out: dict[str, list[dict[str, Any]]] = {}
    for row in (result.get("evidence") or {}).get("source_code") or []:
        if row.get("evidence_kind") == "call" and row.get("algorithm") in family:
            out.setdefault(row["path"], []).append(
                {"line": row["line"], "family": family[row["algorithm"]]})
    return out


def _places(calls: list[dict[str, Any]], anchors: dict[str, list[dict[str, Any]]],
            texts: dict[str, tuple[str, str]], columns: dict[int, tuple[int, str]]
            ) -> list[dict[str, Any]]:
    places: list[dict[str, Any]] = []
    functions_of: dict[str, dict[int, list[tuple[int, int | None]]]] = {}
    for index, row in enumerate(calls):
        if row["class"] == "csprng":
            continue
        column, code = columns[index]
        found: list[tuple[int, dict[str, Any]]] = []
        word = _name_word(code, column)
        if word:
            found.append((0, {"kind": "assigned_to_name", "line": row["line"], "word": word}))
        rows = anchors.get(row["path"], [])
        if rows:
            if row["path"] not in functions_of:
                text, eco = texts[row["path"]]
                functions_of[row["path"]] = (_python_functions(text) if eco == "Py"
                                             else _brace_functions(text, eco))
            functions = functions_of[row["path"]]
            here = _function_at(functions, row["line"], column)
            for anchor in rows:
                if anchor["line"] == row["line"]:
                    scope = 0
                elif here is not None and _function_at(functions, anchor["line"], None) == here:
                    scope = 1
                else:
                    scope = 2
                found.append((scope, {"kind": "public_key_operation", "line": anchor["line"],
                                      "family": anchor["family"]}))
        if not found:
            continue
        scope = _SCOPES[min(s for s, _ in found)]
        nearest = sorted(found, key=lambda f: (f[0], f[1]["line"]))[0][1]
        what = (f"its value assigned to a name that says {nearest['word']}"
                if nearest["kind"] == "assigned_to_name"
                else f"a {nearest['family']} operation on line {nearest['line']}")
        places.append({
            "path": row["path"], "line": row["line"], "ecosystem": row["ecosystem"],
            "class": row["class"], "api": row["api"], **({"why": row["why"]} if "why" in row else {}),
            "link": "co-location", "link_scope": scope,
            "anchors": [a for _, a in sorted(found, key=lambda f: (f[0], f[1]["line"]))],
            "statement": (f"a {row['class']} generator ({row['api']}), {scope.replace('_', ' ')} "
                          f"as {what}: a place to check, not a verdict. Co-location only; the "
                          f"value is not followed from the generator to the key"),
            "excerpt": row["excerpt"], "in_test_code": row["in_test_code"]})
    return places


def section(result: dict[str, Any], root: Path) -> dict[str, Any] | None:
    """The `randomness` section of a finished result. Reads it and the files it read; changes no
    row of it. A failure leaves a statement naming the exception class, never its message (which
    may quote the scanned text): this section must not end a scan."""
    try:
        texts: dict[str, tuple[str, str]] = {}
        columns: list[tuple[int, str]] = []
        calls = _rows(result, root, texts, columns)
        places = _places(calls, _anchor_rows(result), texts, dict(enumerate(columns)))
    except Exception as error:  # noqa: BLE001 -- a context section must not end the scan
        return {"meaning": MEANING, "not_built": type(error).__name__,
                "statement": ("the randomness section was not built for this tree; the findings, "
                              "the evidence and the exit code do not depend on it")}
    return {"meaning": MEANING, "count": len(calls), "calls": calls,
            "places_meaning": PLACES_MEANING, "places": places}
