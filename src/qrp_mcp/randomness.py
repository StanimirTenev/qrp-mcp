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

import bisect
import re
from pathlib import Path, PurePosixPath
from typing import Any

from . import detectors

MEANING = (
    "the random number generators the code calls, one row per generator API on a line, each in one "
    "class from the generator's own documentation: `weak` -- a non-cryptographic PRNG; `csprng` -- a named cryptographic "
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
# Without a backslash in the line this is linear; with one, `"\"\"\"...` left open made every
# quote a new start of a scan to the end, so such a line is blanked by hand (_blank_by_hand).
_STRING = re.compile(r'"[^"\n]*"|\'[^\'\n]*\'|`[^`\n]*`')
_LITERAL_ARG = re.compile(r"\s*(?:-?\d|0x|[\"'`]|new\s+byte\s*\[\s*\]\s*\{|\{)")


def _blank(match: re.Match[str]) -> str:
    text = match.group(0)
    return text[0] + " " * (len(text) - 2) + text[-1]


def _blank_by_hand(line: str) -> str:
    out = list(line)
    quote = None
    index = 0
    while index < len(line):
        char = line[index]
        if quote:
            if char == "\\":
                out[index] = " "
                if index + 1 < len(line):
                    out[index + 1] = " "
                index += 2
                continue
            if char == quote:
                quote = None
            else:
                out[index] = " "
        elif char in "\"'`":
            quote = char
        index += 1
    return "".join(out)


def _without_block_comments(code: str) -> tuple[str, bool]:
    """`/* ... */` blanked by `find`, never by a lazy regex (a line of `/*` left open was quadratic),
    and joined once (a line of closed comments rebuilt per comment was too); True when a comment is
    left open at the end of the line."""
    pieces: list[str] = []
    at = 0
    start = code.find("/*")
    while start >= 0:
        end = code.find("*/", start + 2)
        if end < 0:
            pieces.append(code[at:start])
            return "".join(pieces), True
        pieces.append(code[at:start])
        pieces.append(" " * (end + 2 - start))
        at = end + 2
        start = code.find("/*", at)
    pieces.append(code[at:])
    return "".join(pieces), False


def _code_lines(text: str, eco: str):
    """(line number, original line, the line with string contents blanked and comments removed),
    for every line that may hold a call. Positions in the two lines are the same."""
    hash_comment = eco in ("Py", "PHP")
    slash_comment = eco != "Py"
    in_block = False
    for number, line in enumerate(text.splitlines(), 1):
        code = _blank_by_hand(line) if "\\" in line else _STRING.sub(_blank, line)
        if slash_comment:
            if in_block:
                end = code.find("*/")
                if end < 0:
                    continue
                code = " " * (end + 2) + code[end + 2:]
                in_block = False
            code, in_block = _without_block_comments(code)
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
_PY_IMPORT = re.compile(r"^[ \t]*import[ \t]+([^#;\n]+)", re.M)
_PY_FROM = re.compile(r"^[ \t]*from[ \t]+([\w.]+)[ \t]+import[ \t]+(?:\(([^)]{0,4000})\)|([^#;\n]+))", re.M)


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
        for part in (match.group(2) or match.group(3)).replace("\n", " ").split(","):
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
_GO_IMPORT = re.compile(r'(?:^|[\s(;])(?:([A-Za-z_]\w*|\.)[ \t]+)?"(math/rand(?:/v2)?|crypto/rand)"')


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
            if _PHP_DECLARATION.search(code[max(0, match.start() - 40):match.start()]):
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


# A called name holding one of these words, that no spelling classifies, is counted as seen.
_SEEN_WORDS = frozenset(("rand", "random", "randomness", "rng", "prng", "csprng", "drbg", "urandom",
                         "getrandom", "randint", "randrange", "randbytes", "randbits",
                         "getrandbits", "randbelow", "randn", "srand", "entropy"))
_SEEN_INSIDE = ("mt19937", "urandom", "getrandom", "arc4random")
_SEEN_HINTS = ("rand", "rng", "drbg", "mt19937", "entropy")
_CALLED = re.compile(r"(?<!\w)([A-Za-z_]\w*)\s*\(")


def _seen_word(name: str) -> bool:
    low = name.lower()
    if any(w in low for w in _SEEN_INSIDE):
        return True
    return any(part.lower() in _SEEN_WORDS
               for piece in name.split("_") for part in _NAME_PARTS.findall(piece))


def _rows(result: dict[str, Any], root: Path, texts: dict[str, tuple[str, str]],
          columns: list[tuple[int, str]], counts: dict[str, int]) -> list[dict[str, Any]]:
    """The rows; `texts` gets each file read that holds one, `columns` the column of each row and
    its line as matched, in the order of the rows returned; `counts` the calls with a randomness
    word in their name that no row covers."""
    rows: list[tuple[dict[str, Any], tuple[int, str]]] = []
    for rel in result.get("files_read") or []:
        eco = _ECOSYSTEM.get(PurePosixPath(rel).suffix.lower())
        if not eco:
            continue
        text = _read(root, rel)
        lowered = text.lower()
        if not any(hint in lowered for hint in _SEEN_HINTS + ("secrets",)):
            continue
        counts["files_looked_at"] += 1
        # One row per API on a line: a line of a thousand `rand()` is one place, not a thousand.
        seen: set[tuple[int, str]] = set()
        code_of = {n: c for n, _, c in _code_lines(text, eco)}
        starts: dict[int, list[int]] = {}
        if any(hint in text for hint in _FILE_HINTS[eco]):
            for number, line, column, api, cls, extra in _READERS[eco](text, rel):
                starts.setdefault(number, []).append(column)
                if (number, api) in seen:
                    continue
                seen.add((number, api))
                texts[rel] = (text, eco)
                rows.append(({"path": rel, "line": number, "ecosystem": eco, "class": cls,
                              "api": api, **extra, "excerpt": line.strip()[:200],
                              "in_test_code": detectors.in_test_code(rel)},
                             (column, code_of.get(number, ""))))
        for number, code in code_of.items():
            lowered_line = code.lower()
            if not any(hint in lowered_line for hint in _SEEN_HINTS):
                continue
            # A call is covered by the nearest classified match that starts at or before it,
            # with no `(` between: `random.random(` is one call, seen once.
            covered = sorted(set(starts.get(number, ())))
            reach = [code.find("(", s) for s in covered]
            for match in _CALLED.finditer(code):
                if not _seen_word(match.group(1)):
                    continue
                at = bisect.bisect_right(covered, match.start()) - 1
                if at >= 0 and (reach[at] < 0 or match.start() <= reach[at]):
                    continue
                counts["calls_seen_not_classified"] += 1
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
    "check, not a finding and not a verdict. `anchors` names up to three, nearest first, and "
    "`anchors_count` how many the file holds. A `csprng` row is never a place")
# Our own list of four words, in singular and plural.
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
    window = code[max(0, column - 200):column]
    match = _ASSIGNED.search(window)
    if not match:
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
    # The function open after each brace, so the innermost one is the top: no walk down the stack.
    stack: list[int | None] = []
    previous = ""
    for number, _line, code in _code_lines(text, eco):
        events: list[tuple[int, int | None]] = [(0, stack[-1] if stack else None)]
        # A `;` inside parentheses (`for (i = 0; i < n; i++)`) does not end the statement, and the
        # words since the last brace say whether a control statement opens the block
        # (`if err := f(); err != nil {`).
        separator = block = -1
        depth = 0
        for column, char in enumerate(code):
            if char not in "{};()":
                continue
            if char == "(":
                depth += 1
                continue
            if char == ")":
                depth = max(0, depth - 1)
                continue
            if char == ";":
                if depth == 0:
                    separator = column
                continue
            if char == "{":
                statement = code[separator + 1:column].strip()
                opened = code[block + 1:column].strip()
                if not code[:column].strip():
                    statement = opened = previous[max(previous.rfind(c) for c in ";{}") + 1:].strip()
                last = max(statement.rfind("("), statement.rfind(")"))
                function = ((statement.endswith("=>") or last >= 0 and statement[last] == ")")
                            and not _NOT_HEADER.match(statement) and not _NOT_HEADER.match(opened))
                stack.append(number if function else stack[-1] if stack else None)
                events.append((column + 1, stack[-1]))
            else:
                if stack:
                    stack.pop()
                events.append((column + 1, stack[-1] if stack else None))
            separator = block = column
            depth = 0
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


# A place names its nearest anchors, a requirement its nearest generators, and each says how many
# there are: 20,000 lines alternating a weak call and a key in one file were 10,000 x 10,000.
_CAP = 3


def _nearest(items: list[tuple[int, Any]], line: int, cap: int = _CAP) -> list[tuple[int, Any]]:
    """Up to `cap` of `items` (sorted by line) closest to `line`, nearest first."""
    lines = [item[0] for item in items]
    hi = bisect.bisect_left(lines, line)
    lo = hi - 1
    out = []
    while len(out) < cap and (lo >= 0 or hi < len(items)):
        if hi >= len(items) or (lo >= 0 and line - items[lo][0] <= items[hi][0] - line):
            out.append(items[lo])
            lo -= 1
        else:
            out.append(items[hi])
            hi += 1
    return out


def _functions(texts: dict[str, tuple[str, str]], cache: dict[str, Any], path: str
               ) -> dict[int, list[tuple[int, int | None]]]:
    if path not in cache:
        text, eco = texts[path]
        cache[path] = _python_functions(text) if eco == "Py" else _brace_functions(text, eco)
    return cache[path]


def _places(calls: list[dict[str, Any]], anchors: dict[str, list[dict[str, Any]]],
            texts: dict[str, tuple[str, str]], columns: dict[int, tuple[int, str]]
            ) -> list[dict[str, Any]]:
    places: list[dict[str, Any]] = []
    cache: dict[str, Any] = {}
    grouped: dict[str, tuple[list, dict, dict]] = {}
    for index, row in enumerate(calls):
        if row["class"] == "csprng":
            continue
        column, code = columns[index]
        word = _name_word(code, column)
        path = row["path"]
        rows = anchors.get(path, [])
        here = None
        if rows:
            functions = _functions(texts, cache, path)
            if path not in grouped:
                every = sorted(((a["line"], a) for a in rows), key=lambda item: item[0])
                by_line: dict[int, list] = {}
                by_function: dict[int, list] = {}
                for line, anchor in every:
                    by_line.setdefault(line, []).append((line, anchor))
                    function = _function_at(functions, line, None)
                    if function is not None:
                        by_function.setdefault(function, []).append((line, anchor))
                grouped[path] = (every, by_line, by_function)
            here = _function_at(functions, row["line"], column)
        every, by_line, by_function = grouped.get(path, ([], {}, {}))
        same_line = by_line.get(row["line"], [])
        in_function = by_function.get(here, []) if here is not None else []
        if word or same_line:
            scope = "same_line"
        elif in_function:
            scope = "same_function"
        elif every:
            scope = "same_file"
        else:
            continue
        chosen = _nearest(same_line or in_function or every, row["line"])
        found = ([{"kind": "assigned_to_name", "line": row["line"], "word": word}] if word else [])
        found += [{"kind": "public_key_operation", "line": a["line"], "family": a["family"]}
                  for _, a in chosen]
        closest = found[0]
        what = (f"its value assigned to a name that says {closest['word']}"
                if closest["kind"] == "assigned_to_name"
                else f"a {closest['family']} operation on line {closest['line']}")
        places.append({
            "path": path, "line": row["line"], "ecosystem": row["ecosystem"],
            "class": row["class"], "api": row["api"], **({"why": row["why"]} if "why" in row else {}),
            "link": "co-location", "link_scope": scope,
            "anchors": found, "anchors_count": len(every) + (1 if word else 0),
            "statement": (f"a {row['class']} generator ({row['api']}), {scope.replace('_', ' ')} "
                          f"as {what}: a place to check, not a verdict. Co-location only; the "
                          f"value is not followed from the generator to the key"),
            "excerpt": row["excerpt"], "in_test_code": row["in_test_code"]})
    return places


# --- FIPS 203 and FIPS 204 ---------------------------------------------------------------------------

PQC_MEANING = (
    "an ML-KEM or ML-DSA call row with a generator row of any class in the same function or on the "
    "same line -- what `visible` means here; no library's RNG argument is parsed -- and the "
    "requirement FIPS 203 or FIPS 204 sets on that randomness, quoted with its section and page "
    "(printed page, then the PDF's). The requirement is named, not checked: the scan does not "
    "establish that a generator is an approved RBG or what its security strength is, and a `csprng` "
    "row is not shown to meet it. The row is not told apart as key generation, encapsulation, "
    "signing, decapsulation, verification or a parameter name, so an entry can sit where no "
    "randomness is drawn; for ML-DSA both requirements are given. `generators` names up to three, "
    "nearest first, and `generators_count` how many are in that function")
# Quoted from the PDFs (nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf and .204.pdf), each found
# word for word in a saved text of the page (izdanie-0.52.0/izvori, tools/proveri_izvori.py).
_FIPS_203 = {
    "document": "FIPS 203", "section": "3.3", "page": "16 (PDF page 25)",
    "applies_to": "ML-KEM.KeyGen and ML-KEM.Encaps",
    "quote": ("These random bytes shall be generated using an approved RBG, as prescribed in "
              "SP 800-90A, SP 800-90B, and SP 800-90C [18, 19, 20]. Moreover, this RBG shall have a "
              "security strength of at least 128 bits for ML-KEM-512, at least 192 bits for "
              "ML-KEM-768, and at least 256 bits for ML-KEM-1024."),
}
_FIPS_204_XI = {
    "document": "FIPS 204", "section": "3.6.1", "page": "12 (PDF page 22)",
    "applies_to": "ML-DSA.KeyGen, the seed \U0001d709",
    "quote": ("The seed \U0001d709 shall be a fresh (i.e., not previously used) random value "
              "generated using an approved RBG, as prescribed in SP 800-90A, SP 800-90B, and "
              "SP 800-90C [19, 20, 21]. Moreover, the RBG used shall have a security strength of at "
              "least 192 bits for ML-DSA-65 and 256 bits for ML-DSA-87."),
}
_FIPS_204_XI_44 = {
    "document": "FIPS 204", "section": "3.6.1", "page": "12 (PDF page 22)",
    "applies_to": "ML-DSA.KeyGen, the seed \U0001d709",
    "quote": ("For ML-DSA-44, the RBG should have a security strength of at least 192 bits and "
              "shall have a security strength of at least 128 bits."),
}
_FIPS_204_RND = {
    "document": "FIPS 204", "section": "3.6.1", "page": "12 (PDF page 22)",
    "applies_to": "ML-DSA.Sign and HashML-DSA.Sign, hedged, rnd",
    "quote": ("While this value should ideally be generated by an approved RBG, other methods for "
              "generating fresh random values may be used."),
}
_ML_KEM_BITS = {"512": 128, "768": 192, "1024": 256}


def _requirements(family: str, pset: str | None) -> list[dict[str, Any]]:
    def only(bits: dict[str, int]) -> dict[str, int]:
        return {k: v for k, v in bits.items() if pset is None or k == pset}

    if family == "ML-KEM":
        return [{**_FIPS_203, "level": "shall", "min_strength_bits": only(_ML_KEM_BITS)}]
    out = []
    if only({"65": 192, "87": 256}):
        out.append({**_FIPS_204_XI, "level": "shall", "min_strength_bits": only({"65": 192, "87": 256})})
    if only({"44": 128}):
        out.append({**_FIPS_204_XI_44, "level": "shall", "min_strength_bits": {"44": 128}})
        out.append({**_FIPS_204_XI_44, "level": "should", "min_strength_bits": {"44": 192}})
    out.append({**_FIPS_204_RND, "level": "should"})
    return out


def _pqc_requirements(result: dict[str, Any], calls: list[dict[str, Any]],
                      texts: dict[str, tuple[str, str]], columns: dict[int, tuple[int, str]]
                      ) -> list[dict[str, Any]]:
    by_path: dict[str, list[int]] = {}
    for index, row in enumerate(calls):
        by_path.setdefault(row["path"], []).append(index)
    out = []
    cache: dict[str, Any] = {}
    grouped: dict[str, tuple[dict, dict, dict]] = {}
    for row in (result.get("evidence") or {}).get("source_code") or []:
        if (row.get("algorithm") not in ("ML-KEM", "ML-DSA") or row.get("evidence_kind") != "call"
                or row.get("path") not in by_path):
            continue
        path = row["path"]
        functions = _functions(texts, cache, path)
        if path not in grouped:
            by_line: dict[int, list] = {}
            by_function: dict[int, list] = {}
            function_of: dict[int, int | None] = {}
            for index in by_path[path]:
                line = calls[index]["line"]
                function = _function_at(functions, line, columns[index][0])
                function_of[index] = function
                by_line.setdefault(line, []).append((line, index))
                if function is not None:
                    by_function.setdefault(function, []).append((line, index))
            grouped[path] = (by_line, by_function, function_of)
        by_line, by_function, function_of = grouped[path]
        there = _function_at(functions, row["line"], None)
        same_line = [(line, i) for line, i in by_line.get(row["line"], [])
                     if there is None or function_of[i] != there]
        in_function = by_function.get(there, []) if there is not None else []
        chosen = same_line[:_CAP] + _nearest(in_function, row["line"], _CAP)
        generators = [{"line": calls[i]["line"], "class": calls[i]["class"], "api": calls[i]["api"],
                       "link_scope": "same_line" if calls[i]["line"] == row["line"]
                       else "same_function"}
                      for _, i in sorted(chosen, key=lambda c: (c[0], c[1]))]
        count = len(same_line) + len(in_function)
        if not generators:
            continue
        pset = row.get("parameter_set")
        pset = pset if pset in ({"512", "768", "1024"} if row["algorithm"] == "ML-KEM"
                                else {"44", "65", "87"}) else None
        out.append({
            "path": row["path"], "line": row["line"], "family": row["algorithm"],
            "parameter_set": pset, "generators": generators, "generators_count": count,
            "requirements": _requirements(row["algorithm"], pset),
            "statement": (f"{row['algorithm']} with a generator in the same function: the "
                          f"requirement is named, not checked -- the scan does not establish that "
                          f"the generator is an approved RBG or what its security strength is"),
            "in_test_code": detectors.in_test_code(row["path"])})
    return out


# --- what a code scan cannot know ------------------------------------------------------------------

NOT_READ = {
    "meaning": ("what reading the code cannot show about the randomness behind a key, said rather "
                "than left out: no entropy is estimated, no statistical test is run and nothing is "
                "probed at run time. A `csprng` row names a generator; it says nothing about these"),
    "what": [
        "entropy at boot: whether the kernel's pool was initialised when the first key was made "
        "(getrandom(2) blocks until then unless GRND_NONBLOCK is given)",
        "entropy in a virtual machine or a container: what the host passes in, and a snapshot or "
        "clone that starts from the same generator state",
        "the quality of an HSM's or a PKCS#11 token's generator (SecureRandom `PKCS11`, a provider)",
        "a generator injected at run time: passed in as a parameter, by dependency injection, or "
        "named in a variable (SecureRandom.getInstance(name), EVP_RAND_fetch(ctx, name, ...)); the "
        "last are counted in counts.chosen_at_run_time",
        "a seed taken from configuration or the environment",
        "the statistical quality of any output",
    ],
}
COUNTS_MEANING = (
    "calls_classified: the rows; calls_seen_not_classified: calls whose called name holds a "
    "randomness word (rand, random, rng, drbg, entropy, ...) that no spelling of the catalogue "
    "classifies -- a generator this version does not know, or not a generator at all; calls_seen: "
    "both; chosen_at_run_time: rows whose generator is named in a variable; files_looked_at: code "
    "files read that hold one of those words")


def section(result: dict[str, Any], root: Path) -> dict[str, Any] | None:
    """The `randomness` section of a finished result. Reads it and the files it read; changes no
    row of it. A failure leaves a statement naming the exception class, never its message (which
    may quote the scanned text): this section must not end a scan."""
    try:
        texts: dict[str, tuple[str, str]] = {}
        columns: list[tuple[int, str]] = []
        counts = {"files_looked_at": 0, "calls_seen_not_classified": 0}
        calls = _rows(result, root, texts, columns, counts)
        places = _places(calls, _anchor_rows(result), texts, dict(enumerate(columns)))
        pqc = _pqc_requirements(result, calls, texts, dict(enumerate(columns)))
    except Exception as error:  # noqa: BLE001 -- a context section must not end the scan
        return {"meaning": MEANING, "not_built": type(error).__name__,
                "statement": ("the randomness section was not built for this tree; the findings, "
                              "the evidence and the exit code do not depend on it")}
    return {"meaning": MEANING, "count": len(calls), "calls": calls,
            "places_meaning": PLACES_MEANING, "places": places,
            "pqc_requirements_meaning": PQC_MEANING, "pqc_requirements": pqc,
            "not_read": NOT_READ,
            "counts": {"meaning": COUNTS_MEANING,
                       "calls_seen": len(calls) + counts["calls_seen_not_classified"],
                       "calls_classified": len(calls),
                       "calls_seen_not_classified": counts["calls_seen_not_classified"],
                       "by_class": {c: sum(1 for r in calls if r["class"] == c)
                                    for c in ("weak", "csprng", "check")},
                       "chosen_at_run_time": sum(1 for r in calls if r.get("why")
                                                 == "algorithm_chosen_at_run_time"),
                       "files_looked_at": counts["files_looked_at"]}}
