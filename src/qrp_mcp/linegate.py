"""Which lines of a file any rule could match, found in one pass over the file (release D).

The scan read every line through every rule: 368 k lines of curl, six per-line passes and
4 M regex searches, 45 s. Most lines name nothing a rule looks for. Each rule below is
given a GATE: a shorter regex that every line the rule reports on must match. One search
of the whole file for the union of the gates marks the lines that need reading; every
other line is passed over, and only the state a later line reads (an open block comment,
docstring or denial block) is carried across it. A marked line is read exactly as before,
by every rule, so a gate can only cost time, never a finding: a gate that matches too much
reads more lines, and nothing else.

What makes a gate sound, and the four ways it is kept so:

* a literal that every match of the rule contains (case-folded: the gate is searched with
  IGNORECASE, which matches everything the case-sensitive rule matches and more);
* the rule's own regex with its anchors and look-arounds removed, which matches wherever
  the rule does, and is searched across the joined file without needing a line boundary;
* a look-around kept only where it reads the same at the edge of a line as at a newline
  (`(?<![A-Za-z])`: a newline is not a letter either);
* a line that is not ASCII is always read. The algorithm rules try every pattern on such a
  line (detectors._candidate_patterns), and case-folding beyond ASCII is not a promise
  this file makes.

A rule added to the scan without a gate here makes the gate wrong, so the gate is checked:
tests/test_linegate.py reads every fixture with and without it and requires the same
findings, and runs each rule on every line the gate passed over.

The rules after release AB are not behind it. Certificates and keys (release C) are read from
the file's bytes, and scan_embedded_keys, key_in_source and getproperty_reads read every line.
Release E's indirection rewrites lines and reads them with scan_source_file again, which
computes the gate on the REWRITTEN text: a line naming nothing until it is rewritten is cold
in the file and hot after, so the file's own gate must never be passed to that reading
(tests/test_linegate.py holds such lines, and the rule check is run on rewritten lines too).

`RUST_PARTS` is the same union for the optional compiled core (qrp-mcp-core), whose regex
dialect has no look-arounds: there each look-around is dropped, which only matches more.
"""

from __future__ import annotations

import bisect
import os
import re
from itertools import accumulate
from typing import NamedTuple

from . import components

# --- literals ----------------------------------------------------------------------------
# Lower-case; searched case-insensitively. Each line says which rule needs it.
LITERALS: set[str] = {
    # detectors.scan_openssl3_names (_FETCH_CALL) is a regex part below.
    # detectors.scan_jca_names: _JCA_CALL contains `.getInstance(`.
    ".getinstance(",
    # detectors.scan_cose_algorithms: nothing without _COSE_CONTEXT.
    "public-key", "pubkeycredparams", "cose",
    # opcua.scan: nothing without one of opcua._CHEAP.
    "ecuritypolic", "ua_", "secpol", "set_security_string", "enablesecurity",
    # aws_tls.scan: nothing without one of these two substrings.
    "elbsecuritypolicy-", "sslpolicy.",
    # ike.fortios_addke: FORTIOS_ADDKE contains `addke`.
    "addke",
    # assets._group_setting (scan_tls_groups, scan_hybrid_groups, and the ban test): every
    # alternative of _TLS_GROUP_SETTING contains one of these, _HAPROXY_CURVES `curves`.
    "ecdh_curve", "ecdhcurve", "groups", "curves", "curvepreferences",
    # assets._cipher_setting (static RSA suites, cipher strings): every alternative of
    # _TLS_CIPHER_SETTING and _HAPROXY_CIPHERS contains `cipher`.
    "cipher",
    # detectors._cipher_string_parts: _GNUTLS_PRIORITY contains `priority`.
    "priority",
    # assets.scan_ssh_kex: _SSH_KEX_SETTING contains `KexAlgorithms`.
    "kexalgorithms",
    # detectors.PPK_CONFIG_ASSIGN.
    "ppk",
    # detectors.scan_hybrid_names: nothing without one of these in the lowered line.
    "kem", "sntrup", "wing",
    # assets.scan_protocols: _BARE_TLS_VERSION_SETTING and _VERSION_MACRO contain
    # `_version`; `SSLProtocol all` (_SSL_PROTOCOL_ALL) enables versions without naming one.
    "_version", "sslprotocol",
    # oids.scan: nothing without one of these three.
    "840", "1.3.1", "3, 1",
    # dnssec.scan_records / unnamed_records: RRSIG; DNSKEY (the other spellings are below).
    "rrsig", "dnskey",
    # detectors.scan_cipher_suites: a TLS_/SSL3_/TLS1_/SSL_ token (the dash-joined ones
    # are below).
    "tls_", "tls1_", "ssl3_", "ssl_",
    # detectors._DENIAL_WORDS opens a denial block that governs the lines below it, so a
    # line that could open one is read (the words are matched case-insensitively there).
    "disabled", "disallow", "banned", "blocked", "blocklist", "blacklist", "forbidden",
    "prohibited", "denied", "deny", "reject", "excluded", "unsupported", "removed",
}

_SUITE_CIPHERS = "aes|camellia|chacha|seed|idea|rc4|3des|des|null|aria|rc2"

# --- regex parts ---------------------------------------------------------------------------
# (Python source, the compiled core's source). Searched with IGNORECASE; `(?-i:...)` keeps
# a case-sensitive rule's gate case-sensitive, which is only a matter of speed.
PARTS: list[tuple[str, str]] = [
    # detectors.scan_openssl3_names: _FETCH_CALL without its \b.
    (r"(?-i:EVP_(?:PKEY_Q_keygen|PKEY_CTX_new_from_name|PKEY_is_a|PKEY_CTX_is_a|"
     r"SIGNATURE_fetch|KEYMGMT_fetch|KEM_fetch|KEYEXCH_fetch|MD_fetch|CIPHER_fetch|"
     r"ASYM_CIPHER_fetch))", ""),
    # detectors._key_type_values: nothing without _KEY_TYPE_NAMED.
    (r"key[_-]?type", ""),
    # dnssec._RECORDS without its look-behind: `static-key N`, `initial-key N`,
    # `C?DS N` and `static-ds`/`initial-ds N` (DNSKEY and RRSIG are literals above).
    (r"-key\s+\d|ds\s+\d", ""),
    # detectors.scan_cipher_suites, dash-joined tokens: a token of three or more parts, one
    # of which starts with a bulk cipher. The first part (then two more follow), or a
    # later one (then a part ends just before it).
    (r"(?:" + _SUITE_CIPHERS + r")[a-z0-9]*-[a-z0-9]+-[a-z0-9]|[a-z0-9]-(?:"
     + _SUITE_CIPHERS + r")", ""),
    # detectors._suite_table_entry: _SUITE_TABLE_ENTRY's code and the cipher among its
    # parts (case-sensitive, as there).
    (r"(?-i:0x[0-9A-Fa-f]{4}\s*,[\sA-Z0-9,]*(?:AES|CAMELLIA|CHACHA|SEED|IDEA|RC4|3DES|DES|"
     r"NULL|ARIA|RC2))", ""),
    # assets.scan_protocols, _TLS_VERSION: each alternative's fixed start.
    (r"(?-i:TLSv1|SSLv[23]|tls\.VersionTLS1[0-3]|SslProtocols\.Tls|TLS1_\d_VERSION|"
     r"TLS_?v?1\.\d)", ""),
    # assets.scan_protocols, _SSH_KEY_LINE without its leading boundary.
    (r"(?-i:ssh-(?:rsa|dss|ed25519|mldsa)|ecdsa-sha2-nistp\d|sk-\S+\s+[A-Za-z0-9+/]{20})", ""),
    # assets.scan_protocols, _SSH_PROTOCOL without its anchors.
    (r"(?-i:Protocol\s+[12]|HostKeyAlgorithms|KexAlgorithms|PubkeyAccepted|"
     r"HostbasedAcceptedAlgorithms|Ciphers\s+\S|MACs\s+\S)", ""),
    # detectors._DENIAL_WORDS, the three with a separator.
    (r"not[-_ ]?allowed|must[-_ ]?not|no[-_ ]?longer", ""),
]


_COMPONENT_FIRSTS = {key for key in components.FAMILY if "_" not in key} | {"SHA", "SHA3"}
# Where one of them can start (the size-suffixed names start with one of them too).
_COMPONENT_WORDS = _COMPONENT_FIRSTS


def _component_parts() -> list[tuple[str, str]]:
    """components.scan names a family only through a component that is one of
    components.FAMILY (or a size-suffixed RSA/DSA/DH/FFDHE, or the first half of a name
    that components() puts back together: SHA+1, SHA3+224, DES+EDE3, EC+DH, Ed+DSA).

    A component is a whole token of components._PART, so it is one of three shapes, each
    with the boundary that token has: lower case `ecdh` (after a non-letter, before no
    letter or digit), capitalised `Ecdh` (before no lower-case letter or digit), or capitals
    `ECDH` (after no capital, before no capital or digit or before a capitalised word).
    Digits closing the token stop the same way. Ed+DSA needs no word of its own: its DSA
    is a component of the same shapes."""
    lower: list[tuple[str, bool]] = []      # (text, whether digits close it)
    capital: list[tuple[str, bool]] = []
    caps: list[str] = []
    for key in sorted(_COMPONENT_FIRSTS, key=lambda k: (-len(k), k)):
        letters = re.match(r"[A-Z]*", key).group(0)
        digits = key[len(letters):]
        if not digits.isdigit() and digits:
            # 3DES: a token of capitals and digits only.
            caps.append(re.escape(key))
            continue
        if letters:
            lower.append((re.escape(key.lower()), bool(digits)))
        if len(letters) >= 2:
            capital.append((re.escape(letters[0] + letters[1:].lower() + digits), bool(digits)))
        caps.append(re.escape(key))
    sized = "FFDHE|RSA|DSA|DHE|DH"
    lower.append((r"(?:" + sized.lower() + r")[0-9]{3,5}", True))
    capital.append((r"(?:Ffdhe|Rsa|Dsa|Dhe|Dh)[0-9]{3,5}", True))
    caps.append(r"(?:" + sized + r")[0-9]{3,5}")

    def shapes(entries: list[tuple[str, bool]], digits_after: str, letters_after: str) -> str:
        return "|".join(text + (digits_after if digits else letters_after)
                        for text, digits in entries)
    python = (r"(?-i:(?<![A-Za-z])(?:" + shapes(lower, r"(?![0-9])", r"(?![a-z0-9])")
              + r")|(?:" + shapes(capital, r"(?![0-9])", r"(?![a-z0-9])")
              + r")|(?<![A-Z])(?:" + "|".join(caps) + r")(?:(?![A-Z0-9])|(?=[A-Z][a-z])))")
    # The compiled core has no look-arounds: each reads the character it looked at instead
    # (or the line's edge), which can only mark a neighbouring line as well.
    rust = (r"(?-i:(?:^|[^A-Za-z])(?:" + shapes(lower, r"(?:[^0-9]|$)", r"(?:[^a-z0-9]|$)")
            + r")|(?:" + shapes(capital, r"(?:[^0-9]|$)", r"(?:[^a-z0-9]|$)")
            + r")|(?:^|[^A-Z])(?:" + "|".join(caps) + r")(?:[^A-Z0-9]|$|[A-Z][a-z]))")
    return [(python, rust)]


PARTS += _component_parts()


def _piece(literal: str) -> str:
    """The part of a literal that is safe to look for in the raw line.

    The rules search a line with long hex and base64 runs blanked to spaces
    (detectors._masked). Blanking only ever writes a run of 30 or more spaces between two
    kept characters, so a literal whose spaces are single and inside it cannot have been
    made by blanking. A leading, trailing or doubled space could: then the longest piece
    without one is used, which every occurrence of the literal contains."""
    if literal == literal.strip(" ") and "  " not in literal:
        return literal
    return max(literal.split(" "), key=len)


def _trie(words: list[str]) -> str:
    tree: dict = {}
    for word in words:
        node = tree
        for ch in word:
            node = node.setdefault(ch, {})
        node[""] = {}

    def build(node: dict) -> str:
        branches = [re.escape(ch) + build(child) for ch, child in sorted(node.items()) if ch]
        if "" in node:
            return ""      # a shorter word already marks the line; nothing longer is needed
        if len(branches) == 1:
            return branches[0]
        return "(?:" + "|".join(branches) + ")"
    return build(tree)


def _shortest(words: set[str]) -> list[str]:
    """The words without those containing a shorter one, which marks the same lines."""
    return sorted(w for w in words if not any(v != w and v in w for v in words))


class Hot(NamedTuple):
    """The lines of one file to read, by 0-based index.

    `lines`: any rule but the algorithm patterns could match there (or the line is not
    ASCII), so the line is read by every rule. `patterns`: only an algorithm pattern's
    literal is there; the line is read by every rule if one of those patterns matches it,
    and otherwise it is passed over like the rest. `allowed`: from the compiled core, for
    a line of either set, the indices of the algorithm patterns that can match it (a
    superset of those that do); None where not known, and then every pattern is tried."""
    lines: set[int]
    patterns: set[int]
    allowed: dict[int, frozenset[int]] | None = None


class Gate:
    """The union of every rule's gate, with the algorithm patterns' own literals apart."""

    def __init__(self, algorithm_literals: list[tuple[str, ...] | None],
                 algorithm_patterns: list[re.Pattern] | None = None, blob: str | None = None,
                 use_core: bool = True):
        # A pattern with no literal can match any line: then every line is read.
        self.everything = any(found is None for found in algorithm_literals)
        self._algorithm_literals = algorithm_literals
        self._algorithm_patterns, self._blob = algorithm_patterns, blob
        # None: not yet looked for; False: not used.
        self._core: object = None if use_core else False
        self.words = _shortest(set(LITERALS))
        self.pattern_words = _shortest({_piece(s) for found in algorithm_literals if found
                                        for s in found})
        self.parts = [p for p, _ in PARTS]
        self.rust_parts = [r or p for p, r in PARTS]
        # How the pure-Python search is split, which is a matter of speed only (the same
        # union): Python's regex engine reads case-folded alternatives at a few MB/s, so
        # the case-insensitive gates are searched in the lower-cased text without
        # IGNORECASE, the case-sensitive ones in the text as written, and the component
        # shapes in two steps -- where a family name starts, then whether its shape there
        # is a component's.
        sensitive = [p for p in self.parts[:-1] if p.startswith("(?-i:")]
        folded = [p for p in self.parts[:-1] if not p.startswith("(?-i:")]
        self._folded = re.compile("|".join(["(?:" + _trie(self.words) + ")", *folded]))
        self._sensitive = re.compile("|".join(p[5:-1] for p in sensitive))
        self._component_shape = re.compile(self.parts[-1][5:-1])
        self._component_start = re.compile(
            "(?=" + _trie(sorted({w.lower() for w in _COMPONENT_WORDS})) + ")")
        self._patterns = re.compile(_trie(self.pattern_words))

    def hot_lines(self, lines: list[str], read_all: bool = False) -> Hot | None:
        """The lines any rule could match (see Hot); None when every line is read."""
        if self.everything or read_all:
            return None
        core = self._core or None   # built by compiled(), for a tree big enough to repay it
        if core is not None:
            read, patterns, allowed = core.hot_lines("\n".join(lines))
            return Hot(set(read), set(patterns), {i: frozenset(k) for i, k in allowed})
        hot: set[int] = set()
        text = "\n".join(lines)
        if not text.isascii():
            # Read whole (see the module docstring); blanked here, so the text searched is
            # ASCII and lower-casing it keeps every offset.
            hot.update(i for i, line in enumerate(lines) if not line.isascii())
            text = "\n".join("" if i in hot else line for i, line in enumerate(lines))
        starts = list(accumulate(((0 if i in hot else len(line)) + 1
                                  for i, line in enumerate(lines)), initial=0))
        low = text.lower()

        def mark(regex: re.Pattern, string: str, into: set[int]) -> None:
            # Once a line is marked the rest of it need not be searched.
            pos, end = 0, len(string)
            while pos <= end:
                m = regex.search(string, pos)
                if m is None:
                    return
                first = bisect.bisect_right(starts, m.start()) - 1
                last = bisect.bisect_right(starts, max(m.end() - 1, m.start())) - 1
                into.update(range(first, last + 1))
                pos = starts[last + 1]

        mark(self._folded, low, hot)
        mark(self._sensitive, text, hot)
        pos, end = 0, len(text)
        while pos <= end:
            m = self._component_start.search(low, pos)
            if m is None:
                break
            line = bisect.bisect_right(starts, m.start()) - 1
            if line in hot:
                pos = starts[line + 1]
            elif self._component_shape.match(text, m.start()):
                hot.add(line)
                pos = starts[line + 1]
            else:
                pos = m.start() + 1
        patterns: set[int] = set()
        mark(self._patterns, low, patterns)
        return Hot(hot, patterns - hot)

    def compiled(self):
        """The compiled core's gate, built on first use; None when qrp-mcp-core is not
        installed, QRP_MCP_CORE=0 is set, or it refuses the gate. Then the search below, in
        Python, is used: it marks other lines, never other findings."""
        if self._core is None:
            self._core = False
            if os.environ.get("QRP_MCP_CORE", "").strip() not in ("0", "off", "no"):
                try:
                    import qrp_mcp_core
                    patterns = [rust_regex(p) for p in self._algorithm_patterns or []]
                    self._core = qrp_mcp_core.Gate(
                        self.words, self.rust_parts,
                        [[_piece(s) for s in found or ()] for found in self._algorithm_literals],
                        # Without every pattern, a line with a pattern's literal is a pattern
                        # line whether or not a pattern matches it.
                        patterns if patterns and None not in patterns
                        and len(patterns) == len(self._algorithm_literals) else None,
                        self._blob or "(?!)")
                except (ImportError, ValueError):
                    self._core = False
        return self._core or None


# --- the algorithm patterns in the compiled core's dialect ---------------------------------
try:
    from re import _constants as _sre, _parser as _sre_parse
except ImportError:  # Python 3.10
    import sre_constants as _sre  # type: ignore[no-redef]
    import sre_parse as _sre_parse  # type: ignore[no-redef]

_CATEGORY = {
    _sre.CATEGORY_DIGIT: r"\d", _sre.CATEGORY_NOT_DIGIT: r"\D",
    _sre.CATEGORY_SPACE: r"\s", _sre.CATEGORY_NOT_SPACE: r"\S",
    _sre.CATEGORY_WORD: r"\w", _sre.CATEGORY_NOT_WORD: r"\W",
}


class _Unported(Exception):
    pass


def _char(code: int) -> str:
    """One character. The core searches ASCII lines as bytes (`(?-u)`), so a character
    beyond ASCII, which no such line holds, becomes the byte 0xFF, which none holds either."""
    if code > 0x7F:
        return "\\xFF"
    char = chr(code)
    return char if char.isalnum() or char == "_" else "\\x%02X" % code


def _class(items) -> str:
    out, negate = [], False
    for op, av in items:
        if op is _sre.NEGATE:
            negate = True
        elif op is _sre.LITERAL:
            out.append(_char(av))
        elif op is _sre.RANGE:
            out.append(_char(av[0]) + "-" + _char(av[1] if av[1] <= 0x7F or av[0] > 0x7F
                                                    else 0xFF))
        elif op is _sre.CATEGORY and av in _CATEGORY:
            out.append(_CATEGORY[av])
        else:
            raise _Unported(op)
    return "[" + ("^" if negate else "") + "".join(out) + "]"


def _flags(add: int, delete: int) -> str:
    on = "".join(c for f, c in ((_sre.SRE_FLAG_IGNORECASE, "i"), (_sre.SRE_FLAG_DOTALL, "s"))
                 if add & f)
    off = "".join(c for f, c in ((_sre.SRE_FLAG_IGNORECASE, "i"), (_sre.SRE_FLAG_DOTALL, "s"))
                  if delete & f)
    return on + ("-" + off if off else "")


def _ported(items) -> str:
    out = []
    for op, av in items:
        if op is _sre.LITERAL:
            out.append(_char(av))
        elif op is _sre.NOT_LITERAL:
            out.append("[^" + _char(av) + "]")
        elif op is _sre.ANY:
            out.append(".")
        elif op is _sre.IN:
            out.append(_class(av))
        elif op is _sre.BRANCH:
            out.append("(?:" + "|".join(_ported(a) for a in av[1]) + ")")
        elif op is _sre.SUBPATTERN:
            _group, add, delete, inner = av
            flags = _flags(add, delete)
            out.append("(?" + flags + ":" + _ported(inner) + ")")
        elif op in _REPEATS:
            low, high, inner = av
            count = "{%d,}" % low if high == _sre.MAXREPEAT else "{%d,%d}" % (low, high)
            out.append("(?:" + _ported(inner) + ")" + count)
        elif op is getattr(_sre, "ATOMIC_GROUP", None):
            out.append("(?:" + _ported(av) + ")")
        elif op in (_sre.AT, _sre.ASSERT, _sre.ASSERT_NOT):
            pass          # an anchor, a boundary or a look-around: dropped, which matches more
        elif op is _sre.GROUPREF:
            out.append(".*")   # whatever the group held, on the same line
        else:
            raise _Unported(op)
    return "".join(out)


_REPEATS = {_sre.MAX_REPEAT, _sre.MIN_REPEAT, getattr(_sre, "POSSESSIVE_REPEAT", None)} - {None}


def rust_regex(pattern: re.Pattern) -> str | None:
    """A regex in the compiled core's dialect that matches at least wherever `pattern`
    matches an ASCII line: anchors, \\b and look-arounds dropped, a back-reference read as
    any run of characters, laziness and possessiveness ignored. None for a construct not
    handled here, and then the core does not vouch for any pattern."""
    try:
        body = _ported(_sre_parse.parse(pattern.pattern, pattern.flags))
    except (_Unported, re.error):
        return None
    flags = _flags(pattern.flags, 0)
    return ("(?" + flags + ")" if flags else "") + body
