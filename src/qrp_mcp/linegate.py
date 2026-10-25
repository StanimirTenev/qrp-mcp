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

`RUST_PARTS` is the same union for the optional compiled core (qrp-mcp-core), whose regex
dialect has no look-arounds: there each look-around is dropped, which only matches more.
"""

from __future__ import annotations

import bisect
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
    lower, capital, caps = [], [], []
    for key in sorted(_COMPONENT_FIRSTS, key=lambda k: (-len(k), k)):
        letters = re.match(r"[A-Z]*", key).group(0)
        digits = key[len(letters):]
        if not digits.isdigit() and digits:
            # 3DES: a token of capitals and digits only.
            caps.append(re.escape(key))
            continue
        after = r"(?![0-9])" if digits else r"(?![a-z0-9])"
        if letters:
            lower.append(re.escape(key.lower()) + after)
        if len(letters) >= 2:
            capital.append(re.escape(letters[0] + letters[1:].lower() + digits) + after)
        caps.append(re.escape(key))
    sized = "FFDHE|RSA|DSA|DHE|DH"
    lower.append(r"(?:" + sized.lower() + r")[0-9]{3,5}(?![0-9])")
    capital.append(r"(?:Ffdhe|Rsa|Dsa|Dhe|Dh)[0-9]{3,5}(?![0-9])")
    caps.append(r"(?:" + sized + r")[0-9]{3,5}")
    python = (r"(?-i:(?<![A-Za-z])(?:" + "|".join(lower) + r")|(?:" + "|".join(capital)
              + r")|(?<![A-Z])(?:" + "|".join(caps) + r")(?:(?![A-Z0-9])|(?=[A-Z][a-z])))")
    # The compiled core has no look-arounds: dropped, the part only matches more.
    rust = "(?-i:" + "|".join(re.sub(r"\(\?<?[!=][^)]*\)", "", p)
                              for p in lower + capital + caps) + ")"
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
    and otherwise it is passed over like the rest."""
    lines: set[int]
    patterns: set[int]


class Gate:
    """The union of every rule's gate, with the algorithm patterns' own literals apart."""

    def __init__(self, algorithm_literals: list[tuple[str, ...] | None]):
        # A pattern with no literal can match any line: then every line is read.
        self.everything = any(found is None for found in algorithm_literals)
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
