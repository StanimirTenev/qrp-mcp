"""Algorithm names read from their registries, and identifiers that carry a family (release 3b).

Until 0.36.0 each family rule was a list of the spellings someone had been shown: the SSH key
types an audit hit, the cipher suites of one corpus, `Curl_MD5_*`. On a held-out OpenSSH tree
none of it transferred: `rsa-sha2-512` in a `case` pattern, `$OPENSSL_BIN rsa -noout`,
`rsa_hash_id_from_ident`, `KEY_RSA_CERT` were all silent. Two general readings instead:

1. **Registry names.** Every name of the IANA SSH, TLS, JOSE and COSE registries, the names
   OpenSSH and OpenSSL implement beyond them, and the OpenSSL / ssh-keygen command lines that
   name an algorithm, each mapped once to its family and, where the name implies one, its
   key size, curve or parameter set (`data/registry_names.json`, built by
   scripts/gen_registries.py from the registries, with each source's URL and date). A name
   is matched as a whole token, in code, strings, configuration and shell alike; the
   comment / prose / ban reading of the line is the same as for every other rule.
   Post-quantum and hybrid names are in the table with no family: their own rules read them,
   and no name here can make ML-DSA, SLH-DSA, FN-DSA or EdDSA a DSA, or ML-KEM or ECDH a DH.

2. **Identifiers.** A lower-, snake- or camel-case identifier with a family among its
   components (components.components: `rsa_hash_id_from_ident`, `KEY_RSA_CERT`,
   `sshkey_ecdsa_key`) -- but only in a file that already holds another crypto finding or
   imports a crypto library, because the same words are ordinary elsewhere (`rsa_logo_draw`,
   `DHCP_*`). Two-letter components and DES need a second crypto component beside them.
   The evidence kind says so (`identifier`) and confidence.py keeps it low.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from . import components

_DATA = Path(__file__).with_name("data") / "registry_names.json"

_SOURCE_LABEL = {
    "iana-ssh": "SSH algorithm name (IANA)", "openssh": "SSH algorithm name (OpenSSH)",
    "iana-tls": "TLS name (IANA)", "iana-jose": "JOSE algorithm name (IANA)",
    "iana-cose": "COSE algorithm name (IANA)", "openssl": "OpenSSL curve name",
}


@lru_cache(maxsize=1)
def table() -> dict[str, Any]:
    data = json.loads(_DATA.read_text(encoding="utf-8"))
    names = {r[0].lower(): r for r in data["names"]}
    prefixes = sorted(data["prefixes"], key=lambda r: -len(r[0]))
    quoted = {r[0]: r for r in data["quoted"] if r[1]}
    # Speed only: a line none of these is in (lower-cased) holds no name of the table with a
    # family -- a name holds its first six characters, a glob's stem those of a name it covers.
    hints = ({r[0].lower()[:6] for r in data["names"] if r[1]}
             | {r[0].lower()[:6] for r in prefixes if r[1]}
             | {q + k.lower() for k in quoted for q in "\"'`"})
    return {**data, "by_name": names, "by_prefix": prefixes, "by_quoted": quoted,
            "prefix_starts": tuple(r[0].lower() for r in prefixes),
            "hint": re.compile(_trie(hints))}


def _trie(words: set[str]) -> str:
    """One regex matching any of `words`, as a trie: Python's engine reads a long alternation
    of literals one by one at every position (linegate._trie, for the same reason)."""
    tree: dict = {}
    for word in words:
        node = tree
        for ch in word:
            node = node.setdefault(ch, {})
        node[""] = {}

    def build(node: dict) -> str:
        if "" in node:
            return ""      # a shorter word already matches; nothing longer is needed
        branches = [re.escape(ch) + build(child) for ch, child in sorted(node.items())]
        return branches[0] if len(branches) == 1 else "(?:" + "|".join(branches) + ")"
    return build(tree)


def literals() -> set[str]:
    """Lower-case strings one of which every line this module reports on contains, for the
    line gate (linegate.LITERALS): a whole name holds itself, a glob its first part, a
    command its command word, a quoted name itself, a PEM label itself."""
    t = table()
    out = {r[0].lower() for r in t["names"] if r[1]}
    out |= {r[0].lower() for r in t["prefixes"] if r[1]}
    # A glob `rsa-sha2-*` is not a name: its stem is at least six characters of one (_glob).
    out |= {r[0].lower()[:6] for r in t["names"] if r[1]}
    # A quoted name is read only right after its quote (_QUOTED): `"rs1` is in every such line,
    # where `rs1` alone is in `errs1` too.
    out |= {q + k.lower() for k in t["by_quoted"] for q in "\"'`"}
    out |= {"openssl", "ssh-keygen", "ssh-keyscan", "rsa_keygen_bits", "rsa_padding_mode",
            "rsa_pss_saltlen"}
    out |= {label.lower() for label in t["pem_labels"]}
    return out


# --- 1. registry names ------------------------------------------------------------------------
# A token: the characters SSH, TLS and JOSE names are spelled with. Taken whole; a leading
# - + ! ^ (a list's removal or addition) and a trailing . are not part of the name.
_TOKEN = re.compile(r"[A-Za-z0-9_.@+*-]+")
_QUOTED = re.compile(r"[\"'`]([A-Za-z0-9][A-Za-z0-9_.+/-]{1,40})[\"'`]")


def _params(row: list) -> dict[str, Any]:
    return dict(row[2] or {})


def _describe(row: list, said: str | None = None) -> str:
    name, family, _, use, source = row
    label = _SOURCE_LABEL.get(source, "registry name")
    if use:
        return f"{family} used in a {use} (the {label} {said or name}); {components.MAC_OR_KDF_NOTE}"
    return f"{family} named by the {label} {said or name}"


def _glob(stem: str) -> list | None:
    """A trailing wildcard over registry names -- `rsa-sha2-*` in a shell `case`, `ssh-ed25519*`
    in an ssh_config(5) algorithm list, where patterns are allowed -- names a family when every
    name it covers is of that one family. Parameters only where they all agree."""
    if len(stem) < 6 or not re.search(r"[-_]", stem):
        return None
    rows = [r for key, r in table()["by_name"].items() if key.startswith(stem)]
    families = {r[1] for r in rows}
    if not rows or len(families) != 1 or None in families:
        return None
    params = {json.dumps(r[2], sort_keys=True) for r in rows}
    row = list(rows[0])
    row[2] = rows[0][2] if len(params) == 1 else None
    return row


def _names(line: str) -> list[tuple[list, int, str]]:
    t = table()
    out: list[tuple[list, int, str]] = []
    for m in _TOKEN.finditer(line):
        text, start = m.group(0), m.start()
        lead = len(text) - len(text.lstrip("-+!^."))
        text, start = text[lead:], start + lead
        text = text.rstrip(".-+")
        if len(text) < 6:
            continue
        low = text.lower()
        row = t["by_name"].get(low)
        if row is None and low.startswith(t["prefix_starts"]):
            for prefix in t["by_prefix"]:
                if low.startswith(prefix[0].lower()) and len(low) > len(prefix[0]):
                    row = prefix
                    break
        if row is None and low.endswith("*"):
            row = _glob(low.rstrip("*"))
        if row is not None and row[1]:
            out.append((row, start, text))
    for m in _QUOTED.finditer(line):
        row = t["by_quoted"].get(m.group(1))
        if row is not None:
            out.append((row, m.start(1), m.group(1)))
    return out


# --- OpenSSL and ssh-keygen command lines -------------------------------------------------------
# The command: `openssl`, a path ending in it, or a variable holding it ($OPENSSL, ${OPENSSL_BIN},
# "$OPENSSL"), then the subcommand -- also as the next element of an argument list
# (`["openssl", "genrsa", ...]`).
_OPENSSL = (r"(?:(?<![A-Za-z0-9_.-])(?:[\w./-]*/)?openssl|\$\{?[A-Za-z_]*OPENSSL[A-Za-z_]*\}?)"
            r"[\"']?(?:\s*,\s*[\"']|\s+)")
_OPENSSL_CMD = re.compile(_OPENSSL + r"([a-z0-9-]+)(?![\w-])")
_SIZES = {512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 7680, 8192, 15360, 16384}
_BARE_NUMBER = re.compile(r"(?<![\w.:=-])(?<!-\w)(\d{3,5})(?![\w.])")
_GENPKEY_ALG = re.compile(r"-algorithm[\"']?(?:\s*,\s*[\"']|\s+)[\"']?([A-Za-z0-9-]+)", re.I)
_PKEYOPT_BITS = re.compile(r"(?:rsa_keygen_bits|dsa_paramgen_bits|dh_paramgen_prime_len):(\d{3,5})")
_PKEYOPT_CURVE = re.compile(r"ec_paramgen_curve:([A-Za-z0-9-]+)")
_NEWKEY = re.compile(r"-newkey[\"']?(?:\s*,\s*[\"']|\s+)[\"']?(rsa-pss|rsa|dsa|ec|ed25519|ed448|"
                     r"x25519|x448)(?::(\d{3,5}))?(?![\w-])", re.I)
_DIGEST_OPTION = re.compile(r"(?<![\w-])-(md5|sha1|sha224|md4)(?![\w-])|-md[\"']?\s+[\"']?(md5|sha1)"
                            r"(?![\w-])", re.I)
_ECPARAM_NAME = re.compile(r"-name\s+[\"']?([A-Za-z0-9-]+)")
# RSA's own OpenSSL key options, wherever they are passed (-pkeyopt, -sigopt, a config file).
_RSA_OPTION = re.compile(r"(?<![\w-])rsa_(?:keygen_bits|padding_mode|pss_saltlen)(?![\w])")
_KEYGEN = re.compile(r"(?<![\w./-])ssh-key(?:gen|scan)(?![\w-])")
_KEYGEN_TYPE = re.compile(r"(?<![\w-])-t\s*[\"']?([A-Za-z0-9,@.-]+)")
_KEYGEN_BITS = re.compile(r"(?<![\w-])-b\s*[\"']?(\d{3,5})")
# Not read: `sha1sum file.tar`, `| md5` -- a checksum tool's name is one word, and row 143
# decided it is not a use (tests/test_row_143_narrow_gaps.py).


def _size_after(line: str, start: int) -> int | None:
    for m in _BARE_NUMBER.finditer(line, start):
        before = line[:m.start()].rstrip()
        # `-days 3650`, `-out 2048.pem`: the number is an option's value.
        if re.search(r"(?<![\w-])-[A-Za-z]\w*$", before):
            continue
        if int(m.group(1)) in _SIZES:
            return int(m.group(1))
    return None


def _curve_params(name: str) -> dict[str, Any]:
    row = table()["by_name"].get(name.lower())
    return dict(row[2]) if row and row[2] else {}


def _commands(line: str) -> list[tuple[str, int, str, dict[str, Any]]]:
    t = table()
    out: list[tuple[str, int, str, dict[str, Any]]] = []
    for m in _OPENSSL_CMD.finditer(line):
        cmd, pos = m.group(1).lower(), m.start(1)
        tail = line[m.end():]
        if cmd in t["openssl_commands"]:
            family = t["openssl_commands"][cmd]
            params: dict[str, Any] = {}
            if cmd in ("genrsa", "dhparam", "dsaparam", "gendsa"):
                size = _size_after(line, m.end())
                if size:
                    params["key_size"] = size
            if cmd == "ecparam":
                name = _ECPARAM_NAME.search(tail)
                if name:
                    params = _curve_params(name.group(1))
            out.append((family, pos, f"{family} named by the OpenSSL command `openssl {cmd}`",
                        params))
        elif cmd in t["openssl_digests"]:
            family = t["openssl_digests"][cmd]
            out.append((family, pos, f"{family} named by the OpenSSL command `openssl {cmd}`", {}))
        if cmd in ("genpkey", "req", "x509", "pkey", "pkeyutl", "ca", "dgst", "ts", "cms",
                   "smime", "pkcs12", "crl", "ocsp"):
            alg = _GENPKEY_ALG.search(tail)
            if cmd == "genpkey" and alg and alg.group(1).upper() in t["openssl_genpkey"]:
                family = t["openssl_genpkey"][alg.group(1).upper()]
                params = {}
                bits = _PKEYOPT_BITS.search(tail)
                if bits and family in ("RSA", "DSA", "DH"):
                    params["key_size"] = int(bits.group(1))
                curve = _PKEYOPT_CURVE.search(tail)
                if curve and family == "EC":
                    params = _curve_params(curve.group(1))
                out.append((family, m.end() + alg.start(1),
                            f"{family} named by `openssl genpkey -algorithm {alg.group(1)}`",
                            params))
            newkey = _NEWKEY.search(tail)
            if newkey:
                kind = newkey.group(1).lower()
                family = t["openssl_genpkey"][kind.upper()]
                params = {"key_size": int(newkey.group(2))} if newkey.group(2) and family in (
                    "RSA", "DSA") else {}
                out.append((family, m.end() + newkey.start(1),
                            f"{family} named by `openssl {cmd} -newkey {newkey.group(0).split()[-1]}`",
                            params))
            for d in _DIGEST_OPTION.finditer(tail):
                name = (d.group(1) or d.group(2)).lower()
                family = t["openssl_digests"].get(name)
                if family:
                    out.append((family, m.end() + d.start(), f"{family} named by the OpenSSL "
                                f"option `-{'md ' if d.group(2) else ''}{name}`", {}))
    for m in _RSA_OPTION.finditer(line):
        out.append(("RSA", m.start(), f"RSA named by the OpenSSL key option {m.group(0)}", {}))
    for m in _KEYGEN.finditer(line):
        rest = re.split(r"[|;&]", line[m.end():], maxsplit=1)[0]
        types = _KEYGEN_TYPE.search(rest)
        if not types:
            continue
        bits = _KEYGEN_BITS.search(rest)
        for kind in types.group(1).split(","):
            family = t["ssh_keygen_types"].get(kind.lower())
            row = t["by_name"].get(kind.lower())
            if family is None and row is not None:
                family = row[1]
            if not family:
                continue
            params: dict[str, Any] = {}
            if bits and family in ("RSA", "DSA"):
                params["key_size"] = int(bits.group(1))
            elif bits and family == "ECDSA" and bits.group(1) in ("256", "384", "521"):
                params = {"curve": "P-" + bits.group(1), "key_size": int(bits.group(1))}
            out.append((family, m.end() + types.start(1),
                        f"{family} named by `{m.group(0)} -t {kind}`", params))
    return out


_PEM_LABEL = None


def _pem(line: str) -> list[tuple[str, int, str]]:
    global _PEM_LABEL
    if _PEM_LABEL is None:
        labels = sorted(table()["pem_labels"], key=len, reverse=True)
        alt = "|".join(re.escape(x) for x in labels)
        # Not the armour line itself (`-----BEGIN RSA PRIVATE KEY-----`): a block in the file
        # is the key reader's to parse (certificates.py, scan_embedded_keys), and a header
        # alone is a fixture or a parser's constant. `grep "BEGIN RSA PRIVATE KEY"` and a
        # PEM type `"RSA PRIVATE KEY"` look for or write the key type.
        _PEM_LABEL = re.compile(r"(?<!-)(?:\bBEGIN |\bEND )(" + alt + r")(?![A-Z])(?!-)|[\"'](" + alt
                                + r")[\"']")
    out = []
    for m in _PEM_LABEL.finditer(line):
        label = m.group(1) or m.group(2)
        family = table()["pem_labels"][label]
        out.append((family, m.start(1) if m.group(1) else m.start(2),
                    f"{family} named by the PEM label {label}"))
    return out


def scan(line: str) -> list[tuple[str, int, str, dict[str, Any]]]:
    """(family, position, description, parameters) for each registry name, command line or PEM
    label on this line. Parameters: key_size, curve, parameter_set where the name implies one."""
    low = line.lower()
    out = ([(row[1], pos, _describe(row, said), _params(row)) for row, pos, said in _names(line)]
           if table()["hint"].search(low) else [])
    # Speed only: every command line holds one of these words, every PEM label one of these.
    if "openssl" in low or "rsa_" in low or "ssh-key" in low:
        out += _commands(line)
    if "KEY" in line or "PARAMETERS" in line:
        out += [(family, pos, said, {}) for family, pos, said in _pem(line)]
    return out


# --- 2. identifiers --------------------------------------------------------------------------
_IDENT = re.compile(r"(?<![A-Za-z0-9_$.@-])[A-Za-z_][A-Za-z0-9_]*(?![A-Za-z0-9_@-])")
# In source code a name after a member access is an identifier too (release 3e):
# `KeyUtils.RSA_ALGORITHM`, `WrappingAlgorithm.RSA_OAEP_SHA1_MGF1`, `ds.SIG_RSA_SHA256` were
# silent on the DEV-2 corpus. Not in configuration, where a dotted key is a setting's name
# (`transport.rsa_enabled`, a flag).
_MEMBER = re.compile(r"(?<![A-Za-z0-9_$@-])[A-Za-z_][A-Za-z0-9_]*(?![A-Za-z0-9_@-])")
# Components that say an identifier is about keys, signatures or key exchange: what a two-letter
# family word (EC, DH) or DES needs beside it to be read as the algorithm.
_CRYPTO_WORDS = {"KEY", "KEYS", "KEYPAIR", "PUBKEY", "PRIVKEY", "PUB", "PRIV", "PUBLIC", "PRIVATE",
                 "SIGN", "SIG", "SIGS", "SIGNATURE", "VERIFY", "CERT", "GRP", "GROUP", "PARAM",
                 "PARAMS", "PARAMETERS", "KEX", "KEYGEN", "GEN", "GENERATE", "SECRET", "SHARED",
                 "POINT", "CURVE", "BITS", "MODULUS", "PRIME", "ENCRYPT", "DECRYPT", "CIPHER",
                 "DERIVE", "AGREE", "COMPUTE", "NISTP", "EXCHANGE"}
_SHORT = {"EC", "DH", "DES", "DSS"}
# An identifier that says the algorithm is refused or switched off names it to keep it out:
# `test_md5_is_refused`, `NO_RSA`, `disable_dh` (the identifier form of detectors' ban words).
_DENIAL_PARTS = {"NO", "NOT", "NON", "DISABLE", "DISABLED", "DENY", "DENIED", "REJECT",
                 "REJECTED", "REJECTS", "REFUSE", "REFUSED", "REFUSES", "BAN", "BANNED",
                 "BLOCK", "BLOCKED", "BLOCKLIST", "FORBID", "FORBIDDEN", "UNSUPPORTED",
                 "REMOVED", "WITHOUT", "DISALLOW", "DISALLOWED", "PROHIBITED"}
# A sentence: an identifier quoted in prose (`RSA_SIGN_PKCS1_2048_SHA256 is refused by the
# policy`) is named, not used. Words only prose uses, as detectors._PROSE_WORDS.
_PROSE = {"is", "are", "was", "were", "be", "the", "by", "of", "for", "with", "this", "that",
          "it", "not", "and", "or", "to", "an", "a"}
# A crypto library imported in the file: C headers, Python, Go, Java, JavaScript, Rust, .NET.
CRYPTO_IMPORT = re.compile(
    r"#\s*include\s*[<\"](?:openssl|mbedtls|psa|wolfssl|gnutls|nettle|botan|bearssl|cryptopp|"
    r"libssh2?|nss|sodium|gcrypt|tomcrypt|polarssl|libressl|boringssl)[/._]|"
    r"^\s*(?:from|import)\s+(?:hashlib|ssl|cryptography|Crypto|Cryptodome|nacl|OpenSSL|jwt|jose|"
    r"josepy|paramiko|rsa|ecdsa|ed25519|hmac)\b|"
    r"[\"'](?:crypto/\w+|golang\.org/x/crypto[\w/]*|node:crypto|crypto|node-forge|jose|"
    r"@noble/\w+|tweetnacl|elliptic|jsrsasign)[\"']|"
    r"^\s*import\s+(?:static\s+)?(?:java\.security|javax\.crypto|org\.bouncycastle)\b|"
    r"^\s*use\s+(?:ring|openssl|rsa|p256|p384|ed25519_dalek|x25519_dalek|rustls|sha1|md5|"
    r"aws_lc_rs)\b|"
    r"^\s*using\s+System\.Security\.Cryptography\b", re.M)


# Speed only: every key of components.FAMILY, and every name components() puts together
# (SHA+1, DES+EDE3, EC+DH, Ed+DSA), contains one of these; a name without one has no family.
# EC, DH and DES are short enough to sit inside ordinary words (`sec`, `check`, `codes`): a
# component of components._PART starts after a non-letter in any case, or as a capital after a
# lower-case letter or digit, or capitalised (`Ec`) after any letter or digit.
_HINT = re.compile(r"(?i:rsa|dsa|dss|md5|sha|rc4|arcfour|25519|448|ffdh|tdes|edec)|(?<![A-Za-z])(?i:ec|dh|des)|"
                   r"(?<=[a-z0-9])(?:EC|DH|DES)|(?<=[A-Za-z0-9])(?:Ec|Dh|Des)")


def might_carry_a_family(code: str) -> bool:
    """Speed only: False where no identifier of `code` can carry a family (see _HINT)."""
    return bool(_HINT.search(code))


def identifiers(code: str, members: bool = False) -> list[tuple[str, int, str]]:
    """(family, position, description) for identifiers in `code` (comments and strings already
    blanked) that carry an algorithm family among their components; with `members`, names after
    a member access too."""
    if sum(1 for w in _WORD.findall(code) if w in _PROSE) >= 3:
        return []
    out: list[tuple[str, int, str]] = []
    for m in (_MEMBER if members else _IDENT).finditer(code):
        name = m.group(0)
        if len(name) < 3 or not _HINT.search(name):
            continue
        out += [(family, m.start(), said) for family, said in _carried(name)]
    return out


_WORD = re.compile(r"[A-Za-z]+")
# An identifier that needs no crypto elsewhere in its file (release 3e): a public-key family
# beside an operation on it or one of its own schemes -- `generate_rsa_keys`,
# `_create_raw_rsa_keyring`, `RSA_OAEP_SHA1_MGF1` in AWS Encryption SDK tests that import
# nothing from a crypto library. A name without an operation (`rsaKey`, `KEY_RSA_CERT`)
# still needs the file's context, as do the two-letter EC / DH / DSS; hashes and ciphers too.
_ALONE_FAMILIES = {"RSA", "DSA", "ECDSA", "ECDH", "Ed25519", "Ed448", "EdDSA", "X25519", "X448"}
_ALONE_WORDS = {"GENERATE", "GEN", "KEYGEN", "SIGN", "SIG", "SIGNATURE", "VERIFY", "ENCRYPT",
                "DECRYPT", "DERIVE", "AGREE", "COMPUTE", "EXCHANGE", "KEX", "CREATE",
                "OAEP", "PSS", "PKCS1", "MGF1"}


def stands_alone(name: str) -> bool:
    """Whether identifier `name` names a public-key family without the file's crypto context."""
    if not set(components.components(name)) & _ALONE_WORDS:
        return False
    return any(family in _ALONE_FAMILIES for family, _ in _carried(name))


@lru_cache(maxsize=1 << 16)
def _carried(name: str) -> tuple[tuple[str, str], ...]:
    """(family, description) for each family one identifier carries; the same name recurs
    throughout a tree, so it is decided once."""
    parts = components.components(name)
    found = components.families(parts)
    # A bare family word (`RSA`, `md5`) is a name the family rules chose not to read
    # alone (`total = RC4+RSA`, `greeting=RSA`); an identifier carries it among others.
    if not found or len(parts) < 2 or set(parts) & _DENIAL_PARTS:
        return ()
    # arc4random(3) is the system's random number generator, ChaCha20 on OpenBSD, macOS
    # and glibc 2.36; the RC4 in its name is history.
    if "RANDOM" in parts and ("ARC4" in parts or "RC4" in parts):
        return ()
    upper = set(parts)
    out = []
    for family, use in found:
        words = [p for p in parts if components.FAMILY.get(
            components._SIZED.fullmatch(p).group(1) if components._SIZED.fullmatch(p)
            else p) == family]
        if any(w in _SHORT for w in words) and not (upper & _CRYPTO_WORDS):
            continue
        # DSS beside a signature is FIPS 186's (r, s) signature encoding, which DSA and ECDSA
        # share: pyca's encode_dss_signature, cryptography-kotlin's DssRawSignatureVerifier
        # (release R5; the import of Crypto.Signature.DSS names neither, as here). So is .NET's
        # DSASignatureFormat, which ECDsa.SignData takes too.
        if family == "DSA" and "SIGNATURE" in upper and (set(words) == {"DSS"} or "FORMAT" in upper):
            continue
        out.append((family, f"{family} used in a {use} ({name}); {components.MAC_OR_KDF_NOTE}"
                    if use else f"{family} carried by the identifier {name}"))
    return tuple(out)
