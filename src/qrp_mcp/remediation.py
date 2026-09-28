"""What to replace a finding with, and which standard says so. A suggestion, never an action.

Nothing here edits a file, opens a pull request or asks a model. A wrong answer about
cryptography is worse than none, so every row names the document it comes from and
the address it was read at (read on 2026-09-27). Where no approved standard offers a
replacement, the row says so rather than inventing one.

The role decides the answer. RSA in a key exchange and RSA in a signature are replaced
by different things; where the scan cannot tell which role a family plays, both are
given and the reader chooses.
"""

from __future__ import annotations

import re
from typing import Any

from . import profiles

SOURCES = {
    "FIPS 203": ("ML-KEM, final, 13 August 2024", "https://csrc.nist.gov/pubs/fips/203/final"),
    "FIPS 204": ("ML-DSA, final, 13 August 2024", "https://csrc.nist.gov/pubs/fips/204/final"),
    "FIPS 205": ("SLH-DSA, final, 13 August 2024", "https://csrc.nist.gov/pubs/fips/205/final"),
    "SP 800-208": ("LMS/HSS and XMSS/XMSS^MT, final", "https://csrc.nist.gov/pubs/sp/800/208/final"),
    "NIST IR 8547": ("Transition to PQC Standards, initial public DRAFT, 12 November 2024: "
                     "quantum-vulnerable signatures and key establishment deprecated after 2030 "
                     "at 112-bit strength, disallowed after 2035 (Tables 2 and 4); hybrids "
                     "accommodated as a temporary measure (Sec. 3.2)",
                     "https://csrc.nist.gov/pubs/ir/8547/ipd"),
    "SP 800-131A r2": ("Transitioning the Use of Cryptographic Algorithms and Key Lengths, "
                       "final: RSA len(n) < 2048 disallowed for signature generation; three-key "
                       "TDEA encryption disallowed after 2023; SHA-1 disallowed for signature "
                       "generation", "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final"),
    "RFC 6151": ("MD5 is no longer acceptable where collision resistance is required",
                 "https://www.rfc-editor.org/rfc/rfc6151"),
    "RFC 7465": ("Prohibiting RC4 Cipher Suites in TLS", "https://www.rfc-editor.org/rfc/rfc7465"),
    "FIPS 46-3": ("Data Encryption Standard, withdrawn 19 May 2005",
                  "https://csrc.nist.gov/pubs/fips/46-3/final"),
}

_KEM = {"use": "ML-KEM (ML-KEM-768 or ML-KEM-1024)", "for": "key establishment",
        "standards": ["FIPS 203", "NIST IR 8547"]}
_SIG = {"use": "ML-DSA (ML-DSA-65 or ML-DSA-87), or SLH-DSA where a hash-based scheme is wanted",
        "for": "signatures", "standards": ["FIPS 204", "FIPS 205", "NIST IR 8547"]}
_SIG_FIRMWARE = {"use": "LMS/HSS or XMSS", "for": "firmware and code signing with a bounded "
                 "number of signatures (stateful: the signer must never reuse a state)",
                 "standards": ["SP 800-208"]}
_HYBRID = ("During the transition a hybrid (classical + post-quantum) is accommodated; NIST "
           "treats it as temporary, leading to post-quantum only (NIST IR 8547 Sec. 3.2).")

# family -> list of options; an empty list is an explicit "no approved replacement".
_BY_FAMILY: dict[str, dict[str, Any]] = {}
for fam in ("X25519", "X448", "ECDH", "DH"):
    _BY_FAMILY[fam] = {"options": [_KEM], "note": _HYBRID}
for fam in ("ECDSA", "EdDSA", "Ed25519", "Ed448", "DSA"):
    _BY_FAMILY[fam] = {"options": [_SIG, _SIG_FIRMWARE], "note": _HYBRID}
for fam in ("RSA", "EC"):
    _BY_FAMILY[fam] = {
        "options": [_KEM, _SIG, _SIG_FIRMWARE],
        "note": ("The scan does not tell whether this key is used to establish keys or to "
                 "sign; the replacement depends on that. " + _HYBRID)}
for fam, why in (("BLS", "BLS signatures are chosen for aggregation, which none of the "
                         "approved post-quantum signatures offers"),
                 ("Schnorr", "Schnorr signatures are usually chosen for aggregation or "
                             "threshold schemes, which none of the approved post-quantum "
                             "signatures offers as such")):
    _BY_FAMILY[fam] = {
        "options": [],
        "note": (f"No approved drop-in replacement: {why}. ML-DSA or SLH-DSA replace the "
                 f"signature, not the property; this is a protocol redesign. (Design "
                 f"judgement, not a statement of the standards.)"),
        "standards": ["FIPS 204", "FIPS 205"]}

_WEAK: dict[str, dict[str, Any]] = {
    "MD5": {"use": "SHA-256 or SHA-3-256 (SHA-384/512 for higher strength)",
            "standards": ["RFC 6151", "NIST IR 8547"],
            "note": "RFC 6151: not acceptable where collision resistance is required; "
                    "HMAC-MD5 is less urgent but should go too."},
    "SHA1": {"use": "SHA-256 or SHA-3-256", "standards": ["SP 800-131A r2", "NIST IR 8547"],
              "note": "Disallowed for signature generation; verification allowed for legacy use."},
    "RC4": {"use": "AES-GCM (or ChaCha20-Poly1305 where the protocol offers it)",
            "standards": ["RFC 7465", "NIST IR 8547"], "note": "TLS must not negotiate RC4."},
    "DES": {"use": "AES (AES-256 for long-lived data)", "standards": ["FIPS 46-3", "NIST IR 8547"],
            "note": "The DES standard was withdrawn in 2005."},
    "3DES": {"use": "AES (AES-256 for long-lived data)", "standards": ["SP 800-131A r2", "NIST IR 8547"],
             "note": "Three-key TDEA encryption is disallowed after 2023; decryption for legacy use only."},
}

# The classifier names these by the token it matched.
_WEAK["TRIPLEDES"] = _WEAK["3DES"]
_WEAK_HASHES = {"MD5", "SHA1"}

_UNSTANDARDISED_PQC = {
    "use": "a standardised scheme: ML-KEM for key establishment, ML-DSA or SLH-DSA for signatures",
    "standards": ["FIPS 203", "FIPS 204", "FIPS 205"],
    "note": "This post-quantum scheme is not a NIST standard and is reported as unsafe; do not "
            "count it as quantum-resistant."}

_WEAK_RSA = ("Two steps. Now: at least 2048 bits (SP 800-131A r2 disallows len(n) < 2048 for "
             "signature generation). Then: a post-quantum replacement, below.")


# The role of one RSA or EC occurrence, read from its own line. Everything else names
# its role in its family (ECDSA signs, ECDH and X25519 agree keys), so only these two
# are asked. A key generated or declared on a line is used somewhere else, and this
# reads one line: such a line stays `undetermined` rather than being guessed from what
# keys of that kind usually do. A line with signals for both roles is `undetermined` too.
ROLE_FAMILIES = ("RSA", "EC")

_SIGNATURE = re.compile(
    r"(?<![a-z])sign(?!al)|(?<![a-z])verif|signature|rsassa|(?<![a-z])pss(?![a-z])"
    r"|sha\d*with(rsa|ecdsa)|rsa-sha2|ssh-rsa|ecdsa|(?<![a-z0-9])[rpe]s(256|384|512)(?![0-9])"
    r"|(?<![a-z])(ecdhe|dhe|edh|ecdh|dh)[-_]rsa(?![a-z])|(?<![a-z])arsa(?![a-z])"
    # RSA with a fixed (EC)DH key signs the certificate that carries it (0.23: OpenSSL
    # TLS_CT_RSA_FIXED_ECDH, TLS_ECDH_RSA_WITH_..., both called key transport before).
    r"|rsa_fixed_e?c?dh|op_type_sig"
    # 0.25: the raw RSA operations of a signature in C (wolfSSL, OpenSSL): verification is
    # a public-key "decrypt", signing a private-key "encrypt".
    r"|public_decrypt|private_encrypt"
    r"|1\.2\.840\.113549\.1\.1\.(5|10|11|12|13|14)(?![0-9])")
_KEY_ESTABLISHMENT = re.compile(
    # `ECDHE_RSA` with an underscore is the IANA spelling of the suite the dash form
    # names; 0.21 read only the dash and called nine TLS lines key transport.
    r"oaep|rsaes|rsa1_5|(?<![a-z])(?:(?<!private_)en|(?<!public_)de)crypt|(?<![a-z])kex"
    r"|(?<!fixed_)ecdh(?!e?[-_](rsa|ecdsa))|op_type_crypt"
    # 0.24: RSA-PSK suites transport the premaster secret under RSA (curl, 13 of 20 left
    # undetermined in the 0.23 measurement).
    r"|(?<![a-z])rsa[-_]psk"
    # 0.24: a TLS group is what the key exchange runs over (Mbed TLS, 17 of 20). Only the
    # TLS spellings: `EC_GROUP_new` and `ecp_group` are the curve's mathematical group and
    # say nothing about the role.
    r"|(?<![a-z_])groups\s*[=:(]|groups_list|tls_group|[+-]group-|selected_group"
    r"|have_group_|(?<![a-z_])group\(|(?<![a-z])-groups(?![a-z])"
    # 0.25: the other spellings met in s2n-tls and wolfSSL (4 of 40 group lines were read).
    r"|(?<![a-z_])group::|group\.(supported|negotiated)|kem_group|groupinformation|kx_?group"
    r"|->group\[|(?<![a-z_])groups\[|namedgroup|supported_groups|negotiated_curve|kex_params"
    r"|(?<![a-z])derive|key.?(agreement|exchange|transport)|tls_rsa_with|(?<![a-z])krsa(?![a-z])"
    r"|1\.2\.840\.113549\.1\.1\.7(?![0-9])"
    # An OpenSSL suite name with no key-exchange prefix (RC4-SHA, AES128-GCM-SHA256)
    # is RSA key transport. Found in a cipher list the first draft called signature.
    r"|(?<![a-z0-9_-])(aes\d*|camellia\d*|des-cbc3|rc4|seed|idea)-(gcm-)?(sha|md5)")
# A cipher list longer than the quoted excerpt: the part that was cut can carry the
# other role, so what the excerpt shows is not the whole line.
_EXCERPT_LIMIT = 200
_GENERIC_RSA = re.compile(r"evp_pkey_rsa(?![_a-z])")
_CIPHER_LIST = re.compile(r"[a-z0-9]+-[a-z0-9-]+:[a-z0-9]+-")


def role_of(item: dict[str, Any]) -> str | None:
    """`signature`, `key_establishment` or `undetermined` for an RSA or EC occurrence;
    None for any other family, whose name already says its role."""
    if item.get("algorithm") not in ROLE_FAMILIES:
        return None
    excerpt = str(item.get("excerpt") or "")
    if len(excerpt) >= _EXCERPT_LIMIT and _CIPHER_LIST.search(excerpt.lower()):
        return "undetermined"
    text = f"{excerpt} {item.get('description') or ''}".lower()
    # PSS named beside the generic RSA key type is a table of both uses, not a signature.
    if _GENERIC_RSA.search(text) and "pss" in text:
        return "undetermined"
    sig, kex = bool(_SIGNATURE.search(text)), bool(_KEY_ESTABLISHMENT.search(text))
    if sig and not kex:
        return "signature"
    if kex and not sig:
        return "key_establishment"
    return "undetermined"


def _cite(names: list[str]) -> list[dict[str, str]]:
    return [{"standard": n, "what": SOURCES[n][0], "url": SOURCES[n][1]} for n in names]


def _role_of_option(option: dict[str, Any]) -> str:
    return "key_establishment" if option["for"].startswith("key establishment") else "signature"


def _profile_block(profile: str) -> dict[str, Any]:
    p = profiles.PROFILES[profile]
    block = {"name": profile, "authority": p["authority"], "addresses": p["addresses"],
             "hybrid": p["hybrid"], "source": profiles.source(profile)}
    for key in ("dates", "symmetric", "absent"):
        if p.get(key):
            block[key] = p[key]
    return block


def _profile_options(profile: str, options: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The same roles, in the authority's words. A role the authority does not fill
    (ASD names no hash-based signature) is left out, not filled with NIST's answer.
    An authority with no algorithms of its own (Bulgaria) keeps NIST's options."""
    p = profiles.PROFILES[profile]
    if p["key_establishment"] is None and p["signatures"] is None:
        return options
    out = []
    for option in options:
        if option["for"].startswith("key establishment"):
            use = p["key_establishment"]
        elif option["for"].startswith("signatures"):
            use = p["signatures"]
        else:
            use = p["firmware"]
        if use:
            out.append({"use": use, "for": option["for"], "sources": [profiles.source(profile)]})
    return out


def suggest(finding: dict[str, Any],
            roles: dict[str, int] | None = None,
            profile: str = "nist") -> dict[str, Any] | None:
    """A replacement for one classified finding, or None where none is due.

    Post-quantum and quantum-resistant findings get nothing: suggesting a replacement
    for ML-KEM would be noise at best.

    `roles` counts the roles read from the lines of an RSA or EC finding (code only,
    not comments). A path is dropped only when no line showed that role and no line
    was undetermined; otherwise it stays, with how many lines it is for.

    `profile` names whose rules to follow (see `profiles`); the default is NIST.
    """
    if profile != "nist" and profile not in profiles.PROFILES:
        raise ValueError(f"unknown profile {profile!r}; known: {', '.join(profiles.names())}")
    cls = finding.get("classification")
    fam = finding.get("algorithm_family")
    if cls == "classical_vulnerable" and fam in _BY_FAMILY:
        row = _BY_FAMILY[fam]
        options = [{"use": o["use"], "for": o["for"], "sources": _cite(o["standards"])}
                   for o in row["options"]]
        if profile != "nist" and options:
            options = _profile_options(profile, options)
        note = row["note"]
        if fam in ROLE_FAMILIES and roles:
            undetermined = roles.get("undetermined", 0)
            kept = []
            for option in options:
                seen = roles.get(_role_of_option(option), 0)
                if seen or undetermined:
                    kept.append({**option, "lines_with_this_role": seen,
                                 "lines_undetermined": undetermined})
            options = kept
            note = (f"Role read from each line of code: {roles.get('signature', 0)} signature, "
                    f"{roles.get('key_establishment', 0)} key establishment, {undetermined} "
                    f"undetermined -- a key generated or declared on a line is used elsewhere, "
                    f"and one line cannot say how. " + _HYBRID)
        out = {
            "kind": "suggestion, not applied",
            "options": options,
            "note": note,
        }
        if fam in ROLE_FAMILIES and roles:
            out["roles_seen"] = dict(roles)
        if not row["options"]:
            out["sources"] = _cite(row["standards"])
        if fam == "RSA" and finding.get("weak_key"):
            own = profile != "nist" and profiles.PROFILES[profile].get("weak_rsa")
            if own:
                # The authority's own minimum, checked against its text, is the first step.
                out["note"] = (f"Two steps. Now: {own}. Then: a post-quantum replacement, "
                               f"below. " + out["note"])
                out["sources_first_step"] = [profiles.source(profile)]
            else:
                out["note"] = _WEAK_RSA + " " + out["note"]
                out["sources_first_step"] = _cite(["SP 800-131A r2"])
                if profile != "nist":
                    out["first_step_follows"] = ("NIST: this profile's document sets no RSA "
                                                 "minimum that has been checked")
        if profile != "nist":
            out["profile"] = _profile_block(profile)
            out["note"] = out["note"].replace(
                _HYBRID, "Hybrid, under this profile: " + profiles.PROFILES[profile]["hybrid"])
        return out
    if cls == "deprecated_weak":
        if finding.get("pqc_family"):
            row = _UNSTANDARDISED_PQC
        elif fam in _WEAK:
            row = _WEAK[fam]
        else:
            return None
        out = {"kind": "suggestion, not applied",
               "options": [{"use": row["use"], "for": "replacement",
                            "sources": _cite(row["standards"])}],
               "note": row["note"]}
        if profile != "nist":
            out["profile"] = _profile_block(profile)
            own = profiles.PROFILES[profile].get(
                "weak_hash" if fam in _WEAK_HASHES else "weak_cipher")
            if own and not finding.get("pqc_family"):
                # The authority's own minimum, checked against its text, replaces
                # NIST's row: a first line that contradicts the chosen profile is read
                # first and believed.
                out["options"] = [{"use": own, "for": "replacement",
                                   "sources": [profiles.source(profile)]}]
            else:
                out["follows"] = ("NIST: this profile's document sets no minimum for this "
                                  "algorithm that has been checked, so NIST's row is shown")
        return out
    return None


def covered_families() -> set[str]:
    return set(_BY_FAMILY) | set(_WEAK)
