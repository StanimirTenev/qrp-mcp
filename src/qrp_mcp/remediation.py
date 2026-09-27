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

from typing import Any

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

_UNSTANDARDISED_PQC = {
    "use": "a standardised scheme: ML-KEM for key establishment, ML-DSA or SLH-DSA for signatures",
    "standards": ["FIPS 203", "FIPS 204", "FIPS 205"],
    "note": "This post-quantum scheme is not a NIST standard and is reported as unsafe; do not "
            "count it as quantum-resistant."}

_WEAK_RSA = ("Two steps. Now: at least 2048 bits (SP 800-131A r2 disallows len(n) < 2048 for "
             "signature generation). Then: a post-quantum replacement, below.")


def _cite(names: list[str]) -> list[dict[str, str]]:
    return [{"standard": n, "what": SOURCES[n][0], "url": SOURCES[n][1]} for n in names]


def suggest(finding: dict[str, Any]) -> dict[str, Any] | None:
    """A replacement for one classified finding, or None where none is due.

    Post-quantum and quantum-resistant findings get nothing: suggesting a replacement
    for ML-KEM would be noise at best.
    """
    cls = finding.get("classification")
    fam = finding.get("algorithm_family")
    if cls == "classical_vulnerable" and fam in _BY_FAMILY:
        row = _BY_FAMILY[fam]
        out = {
            "kind": "suggestion, not applied",
            "options": [{"use": o["use"], "for": o["for"], "sources": _cite(o["standards"])}
                        for o in row["options"]],
            "note": row["note"],
        }
        if not row["options"]:
            out["sources"] = _cite(row["standards"])
        if fam == "RSA" and finding.get("weak_key"):
            out["note"] = _WEAK_RSA + " " + out["note"]
            out["sources_first_step"] = _cite(["SP 800-131A r2"])
        return out
    if cls == "deprecated_weak":
        if finding.get("pqc_family"):
            row = _UNSTANDARDISED_PQC
        elif fam in _WEAK:
            row = _WEAK[fam]
        else:
            return None
        return {"kind": "suggestion, not applied",
                "options": [{"use": row["use"], "for": "replacement",
                             "sources": _cite(row["standards"])}],
                "note": row["note"]}
    return None


def covered_families() -> set[str]:
    return set(_BY_FAMILY) | set(_WEAK)
