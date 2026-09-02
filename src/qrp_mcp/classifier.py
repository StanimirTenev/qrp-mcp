"""Deterministic classification of cryptographic algorithms for quantum vulnerability.

No network, no LLM, no external services: the same input always produces the same output.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, Field

CONTRACT_VERSION = "cfp-v1"

# ---------------------------------------------------------------------------
# Deterministic algorithm knowledge base
# ---------------------------------------------------------------------------
# Classification values:
#   classical_vulnerable  -> public-key algorithm broken by a large quantum
#                            computer (Shor).
#   pqc_ready             -> post-quantum algorithm (NIST PQC / draft names).
#   symmetric_reduced     -> symmetric cipher; only weakened by Grover, not
#                            broken. Not a migration blocker on its own.
#   hash                  -> hash primitive of acceptable strength.
#   deprecated_weak       -> broken/deprecated primitive regardless of quantum.
#   unknown               -> could not be classified.

Classification = Literal[
    # Not an algorithm: a mechanism that confers quantum resistance without one.
    # RFC 8784 is the case, and it is kept distinct from pqc_ready so that a
    # preshared key is never counted as if it were ML-KEM.
    "quantum_resistant_mechanism",
    "classical_vulnerable",
    "pqc_ready",
    "symmetric_reduced",
    "hash",
    "deprecated_weak",
    "unknown",
]

Usage = Literal["signature", "public_key", "key_exchange", "cipher", "explicit"]

# The longest matching token wins, so this list is grouped for reading rather
# than ordered for correctness. Adding a short token can no longer shadow a
# longer one that was already here.
# fields: token, family, classification, kind
_PUBLIC_KEY_FAMILIES: list[tuple[str, str, str, str]] = [
    # A mechanism rather than an algorithm. RFC 8784 mixes a preshared key into
    # IKEv2 key derivation, so the session resists a quantum adversary without any
    # post-quantum algorithm being present. A scanner that only reads algorithm
    # names cannot see this by construction -- which is why a deployment that had
    # done the work read as "classical_only" here until it was pointed out.
    ("PPK", "PPK (RFC 8784)", "quantum_resistant_mechanism", "key_exchange"),
    # Post-quantum
    ("MLKEM", "ML-KEM", "pqc_ready", "key_exchange"),
    ("KYBER", "ML-KEM", "pqc_ready", "key_exchange"),
    ("MLDSA", "ML-DSA", "pqc_ready", "signature"),
    ("DILITHIUM", "ML-DSA", "pqc_ready", "signature"),
    ("SLHDSA", "SLH-DSA", "pqc_ready", "signature"),
    ("SPHINCS", "SLH-DSA", "pqc_ready", "signature"),
    ("FALCON", "Falcon", "pqc_ready", "signature"),
    ("FRODO", "FrodoKEM", "pqc_ready", "key_exchange"),
    ("CLASSICMCELIECE", "Classic McEliece", "pqc_ready", "key_exchange"),
    ("MCELIECE", "Classic McEliece", "pqc_ready", "key_exchange"),
    # Streamlined NTRU Prime by its own name: in "sntrup761x25519" the letters
    # "ntru" are inside a longer word, so the generic token no longer reaches it.
    ("SNTRUP", "NTRU", "pqc_ready", "key_exchange"),
    ("NTRU", "NTRU", "pqc_ready", "key_exchange"),
    ("BIKE", "BIKE", "pqc_ready", "key_exchange"),
    ("HQC", "HQC", "pqc_ready", "key_exchange"),
    ("XMSS", "XMSS", "pqc_ready", "signature"),
    # Stateful hash-based signatures, SP 800-208. CNSA 2.0 requires LMS or XMSS
    # for firmware and code signing, so leaving them out was not a small gap. LMS
    # used to be excluded because the squashed token also matched inside "films";
    # requiring the token to begin a word removed that reason.
    ("HSS", "HSS/LMS", "pqc_ready", "signature"),
    ("LMS", "HSS/LMS", "pqc_ready", "signature"),
    # FIPS 206 renames Falcon to FN-DSA, and "DSA" sits inside "FN-DSA": before
    # the longest token began winning, a standardised post-quantum signature was
    # reported as classical DSA.
    ("FNDSA", "Falcon", "pqc_ready", "signature"),
    # The nine schemes NIST advanced to the third additional-signatures round on
    # 14 May 2026. None is standardised; all are candidates, and an inventory that
    # cannot name them reports "unknown", which reads as nothing found.
    ("FAEST", "FAEST", "pqc_ready", "signature"),
    ("SQISIGN", "SQIsign", "pqc_ready", "signature"),
    ("QRUOV", "QR-UOV", "pqc_ready", "signature"),
    ("SNOVA", "SNOVA", "pqc_ready", "signature"),
    ("SDITH", "SDitH", "pqc_ready", "signature"),
    ("MQOM", "MQOM", "pqc_ready", "signature"),
    ("MAYO", "MAYO", "pqc_ready", "signature"),
    ("UOV", "UOV", "pqc_ready", "signature"),
    # Dropped by NIST at the end of the second round. Naming it is the point:
    # unrecognised reads as nothing found, not as a scheme that lost its process.
    ("CROSS", "CROSS", "pqc_ready", "signature"),
    # Post-quantum by design, but no longer safe to rely on. Recognising them is
    # the point: unrecognised is the worst of the three outcomes, because it
    # reads as "nothing found" rather than "found and broken".
    ("SIKE", "SIKE", "pqc_ready", "key_exchange"),
    ("HAWK", "HAWK", "pqc_ready", "signature"),
    # LMS is deliberately absent: the squashed token "LMS" also matches ordinary
    # words such as "films", and a false positive here is worse than a miss.
    # Classical elliptic-curve
    ("ECDSA", "ECDSA", "classical_vulnerable", "signature"),
    ("EDDSA", "EdDSA", "classical_vulnerable", "signature"),
    ("ED25519", "Ed25519", "classical_vulnerable", "signature"),
    ("ED448", "Ed448", "classical_vulnerable", "signature"),
    ("X25519", "X25519", "classical_vulnerable", "key_exchange"),
    ("CURVE25519", "X25519", "classical_vulnerable", "key_exchange"),
    ("X448", "X448", "classical_vulnerable", "key_exchange"),
    ("ECDH", "ECDH", "classical_vulnerable", "key_exchange"),
    ("ECPUBLICKEY", "EC", "classical_vulnerable", "public_key"),
    # Classical RSA / DSA / DH
    ("RSASSA", "RSA", "classical_vulnerable", "public_key"),
    ("RSAPSS", "RSA", "classical_vulnerable", "public_key"),
    ("RSA", "RSA", "classical_vulnerable", "public_key"),
    ("DSA", "DSA", "classical_vulnerable", "signature"),
    # Signature schemes common in blockchains. Both rest on discrete-log/pairing
    # hardness and fall to Shor exactly as ECDSA does.
    ("SCHNORR", "Schnorr", "classical_vulnerable", "signature"),
    ("BLS", "BLS", "classical_vulnerable", "signature"),
    ("DIFFIEHELLMAN", "DH", "classical_vulnerable", "key_exchange"),
    ("DHE", "DH", "classical_vulnerable", "key_exchange"),
    ("DH", "DH", "classical_vulnerable", "key_exchange"),
    # Named curves, before the generic token. secp256k1 used to be classified
    # only because "EC" happens to sit inside the letters of "secp" -- right for
    # the wrong reason, and it stopped being right the moment token matching
    # required a word boundary.
    ("SECP", "EC", "classical_vulnerable", "public_key"),
    ("BRAINPOOL", "EC", "classical_vulnerable", "public_key"),
    ("PRIME256V1", "EC", "classical_vulnerable", "public_key"),
    ("EC", "EC", "classical_vulnerable", "public_key"),
]

# The mathematical family a post-quantum scheme rests on, and where it stands.
# "Post-quantum" is not one property. Families fail in different ways and on
# different timelines, and a scheme can be post-quantum by design while being
# withdrawn or broken in practice: SIKE fell to a classical attack in 2022, and
# HAWK was withdrawn from NIST standardisation in 2026. A tool that reports both
# as simply "PQC" is reporting a category, not an assessment.
#   standardised -> published standard
#   selected     -> chosen for standardisation, standard not yet published
#   candidate    -> under evaluation or recommended by a national body
#   withdrawn    -> pulled from standardisation by its own authors
#   eliminated   -> dropped by NIST at the end of an evaluation round
#   broken       -> a practical attack is public
_PQC_SCHEMES: dict[str, tuple[str, str]] = {
    "ML-KEM": ("structured lattice", "standardised"),
    "ML-DSA": ("structured lattice", "standardised"),
    "SLH-DSA": ("hash-based", "standardised"),
    "XMSS": ("hash-based", "standardised"),
    "Falcon": ("structured lattice", "selected"),
    "HQC": ("code-based", "selected"),
    "Classic McEliece": ("code-based", "candidate"),
    "BIKE": ("code-based", "candidate"),
    "FrodoKEM": ("unstructured lattice", "candidate"),
    "NTRU": ("structured lattice", "candidate"),
    "HAWK": ("structured lattice", "withdrawn"),
    "SIKE": ("isogeny-based", "broken"),
    "HSS/LMS": ("hash-based", "standardised"),
    "SQIsign": ("isogeny-based", "candidate"),
    "FAEST": ("symmetric-based", "candidate"),
    "SDitH": ("code-based", "candidate"),
    "MQOM": ("multivariate", "candidate"),
    "MAYO": ("multivariate", "candidate"),
    "UOV": ("multivariate", "candidate"),
    "QR-UOV": ("multivariate", "candidate"),
    "SNOVA": ("multivariate", "candidate"),
    "CROSS": ("code-based", "eliminated"),
}

_PQC_UNSAFE = ("withdrawn", "broken", "eliminated")

# Weak / deprecated tokens that can co-occur (e.g. a weak signature hash).
_WEAK_TOKENS: list[tuple[str, str]] = [
    ("MD5", "MD5 is cryptographically broken"),
    ("SHA1", "SHA-1 is deprecated and collision-prone"),
    ("RC4", "RC4 is insecure"),
    ("TRIPLEDES", "3DES is deprecated"),
    ("3DES", "3DES is deprecated"),
    ("DES", "DES is broken"),
]

_SYMMETRIC_TOKENS: list[tuple[str, str]] = [
    ("CHACHA", "ChaCha20"),
    ("AES", "AES"),
]

_HASH_TOKENS: list[tuple[str, str]] = [
    ("SHA512", "SHA-512"),
    ("SHA384", "SHA-384"),
    ("SHA256", "SHA-256"),
    ("SHA224", "SHA-224"),
    ("SHA3", "SHA-3"),
]

_SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

WEAK_RSA_MIN_BITS = 2048


def _squash(value: str) -> str:
    """Uppercase and strip non-alphanumeric chars for robust token matching."""
    return re.sub(r"[^A-Z0-9]", "", value.upper())


# Scheme names that are also ordinary English words. A value that is nothing but
# the name is an algorithm field saying BIKE, and is taken at face value. Inside a
# longer phrase the word has to carry a parameter set, because "my bike" and
# "frodo baggins" are not cryptography. The source detectors draw the same line.
_WORDLIKE_SUFFIX: dict[str, str] = {
    "FALCON": r"[-_]?(512|1024)",
    "BIKE": r"[-_]?L[135]",
    "FRODO": r"KEM|[-_]?(640|976|1344)",
    "HAWK": r"[-_]?(256|512|1024)",
    # "mayo" and "cross" are ordinary words long before they were signature
    # schemes -- Mayo Clinic, crossroads, cross-site.
    "MAYO": r"[-_]?[1235]",
    "CROSS": r"[-_]?R[-_]?SDP",
}


def _starts_a_word(raw: str, token: str) -> bool:
    """True if `token` appears in `raw` as a name in its own right.

    Squashing strips the separators, and once they are gone a longer name and a
    shorter one are the same string: "XMSS" is inside "FXMSS", and FXMSS is a
    different construction with no security proof. So the token is re-checked
    against the original value, allowing separators between its characters but
    requiring a non-letter, or the start of the string, in front of it.

    Only the front is anchored. Parameter sets are suffixes -- XMSSMT and
    ML-KEM-768 must still match -- so anchoring the end would refuse the forms
    real code and real certificates actually carry.

    A lowercase-to-uppercase step counts as a boundary, because certificate
    algorithm names are camelCase: the RSA in "md5WithRSAEncryption" is a name,
    while the ec in "specification" is not.
    """
    pattern = r"[-_ .]*".join(re.escape(c) for c in token)
    suffix = _WORDLIKE_SUFFIX.get(token)
    for match in re.finditer(pattern, raw, re.IGNORECASE):
        start = match.start()
        if start and raw[start - 1].isalpha():
            # camelCase is the one letter-to-letter step that is still a boundary.
            if not (raw[start - 1].islower() and raw[start].isupper()):
                continue
        if suffix and _squash(raw) != token:
            if not re.match(suffix, raw[match.end():], re.IGNORECASE):
                continue
        return True
    return False


# Object identifiers, as certificates and third-party CBOMs carry them. An OID
# has no letters, so token matching can never reach it: 2.16.840.1.101.3.4.3.17
# is ML-DSA-44 and classified as "unknown" until the number itself is looked up.
# The arcs are hierarchical, so the longest matching prefix wins -- the same
# specificity rule the token table uses.
_OID_FAMILIES: list[tuple[str, str, str, str]] = [
    # NIST CSOR post-quantum. sigAlgs = 2.16.840.1.101.3.4.3, kems = ...3.4.4
    *[(f"2.16.840.1.101.3.4.3.{n}", "ML-DSA", "pqc_ready", "signature") for n in (17, 18, 19)],
    # SLH-DSA: twelve pure variants and twelve pre-hash variants.
    *[
        (f"2.16.840.1.101.3.4.3.{n}", "SLH-DSA", "pqc_ready", "signature")
        for n in [*range(20, 32), *range(35, 47)]
    ],
    *[(f"2.16.840.1.101.3.4.4.{n}", "ML-KEM", "pqc_ready", "key_exchange") for n in (1, 2, 3)],
    # Classical. PKCS#1, ANSI X9.62 / X9.57, the EdDSA arc, and the SECG and
    # brainpool named-curve arcs.
    ("1.2.840.113549.1.1", "RSA", "classical_vulnerable", "public_key"),
    ("1.2.840.10045.4", "ECDSA", "classical_vulnerable", "signature"),
    ("1.2.840.10045.2.1", "EC", "classical_vulnerable", "public_key"),
    ("1.2.840.10045.3", "EC", "classical_vulnerable", "public_key"),
    ("1.2.840.10040.4", "DSA", "classical_vulnerable", "signature"),
    ("1.3.101.110", "X25519", "classical_vulnerable", "key_exchange"),
    ("1.3.101.111", "X448", "classical_vulnerable", "key_exchange"),
    ("1.3.101.112", "Ed25519", "classical_vulnerable", "signature"),
    ("1.3.101.113", "Ed448", "classical_vulnerable", "signature"),
    ("1.3.132.0", "EC", "classical_vulnerable", "public_key"),
    ("1.3.36.3.3.2.8", "EC", "classical_vulnerable", "public_key"),
]

_LOOKS_LIKE_AN_OID = re.compile(r"^\d+(?:\.\d+)+$")


def _find_oid_family(raw: str) -> tuple[str, str, str, str] | None:
    """Resolve a dotted object identifier to a family, longest arc first."""
    value = (raw or "").strip()
    if not _LOOKS_LIKE_AN_OID.match(value):
        return None
    matches = [
        entry
        for entry in _OID_FAMILIES
        if value == entry[0] or value.startswith(entry[0] + ".")
    ]
    if not matches:
        return None
    return max(matches, key=lambda entry: len(entry[0]))


def _all_public_key_families(squashed: str, raw: str) -> list[tuple[str, str, str, str]]:
    """Every family whose token appears in the value, longest token first.

    Longest first rather than list order, because the recurring defect in this
    file has been a short generic token shadowing a longer specific one: DSA
    eating FN-DSA, AES eating FAEST, EC eating McEliece and secp256k1. Ordering
    the table by hand made that a matter of vigilance; ordering the matches by
    length makes it a property of the matcher.
    """
    oid = _find_oid_family(raw)
    if oid is not None:
        # An OID names exactly one algorithm. There is no phrase to search and no
        # second component hiding in the digits.
        return [oid]

    hits = [
        entry
        for entry in _PUBLIC_KEY_FAMILIES
        if entry[0] in squashed and _starts_a_word(raw, entry[0])
    ]
    # Post-quantum first, then longest token. A hybrid or a composite holds if
    # either half holds, so X25519MLKEM768 is a post-quantum key agreement that
    # also contains X25519 -- not an X25519 exchange that happens to mention
    # ML-KEM. Length breaks the remaining ties, which is what stops DSA from
    # shadowing FN-DSA.
    hits.sort(key=lambda entry: (entry[2] == "pqc_ready", len(entry[0])), reverse=True)

    seen: set[str] = set()
    unique: list[tuple[str, str, str, str]] = []
    for entry in hits:
        # A token contained in one already accepted is the same name seen through
        # a shorter lens: EC inside ECDSA, RSA inside RSASSA. It is not a second
        # component, and listing it would make every ECDSA finding look composite.
        if any(entry[0] in kept[0] for kept in unique):
            continue
        if entry[1] in seen:
            continue
        seen.add(entry[1])
        unique.append(entry)
    return unique


def _find_public_key_family(squashed: str, raw: str) -> tuple[str, str, str, str] | None:
    families = _all_public_key_families(squashed, raw)
    return families[0] if families else None


def _find_weak_token(squashed: str) -> tuple[str, str] | None:
    for token, note in _WEAK_TOKENS:
        if token in squashed:
            return token, note
    return None


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class FingerprintRequest(BaseModel):
    asset_name: str = Field(..., min_length=1)
    algorithms: list[str] | None = None
    tls_metadata: dict[str, Any] | None = None
    crypto_evidence: dict[str, Any] | None = None


class Finding(BaseModel):
    source: str
    location: str
    raw_value: str
    algorithm_family: str
    # Every other family named in the same value. A composite certificate
    # algorithm carries two: id-MLDSA44-RSA2048-PSS-SHA256 is ML-DSA *and*
    # RSA-2048, and an inventory that reports only the post-quantum half is
    # describing the half that is fine.
    also_present: list[str] = Field(default_factory=list)
    pqc_family: str | None = None
    pqc_status: str | None = None
    classification: Classification
    quantum_vulnerable: bool
    weak_key: bool
    severity: str
    reason: str


class FingerprintSummary(BaseModel):
    total_findings: int
    quantum_vulnerable_count: int
    pqc_ready_count: int
    weak_count: int
    highest_severity: str
    pqc_readiness: str


class FingerprintResponse(BaseModel):
    contract_version: str
    asset_name: str
    findings: list[Finding]
    summary: FingerprintSummary


# ---------------------------------------------------------------------------
# Core classifier
# ---------------------------------------------------------------------------
def classify_algorithm(
    raw_value: str,
    usage: Usage,
    *,
    source: str,
    location: str,
    key_size: int | None = None,
) -> Finding:
    """Classify a single algorithm string deterministically.

    `usage` records what the algorithm is used for at the call site; it is carried
    through the evidence contract even though the classification itself does not
    branch on it.
    """
    squashed = _squash(raw_value or "")
    weak = _find_weak_token(squashed)
    families = _all_public_key_families(squashed, raw_value or "")
    family_entry = families[0] if families else None
    also_present = [entry[1] for entry in families[1:]]
    # Said out loud in the reason as well as carried in the field: a composite or
    # hybrid name is the one place where reporting a single family drops half of
    # what the value says.
    alongside = (
        f" The same value also names {', '.join(also_present)}." if also_present else ""
    )

    if family_entry is not None:
        _token, family, classification, _kind = family_entry

        if classification == "quantum_resistant_mechanism":
            return Finding(
                source=source,
                location=location,
                raw_value=raw_value,
                algorithm_family=family,
                also_present=also_present,
                pqc_family="preshared secret",
                pqc_status="standardised",
                classification="quantum_resistant_mechanism",
                quantum_vulnerable=False,
                weak_key=False,
                severity="info",
                reason=(
                    "RFC 8784 mixes a postquantum preshared key into IKEv2 key "
                    "derivation, so the session resists a quantum adversary with no "
                    "post-quantum algorithm present. This is not an algorithm and is "
                    "not counted as one. Whether it actually holds depends on the "
                    "entropy of the preshared key and on it being distributed out of "
                    "band -- neither of which is visible from a file."
                    f"{alongside}"
                ),
            )

        if classification == "pqc_ready":
            pqc_family, pqc_status = _PQC_SCHEMES[family]

            if pqc_status in _PQC_UNSAFE:
                return Finding(
                    source=source,
                    location=location,
                    raw_value=raw_value,
                    algorithm_family=family,
                    also_present=also_present,
                    pqc_family=pqc_family,
                    pqc_status=pqc_status,
                    classification="deprecated_weak",
                    quantum_vulnerable=False,
                    weak_key=False,
                    severity="high",
                    reason=(
                        f"{family} is a post-quantum ({pqc_family}) scheme that is "
                        f"{pqc_status}; it must not be counted as quantum-resistant."
                    ),
                )

            return Finding(
                source=source,
                location=location,
                raw_value=raw_value,
                algorithm_family=family,
                also_present=also_present,
                pqc_family=pqc_family,
                pqc_status=pqc_status,
                classification="pqc_ready",
                quantum_vulnerable=False,
                weak_key=False,
                severity="info",
                reason=(
                    f"{family} is a post-quantum {pqc_family} scheme "
                    f"({pqc_status}); quantum-resistant.{alongside}"
                ),
            )

        # classical_vulnerable public-key algorithm
        weak_key = bool(
            family == "RSA" and key_size is not None and 0 < key_size < WEAK_RSA_MIN_BITS
        )

        severity = "high"
        reasons = [f"{family} is broken by a large-scale quantum computer (Shor's algorithm)."]
        if weak_key:
            severity = "critical"
            reasons.append(f"RSA key size {key_size} is below the {WEAK_RSA_MIN_BITS}-bit minimum.")
        if weak is not None:
            severity = "critical"
            reasons.append(weak[1] + ".")

        return Finding(
            source=source,
            location=location,
            raw_value=raw_value,
            algorithm_family=family,
            also_present=also_present,
            classification="classical_vulnerable",
            quantum_vulnerable=True,
            weak_key=weak_key,
            severity=severity,
            reason=" ".join(reasons),
        )

    # No public-key family. Handle weak-only, symmetric, hash, unknown.
    if weak is not None:
        return Finding(
            source=source,
            location=location,
            raw_value=raw_value,
            algorithm_family=weak[0],
            classification="deprecated_weak",
            quantum_vulnerable=False,
            weak_key=False,
            severity="high",
            reason=weak[1] + ".",
        )

    for token, label in _SYMMETRIC_TOKENS:
        if token in squashed:
            return Finding(
                source=source,
                location=location,
                raw_value=raw_value,
                algorithm_family=label,
                classification="symmetric_reduced",
                quantum_vulnerable=False,
                weak_key=False,
                severity="low",
                reason=f"{label} is symmetric; Grover halves effective strength but does not break it.",
            )

    for token, label in _HASH_TOKENS:
        if token in squashed:
            return Finding(
                source=source,
                location=location,
                raw_value=raw_value,
                algorithm_family=label,
                classification="hash",
                quantum_vulnerable=False,
                weak_key=False,
                severity="info",
                reason=f"{label} hash is of acceptable strength.",
            )

    return Finding(
        source=source,
        location=location,
        raw_value=raw_value,
        algorithm_family="unknown",
        classification="unknown",
        quantum_vulnerable=False,
        weak_key=False,
        severity="low",
        reason="Algorithm could not be classified; manual review recommended.",
    )


# ---------------------------------------------------------------------------
# Evidence extraction
# ---------------------------------------------------------------------------
def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _certificate_algorithms(certificate: dict[str, Any]) -> tuple[str | None, str | None, int | None]:
    """Return (signature, public_key, key_size) from either the nested form or the
    older flat form."""
    algorithms = certificate.get("algorithms")
    if isinstance(algorithms, dict):
        signature = algorithms.get("signature")
        public_key = algorithms.get("public_key")
    else:
        signature = certificate.get("signature_algorithm")
        public_key = certificate.get("public_key_algorithm")

    key = certificate.get("key")
    if isinstance(key, dict) and key.get("size_bits") is not None:
        key_size = _safe_int(key.get("size_bits"))
    else:
        key_size = _safe_int(certificate.get("public_key_size"))

    sig = signature if isinstance(signature, str) and signature.strip() else None
    pub = public_key if isinstance(public_key, str) and public_key.strip() else None
    return sig, pub, key_size


def extract_findings(request: FingerprintRequest) -> list[Finding]:
    findings: list[Finding] = []

    tls = request.tls_metadata or {}
    certificate = tls.get("certificate")
    if isinstance(certificate, dict):
        signature, public_key, key_size = _certificate_algorithms(certificate)
        if public_key is not None:
            findings.append(
                classify_algorithm(
                    public_key,
                    "public_key",
                    source="tls_certificate",
                    location="tls_metadata.certificate.public_key",
                    key_size=key_size,
                )
            )
        if signature is not None:
            findings.append(
                classify_algorithm(
                    signature,
                    "signature",
                    source="tls_certificate",
                    location="tls_metadata.certificate.signature",
                    key_size=key_size,
                )
            )

    cipher_suite = tls.get("cipher_suite")
    if isinstance(cipher_suite, str) and cipher_suite.strip():
        findings.append(
            classify_algorithm(
                cipher_suite,
                "cipher",
                source="tls_cipher_suite",
                location="tls_metadata.cipher_suite",
            )
        )

    packages = (
        ((request.crypto_evidence or {}).get("package_metadata", {}) or {}).get("packages", [])
    )
    if isinstance(packages, list):
        for index, package in enumerate(packages):
            name = package.get("name") if isinstance(package, dict) else None
            if isinstance(name, str) and name.strip():
                findings.append(
                    Finding(
                        source="host_package",
                        location=f"crypto_evidence.package_metadata.packages[{index}]",
                        raw_value=name,
                        algorithm_family=name,
                        classification="unknown",
                        quantum_vulnerable=False,
                        weak_key=False,
                        severity="info",
                        reason="Crypto-relevant package present; expands cryptographic attack surface.",
                    )
                )

    for index, algorithm in enumerate(request.algorithms or []):
        if isinstance(algorithm, str) and algorithm.strip():
            findings.append(
                classify_algorithm(
                    algorithm,
                    "explicit",
                    source="explicit_algorithm",
                    location=f"algorithms[{index}]",
                )
            )

    repo_scan = ((request.crypto_evidence or {}).get("repo_scan", {}) or {})

    ci_pipeline_findings = repo_scan.get("ci_pipeline_findings", [])
    if isinstance(ci_pipeline_findings, list):
        for item in ci_pipeline_findings:
            if not isinstance(item, dict):
                continue
            command_type = item.get("command_type")
            if not (isinstance(command_type, str) and command_type.strip()):
                continue
            findings.append(
                Finding(
                    source="repo_ci_pipeline",
                    location=f"{item.get('path', '?')}:{item.get('line', '?')}",
                    raw_value=command_type,
                    algorithm_family="signing_command",
                    classification="unknown",
                    quantum_vulnerable=False,
                    weak_key=False,
                    severity="info",
                    reason="CI/CD signing command detected; the signing key's algorithm is not "
                    "visible from the pipeline config alone and should be reviewed manually.",
                )
            )

    embedded_key_findings = repo_scan.get("embedded_key_findings", [])
    if isinstance(embedded_key_findings, list):
        for item in embedded_key_findings:
            if not isinstance(item, dict):
                continue
            findings.append(
                Finding(
                    source="repo_embedded_key",
                    location=f"{item.get('path', '?')}:{item.get('line', '?')}",
                    raw_value=item.get("description") or "embedded private key material",
                    algorithm_family="private_key",
                    classification="unknown",
                    quantum_vulnerable=False,
                    weak_key=True,
                    severity="critical",
                    reason="Embedded private key material committed to the repository; rotate "
                    "the key and remove it from version control history.",
                )
            )

    return findings


def summarize(findings: list[Finding]) -> FingerprintSummary:
    vulnerable = sum(1 for f in findings if f.quantum_vulnerable)
    pqc = sum(1 for f in findings if f.classification == "pqc_ready")
    weak = sum(1 for f in findings if f.classification == "deprecated_weak" or f.weak_key)

    highest = "info"
    for finding in findings:
        if _SEVERITY_RANK[finding.severity] > _SEVERITY_RANK[highest]:
            highest = finding.severity

    crypto_findings = [f for f in findings if f.classification != "unknown"]
    # A quantum-resistant mechanism carries no algorithm, so counting only
    # algorithms reports a protected deployment as unprotected. RFC 8784 is the
    # case: classical key exchange plus a preshared key, which is quantum-resistant
    # and would otherwise read here as "classical_only" -- the strongest possible
    # way of saying "you have not started" about someone who had finished.
    mechanisms = sum(1 for f in findings
                     if f.classification == "quantum_resistant_mechanism")
    if vulnerable and pqc:
        readiness = "hybrid_partial"
    elif mechanisms:
        readiness = "mechanism_protected"
    elif vulnerable:
        readiness = "classical_only"
    elif pqc:
        readiness = "pqc_ready"
    elif crypto_findings:
        readiness = "no_quantum_vulnerable_detected"
    else:
        readiness = "unknown"

    return FingerprintSummary(
        total_findings=len(findings),
        quantum_vulnerable_count=vulnerable,
        pqc_ready_count=pqc,
        weak_count=weak,
        highest_severity=highest,
        pqc_readiness=readiness,
    )


def fingerprint(request: FingerprintRequest) -> FingerprintResponse:
    findings = extract_findings(request)
    return FingerprintResponse(
        contract_version=CONTRACT_VERSION,
        asset_name=request.asset_name,
        findings=findings,
        summary=summarize(findings),
    )


def known_algorithms() -> list[dict[str, Any]]:
    """The deterministic algorithm knowledge base, de-duplicated by family."""
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for _token, family, classification, kind in _PUBLIC_KEY_FAMILIES:
        if family not in seen:
            seen.add(family)
            unique.append({"family": family, "classification": classification, "kind": kind})
    return unique
