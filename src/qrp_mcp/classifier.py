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
    "classical_vulnerable",
    "pqc_ready",
    "symmetric_reduced",
    "hash",
    "deprecated_weak",
    "unknown",
]

Usage = Literal["signature", "public_key", "key_exchange", "cipher", "explicit"]

# Ordered most-specific-first. The first token found in the squashed value wins.
# fields: token, family, classification, kind
_PUBLIC_KEY_FAMILIES: list[tuple[str, str, str, str]] = [
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
    ("NTRU", "NTRU", "pqc_ready", "key_exchange"),
    ("BIKE", "BIKE", "pqc_ready", "key_exchange"),
    ("HQC", "HQC", "pqc_ready", "key_exchange"),
    ("XMSS", "XMSS", "pqc_ready", "signature"),
    # Post-quantum by design, but no longer safe to rely on. Recognising them is
    # the point: unrecognised is the worst of the three outcomes, because it
    # reads as "nothing found" rather than "found and broken".
    ("SIKE", "SIKE", "pqc_ready", "key_exchange"),
    ("HAWK", "HAWK", "pqc_ready", "signature"),
    # LMS is deliberately absent: the squashed token "LMS" also matches ordinary
    # words such as "films", and a false positive here is worse than a miss.
    # Classical elliptic-curve (specific before generic EC)
    ("ECDSA", "ECDSA", "classical_vulnerable", "signature"),
    ("EDDSA", "EdDSA", "classical_vulnerable", "signature"),
    ("ED25519", "Ed25519", "classical_vulnerable", "signature"),
    ("ED448", "Ed448", "classical_vulnerable", "signature"),
    ("X25519", "X25519", "classical_vulnerable", "key_exchange"),
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
#   withdrawn    -> pulled from standardisation
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
}

_PQC_UNSAFE = ("withdrawn", "broken")

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


def _find_public_key_family(squashed: str) -> tuple[str, str, str, str] | None:
    for entry in _PUBLIC_KEY_FAMILIES:
        if entry[0] in squashed:
            return entry
    return None


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
    family_entry = _find_public_key_family(squashed)

    if family_entry is not None:
        _token, family, classification, _kind = family_entry

        if classification == "pqc_ready":
            pqc_family, pqc_status = _PQC_SCHEMES[family]

            if pqc_status in _PQC_UNSAFE:
                return Finding(
                    source=source,
                    location=location,
                    raw_value=raw_value,
                    algorithm_family=family,
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
                pqc_family=pqc_family,
                pqc_status=pqc_status,
                classification="pqc_ready",
                quantum_vulnerable=False,
                weak_key=False,
                severity="info",
                reason=(
                    f"{family} is a post-quantum {pqc_family} scheme "
                    f"({pqc_status}); quantum-resistant."
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
    if vulnerable and pqc:
        readiness = "hybrid_partial"
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
