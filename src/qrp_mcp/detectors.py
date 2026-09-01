"""Detection patterns for classical crypto usage and CI signing commands."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

SOURCE_EXTENSIONS = {
    ".py", ".go", ".js", ".ts", ".java", ".rb", ".php", ".c", ".cpp", ".cs", ".sh",
    # Smart contracts and chain tooling
    ".sol", ".rs", ".move", ".cairo",
}

EXCLUDED_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", "vendor", "dist", "build", ".tox", "target",
}

CI_CONFIG_FILENAMES = {".gitlab-ci.yml", "Jenkinsfile", "azure-pipelines.yml"}

IAC_EXTENSIONS = {".tf", ".tfvars"}

# (algorithm, description, compiled regex matched against a single source line)
ALGORITHM_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("RSA", "RSA usage", re.compile(
        r"Crypto\.PublicKey\.RSA|Crypto\.PublicKey\s+import\s+RSA|"
        r"hazmat\.primitives\.asymmetric\.rsa|crypto/rsa|"
        r"KeyPairGenerator\.getInstance\(\s*[\"']RSA[\"']|openssl\s+genrsa|-newkey\s+rsa",
        re.IGNORECASE,
    )),
    ("DSA", "DSA usage", re.compile(
        r"Crypto\.PublicKey\s+import\s+DSA|"
        r"hazmat\.primitives\.asymmetric\.dsa|crypto/dsa|"
        r"KeyPairGenerator\.getInstance\(\s*[\"']DSA[\"']|openssl\s+dsaparam",
        re.IGNORECASE,
    )),
    ("ECDSA", "ECDSA usage", re.compile(r"crypto/ecdsa|\bECDSA\b", re.IGNORECASE)),
    ("EC", "Elliptic curve usage", re.compile(
        r"hazmat\.primitives\.asymmetric\.ec\b|crypto/elliptic|"
        r"KeyPairGenerator\.getInstance\(\s*[\"']EC[\"']|openssl\s+ecparam",
        re.IGNORECASE,
    )),
    ("DH", "Diffie-Hellman usage", re.compile(
        r"hazmat\.primitives\.asymmetric\.dh\b|crypto/dh\b|Diffie[- ]?Hellman", re.IGNORECASE,
    )),
    ("MD5", "MD5 usage", re.compile(
        r"hashlib\.md5|crypto/md5|MessageDigest\.getInstance\(\s*[\"']MD5[\"']|"
        r"createHash\(\s*[\"']md5[\"']|openssl\s+dgst\s+-md5",
        re.IGNORECASE,
    )),
    ("SHA1", "SHA-1 usage", re.compile(
        r"hashlib\.sha1|crypto/sha1|MessageDigest\.getInstance\(\s*[\"']SHA-?1[\"']|"
        r"createHash\(\s*[\"']sha1[\"']|openssl\s+dgst\s+-sha1",
        re.IGNORECASE,
    )),
    ("RC4", "RC4 usage", re.compile(r"crypto/rc4|\bRC4\b", re.IGNORECASE)),
    ("DES", "DES/3DES usage", re.compile(r"crypto/des\b|DESede|3DES|TripleDES", re.IGNORECASE)),
    # Blockchain / wallet signing. These map onto the same classical primitives -- a
    # secp256k1 signature is ECDSA, and Shor breaks it like any other elliptic curve.
    ("ECDSA", "secp256k1 (ECDSA) usage", re.compile(
        r"secp256k1|\bbtcec\b|bitcoinjs-lib|\bECPair\b|"
        r"\becrecover\s*\(|ECDSA\.recover|\bethers\b|\bweb3\b|"
        r"eth_sign|personal_sign|signTypedData",
        re.IGNORECASE,
    )),
    # X25519 is the classical half of every RFC 10024 TLS hybrid. Without it,
    # "X25519MLKEM768" reports the post-quantum half only, and the component Shor
    # actually breaks disappears from the inventory.
    ("X25519", "X25519 key agreement usage", re.compile(
        r"(?<![A-Za-z])x25519", re.IGNORECASE,
    )),
    ("X448", "X448 key agreement usage", re.compile(
        r"(?<![A-Za-z])x448(?![0-9])", re.IGNORECASE,
    )),
    ("Ed25519", "Ed25519 usage", re.compile(
        r"\bed25519\b|tweetnacl|\bnacl\.sign\b|@solana/web3\.js|solana_program::|"
        r"sodium_crypto_sign",
        re.IGNORECASE,
    )),
    ("Schnorr", "Schnorr signature usage", re.compile(
        r"\bschnorr\b|\bbip340\b|\btaproot\b", re.IGNORECASE,
    )),
    ("BLS", "BLS signature usage", re.compile(
        r"bls12[-_]?381|\bblst\b|@chainsafe/bls|\bbls_sig\b", re.IGNORECASE,
    )),
    # Post-quantum schemes. Without these, a codebase that has already adopted
    # ML-KEM scans as having no post-quantum cryptography at all, which reads as
    # "not started" rather than "migrating".
    # Where the scheme name is also an ordinary English word (falcon, bike, hawk,
    # frodo), the pattern requires a parameter set: a false positive on a bicycle
    # is worse than missing an unparameterised mention.
    # Neither end carries a plain \b. Real code writes the parameter set as a
    # suffix (slh_dsa_sha2_128s, ml_kem_768_keygen, mceliece348864), and RFC 10024
    # names the TLS hybrids by concatenation: X25519MLKEM768 puts a digit in front
    # of the scheme. A word boundary refuses both. What does the protective work is
    # the lookbehind for a LETTER -- it is why "FXMSS" still does not match XMSS.
    ("ML-KEM", "ML-KEM (Kyber) usage", re.compile(
        r"(?<![A-Za-z])ml[-_]?kem|(?<![A-Za-z])kyber|pqcrystals[-_]?kyber|crypto_kem_kyber", re.IGNORECASE,
    )),
    ("ML-DSA", "ML-DSA (Dilithium) usage", re.compile(
        r"(?<![A-Za-z])ml[-_]?dsa|(?<![A-Za-z])dilithium|pqcrystals[-_]?dilithium", re.IGNORECASE,
    )),
    ("SLH-DSA", "SLH-DSA (SPHINCS+) usage", re.compile(
        r"(?<![A-Za-z])slh[-_]?dsa|(?<![A-Za-z])sphincs", re.IGNORECASE,
    )),
    ("Falcon", "Falcon (FN-DSA) usage", re.compile(
        r"(?<![A-Za-z])falcon[-_]?(512|1024)|(?<![A-Za-z])fn[-_]?dsa", re.IGNORECASE,
    )),
    ("Classic McEliece", "Classic McEliece usage", re.compile(
        r"(?<![A-Za-z])classic[-_ ]?mceliece|(?<![A-Za-z])mceliece", re.IGNORECASE,
    )),
    ("NTRU", "NTRU usage", re.compile(r"(?<![A-Za-z])ntru|(?<![A-Za-z])sntrup\d+", re.IGNORECASE)),
    ("BIKE", "BIKE usage", re.compile(r"(?<![A-Za-z])bike[-_]?l[135]", re.IGNORECASE)),
    ("HQC", "HQC usage", re.compile(r"(?<![A-Za-z])hqc[-_]?(128|192|256)", re.IGNORECASE)),
    ("XMSS", "XMSS usage", re.compile(r"(?<![A-Za-z])xmss", re.IGNORECASE)),
    ("FrodoKEM", "FrodoKEM usage", re.compile(
        r"(?<![A-Za-z])frodokem|(?<![A-Za-z])frodo[-_]?(640|976|1344)", re.IGNORECASE,
    )),
    # Recognising these two is the point: both are post-quantum by design and
    # neither is safe to rely on. Unrecognised, they read as "nothing found".
    ("SIKE", "SIKE usage (broken)", re.compile(
        r"(?<![A-Za-z])sikep?\d{3}|(?<![A-Za-z])sike\b|(?<![A-Za-z])sike[-_]", re.IGNORECASE,
    )),
    ("HAWK", "HAWK usage (withdrawn)", re.compile(
        r"(?<![A-Za-z])hawk[-_]?(256|512|1024)", re.IGNORECASE,
    )),
]

# (command_type, compiled regex) for signing commands found in CI/build configs.
SIGNING_COMMAND_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("gpg_sign", re.compile(r"\bgpg\s+(--detach-sign|--sign|-s)\b")),
    ("openssl_sign", re.compile(r"\bopenssl\s+(dgst|smime|cms)\b.*-sign\b")),
    ("cosign_sign", re.compile(r"\bcosign\s+sign\b")),
    ("signtool_sign", re.compile(r"\bsigntool\s+sign\b", re.IGNORECASE)),
    ("jarsigner", re.compile(r"\bjarsigner\b")),
    ("codesign", re.compile(r"\bcodesign\b")),
]

# (algorithm, description, compiled regex) for key algorithms declared in IaC syntax
# (Terraform tls_private_key/aws_kms_key resources, cert-manager Certificate manifests) --
# distinct from ALGORITHM_PATTERNS, which target source-code import/API syntax that doesn't
# appear in HCL or YAML.
IAC_ALGORITHM_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("RSA", "RSA key algorithm declared in IaC", re.compile(
        r"algorithm\s*[:=]\s*\"?RSA\"?|customer_master_key_spec\s*=\s*\"RSA_\d+\"|"
        r"key_algorithm\s*[:=]\s*\"?RSA\"?",
        re.IGNORECASE,
    )),
    ("ECDSA", "ECDSA key algorithm declared in IaC", re.compile(
        r"algorithm\s*[:=]\s*\"?ECDSA\"?|customer_master_key_spec\s*=\s*\"ECC_\w+\"",
        re.IGNORECASE,
    )),
]

# PEM private key block header, embedded directly in an IaC file (e.g. a test key checked
# into a Terraform variable or a Kubernetes Secret manifest).
EMBEDDED_KEY_PATTERN = re.compile(r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|ENCRYPTED)?\s*PRIVATE KEY-----")


def iter_repo_files(repo_path: Path):
    for path in sorted(repo_path.rglob("*")):
        if not path.is_file():
            continue
        if any(part in EXCLUDED_DIRS for part in path.relative_to(repo_path).parts):
            continue
        yield path


def is_ci_config_file(path: Path, repo_path: Path) -> bool:
    rel = path.relative_to(repo_path).as_posix()
    if rel.startswith(".github/workflows/") and path.suffix in {".yml", ".yaml"}:
        return True
    if rel.startswith(".circleci/") and path.suffix in {".yml", ".yaml"}:
        return True
    return path.name in CI_CONFIG_FILENAMES


def _read_lines(path: Path) -> list[str] | None:
    """Lines of the file, or None when it could not be read.

    None is not an empty file. A file the scanner cannot open -- no permission, an I/O
    error, a path it lacks the rights for -- yields no findings, and returning [] here
    would make that indistinguishable from a file that WAS read and is clean. scan_repo
    reports those paths separately, so a failed check cannot read as a pass.
    """
    try:
        return path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return None


def is_iac_file(path: Path, repo_path: Path, lines: list[str] | None = None) -> bool:
    if path.suffix in IAC_EXTENSIONS:
        return True
    if path.suffix in {".yaml", ".yml"}:
        # Content-sniff for a Kubernetes manifest shape rather than trusting the extension
        # alone -- most .yaml files in a repo are not IaC.
        lines = (_read_lines(path) or []) if lines is None else lines
        has_api_version = any(re.match(r"^apiVersion:\s*\S+", line) for line in lines)
        has_kind = any(re.match(r"^kind:\s*\S+", line) for line in lines)
        return has_api_version and has_kind
    return False


def scan_source_file(path: Path, rel_path: str,
                     lines: list[str] | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    lines = (_read_lines(path) or []) if lines is None else lines
    for line_no, line in enumerate(lines, start=1):
        for algorithm, description, pattern in ALGORITHM_PATTERNS:
            if pattern.search(line):
                findings.append({
                    "path": rel_path,
                    "line": line_no,
                    "algorithm": algorithm,
                    "description": description,
                    "excerpt": line.strip()[:200],
                })
    return findings


def scan_ci_file(path: Path, rel_path: str,
                 lines: list[str] | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    lines = (_read_lines(path) or []) if lines is None else lines
    for line_no, line in enumerate(lines, start=1):
        for command_type, pattern in SIGNING_COMMAND_PATTERNS:
            if pattern.search(line):
                findings.append({
                    "path": rel_path,
                    "line": line_no,
                    "command_type": command_type,
                    "excerpt": line.strip()[:200],
                })
    return findings


def scan_iac_file(path: Path, rel_path: str,
                  lines: list[str] | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Returns (algorithm_findings, embedded_key_findings) for a Terraform/Kubernetes IaC file."""
    algorithm_findings: list[dict[str, Any]] = []
    embedded_key_findings: list[dict[str, Any]] = []
    lines = (_read_lines(path) or []) if lines is None else lines
    for line_no, line in enumerate(lines, start=1):
        for algorithm, description, pattern in IAC_ALGORITHM_PATTERNS:
            if pattern.search(line):
                algorithm_findings.append({
                    "path": rel_path,
                    "line": line_no,
                    "algorithm": algorithm,
                    "description": description,
                    "excerpt": line.strip()[:200],
                })
        if EMBEDDED_KEY_PATTERN.search(line):
            embedded_key_findings.append({
                "path": rel_path,
                "line": line_no,
                "description": "Embedded private key material",
                "excerpt": line.strip()[:200],
            })
    return algorithm_findings, embedded_key_findings


def scan_repo(repo_path: Path) -> dict[str, Any]:
    source_findings: list[dict[str, Any]] = []
    ci_findings: list[dict[str, Any]] = []
    iac_findings: list[dict[str, Any]] = []
    embedded_key_findings: list[dict[str, Any]] = []
    files_scanned = {"source": 0, "ci_config": 0, "iac": 0}

    unreadable: list[str] = []

    for path in iter_repo_files(repo_path):
        rel_path = path.relative_to(repo_path).as_posix()
        is_ci = is_ci_config_file(path, repo_path)
        if not (is_ci or path.suffix in IAC_EXTENSIONS or path.suffix in SOURCE_EXTENSIONS
                or path.suffix in {".yaml", ".yml"}):
            continue

        # Read once, here: classification and scanning must see the same content, and a
        # file that cannot be read has to leave a mark rather than pass as scanned-clean.
        lines = _read_lines(path)
        if lines is None:
            unreadable.append(rel_path)
            continue

        if is_ci:
            files_scanned["ci_config"] += 1
            ci_findings.extend(scan_ci_file(path, rel_path, lines))
        elif is_iac_file(path, repo_path, lines):
            files_scanned["iac"] += 1
            algo_findings, key_findings = scan_iac_file(path, rel_path, lines)
            iac_findings.extend(algo_findings)
            embedded_key_findings.extend(key_findings)
        elif path.suffix in SOURCE_EXTENSIONS:
            files_scanned["source"] += 1
            source_findings.extend(scan_source_file(path, rel_path, lines))

    return {
        "files_scanned": files_scanned,
        # Attempted and NOT read. files_scanned counts only files actually read, so
        # "0 findings" can be checked against a denominator instead of trusted.
        "unreadable_files": unreadable,
        "source_code_findings": source_findings,
        "ci_pipeline_findings": ci_findings,
        "iac_findings": iac_findings,
        "embedded_key_findings": embedded_key_findings,
        "detected_algorithms": sorted({f["algorithm"] for f in source_findings + iac_findings}),
    }
