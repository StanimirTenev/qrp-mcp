"""Detection patterns for classical crypto usage and CI signing commands."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .certificates import is_certificate_file, scan_certificate_file

SOURCE_EXTENSIONS = {
    ".py", ".go", ".js", ".ts", ".java", ".rb", ".php", ".c", ".cpp", ".cs", ".sh",
    # C and C++ headers. Declarations live here, and in a C codebase they are
    # roughly half the tree -- reading .c but not .h reports a fraction of the
    # file count as if it were the whole language.
    ".h", ".hpp", ".hh", ".cc", ".cxx",
    # PowerShell and Perl. .sh was already here, so leaving these out was an
    # oversight rather than a scope decision: a Windows estate keeps its
    # certificate handling in .ps1, and OpenSSL's build is Perl.
    ".ps1", ".psm1", ".pl", ".pm",
    # Smart contracts and chain tooling
    ".sol", ".rs", ".move", ".cairo",
}

EXCLUDED_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", "vendor", "dist", "build", ".tox", "target",
    # Test caches are generated, like the rest of this set. Counting them pads the
    # denominator with files no reader cares about, which weakens the one number
    # this scanner exists to state honestly.
    ".pytest_cache", ".mypy_cache", ".ruff_cache",
}

CI_CONFIG_FILENAMES = {".gitlab-ci.yml", "Jenkinsfile", "azure-pipelines.yml"}

IAC_EXTENSIONS = {".tf", ".tfvars"}

# Where cryptographic choices are configured rather than written. A TLS or SSH
# hybrid group -- X25519MLKEM768, mlkem768x25519-sha256 -- is almost never a
# string in code; it is a line in nginx.conf or sshd_config. Scanning only source
# meant the whole RFC 10024 vocabulary could be deployed and stay invisible.
CONFIG_EXTENSIONS = {".conf", ".cnf", ".ini", ".toml", ".properties", ".cfg"}

# The same files that carry no extension at all.
CONFIG_FILENAMES = {"sshd_config", "ssh_config", "ssl.conf", "krb5.conf"}

# (algorithm, description, compiled regex matched against a single source line)
ALGORITHM_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("RSA", "RSA usage", re.compile(
        r"Crypto\.PublicKey\.RSA|Crypto\.PublicKey\s+import\s+RSA|"
        r"hazmat\.primitives\.asymmetric\.rsa|crypto/rsa|"
        r"KeyPairGenerator\.getInstance\(\s*[\"']RSA[\"']|openssl\s+genrsa|-newkey\s+rsa|"
        # C / OpenSSL: the library's own API, which is what a C tree actually contains.
        r"\bRSA_new\b|\bRSA_generate_key\w*|\bRSA_public_encrypt\b|\bRSA_private_decrypt\b|"
        r"\bEVP_PKEY_RSA\b|\bEVP_RSA_gen\b|\bPEM_read_\w*RSA\w*|\bd2i_RSA\w*|"
        # .NET / PowerShell: a Windows estate keeps its certificate handling here.
        r"\bRSACryptoServiceProvider\b|\bRSACng\b|\bRSAOpenSsl\b|\bRSA\.Create\b|"
        r"\bRSACertificateExtensions\b|\bGetRSAPublicKey\b|\bGetRSAPrivateKey\b|"
        r"-KeyAlgorithm\s+[\"']?RSA",
        re.IGNORECASE,
    )),
    ("DSA", "DSA usage", re.compile(
        r"Crypto\.PublicKey\s+import\s+DSA|"
        r"hazmat\.primitives\.asymmetric\.dsa|crypto/dsa|"
        r"KeyPairGenerator\.getInstance\(\s*[\"']DSA[\"']|openssl\s+dsaparam|"
        r"\bDSA_new\b|\bDSA_generate_key\w*|\bEVP_PKEY_DSA\b|"
        r"\bDSACryptoServiceProvider\b|\bDSACng\b",
        re.IGNORECASE,
    )),
    ("ECDSA", "ECDSA usage", re.compile(
        r"crypto/ecdsa|(?<![A-Za-z])ECDSA|"
        # C / OpenSSL.
        r"\bECDSA_do_sign\b|\bECDSA_sign\b|\bECDSA_verify\b|\bECDSA_SIG_\w+|"
        # .NET spells it ECDsa, so \bECDSA\b does not reach ECDsaCng or
        # ECDsaCertificateExtensions -- the exact call our own Windows agent makes.
        r"\bECDsaCng\b|\bECDsaOpenSsl\b|\bECDsa\.Create\b|"
        r"\bECDsaCertificateExtensions\b|\bGetECDsaPublicKey\b|\bGetECDsaPrivateKey\b",
        re.IGNORECASE,
    )),
    ("EC", "Elliptic curve usage", re.compile(
        r"hazmat\.primitives\.asymmetric\.ec\b|crypto/elliptic|"
        r"KeyPairGenerator\.getInstance\(\s*[\"']EC[\"']|openssl\s+ecparam|"
        r"\bEC_KEY_new\w*|\bEC_GROUP_new\w*|\bEVP_PKEY_EC\b|\bEC_POINT_\w+|"
        r"\bECCurve\.|\bECParameters\b|"
        # IKE proposal syntax: ecp384 is NIST P-384 and lives in swanctl.conf,
        # where a scanner reading only library calls never meets it.
        r"(?<![A-Za-z])ecp(?:192|224|256|384|521)(?![0-9])",
        re.IGNORECASE,
    )),
    ("DH", "Diffie-Hellman usage", re.compile(
        r"hazmat\.primitives\.asymmetric\.dh\b|crypto/dh\b|Diffie[- ]?Hellman|"
        r"\bDH_new\b|\bDH_generate_key\b|\bEVP_PKEY_DH\b|"
        r"\bECDiffieHellmanCng\b|\bECDiffieHellman\.Create\b|"
        # IKE modp groups: modp2048 is group 14, and Shor breaks it like any
        # finite-field Diffie-Hellman.
        r"(?<![A-Za-z])modp(?:1024|1536|2048|3072|4096|6144|8192)(?![0-9])",
        re.IGNORECASE,
    )),
    ("MD5", "MD5 usage", re.compile(
        r"hashlib\.md5|crypto/md5|MessageDigest\.getInstance\(\s*[\"']MD5[\"']|"
        r"createHash\(\s*[\"']md5[\"']|openssl\s+dgst\s+-md5|"
        r"\bMD5_Init\b|\bMD5_Update\b|\bEVP_md5\b|"
        r"\bMD5CryptoServiceProvider\b|\bMD5\.Create\b",
        re.IGNORECASE,
    )),
    ("SHA1", "SHA-1 usage", re.compile(
        r"hashlib\.sha1|crypto/sha1|MessageDigest\.getInstance\(\s*[\"']SHA-?1[\"']|"
        r"createHash\(\s*[\"']sha1[\"']|openssl\s+dgst\s+-sha1|"
        r"\bSHA1_Init\b|\bSHA1_Update\b|\bEVP_sha1\b|"
        r"\bSHA1CryptoServiceProvider\b|\bSHA1Managed\b|\bSHA1\.Create\b",
        re.IGNORECASE,
    )),
    ("RC4", "RC4 usage", re.compile(
        r"crypto/rc4|\bRC4\b|\bRC4_set_key\b|\bEVP_rc4\b", re.IGNORECASE,
    )),
    ("DES", "DES/3DES usage", re.compile(
        r"crypto/des\b|DESede|3DES|TripleDES|"
        r"\bDES_set_key\w*|\bDES_ecb_encrypt\b|\bEVP_des_\w+|"
        r"\bDESCryptoServiceProvider\b|\bTripleDESCng\b", re.IGNORECASE,
    )),
    # Blockchain / wallet signing. These map onto the same classical primitives -- a
    # secp256k1 signature is ECDSA, and Shor breaks it like any other elliptic curve.
    ("ECDSA", "secp256k1 (ECDSA) usage", re.compile(
        r"secp256k1|\bbtcec\b|bitcoinjs-lib|\bECPair\b|"
        r"\becrecover\s*\(|ECDSA\.recover|\bethers\b|\bweb3\b|"
        r"eth_sign|personal_sign|signTypedData",
        re.IGNORECASE,
    )),
    # RFC 8784. Quantum resistance with no post-quantum algorithm to find, so it
    # is matched by the configuration directives that turn it on rather than by a
    # scheme name. Bare "ppk" is deliberately not enough: .ppk is also PuTTY's key
    # format, and a key file is not a postquantum preshared key.
    ("PPK", "RFC 8784 postquantum preshared key", re.compile(
        r"(?<![A-Za-z])ppk_(?:id|required|secret|dynamic)(?![A-Za-z])|"
        r"(?<![A-Za-z])ppk[ \t]*=|@ppk(?![A-Za-z])|"
        r"(?<![A-Za-z])ppk[ \t]+(?:manual|dynamic)(?![A-Za-z])|"
        r"RFC[ \t-]?8784",
        re.IGNORECASE,
    )),
    # X25519 is the classical half of every RFC 10024 TLS hybrid. Without it,
    # "X25519MLKEM768" reports the post-quantum half only, and the component Shor
    # actually breaks disappears from the inventory.
    ("X25519", "X25519 key agreement usage", re.compile(
        r"(?<![A-Za-z])x25519|(?<![A-Za-z])curve25519", re.IGNORECASE,
    )),
    # Uppercase X448 is unambiguous. Lowercase x448 is not: Bitcoin Core lists
    # node service flags in hex -- "x1, x5, x9, x408, x448, xc08" -- and three of
    # those read as the curve. Lowercase therefore has to be attached to an
    # identifier (asymmetric.x448, ossl_x448, param.x448) rather than standing
    # alone in prose.
    ("X448", "X448 key agreement usage", re.compile(r"(?<![A-Za-z])X448(?![0-9])")),
    ("X448", "X448 key agreement usage", re.compile(
        r"(?<=[._/-])x448(?![0-9])|(?<![A-Za-z])x448(?=[._])",
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
    # A trailing guard as well as a leading one: "ntrunc" (n truncated) is a
    # variable in Bitcoin Core and matched 22 times. The real parameter sets are
    # spelled ntruhps2048509 / ntruhrss701 / ntru_prime, so they are named rather
    # than left to a boundary that cannot tell them from an ordinary word.
    ("NTRU", "NTRU usage", re.compile(
        r"(?<![A-Za-z])ntru(?:hps|hrss|prime|[-_\d]|(?![A-Za-z]))|"
        r"(?<![A-Za-z])sntrup\d+",
        re.IGNORECASE,
    )),
    ("BIKE", "BIKE usage", re.compile(r"(?<![A-Za-z])bike[-_]?l[135]", re.IGNORECASE)),
    ("HQC", "HQC usage", re.compile(r"(?<![A-Za-z])hqc[-_]?(128|192|256)", re.IGNORECASE)),
    ("XMSS", "XMSS usage", re.compile(r"(?<![A-Za-z])xmss", re.IGNORECASE)),
    # Stateful hash-based, SP 800-208. CNSA 2.0 requires LMS or XMSS for firmware
    # and code signing, so a firmware pipeline that had complied scanned as empty.
    ("HSS/LMS", "LMS/HSS stateful signature usage", re.compile(
        r"(?<![A-Za-z])lms[-_]?sha|(?<![A-Za-z])hss[-_/]?lms|(?<![A-Za-z])lms[-_]?(sha256|shake)|"
        r"(?<![A-Za-z])hsslms|lms_sha256_m\d+_h\d+",
        re.IGNORECASE,
    )),
    # The nine schemes NIST advanced to the third additional-signatures round on
    # 14 May 2026, plus CROSS, which it dropped. "mayo" and "cross" are ordinary
    # words, so those two need their parameter set, as falcon and bike do.
    ("FAEST", "FAEST usage", re.compile(r"(?<![A-Za-z])faest", re.IGNORECASE)),
    ("SQIsign", "SQIsign usage", re.compile(r"(?<![A-Za-z])sqisign", re.IGNORECASE)),
    ("SNOVA", "SNOVA usage", re.compile(r"(?<![A-Za-z])snova", re.IGNORECASE)),
    ("SDitH", "SDitH usage", re.compile(r"(?<![A-Za-z])sdith", re.IGNORECASE)),
    ("MQOM", "MQOM usage", re.compile(r"(?<![A-Za-z])mqom", re.IGNORECASE)),
    ("QR-UOV", "QR-UOV usage", re.compile(r"(?<![A-Za-z])qr[-_]?uov", re.IGNORECASE)),
    ("UOV", "UOV usage", re.compile(r"(?<![A-Za-z])uov[-_]?(i|ip|iii|v|s|pkc)", re.IGNORECASE)),
    ("MAYO", "MAYO usage", re.compile(r"(?<![A-Za-z])mayo[-_]?[1235]", re.IGNORECASE)),
    ("CROSS", "CROSS usage (dropped by NIST)", re.compile(
        r"(?<![A-Za-z])cross[-_]?r?[-_]?sdp", re.IGNORECASE,
    )),
    ("FrodoKEM", "FrodoKEM usage", re.compile(
        r"(?<![A-Za-z])frodokem|(?<![A-Za-z])frodo[-_]?(640|976|1344)", re.IGNORECASE,
    )),
    # Recognising these two is the point: both are post-quantum by design and
    # neither is safe to rely on. Unrecognised, they read as "nothing found".
    # Parameterised or hyphenated forms, case-insensitively. The bare word is
    # handled separately below: lowercase "sike" is a word in Venda, and matched
    # a translation string in Bitcoin Core -- which would have reported the one
    # broken scheme in the list as present in Bitcoin.
    ("SIKE", "SIKE usage (broken)", re.compile(
        r"(?<![A-Za-z])sikep?\d{3}|(?<![A-Za-z])sike[-_]", re.IGNORECASE,
    )),
    ("SIKE", "SIKE usage (broken)", re.compile(r"(?<![A-Za-z])SIKE(?![A-Za-z])")),
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


def is_config_file(path: Path) -> bool:
    """A configuration file, by extension or by one of the extensionless names."""
    return path.suffix in CONFIG_EXTENSIONS or path.name in CONFIG_FILENAMES


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


# A cipher suite names what it excludes as well as what it allows: an OpenSSL
# cipher string writes "!3DES !MD5 !RC4". Reporting those as usage does not pad
# the answer, it inverts it -- the one configuration that took the trouble to ban
# a primitive gets recorded as using it. Found in Certbot's Apache fixtures,
# where eight of nine DES findings were the string "!3DES".
#
# This applies to CONFIGURATION ONLY. In C, "!" is logical negation, and applying
# the rule to source deleted 190 real findings in OpenSSL alone -- if (!MD5_Init(&c)),
# if (!EC_POINT_set_affine_coordinates(...)), if (!ml_kem_has(key, selection)).
# A rule that hides real cryptography is the same failure as one that invents it.
def _is_excluded(line: str, start: int) -> bool:
    """True when the match is an exclusion in a cipher list, not a use of it."""
    i = start - 1
    # Step back over a leading digit, so "!3DES" is judged from the "!" and not
    # from the "3" that the DES pattern happens to start on.
    while i >= 0 and line[i].isdigit():
        i -= 1
    return i >= 0 and line[i] == "!"


def scan_source_file(path: Path, rel_path: str,
                     lines: list[str] | None = None,
                     cipher_exclusions: bool = False) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    lines = (_read_lines(path) or []) if lines is None else lines
    for line_no, line in enumerate(lines, start=1):
        # One line, one finding per algorithm. Several patterns can carry the same
        # name -- ECDSA is matched both by its own name and by secp256k1, X448 by
        # its upper and lower case forms -- and counting each pattern separately
        # inflates the headline number by however many ways the line could be
        # spotted, which is not a property of the code being scanned.
        seen_on_line: set[str] = set()
        for algorithm, description, pattern in ALGORITHM_PATTERNS:
            if algorithm in seen_on_line:
                continue
            # Every match on the line, not the first: a cipher string can both ban
            # and allow the same family -- "ALL:!ECDH:ECDHE-RSA-AES256" -- and
            # judging the line by its first match would throw the real use away
            # along with the exclusion.
            matches = list(pattern.finditer(line))
            if not matches:
                continue
            if cipher_exclusions and all(_is_excluded(line, m.start()) for m in matches):
                continue
            seen_on_line.add(algorithm)
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
    files_scanned = {"source": 0, "ci_config": 0, "iac": 0, "config": 0, "certificate": 0}

    unreadable: list[str] = []
    # The denominator. files_scanned says how much was read; on its own it does not
    # say how much there was. A file skipped because the tool does not claim its
    # type is not a failure, but leaving it uncounted turns coverage into a number
    # with no base -- which is the thing this scanner exists to refuse.
    files_present = 0
    skipped_kinds: dict[str, int] = {}

    for path in iter_repo_files(repo_path):
        files_present += 1
        rel_path = path.relative_to(repo_path).as_posix()
        is_ci = is_ci_config_file(path, repo_path)
        if not (is_ci or path.suffix in IAC_EXTENSIONS or path.suffix in SOURCE_EXTENSIONS
                or path.suffix in {".yaml", ".yml"} or is_config_file(path)
                or is_certificate_file(path)):
            kind = path.suffix.lower() or "(no extension)"
            skipped_kinds[kind] = skipped_kinds.get(kind, 0) + 1
            continue

        # Read once, here: classification and scanning must see the same content, and a
        # file that cannot be read has to leave a mark rather than pass as scanned-clean.
        lines = _read_lines(path)
        if lines is None:
            unreadable.append(rel_path)
            continue

        if is_certificate_file(path):
            # Certificates and keys are read as bytes, not lines: a .der carries no
            # lines at all, and a .pem that fails to decode must still be counted.
            files_scanned["certificate"] += 1
            algo_findings, key_findings = scan_certificate_file(path, rel_path)
            source_findings.extend(algo_findings)
            embedded_key_findings.extend(key_findings)
        elif is_ci:
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
        else:
            # Configuration: the extensions above, and any YAML that is not a
            # manifest. This branch exists so that nothing can be opened and then
            # dropped: reaching here used to fall off the end of the loop, leaving
            # a file that was read, counted nowhere, and listed nowhere -- which is
            # the one thing this scanner is not allowed to do.
            #
            # Both pattern sets run, because a config file carries both shapes: a
            # cipher list reads like source, a key algorithm declaration reads like
            # infrastructure.
            files_scanned["config"] += 1
            source_findings.extend(
                scan_source_file(path, rel_path, lines, cipher_exclusions=True))
            algo_findings, key_findings = scan_iac_file(path, rel_path, lines)
            iac_findings.extend(algo_findings)
            embedded_key_findings.extend(key_findings)

    return {
        "files_scanned": files_scanned,
        # Files found under the path, excluding the vendored and build directories in
        # EXCLUDED_DIRS. present = scanned + unreadable + skipped, always.
        "files_present": files_present,
        # Not read because this tool does not claim the file type, counted by
        # extension. Not a gap in the scan -- a boundary of it, stated rather than
        # left for the reader to assume away.
        "files_skipped_by_type": dict(
            sorted(skipped_kinds.items(), key=lambda kv: kv[1], reverse=True)
        ),
        # Attempted and NOT read. files_scanned counts only files actually read, so
        # "0 findings" can be checked against a denominator instead of trusted.
        "unreadable_files": unreadable,
        "source_code_findings": source_findings,
        "ci_pipeline_findings": ci_findings,
        "iac_findings": iac_findings,
        "embedded_key_findings": embedded_key_findings,
        "detected_algorithms": sorted({f["algorithm"] for f in source_findings + iac_findings}),
    }
