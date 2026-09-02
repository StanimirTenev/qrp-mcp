"""Reading the files cryptography actually lives in: certificates and keys.

Scanning five well-known repositories put a number on the gap. OpenSSL alone
carried 894 .pem and 64 .der files that were never opened; across the five there
were 1,284 public keys, 1,059 private keys and 652 certificates. The scanner had
both halves of the ability already -- it recognised "-----BEGIN PRIVATE KEY-----"
and it resolved object identifiers -- and no path that opened such a file, so
embedded_key_findings was 0 in every one of them.

What this does NOT do is parse X.509. It walks the DER for ASN.1 OBJECT
IDENTIFIER values and keeps the ones the classifier already knows by name. That
is a deliberately narrow claim: a test corpus is full of deliberately malformed
certificates -- OpenSSL's is, by design -- and a real parser would have to decide
what a broken structure means. Accepting only recognised identifiers means
malformed input yields nothing rather than yields nonsense.
"""

from __future__ import annotations

import base64
import re
from pathlib import Path
from typing import Any

# The extensions the material is kept under. .key and .pub are included because a
# deployment writes them far more often than it writes .pem.
CERTIFICATE_EXTENSIONS = {
    ".pem", ".der", ".crt", ".cer", ".cert", ".csr", ".key", ".pub", ".p12", ".pfx",
}

_PEM_BLOCK = re.compile(
    r"-----BEGIN ([A-Z0-9 ]+?)-----(.*?)-----END \1-----", re.DOTALL,
)

# What the PEM label alone tells you, before decoding anything. "PRIVATE KEY" on
# its own does not name an algorithm; "RSA PRIVATE KEY" does.
_LABEL_ALGORITHMS = {
    "RSA PRIVATE KEY": "RSA",
    "RSA PUBLIC KEY": "RSA",
    "DSA PRIVATE KEY": "DSA",
    "DSA PARAMETERS": "DSA",
    "EC PRIVATE KEY": "EC",
    "EC PARAMETERS": "EC",
    "DH PARAMETERS": "DH",
    "X9.42 DH PARAMETERS": "DH",
}

_PRIVATE_KEY_LABEL = re.compile(r"PRIVATE KEY$")

# OpenSSH public keys and known_hosts lines name their algorithm in the clear.
_SSH_KEY_TYPES = {
    "ssh-rsa": "RSA",
    "ssh-dss": "DSA",
    "ssh-ed25519": "Ed25519",
    "sk-ssh-ed25519@openssh.com": "Ed25519",
    "ecdsa-sha2-nistp256": "ECDSA",
    "ecdsa-sha2-nistp384": "ECDSA",
    "ecdsa-sha2-nistp521": "ECDSA",
    "sk-ecdsa-sha2-nistp256@openssh.com": "ECDSA",
    "ssh-mldsa44": "ML-DSA",
    "ssh-mldsa65": "ML-DSA",
    "ssh-mldsa44-ed25519": "ML-DSA",
    "sntrup761x25519-sha512": "NTRU",
    "sntrup761x25519-sha512@openssh.com": "NTRU",
    "mlkem768x25519-sha256": "ML-KEM",
}


def _decode_oid(body: bytes) -> str:
    """DER contents octets of an OBJECT IDENTIFIER -> dotted decimal."""
    if not body:
        return ""
    first = body[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in body[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def _iter_oids(der: bytes) -> set[str]:
    """Every well-formed OBJECT IDENTIFIER in the blob.

    A linear walk rather than a structural parse. The caller keeps only the
    identifiers the classifier recognises, so a coincidental 0x06 in a signature
    yields an unknown string and is dropped rather than reported.
    """
    found: set[str] = set()
    i, n = 0, len(der)
    while i < n - 1:
        if der[i] == 0x06:
            length = der[i + 1]
            # Short form only: every algorithm identifier fits well inside 127
            # bytes, and refusing the long form keeps the walk from being steered
            # by a crafted length byte.
            if 1 <= length <= 32 and i + 2 + length <= n:
                found.add(_decode_oid(der[i + 2:i + 2 + length]))
                i += 2 + length
                continue
        i += 1
    return found


def is_certificate_file(path: Path) -> bool:
    return path.suffix.lower() in CERTIFICATE_EXTENSIONS


def scan_certificate_file(path: Path, rel_path: str) -> tuple[list[dict[str, Any]],
                                                              list[dict[str, Any]]]:
    """Returns (algorithm_findings, embedded_key_findings) for one file.

    Never raises: a corpus of certificates is a corpus of edge cases, and a file
    that cannot be understood has to leave the scan as nothing found rather than
    as an exception.
    """
    from .classifier import _find_oid_family  # local: avoids an import cycle

    algorithms: list[dict[str, Any]] = []
    keys: list[dict[str, Any]] = []
    seen: set[str] = set()

    def record(algorithm: str, description: str, line: int, excerpt: str) -> None:
        if algorithm in seen:
            return
        seen.add(algorithm)
        algorithms.append({
            "path": rel_path,
            "line": line,
            "algorithm": algorithm,
            "description": description,
            "excerpt": excerpt[:200],
        })

    try:
        raw = path.read_bytes()
    except OSError:
        return [], []

    blobs: list[bytes] = []
    text = raw.decode("utf-8", errors="replace")

    for match in _PEM_BLOCK.finditer(text):
        label = match.group(1).strip()
        line_no = text.count("\n", 0, match.start()) + 1

        named = _LABEL_ALGORITHMS.get(label)
        if named:
            record(named, f"{named} in a {label.lower()} block", line_no,
                   f"-----BEGIN {label}-----")
        if _PRIVATE_KEY_LABEL.search(label):
            keys.append({
                "path": rel_path,
                "line": line_no,
                "type": label,
                "description": f"private key material in a {label.lower()} block",
            })
        try:
            blobs.append(base64.b64decode(match.group(2), validate=False))
        except (ValueError, TypeError):
            continue

    # A .der or .p12 is the same content without the armour.
    if not blobs and not text.lstrip().startswith("-----BEGIN"):
        blobs.append(raw)

    for line_no, line in enumerate(text.splitlines(), start=1):
        head = line.split(" ", 1)[0].strip()
        named = _SSH_KEY_TYPES.get(head)
        if named:
            record(named, f"{named} in an SSH key of type {head}", line_no, line)

    for blob in blobs:
        for oid in _iter_oids(blob):
            entry = _find_oid_family(oid)
            if entry is not None:
                record(entry[1], f"{entry[1]} identified by object identifier {oid}",
                       1, oid)

    return algorithms, keys
