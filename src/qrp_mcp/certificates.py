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
import os
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

# "1024 65537 15389543160... RSA1 #1" -- bits, exponent, modulus, comment.
_SSH1_KEY = re.compile(r"^(\d{3,5})\s+\d{1,10}\s+\d{50,}(?:\s+\S.*)?$")

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
    # A composite names both halves, so the classifier can carry Ed25519 beside ML-DSA
    # rather than drop it (ZA-OPRAVYANE row 18, 08.10.2026: also_present was empty).
    "ssh-mldsa44-ed25519": "ML-DSA-44-Ed25519",
    "ssh-mldsa44@openssh.com": "ML-DSA",
    "ssh-mldsa65@openssh.com": "ML-DSA",
    # Not the same key: OpenSSH 10.4 shipped this composite as an experiment under the
    # vendor suffix; 10.6 enabled it without the suffix and says keys made with the
    # experimental support "must be regenerated and/or removed" (release notes, 10.6).
    "ssh-mldsa44-ed25519@openssh.com": "ML-DSA-44-Ed25519 experimental",
    "sntrup761x25519-sha512": "NTRU",
    "sntrup761x25519-sha512@openssh.com": "NTRU",
    "mlkem768x25519-sha256": "ML-KEM",
}


# Named curves by object identifier: RFC 5480 section 2.1.1.1 for the NIST three, SEC 2
# v2.0 appendix A.2.1 for secp256k1 (ellipticCurve 10). Without these the curve was never
# named: id-ecPublicKey records "EC" first and the curve identifier repeats the family
# (ZA-OPRAVYANE row 32, 22.10.2026).
CURVE_OIDS: dict[str, tuple[str, int]] = {
    "1.2.840.10045.3.1.7": ("P-256", 256),
    "1.3.132.0.34": ("P-384", 384),
    "1.3.132.0.35": ("P-521", 521),
    "1.3.132.0.10": ("secp256k1", 256),
}

# -- A private key recoverable from the public key ---------------------------------------
#
# A public point equal to k*G for a small k gives the private key away: the eight keys in
# Bill Buchanan's post of 22.10.2026 all had k < 256, and one was 4*G on P-384. Checking
# it needs only the public key, so it runs on every uncompressed point this file can
# locate, not on a decoded certificate (this module does not parse X.509; see above).
# The bound is stated, not implied: a scalar of 257 is not found.
SMALL_SCALAR_BOUND = 256

# (p, a, Gx, Gy) from SEC 2 v2.0 section 2.4.1, 2.4.2, 2.5.1, 2.6.1. The NIST three agree
# with RFC 5903 section 3, checked 22.10.2026. b is not needed: a point is compared with
# the table below, not tested for membership.
_CURVES: dict[str, tuple[int, int, int, int]] = {
    "P-256": (
        0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
        0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
        0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5),
    "P-384": (
        0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
        0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc,
        0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
        0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f),
    "P-521": (
        (1 << 521) - 1,
        (1 << 521) - 4,
        0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
        0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650),
    "secp256k1": (
        0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
        0,
        0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
        0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
}
_SMALL_MULTIPLES: dict[str, dict[tuple[int, int], int]] = {}


def _small_multiples(curve: str) -> dict[tuple[int, int], int]:
    """{k*G: k} for k = 1..SMALL_SCALAR_BOUND, built once per curve: 256 affine
    additions, so a key costs a dictionary lookup."""
    if curve not in _SMALL_MULTIPLES:
        p, a, gx, gy = _CURVES[curve]
        table = {(gx, gy): 1}
        x, y = gx, gy
        for k in range(2, SMALL_SCALAR_BOUND + 1):
            if (x, y) == (gx, gy):
                slope = (3 * x * x + a) * pow(2 * y, -1, p) % p
            else:
                slope = (gy - y) * pow(gx - x, -1, p) % p
            nx = (slope * slope - x - gx) % p
            x, y = nx, (slope * (x - nx) - y) % p
            table[(x, y)] = k
        _SMALL_MULTIPLES[curve] = table
    return _SMALL_MULTIPLES[curve]


# -- The size of an RSA public key --------------------------------------------------------
#
# A certificate's RSA key was named and never sized: `key_size: None` for four RSA files
# in the probe of 22.10.2026, two of them 2048 bits (ZA-OPRAVYANE row 46). The size is in
# the public key, so it is read from there and nowhere else: a SubjectPublicKeyInfo whose
# AlgorithmIdentifier is rsaEncryption with NULL parameters (RFC 3279 section 2.3.1), then
# BIT STRING, SEQUENCE, and the modulus INTEGER (RFC 8017 A.1.1); or an `RSA PUBLIC KEY`
# block, which is that SEQUENCE alone. Still not an X.509 parser: the walk is anchored on
# those bytes and anything else yields nothing. A private key (PKCS#1 or PKCS#8) is not
# read for its size.
_RSA_SPKI_ALGORITHM = bytes.fromhex("300d06092a864886f70d0101010500")


def _der_header(blob: bytes, i: int, tag: int) -> tuple[int, int] | None:
    """(length, start of contents) of the element at i if its tag is `tag`."""
    if i + 1 >= len(blob) or blob[i] != tag:
        return None
    first = blob[i + 1]
    if first < 0x80:
        return first, i + 2
    count = first & 0x7F
    if not 1 <= count <= 3 or i + 2 + count > len(blob):
        return None
    return int.from_bytes(blob[i + 2:i + 2 + count], "big"), i + 2 + count


def _modulus_bits(blob: bytes, i: int) -> int | None:
    """Bits of the modulus of the RSAPublicKey SEQUENCE at i."""
    seq = _der_header(blob, i, 0x30)
    if seq is None:
        return None
    integer = _der_header(blob, seq[1], 0x02)
    if integer is None or integer[1] + integer[0] > len(blob):
        return None
    bits = int.from_bytes(blob[integer[1]:integer[1] + integer[0]], "big").bit_length()
    # Outside this range the bytes were not a modulus; say nothing rather than a number.
    return bits if 512 <= bits <= 16384 else None


def rsa_key_sizes(blob: bytes, pkcs1_public: bool = False) -> set[int]:
    """Sizes of the RSA public keys in a DER blob."""
    sizes: set[int] = set()
    if pkcs1_public:
        bits = _modulus_bits(blob, 0)
        if bits:
            sizes.add(bits)
    at = blob.find(_RSA_SPKI_ALGORITHM)
    while at != -1:
        bit_string = _der_header(blob, at + len(_RSA_SPKI_ALGORITHM), 0x03)
        if bit_string is not None and blob[bit_string[1]:bit_string[1] + 1] == b"\x00":
            bits = _modulus_bits(blob, bit_string[1] + 1)
            if bits:
                sizes.add(bits)
        at = blob.find(_RSA_SPKI_ALGORITHM, at + 1)
    return sizes


def _der_length(n: int) -> bytes:
    return bytes([n]) if n < 0x80 else bytes([0x81, n])


# Where an uncompressed point sits, by curve: a DER BIT STRING `03 len 00 04 X Y`
# (SubjectPublicKeyInfo, SEC 1 ECPrivateKey, PKCS#8), and OpenSSH's wire string
# `nistpNNN` followed by `04 X Y` (a .pub line and an openssh-key-v1 file both carry it).
def _point_markers(curve: str) -> list[bytes]:
    size = (_CURVES[curve][0].bit_length() + 7) // 8
    markers = [b"\x03" + _der_length(2 + 2 * size) + b"\x00\x04"]
    ssh = {"P-256": b"nistp256", "P-384": b"nistp384", "P-521": b"nistp521"}.get(curve)
    if ssh:
        markers.append(len(ssh).to_bytes(4, "big") + ssh
                       + (1 + 2 * size).to_bytes(4, "big") + b"\x04")
    return markers


def small_scalar_keys(rel_path: str, raw: bytes) -> list[dict[str, Any]]:
    """EC public points in this file that equal k*G for k <= SMALL_SCALAR_BOUND.

    Only uncompressed points, in DER or in OpenSSH's encoding; a compressed point, a
    key inside an encrypted container and a raw point with no marker are not checked."""
    text = raw.decode("utf-8", errors="replace")
    blobs: list[tuple[bytes, int]] = []
    for match in _PEM_BLOCK.finditer(text):
        try:
            blobs.append((base64.b64decode(match.group(2), validate=False),
                          text.count("\n", 0, match.start()) + 1))
        except (ValueError, TypeError):
            continue
    for line_no, line in enumerate(text.splitlines(), start=1):
        fields = line.split()
        if len(fields) >= 2 and "ecdsa-sha2-nistp" in fields[0]:
            try:
                blobs.append((base64.b64decode(fields[1], validate=False), line_no))
            except (ValueError, TypeError):
                continue
    if not blobs and not text.lstrip().startswith("-----BEGIN"):
        blobs.append((raw, 1))
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for blob, line_no in blobs:
        for curve in _CURVES:
            size = (_CURVES[curve][0].bit_length() + 7) // 8
            for marker in _point_markers(curve):
                start = blob.find(marker)
                while start != -1:
                    body = blob[start + len(marker):start + len(marker) + 2 * size]
                    if len(body) == 2 * size:
                        point = (int.from_bytes(body[:size], "big"),
                                 int.from_bytes(body[size:], "big"))
                        k = _small_multiples(curve).get(point)
                        if k is not None and (curve, k) not in seen:
                            seen.add((curve, k))
                            out.append({
                                "path": rel_path, "line": line_no, "algorithm": "EC",
                                "curve": curve, "scalar": k,
                                "bound": SMALL_SCALAR_BOUND,
                                "basis": "public_point_is_small_multiple",
                                "description": (
                                    f"private key recoverable: the public point is "
                                    f"{k}*G on {curve}, so the private scalar is {k}. "
                                    f"Found from the public key alone, by comparing it "
                                    f"with k*G for every k <= {SMALL_SCALAR_BOUND}."),
                            })
                    start = blob.find(marker, start + 1)
    return out


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


# Key material is often kept in a file with no extension at all (id_rsa,
# id_ed25519) or with one this tool does not claim (.prv). Recognising it by
# extension alone left 45 such files unread in the OpenSSH tree -- found by
# comparing against CBOMkit-theia. So a small file is peeked at instead: the
# header is on the first line, and the size cap keeps this from turning into a
# reason to open every blob in the tree.
KEY_PEEK_MAX_BYTES = 64 * 1024
_KEY_HEADER = re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.M)
# A header on its own is documentation: OpenSSL's PEM_read.pod prints the markers
# with the body elided ("MIICdg...."). Key material carries real base64, and the
# smallest private key there is runs to several hundred characters of it. Summed
# over lines rather than measured on one, because wrap width varies by writer.
_KEY_BODY_LINE = re.compile(rb"^[ \t]*[A-Za-z0-9+/]{16,}={0,2}[ \t]*$", re.M)
KEY_BODY_MIN_CHARS = 100


def looks_like_key_file(path: Path) -> bool:
    """True when an unclaimed file begins with key material."""
    try:
        if path.stat().st_size > KEY_PEEK_MAX_BYTES:
            return False
        with path.open("rb") as fh:
            head = fh.read(4096)
    except OSError:
        return False
    if not _KEY_HEADER.search(head):
        return False
    body = sum(len(m.group().strip()) for m in _KEY_BODY_LINE.finditer(head))
    return body >= KEY_BODY_MIN_CHARS


# The PKCS#12 bag identifiers that mean "a private key is in here".
_PKCS12_KEY_BAGS = {
    "1.2.840.113549.1.12.10.1.1",  # keyBag
    "1.2.840.113549.1.12.10.1.2",  # pkcs8ShroudedKeyBag
}


def is_certificate_file(path: Path) -> bool:
    return path.suffix.lower() in CERTIFICATE_EXTENSIONS


def _read_bytes_once(path: Path) -> bytes | None:
    """Read without following a link at the final component, as the scan does."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            return handle.read()
    except OSError:
        return None


def scan_certificate_file(path: Path, rel_path: str,
                          raw: bytes | None = None) -> tuple[list[dict[str, Any]],
                                                             list[dict[str, Any]]]:
    """Returns (algorithm_findings, embedded_key_findings) for one file.

    Never raises: a corpus of certificates is a corpus of edge cases, and a file
    that cannot be understood has to leave the scan as nothing found rather than
    as an exception.

    `raw` is the snapshot the caller already read. It has to be passed, because
    opening the path a second time reads a file that may no longer be the one that
    was hashed: an independent analysis replaced the path between the two reads and
    got a finding that the corpus digest did not describe, and replaced it with a
    symlink to get an algorithm from outside the tree with no link reported. One
    read feeds the digest, the parse and the evidence, or they are describing
    different bytes.
    """
    from .classifier import _find_oid_family  # local: avoids an import cycle

    algorithms: list[dict[str, Any]] = []
    keys: list[dict[str, Any]] = []
    seen: set[str] = set()

    def record(algorithm: str, description: str, line: int, excerpt: str,
               kind: str = "declaration") -> None:
        if algorithm in seen:
            return
        seen.add(algorithm)
        algorithms.append({
            "path": rel_path,
            "line": line,
            "algorithm": algorithm,
            "description": description,
            "excerpt": excerpt[:200],
            "evidence_kind": kind,
        })

    if raw is None:
        # No snapshot supplied: this is a direct call, so read once here. The
        # scan path always supplies one.
        try:
            raw = _read_bytes_once(path)
        except OSError:
            return [], []
        if raw is None:
            return [], []

    blobs: list[bytes] = []
    # The blobs that are an `RSA PUBLIC KEY` block, read as a bare RSAPublicKey.
    pkcs1_public: set[int] = set()
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
        if label == "RSA PUBLIC KEY":
            pkcs1_public.add(len(blobs) - 1)

    # A .der or .p12 is the same content without the armour.
    if not blobs and not text.lstrip().startswith("-----BEGIN"):
        blobs.append(raw)

    for line_no, line in enumerate(text.splitlines(), start=1):
        # SSH protocol 1 public key: bits, exponent, modulus, all in decimal.
        # OpenSSH keeps six of these and every one read as nothing.
        proto1 = _SSH1_KEY.match(line)
        if proto1:
            record("RSA", f"RSA in an SSH protocol 1 public key of {proto1.group(1)} bits",
                   line_no, line[:80])
            if algorithms and algorithms[-1]["algorithm"] == "RSA":
                algorithms[-1]["key_size"] = int(proto1.group(1))
            continue
        head = line.split(" ", 1)[0].strip()
        # An SSH certificate is a public key line whose type carries the suffix
        # -cert-v01@openssh.com. The algorithm is the same one, certified; openssh
        # keeps 41 such files and every one of them read as nothing.
        certified = head.endswith("-cert-v01@openssh.com")
        if certified:
            head = head[:-len("-cert-v01@openssh.com")]
            if head.startswith("sk-"):
                head += "@openssh.com"
        named = _SSH_KEY_TYPES.get(head)
        if named:
            record(named, f"{named} in an SSH {'certificate' if certified else 'key'} "
                   f"of type {head}", line_no, line)

    for blob in blobs:
        # Sorted: _iter_oids returns a set, so the order of the evidence list
        # changed between interpreters with different hash seeds. A report whose
        # own field order moves between runs cannot be diffed.
        for oid in sorted(_iter_oids(blob)):
            entry = _find_oid_family(oid)
            if entry is not None:
                # What this says, exactly: the identifier's bytes are in the file.
                # It does not say the file decoded as a certificate. An independent
                # analysis put a valid RSA identifier into arbitrary bytes in a .der
                # and got an RSA finding, which is correct for what was measured and
                # was described here in words that claimed more. The narrow sentence
                # is the true one.
                record(entry[1],
                       f"{entry[1]} object identifier {oid} observed in the file; "
                       f"the file was not decoded as a certificate",
                       1, oid, kind="reference")

    # The curve of an EC key, from its named-curve identifier. Attached to the EC
    # finding however it was recorded (a PEM label, id-ecPublicKey, the curve OID).
    curves = sorted({CURVE_OIDS[oid] for blob in blobs for oid in _iter_oids(blob)
                     if oid in CURVE_OIDS}, key=lambda c: c[1])
    for item in algorithms:
        if item["algorithm"] == "EC" and curves:
            item["curve"] = ", ".join(name for name, _ in curves)
            item["key_size"] = curves[0][1]
            item["description"] += f"; curve {item['curve']} from its object identifier"

    # The size of an RSA key, from its public key (ZA-OPRAVYANE row 46). The smallest when
    # a file holds several, as for the curve above; all of them in the description.
    sizes = sorted(set().union(*(rsa_key_sizes(blob, n in pkcs1_public)
                                 for n, blob in enumerate(blobs))) if blobs else set())
    for item in algorithms:
        if item["algorithm"] == "RSA" and sizes and "key_size" not in item:
            item["key_size"] = sizes[0]
            item["description"] += (f"; modulus of {', '.join(map(str, sizes))} bits "
                                    f"from its public key")

    # PKCS#12. The wrapper is not encrypted even when everything inside it is, so
    # it still names its bags: a shrouded key bag means a private key is in the
    # file, and saying only that is more honest than saying nothing. Cryben's
    # benchmark-server.p12 is a claimed extension that produced neither a finding
    # nor a note -- the silent skip this scanner argues against, in this scanner.
    if not algorithms and not keys:
        wrapper = _iter_oids(raw)
        if wrapper & _PKCS12_KEY_BAGS:
            keys.append({
                "path": rel_path,
                "line": 1,
                "type": "PKCS#12 shrouded key bag",
                "description": ("private key material in a PKCS#12 key bag; the bag is "
                                "encrypted and was not decoded, so the algorithm is unknown"),
            })

    return algorithms, keys


def is_undecoded(algorithms: list, keys: list) -> bool:
    """A claimed file that gave up nothing an algorithm can be named from."""
    return not algorithms and not any(
        key.get("type") != "PKCS#12 shrouded key bag" for key in keys)
