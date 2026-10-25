"""Reading the files cryptography actually lives in: certificates and keys.

Scanning five well-known repositories put a number on the gap. OpenSSL alone
carried 894 .pem and 64 .der files that were never opened; across the five there
were 1,284 public keys, 1,059 private keys and 652 certificates. The scanner had
both halves of the ability already -- it recognised "-----BEGIN PRIVATE KEY-----"
and it resolved object identifiers -- and no path that opened such a file, so
embedded_key_findings was 0 in every one of them.

Since release C, a certificate is parsed with `cryptography`, a declared dependency
(ZA-OPRAVYANE row 127): each certificate of a PEM, DER, PKCS#7 or password-less PKCS#12
file is a row of its own, at its BEGIN line, with key, signature and validity. What the
library will not parse keeps the narrow path it always had: a walk of the DER for ASN.1
OBJECT IDENTIFIER values the classifier already knows by name. A test corpus is full of
deliberately malformed certificates -- OpenSSL's is, by design -- and accepting only
recognised identifiers means malformed input yields nothing rather than nonsense. The
block that did not parse is named, with its reason, in the coverage (`unparsed_material`).
"""

from __future__ import annotations

import base64
import re
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# The extensions the material is kept under. .key and .pub are included because a
# deployment writes them far more often than it writes .pem.
CERTIFICATE_EXTENSIONS = {
    ".pem", ".der", ".crt", ".cer", ".cert", ".csr", ".key", ".pub", ".p12", ".pfx",
    # Java keystores. JKS keeps its certificates in clear DER -- only the integrity check
    # needs the password -- so their object identifiers read like a .der's
    # (ZA-OPRAVYANE row 84: spring-security-samples' server.jks, 65 SHA1withRSA
    # certificates, unread). A keystore keytool wrote as PKCS#12 reads like a .p12.
    ".jks", ".keystore",
    # PKCS#7 certificate bundles (release C): a chain as one file, read with `cryptography`.
    ".p7b", ".p7c",
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


# What a PKCS#12 file names outside its encryption: the password-based scheme its bags are
# encrypted with (RFC 7292 Appendix C, pkcs-12PbeIds) and the digest of its MAC. Both are
# readable without the password and were not reported -- the file said only
# "claimed_but_not_decoded" (ZA-OPRAVYANE row 85: spring-security-samples' dianne/rod/scott
# .p12, 40-bit RC2 and a SHA-1 MAC).
_PKCS12_PBE = {
    "1.2.840.113549.1.12.1.1": ("RC4", "pbeWithSHAAnd128BitRC4"),
    "1.2.840.113549.1.12.1.2": ("RC4", "pbeWithSHAAnd40BitRC4"),
    "1.2.840.113549.1.12.1.3": ("3DES", "pbeWithSHAAnd3-KeyTripleDES-CBC"),
    "1.2.840.113549.1.12.1.4": ("3DES", "pbeWithSHAAnd2-KeyTripleDES-CBC"),
    "1.2.840.113549.1.12.1.5": ("RC2", "pbeWithSHAAnd128BitRC2-CBC"),
    "1.2.840.113549.1.12.1.6": ("RC2", "pbeWithSHAAnd40BitRC2-CBC"),
}
_PKCS12_MARKERS = set(_PKCS12_PBE) | _PKCS12_KEY_BAGS | {
    "1.2.840.113549.1.12.10.1.3",  # certBag
}
_SHA1_OID = "1.3.14.3.2.26"


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


# -- Certificates and keys parsed with `cryptography` (release C, ZA-OPRAVYANE row 127) ----
#
# A bundle was one row at line 1: object identifiers "observed in the file; the file was not
# decoded as a certificate" (certbot fullchain1.pem:30, li-trust-store ca-bundle.pem:29 were
# PostShor's rows, not ours). Now each certificate is parsed and is a row at its own BEGIN
# line, with the subject key, the signature, the validity and the names. What the library
# will not parse falls back to the identifier walk below, and is named in the coverage.

# Composite ML-DSA signatures, draft-ietf-lamps-pq-composite-sigs-19 section 6 (fetched
# 25.10.2026). Earlier drafts used other arcs; these are the ones the draft now assigns. The
# same identifier is the key's and the signature's: a composite key signs only as itself.
COMPOSITE_SIGNATURES: dict[str, tuple[str, tuple[str, str]]] = {
    "1.3.6.1.5.5.7.6.37": ("id-MLDSA44-RSA2048-PSS-SHA256", ("ML-DSA", "RSA")),
    "1.3.6.1.5.5.7.6.38": ("id-MLDSA44-RSA2048-PKCS15-SHA256", ("ML-DSA", "RSA")),
    "1.3.6.1.5.5.7.6.39": ("id-MLDSA44-Ed25519-SHA512", ("ML-DSA", "Ed25519")),
    "1.3.6.1.5.5.7.6.40": ("id-MLDSA44-ECDSA-P256-SHA256", ("ML-DSA", "ECDSA")),
    "1.3.6.1.5.5.7.6.41": ("id-MLDSA65-RSA3072-PSS-SHA512", ("ML-DSA", "RSA")),
    "1.3.6.1.5.5.7.6.42": ("id-MLDSA65-RSA3072-PKCS15-SHA512", ("ML-DSA", "RSA")),
    "1.3.6.1.5.5.7.6.43": ("id-MLDSA65-RSA4096-PSS-SHA512", ("ML-DSA", "RSA")),
    "1.3.6.1.5.5.7.6.44": ("id-MLDSA65-RSA4096-PKCS15-SHA512", ("ML-DSA", "RSA")),
    "1.3.6.1.5.5.7.6.45": ("id-MLDSA65-ECDSA-P256-SHA512", ("ML-DSA", "ECDSA")),
    "1.3.6.1.5.5.7.6.46": ("id-MLDSA65-ECDSA-P384-SHA512", ("ML-DSA", "ECDSA")),
    "1.3.6.1.5.5.7.6.47": ("id-MLDSA65-ECDSA-brainpoolP256r1-SHA512", ("ML-DSA", "ECDSA")),
    "1.3.6.1.5.5.7.6.48": ("id-MLDSA65-Ed25519-SHA512", ("ML-DSA", "Ed25519")),
    "1.3.6.1.5.5.7.6.49": ("id-MLDSA87-ECDSA-P384-SHA512", ("ML-DSA", "ECDSA")),
    "1.3.6.1.5.5.7.6.50": ("id-MLDSA87-ECDSA-brainpoolP384r1-SHA512", ("ML-DSA", "ECDSA")),
    "1.3.6.1.5.5.7.6.51": ("id-MLDSA87-Ed448-SHAKE256", ("ML-DSA", "Ed448")),
    "1.3.6.1.5.5.7.6.52": ("id-MLDSA87-RSA3072-PSS-SHA512", ("ML-DSA", "RSA")),
    "1.3.6.1.5.5.7.6.53": ("id-MLDSA87-RSA4096-PSS-SHA512", ("ML-DSA", "RSA")),
    "1.3.6.1.5.5.7.6.54": ("id-MLDSA87-ECDSA-P521-SHA512", ("ML-DSA", "ECDSA")),
}

_ML_DSA_SETS = {"2.16.840.1.101.3.4.3.17": "ML-DSA-44", "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
                "2.16.840.1.101.3.4.3.19": "ML-DSA-87"}

# `cryptography`'s curve names, in the spelling CURVE_OIDS uses.
_CURVE_NAMES = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}

_CERTIFICATE_LABELS = {"CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE"}
_CERTIFICATE_SUFFIXES = {".der", ".crt", ".cer", ".cert", ".p7b", ".p7c"}

# Why a block or a file that was read gave up less than it holds. Closed, like coverage's
# REASONS; adding one means adding it here first.
UNPARSED_REASONS = {
    "not_parsed_as_certificate": "a certificate block or file that `cryptography` did not "
                                 "parse: truncated, malformed, or not a certificate",
    "not_parsed_as_pkcs7": "a PKCS#7 block that did not parse as a certificate bundle",
    "not_parsed_as_key": "a private-key block whose body did not parse as a key",
    "password_protected": "encrypted under a password, or damaged: it did not open without one",
    "format_not_parsed": "a format `cryptography` does not read (a Java keystore)",
}


def _iso(moment: Any) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _as_of() -> tuple[Any, str]:
    """What `expired` is relative to: SOURCE_DATE_EPOCH, else the clock of this scan."""
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if epoch.isdigit():
        return datetime.fromtimestamp(int(epoch), timezone.utc), "SOURCE_DATE_EPOCH"
    return datetime.now(timezone.utc), "scan time"


def _cn(name: Any) -> str | None:
    from cryptography.x509.oid import NameOID
    try:
        values = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return str(values[0].value) if values else None
    except Exception:  # noqa: BLE001 -- a name the library cannot read is no name
        return None


def _oid_name(oid: Any) -> str:
    dotted = oid.dotted_string
    if dotted in COMPOSITE_SIGNATURES:
        return COMPOSITE_SIGNATURES[dotted][0]
    name = getattr(oid, "_name", "") or ""
    if name and name != "Unknown OID":
        return name
    from .oids import OIDS
    return OIDS[dotted][1] if dotted in OIDS else dotted


def _key_info(key: Any) -> dict[str, Any]:
    """Family, size and curve of a key object (public or private)."""
    from cryptography.hazmat.primitives.asymmetric import (
        dsa, ec, ed448, ed25519, rsa, x448, x25519)
    if isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        return {"algorithm": "RSA", "size": key.key_size}
    if isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        return {"algorithm": "EC", "size": key.key_size,
                "curve": _CURVE_NAMES.get(key.curve.name, key.curve.name)}
    if isinstance(key, (dsa.DSAPublicKey, dsa.DSAPrivateKey)):
        return {"algorithm": "DSA", "size": key.key_size}
    # By class name: touching the `dh` module raises a deprecation warning in every scan.
    if type(key).__name__ in ("DHPublicKey", "DHPrivateKey"):
        return {"algorithm": "DH", "size": key.key_size}
    for kinds, family, size in (
            ((ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey), "Ed25519", 256),
            ((ed448.Ed448PublicKey, ed448.Ed448PrivateKey), "Ed448", 456),
            ((x25519.X25519PublicKey, x25519.X25519PrivateKey), "X25519", 256),
            ((x448.X448PublicKey, x448.X448PrivateKey), "X448", 448)):
        if isinstance(key, kinds):
            return {"algorithm": family, "size": size}
    # ML-DSA keys by their class (MLDSA65PublicKey), so an older `cryptography` without
    # the module still imports this file.
    name = type(key).__name__
    if name.startswith("MLDSA") and name[5:7].isdigit():
        return {"algorithm": "ML-DSA", "parameter_set": f"ML-DSA-{name[5:7]}"}
    return {}


def _public_key(cert: Any) -> tuple[dict[str, Any], list[str]]:
    """The subject key, and the families it puts in the inventory."""
    from .classifier import _find_oid_family  # local: avoids an import cycle
    try:
        oid = cert.public_key_algorithm_oid.dotted_string
    except Exception:  # noqa: BLE001
        return {"algorithm": None}, []
    if oid in COMPOSITE_SIGNATURES:
        name, halves = COMPOSITE_SIGNATURES[oid]
        return {"algorithm": name, "oid": oid, "composite": list(halves)}, list(halves)
    try:
        info = _key_info(cert.public_key())
    except Exception:  # noqa: BLE001 -- an algorithm the library does not load
        info = {}
    if oid in _ML_DSA_SETS:
        info = {"algorithm": "ML-DSA", "parameter_set": _ML_DSA_SETS[oid]}
    if not info:
        entry = _find_oid_family(oid)
        info = {"algorithm": entry[1] if entry else None}
    info["oid"] = oid
    return info, [info["algorithm"]] if info["algorithm"] else []


def _signature(cert: Any) -> tuple[dict[str, Any], list[str]]:
    from .classifier import _find_oid_family  # local: avoids an import cycle
    from .oids import OIDS
    oid = cert.signature_algorithm_oid
    dotted = oid.dotted_string
    if dotted in COMPOSITE_SIGNATURES:
        families = list(COMPOSITE_SIGNATURES[dotted][1])
    elif dotted in OIDS:
        # A hash named inside the identifier is a second family (sha1WithRSAEncryption).
        families = list(OIDS[dotted][0])
    else:
        entry = _find_oid_family(dotted)
        families = [entry[1]] if entry else []
    return {"name": _oid_name(oid), "oid": dotted, "families": families}, families


def _self_signed(cert: Any) -> tuple[bool, bool | None]:
    """(issuer is the subject and the signature does not refute it, signature checked)."""
    from cryptography.exceptions import InvalidSignature
    if cert.issuer != cert.subject:
        return False, None
    try:
        cert.verify_directly_issued_by(cert)
    except InvalidSignature:
        return False, False
    except Exception:  # noqa: BLE001 -- not checkable here (composite, unsupported key)
        return True, None
    return True, True


def describe_certificate(cert: Any, fmt: str, index: int) -> tuple[dict[str, Any], list[str]]:
    """What one certificate says, and the families its key and signature name."""
    import hashlib
    from cryptography.hazmat.primitives.serialization import Encoding
    public_key, key_families = _public_key(cert)
    signature, signature_families = _signature(cert)
    self_signed, checked = _self_signed(cert)
    now, basis = _as_of()
    try:
        subject, issuer = cert.subject.rfc4514_string(), cert.issuer.rfc4514_string()
    except Exception:  # noqa: BLE001
        subject, issuer = "", ""
    families: list[str] = []
    for family in key_families + signature_families:
        if family not in families:
            families.append(family)
    return {
        "format": fmt,
        "index": index,
        "sha256": hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest(),
        "subject": subject,
        "issuer": issuer,
        "subject_cn": _cn(cert.subject),
        "issuer_cn": _cn(cert.issuer),
        "serial": format(cert.serial_number, "x"),
        "not_before": _iso(cert.not_valid_before_utc),
        "not_after": _iso(cert.not_valid_after_utc),
        # Relative to a stated moment. Kept out of the CBOM: there validity is data.
        "expired": now > cert.not_valid_after_utc,
        "expired_as_of": _iso(now),
        "expired_basis": basis,
        "self_signed": self_signed,
        "self_signature_verified": checked,
        "public_key": public_key,
        "signature_algorithm": signature,
    }, families


def _certificate_rows(rel_path: str, line: int, excerpt: str, cert: dict[str, Any],
                      families: list[str]) -> list[dict[str, Any]]:
    key = cert["public_key"]
    key_families = key.get("composite") or [key.get("algorithm")]
    shown = cert["subject"] or "an empty subject"
    rows = []
    for family in families:
        role = "subject_public_key" if family in key_families else "signature"
        row: dict[str, Any] = {
            "path": rel_path, "line": line, "algorithm": family,
            # Clock-free: the description reaches the CBOM where an excerpt is trimmed.
            "description": (f"{family} in certificate {cert['index']} ({shown}): key "
                            f"{key.get('algorithm')}"
                            + (f" {key['size']}" if key.get("size") else "")
                            + (f" {key['curve']}" if key.get("curve") else "")
                            + f", signed with {cert['signature_algorithm']['name']}, valid "
                              f"{cert['not_before']} to {cert['not_after']}"),
            "excerpt": excerpt[:200],
            "evidence_kind": "declaration",
            "certificate_role": role,
            "certificate": cert,
        }
        if role == "subject_public_key" and not key.get("composite"):
            if key.get("size"):
                row["key_size"] = key["size"]
            if key.get("curve"):
                row["curve"] = key["curve"]
        rows.append(row)
    return rows


def _first_tlv(blob: bytes) -> bytes:
    """The leading DER element alone: OpenSSL's TRUSTED CERTIFICATE appends its aux data."""
    head = _der_header(blob, 0, 0x30)
    return blob[:head[1] + head[0]] if head else blob


_JKS_MAGIC = (b"\xfe\xed\xfe\xed", b"\xce\xce\xce\xce")


def _other_x509(raw: bytes) -> bool:
    """A DER request or revocation list: parsed, and not a certificate (certbot csr.der)."""
    from cryptography import x509
    for load in (x509.load_der_x509_csr, x509.load_der_x509_crl):
        try:
            load(raw)
            return True
        except Exception:  # noqa: BLE001
            continue
    return False


def _key_fields(info: dict[str, Any]) -> dict[str, Any]:
    if not info:
        return {"key_unread": "family_not_named"}
    return {"key_algorithm": info["algorithm"],
            **{field: info[name] for field, name in (("key_size", "size"), ("curve", "curve"),
                                                     ("parameter_set", "parameter_set"))
               if info.get(name)}}


def _load_private_key(pem: bytes) -> dict[str, Any]:
    from cryptography.hazmat.primitives import serialization
    try:
        key = serialization.load_pem_private_key(pem, None)
    except TypeError:
        return {"key_unread": "password_protected"}
    except Exception:  # noqa: BLE001 -- never raises: the corpus is edge cases
        return {"key_unread": "body_not_a_key"}
    return _key_fields(_key_info(key))


def _material(rel_path: str, raw: bytes) -> dict[str, Any]:
    """Parse what `cryptography` can: certificates by line, private keys by line, the
    blocks that did not parse, and which PEM blocks were certificates read in full."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12

    certs: list[tuple[int, str, dict[str, Any], list[str]]] = []
    keys: dict[int, dict[str, Any]] = {}
    problems: list[dict[str, Any]] = []
    parsed_blocks: set[int] = set()

    def add(line: int, excerpt: str, fmt: str, found: list[Any]) -> None:
        for index, cert in enumerate(found, start=1):
            try:
                described, families = describe_certificate(cert, fmt, index)
            except Exception:  # noqa: BLE001 -- parsed lazily; a field may still fail
                continue
            certs.append((line, excerpt, described, families))

    def problem(line: int, label: str, reason: str) -> None:
        problems.append({"path": rel_path, "line": line, "label": label, "reason": reason})

    text = raw.decode("utf-8", errors="replace")
    blocks = list(_PEM_BLOCK.finditer(text))
    for n, match in enumerate(blocks):
        label = match.group(1).strip()
        line = text.count("\n", 0, match.start()) + 1
        if label in _CERTIFICATE_LABELS or label == "PKCS7":
            try:
                body = base64.b64decode(match.group(2), validate=False)
                if label == "PKCS7":
                    found = pkcs7.load_der_pkcs7_certificates(body)
                else:
                    found = [x509.load_der_x509_certificate(
                        _first_tlv(body) if label == "TRUSTED CERTIFICATE" else body)]
            except Exception:  # noqa: BLE001 -- never raises: the corpus is edge cases
                problem(line, label, "not_parsed_as_pkcs7" if label == "PKCS7"
                        else "not_parsed_as_certificate")
                continue
            parsed_blocks.add(n)
            add(line, f"-----BEGIN {label}-----", "PKCS#7" if label == "PKCS7" else "PEM",
                found)
        elif _PRIVATE_KEY_LABEL.search(label) and label != "OPENSSH PRIVATE KEY":
            keys[line] = _load_private_key(match.group(0).encode())
            unread = keys[line].get("key_unread")
            if unread in ("password_protected", "body_not_a_key"):
                problem(line, label, "password_protected" if unread == "password_protected"
                        else "not_parsed_as_key")

    if not blocks and not text.lstrip().startswith("-----BEGIN"):
        suffix = os.path.splitext(rel_path)[1].lower()
        if raw[:4] in _JKS_MAGIC:
            problem(1, "JKS", "format_not_parsed")
        elif raw[:1] == b"\x30":
            for fmt, load in (("DER", lambda b: [x509.load_der_x509_certificate(b)]),
                              ("PKCS#7", pkcs7.load_der_pkcs7_certificates)):
                try:
                    found = load(raw)
                except Exception:  # noqa: BLE001
                    continue
                add(1, f"{fmt} certificate file", fmt, found)
                break
            else:
                if _iter_oids(raw) & _PKCS12_MARKERS:
                    try:
                        bundle = pkcs12.load_pkcs12(raw, None)
                    except Exception:  # noqa: BLE001
                        problem(1, "PKCS#12", "password_protected")
                    else:
                        found = ([bundle.cert.certificate] if bundle.cert else []) + [
                            c.certificate for c in bundle.additional_certs]
                        add(1, "PKCS#12 file", "PKCS#12", found)
                elif suffix in _CERTIFICATE_SUFFIXES and not _other_x509(raw):
                    problem(1, "DER", "not_parsed_as_certificate")
    return {"certificates": certs, "keys": keys, "problems": problems,
            "parsed_blocks": parsed_blocks}


_LAST_MATERIAL: list[Any] = [None, None, None]


def _material_once(rel_path: str, raw: bytes) -> dict[str, Any]:
    """One parse per file: the findings and the coverage ask about the same bytes."""
    if _LAST_MATERIAL[0] == rel_path and _LAST_MATERIAL[1] is raw:
        return _LAST_MATERIAL[2]
    try:
        result = _material(rel_path, raw)
    except Exception:  # noqa: BLE001 -- never raises
        result = {"certificates": [], "keys": {}, "problems": [], "parsed_blocks": set()}
    _LAST_MATERIAL[:] = [rel_path, raw, result]
    return result


def unparsed_material(path: Path, rel_path: str, raw: bytes | None = None) -> list[dict[str, Any]]:
    """The blocks and files that were read and did not parse, each with its reason."""
    if raw is None:
        raw = _read_bytes_once(path)
        if raw is None:
            return []
    return list(_material_once(rel_path, raw)["problems"])


# A PEM block written as string literals in code: `"-----BEGIN PRIVATE KEY-----\n"` and
# the body on the lines beneath, each in quotes (curl docs/examples/usercertinmem.c:67).
_LITERAL = re.compile(r'"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'')


def key_in_source(lines: list[str], index: int) -> dict[str, Any]:
    """Family and size of the private key whose header is on lines[index], or why not.
    Nothing when no whole block can be put together from the lines."""
    pieces: list[str] = []
    for line in lines[index:index + 200]:
        literals = [a or b for a, b in _LITERAL.findall(line)]
        piece = "".join(literals) if literals else line.strip()
        pieces.append(piece.replace("\\r", "").replace("\\n", "\n"))
        if "-----END" in piece:
            break
    match = _PEM_BLOCK.search("\n".join(pieces))
    if not match or not _PRIVATE_KEY_LABEL.search(match.group(1)) \
            or match.group(1).strip() == "OPENSSH PRIVATE KEY":
        return {}
    label, body = match.group(1), re.sub(r"\s+", "", match.group(2))
    return _load_private_key(
        f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n".encode())


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
    # What `cryptography` read (release C). A block it parsed as certificates is reported
    # from the parse, at its own line, and kept out of the identifier walk below.
    material = _material_once(rel_path, raw)
    found_blocks = False

    for n, match in enumerate(_PEM_BLOCK.finditer(text)):
        found_blocks = True
        label = match.group(1).strip()
        line_no = text.count("\n", 0, match.start()) + 1
        if n in material["parsed_blocks"]:
            continue

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
                **material["keys"].get(line_no, {}),
            })
        try:
            blobs.append(base64.b64decode(match.group(2), validate=False))
        except (ValueError, TypeError):
            continue
        if label == "RSA PUBLIC KEY":
            pkcs1_public.add(len(blobs) - 1)

    # A .der or .p12 is the same content without the armour -- unless it was parsed.
    if not blobs and not found_blocks and not material["certificates"] \
            and not text.lstrip().startswith("-----BEGIN"):
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

    # Each parsed certificate, at its own line (release C). After the two passes above,
    # which set one file-wide curve and size: a certificate's are its own.
    for line_no, excerpt, cert, families in material["certificates"]:
        algorithms.extend(_certificate_rows(rel_path, line_no, excerpt, cert, families))

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

    # PKCS#12's own algorithms, from the wrapper (see _PKCS12_PBE). After the key bag above,
    # which is said only when nothing else was. The SHA-1 identifier is named only in a file
    # that is PKCS#12 by its identifiers: there the bags are encrypted, and what is left in
    # clear is where the format names its MAC digest. Marked, so the file still counts as
    # not decoded: its contents were not read, only the wrapper.
    wrapper_oids = _iter_oids(raw)
    if wrapper_oids & _PKCS12_MARKERS:
        for oid in sorted(wrapper_oids & set(_PKCS12_PBE)):
            family, name = _PKCS12_PBE[oid]
            if family in seen:
                continue
            record(family, f"{family}: PKCS#12 bags encrypted with {name} ({oid}), named in "
                           f"the file's unencrypted wrapper", 1, oid, kind="reference")
            algorithms[-1]["pkcs12_wrapper"] = True
        if _SHA1_OID in wrapper_oids and "SHA1" not in seen:
            record("SHA1", f"SHA-1 object identifier {_SHA1_OID} in the unencrypted wrapper "
                           f"of a PKCS#12 file, where the format names its MAC digest",
                   1, _SHA1_OID, kind="reference")
            algorithms[-1]["pkcs12_wrapper"] = True

    return algorithms, keys


def is_undecoded(algorithms: list, keys: list) -> bool:
    """A claimed file that gave up nothing an algorithm can be named from. A PKCS#12
    wrapper's own encryption and MAC are not its contents."""
    return not [a for a in algorithms if not a.get("pkcs12_wrapper")] and not any(
        key.get("type") != "PKCS#12 shrouded key bag" for key in keys)
