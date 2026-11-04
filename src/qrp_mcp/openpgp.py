"""OpenPGP keys (`.asc`, `.gpg`, `.pgp` and armored key blocks; ZA-OPRAVYANE row 337), read
from their packets as RFC 9580 lays them out (https://www.rfc-editor.org/rfc/rfc9580):

* 4.2: the first octet's bit 6 tells the OpenPGP format ("Bits 5 to 0 -- Packet Type ID") from
  the Legacy one ("Bits 5 to 2 -- Packet Type ID", "Bits 1 to 0 -- length-type"); 4.2.1 and
  4.2.2 give the lengths.
* Table 3: "5 Secret Key Packet", "6 Public Key Packet", "7 Secret Subkey Packet",
  "14 Public Subkey Packet".
* 5.5.2.2: a version 4 key is "A 1-octet version number (4)", "A 4-octet number denoting the
  time that the key was created", "A 1-octet number denoting the public key algorithm of the
  key", then the key material; version 6 adds a 4-octet count of it (5.5.2.3).
* 9.1: algorithm 1, 2, 3 RSA, 16 Elgamal, 17 DSA, 18 ECDH, 19 ECDSA, 22 EdDSALegacy,
  25 X25519, 26 X448, 27 Ed25519, 28 Ed448. 3.2: an MPI is "a 2-octet scalar that is the
  length of the MPI in bits", so the first MPI of an RSA key (n) or a DSA or Elgamal key (p)
  is its size. 9.2: the curve OIDs of ECDH, ECDSA and EdDSALegacy keys.

A key whose packets do not parse is named as not decoded; partial body lengths (4.2.1.4) are
used only for data packets, never keys, and end the reading.
"""

from __future__ import annotations

import base64
import re
from typing import Any

KEY_EXTENSIONS = {".asc", ".gpg", ".pgp"}
_KEY_TAGS = {5: "secret key", 6: "public key", 7: "secret subkey", 14: "public subkey"}
_ALGORITHMS = {1: "RSA", 2: "RSA", 3: "RSA", 16: "ElGamal", 17: "DSA", 18: "ECDH",
               19: "ECDSA", 22: "EdDSA", 25: "X25519", 26: "X448", 27: "Ed25519", 28: "Ed448"}
_CURVES = {bytes.fromhex("2A8648CE3D030107"): ("P-256", 256),
           bytes.fromhex("2B81040022"): ("P-384", 384),
           bytes.fromhex("2B81040023"): ("P-521", 521),
           bytes.fromhex("2B2403030208010107"): ("brainpoolP256r1", 256),
           bytes.fromhex("2B240303020801010B"): ("brainpoolP384r1", 384),
           bytes.fromhex("2B240303020801010D"): ("brainpoolP512r1", 512),
           bytes.fromhex("2B06010401DA470F01"): ("Ed25519", None),
           bytes.fromhex("2B060104019755010501"): ("Curve25519", None)}
_ARMOR = re.compile(rb"-----BEGIN PGP (?:PUBLIC|PRIVATE) KEY BLOCK-----\r?\n(.*?)"
                    rb"-----END PGP (?:PUBLIC|PRIVATE) KEY BLOCK-----", re.S)


def _packets(data: bytes) -> list[tuple[int, bytes]] | None:
    """(tag, body) of each packet; None when the bytes are not OpenPGP packets."""
    out: list[tuple[int, bytes]] = []
    i = 0
    while i < len(data):
        first = data[i]
        if not first & 0x80:
            return None
        if first & 0x40:
            tag, i = first & 0x3F, i + 1
            if i >= len(data):
                return None
            o = data[i]
            if o < 192:
                length, i = o, i + 1
            elif o < 224:
                if i + 1 >= len(data):
                    return None
                length, i = ((o - 192) << 8) + data[i + 1] + 192, i + 2
            elif o == 255:
                length, i = int.from_bytes(data[i + 1:i + 5], "big"), i + 5
            else:
                return out or None          # partial length: a data packet, not a key
        else:
            tag, kind, i = (first >> 2) & 0x0F, first & 0x03, i + 1
            if kind == 3:
                length = len(data) - i
            else:
                size = (1, 2, 4)[kind]
                length, i = int.from_bytes(data[i:i + size], "big"), i + size
        if i + length > len(data):
            return None
        out.append((tag, data[i:i + length]))
        i += length
    return out


def _key(body: bytes) -> dict[str, Any] | None:
    if len(body) < 6 or body[0] not in (4, 6):
        return None
    algorithm = _ALGORITHMS.get(body[5])
    if algorithm is None:
        return {"algorithm_id": body[5]}
    material = body[10:] if body[0] == 6 else body[6:]
    item: dict[str, Any] = {"family": algorithm, "algorithm_id": body[5]}
    if algorithm in ("RSA", "DSA", "ElGamal") and len(material) >= 2:
        item["key_size"] = int.from_bytes(material[:2], "big")
    elif algorithm in ("ECDH", "ECDSA", "EdDSA") and material:
        curve = _CURVES.get(material[1:1 + material[0]])
        if curve:
            item["curve"], size = curve
            if size:
                item["key_size"] = size
            # The scan's families for the 25519 curves (as an Ed25519 or X25519 key is named
            # everywhere else).
            item["family"] = {("EdDSA", "Ed25519"): "Ed25519",
                              ("ECDH", "Curve25519"): "X25519"}.get((algorithm, item["curve"]),
                                                                    algorithm)
    return item


def keys(raw: bytes) -> list[dict[str, Any]] | None:
    """The keys of an OpenPGP file, armored or binary; None when it does not decode."""
    blobs = []
    if b"-----BEGIN PGP" in raw:
        for match in _ARMOR.finditer(raw):
            parts = re.split(rb"\r?\n[ \t]*\r?\n", match.group(1), maxsplit=1)
            text = parts[-1]                # after the armor headers and their blank line
            body = b"".join(line.strip() for line in text.splitlines()
                            if line.strip() and not line.startswith(b"="))
            try:
                blobs.append(base64.b64decode(body, validate=True))
            except (ValueError, TypeError):
                return None
    else:
        blobs.append(raw)
    out: list[dict[str, Any]] = []
    for blob in blobs:
        packets = _packets(blob)
        if packets is None:
            return None
        for tag, body in packets:
            if tag in _KEY_TAGS:
                key = _key(body)
                if key is None:
                    return None
                out.append({**key, "packet": _KEY_TAGS[tag]})
    return out or None


def scan(rel_path: str, raw: bytes) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(algorithm rows, secret key rows); both empty when the file does not decode."""
    found = keys(raw)
    rows: list[dict[str, Any]] = []
    secrets: list[dict[str, Any]] = []
    for key in found or []:
        family = key.get("family")
        if family is None:
            continue
        size = f", {key['key_size']} bits" if "key_size" in key else ""
        curve = f", curve {key['curve']}" if "curve" in key else ""
        row = {"path": rel_path, "line": 1, "algorithm": family, "evidence_kind": "declaration",
               "excerpt": f"OpenPGP {key['packet']} packet, algorithm {key['algorithm_id']}",
               "description": (f"{family} in an OpenPGP {key['packet']} (RFC 9580 algorithm "
                               f"{key['algorithm_id']}{size}{curve})")}
        for field in ("key_size", "curve"):
            if field in key:
                row[field] = key[field]
        rows.append(row)
        if key["packet"].startswith("secret"):
            secrets.append({"path": rel_path, "line": 1, "type": f"OpenPGP {key['packet']}",
                            "description": f"private key material in an OpenPGP {key['packet']}",
                            "key_algorithm": family,
                            **({"key_size": key["key_size"]} if "key_size" in key else {})})
    return rows, secrets
