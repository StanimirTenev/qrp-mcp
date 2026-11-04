""".NET strong-name key files (`.snk`, ZA-OPRAVYANE row 311), read from their bytes.

`sn -k` "Generates a new RSACryptoServiceProvider key of the specified size and writes it to
the specified file. Both a public and private key are written to the file."
(https://learn.microsoft.com/en-us/dotnet/framework/tools/sn-exe-strong-name-tool). The file
is a CryptoAPI key BLOB (https://learn.microsoft.com/en-us/windows/win32/seccrypto/base-provider-key-blobs):
a PUBLICKEYSTRUC (8 bytes), an RSAPUBKEY whose `magic` is "RSA1 (0x31415352) for public keys
and ... RSA2 (0x32415352) for private keys" and whose `bitlen` is the "Number of bits in the
modulus" (https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-rsapubkey),
then the modulus (bitlen/8 bytes) and, in a private BLOB, five halves and the private
exponent. A file is decoded only when its length is exactly that layout's; any other file
(the 12-byte-prefixed public key `sn -p` writes, an encrypted BLOB) is named as not decoded.
"""

from __future__ import annotations

import struct
from typing import Any

_PUBLIC, _PRIVATE = 0x06, 0x07


def decode(raw: bytes) -> dict[str, Any] | None:
    """{"private": bool, "bits": int} for a plain RSA key BLOB; None for anything else."""
    if len(raw) < 20 or raw[0] not in (_PUBLIC, _PRIVATE):
        return None
    magic, bits = raw[8:12], struct.unpack_from("<I", raw, 12)[0]
    if bits == 0 or bits % 16:
        return None
    if raw[0] == _PRIVATE and magic == b"RSA2" and len(raw) == 20 + 9 * bits // 16:
        return {"private": True, "bits": bits}
    if raw[0] == _PUBLIC and magic == b"RSA1" and len(raw) == 20 + bits // 8:
        return {"private": False, "bits": bits}
    return None


def scan(rel_path: str, raw: bytes) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(algorithm rows, private key rows) of one .snk; both empty when it does not decode."""
    key = decode(raw)
    if key is None:
        return [], []
    kind = "private and public key" if key["private"] else "public key"
    row = {"path": rel_path, "line": 1, "algorithm": "RSA", "key_size": key["bits"],
           "description": (f"RSA {key['bits']}-bit strong-name {kind} (.snk, CryptoAPI "
                           f"{'RSA2' if key['private'] else 'RSA1'} key BLOB): the key a .NET "
                           f"assembly's strong-name signature is made with"),
           "excerpt": f".snk {'RSA2' if key['private'] else 'RSA1'} BLOB, bitlen {key['bits']}",
           "evidence_kind": "declaration"}
    keys = ([{"path": rel_path, "line": 1, "type": "strong-name key pair (.snk)",
              "description": "private key material in a .NET strong-name key pair",
              "key_algorithm": "RSA", "key_size": key["bits"]}] if key["private"] else [])
    return [row], keys
