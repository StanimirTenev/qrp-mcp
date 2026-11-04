""".NET strong-name key files (ZA-OPRAVYANE row 311; fixture L1/f13-snk). `.snk` was type not
claimed on 0.41.0. The layout, from Microsoft Learn:

* https://learn.microsoft.com/en-us/windows/win32/seccrypto/base-provider-key-blobs -- a
  private key BLOB is PUBLICKEYSTRUC, RSAPUBKEY, `modulus[rsapubkey.bitlen/8]`, five
  `[rsapubkey.bitlen/16]` fields and `privateExponent[rsapubkey.bitlen/8]`; "All values are
  in little-endian format."
* https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-rsapubkey -- magic
  "Set to RSA1 (0x31415352) for public keys and to RSA2 (0x32415352) for private keys";
  bitlen "Number of bits in the modulus."
* https://learn.microsoft.com/en-us/dotnet/framework/tools/sn-exe-strong-name-tool -- `sn -k`
  "Generates a new RSACryptoServiceProvider key of the specified size and writes it to the
  specified file. Both a public and private key are written to the file."
"""

import os
import struct

from qrp_mcp.scan import scan_directory


def _blob(bits, private=True):
    header = bytes([0x07 if private else 0x06, 0x02, 0, 0]) + struct.pack("<I", 0x2400)
    rsapubkey = (b"RSA2" if private else b"RSA1") + struct.pack("<II", bits, 65537)
    body = os.urandom(9 * bits // 16 if private else bits // 8)
    return header + rsapubkey + body


def test_private_key_pair(tmp_path):
    (tmp_path / "key.snk").write_bytes(_blob(1024))
    result = scan_directory(tmp_path)
    assert result["files_read"] == ["key.snk"]
    [row] = result["evidence"]["source_code"]
    assert (row["algorithm"], row["key_size"]) == ("RSA", 1024)
    [key] = result["evidence"]["embedded_keys"]
    assert (key["key_algorithm"], key["key_size"]) == ("RSA", 1024)
    assert 1024 in result["algorithm_key_sizes_observed"]["RSA"]


def test_public_key_blob(tmp_path):
    (tmp_path / "pub.snk").write_bytes(_blob(2048, private=False))
    result = scan_directory(tmp_path)
    assert [(r["algorithm"], r["key_size"]) for r in result["evidence"]["source_code"]] == [("RSA", 2048)]
    assert result["evidence"]["embedded_keys"] == []


def test_a_file_that_is_not_the_layout_is_named_not_decoded(tmp_path):
    (tmp_path / "odd.snk").write_bytes(_blob(1024)[:-7])
    result = scan_directory(tmp_path)
    assert result["evidence"]["source_code"] == []
    assert result["claimed_but_not_decoded"] == ["odd.snk"]
