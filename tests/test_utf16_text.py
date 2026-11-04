"""Rows 361 and 362 (04.11.2026): UTF-16 text the scan said it read.

361: a C# file written by .NET as UTF-16 LE with no byte-order mark -- "The GetBytes method
does not prepend a preamble to the beginning of a sequence of encoded bytes"
(https://learn.microsoft.com/en-us/dotnet/api/system.text.unicodeencoding.getbytes) -- with
Bulgarian comments and `RSA.Create(1024); MD5.Create();`. The NUL-share test wanted 90% of
the pairs; Cyrillic puts 0x04 there, the file decoded as UTF-8 noise, and nothing was found.

362: a PEM certificate saved by PowerShell: "Out-File and the redirection operators > and >>
create UTF-16LE"
(https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_character_encoding?view=powershell-5.1).
The certificate reader decoded every file as UTF-8, found no block, and the verdict said read."""

from __future__ import annotations

import shutil
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "b042"


def test_utf16_without_bom_and_with_cyrillic_is_read(tmp_path):
    from qrp_mcp.scan import scan_directory
    shutil.copy(FIXTURES / "keys-utf16-nobom-cyrillic.cs", tmp_path / "keys.cs")
    found = {e["algorithm"] for e in scan_directory(tmp_path)["evidence"]["source_code"]}
    assert {"RSA", "MD5"} <= found


def test_binary_with_nul_on_both_sides_is_not_taken_for_utf16():
    from qrp_mcp.certificates import decode_text
    raw = bytes(range(256)) * 4
    assert decode_text(raw) == raw.decode("utf-8", errors="ignore")


def test_pem_certificate_saved_as_utf16_is_parsed(tmp_path):
    from qrp_mcp.scan import scan_directory
    pem = (FIXTURES / "forti-cert.conf").read_text()
    block = pem[pem.index("-----BEGIN"):pem.index("-----END CERTIFICATE-----") + 25]
    for name in ("web01.pem", "web01.crt"):
        (tmp_path / name).write_bytes(b"\xff\xfe" + (block + "\r\n").encode("utf-16-le"))
    result = scan_directory(tmp_path)
    certs = {(e["path"], e["algorithm"], e["key_size"])
             for e in result["evidence"]["source_code"] if e.get("certificate")}
    assert certs == {("web01.pem", "RSA", 2048), ("web01.crt", "RSA", 2048)}
    assert result["claimed_but_not_decoded"] == []
