"""ZA-OPRAVYANE row 202 (LinkedIn, 04.11.2026; fixture from the room's probe `sb-swift`).

IBM MQ `.mqsc` scripts were `type_not_claimed`, so `SSLCIPH('TLS_RSA_WITH_AES_256_CBC_SHA256')`
-- static RSA key exchange on a channel -- was not seen. `.mqsc` is now a claimed configuration
type and its CipherSpec read as the IANA suite name it is. An empty `SSLCIPH(' ')` (a channel
without TLS) is not read as anything; that is said in the README, not detected."""

from __future__ import annotations

import shutil
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures" / "row-202" / "channels.mqsc"


def test_mqsc_cipherspec_gives_rsa_key_establishment(tmp_path):
    from qrp_mcp.scan import scan_directory
    shutil.copy(FIXTURE, tmp_path / "channels.mqsc")
    result = scan_directory(tmp_path)
    assert "channels.mqsc" in result["files_read"]
    rows = [e for e in result["evidence"]["source_code"] if e["algorithm"] == "RSA"]
    assert [(e["line"], e["role"]) for e in rows] == [(1, "key_establishment")]
    assert ".mqsc" in result["coverage"]["instrument"]["claimed_types"]["config"]
