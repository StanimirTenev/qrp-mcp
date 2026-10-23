"""Java keystores are read (ZA-OPRAVYANE row 84, swarm C of 22.10.2026, `roy-2026-10-22/
c-korpus` test_c6: spring-security-samples' server.jks, 65 SHA1withRSA and 4 MD5withRSA
certificates, unread).

A JKS keeps its certificates in clear DER (magic 0xFEEDFEED; only the integrity check needs
the password), so their identifiers read like a .der's. The fixture is the swarm's own
keystore (fixtures/r6-jks, written by keytool; no repository file copied).
"""

import base64
from pathlib import Path

import pytest

from qrp_mcp.scan import scan_directory

FIXTURE = Path(__file__).parent / "fixtures" / "server.jks.b64"


@pytest.mark.parametrize("name", ["server.jks", "debug.keystore"])
def test_keystore_is_read(tmp_path, name):
    (tmp_path / name).write_bytes(base64.b64decode(FIXTURE.read_text()))
    result = scan_directory(tmp_path)
    assert name in result["files_read"]
    assert "RSA" in result["detected_algorithms"]
    assert result["algorithm_key_sizes"].get("RSA") == 2048
