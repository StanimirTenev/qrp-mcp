"""COSE algorithm identifiers in WebAuthn and mdoc requests (ZA-OPRAVYANE row 87, swarm C of
22.10.2026, `roy-2026-10-22/c-korpus` test_c9: identity-samples, where ECDSA was seen only in
the comment `// ES256`). Numbers from IANA's COSE Algorithms registry (algorithms.csv,
read 23.10.2026). A bare `"alg": -7` stays a number: the line has to say COSE or public-key.
"""

import pytest

from qrp_mcp.scan import scan_directory


@pytest.mark.parametrize("family, line", [
    ("ECDSA", '  "pubKeyCredParams": [{"type": "public-key", "alg": -7}],'),
    ("RSA", "    { type: 'public-key', alg: -257 },"),
    ("Ed25519", '{"type": "public-key", "alg": -19}'),
])
def test_cose_id(tmp_path, family, line):
    (tmp_path / "Request.kt").write_text(line + "\n", encoding="utf-8")
    assert family in scan_directory(tmp_path)["detected_algorithms"]


def test_a_bare_number_is_not_an_algorithm(tmp_path):
    (tmp_path / "a.json").write_text('{"alg": -7, "offset": 3}\n', encoding="utf-8")
    assert "ECDSA" not in scan_directory(tmp_path)["detected_algorithms"]
