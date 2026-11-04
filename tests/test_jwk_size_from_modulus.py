"""Row 331 (04.11.2026): a JWKS key's size read from its `kid` label.

`"kid": "rsa4096"` on a 1024-bit modulus gave RSA 4096 with high confidence, and the key was
not weak. `kid` is a free label: "The "kid" (key ID) parameter is used to match a specific
key" (RFC 7517 §4.5, https://www.rfc-editor.org/rfc/rfc7517#section-4.5). The size is the
modulus: "The "n" (modulus) parameter contains the modulus value for the RSA public key"
(RFC 7518 §6.3.1.1, https://www.rfc-editor.org/rfc/rfc7518#section-6.3.1.1)."""

from __future__ import annotations

import shutil
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "b042"


def test_size_comes_from_n_not_from_kid(tmp_path):
    from qrp_mcp.scan import scan_directory
    shutil.copy(FIXTURES / "jwks-kid.json", tmp_path / "jwks.json")
    result = scan_directory(tmp_path)
    rsa = {e["line"]: e.get("key_size") for e in result["evidence"]["source_code"]
           if e["algorithm"] == "RSA"}
    assert 5 not in rsa  # the kid line names nothing
    assert rsa[4] == 1024 and rsa[12] == 2048
    assert result["algorithm_key_sizes_observed"]["RSA"] == [1024, 2048]
    assert 4096 not in result["algorithm_key_sizes_observed"]["RSA"]
    assert result["summary"]["weak_count"] >= 1
